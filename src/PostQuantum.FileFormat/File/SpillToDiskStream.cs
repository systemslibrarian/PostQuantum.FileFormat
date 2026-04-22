using PostQuantum.FileFormat.Crypto;

namespace PostQuantum.FileFormat.File;

/// <summary>
/// Read/write stream that starts in memory and transparently spills to a
/// 0600-mode <see cref="FileStream"/> with <see cref="FileOptions.DeleteOnClose"/>
/// once a configured threshold of bytes has been written. Used by
/// <see cref="AuthenticatedModeDecryptor"/> to stage plaintext until the
/// file signature has been verified, without imposing an a-priori size
/// ceiling.
///
/// Security properties:
///   * The on-disk spill file is created with mode 0600 on Unix so that
///     other users on a multi-user host cannot read the staged plaintext.
///   * <see cref="FileOptions.DeleteOnClose"/> removes the file even if
///     the process is killed mid-decrypt and never reaches the dispose
///     path.
///   * The file path is returned via <see cref="TempFilePath"/> for
///     defense-in-depth manual cleanup by the caller.
/// </summary>
internal sealed class SpillToDiskStream : Stream
{
    private readonly long _threshold;
    private MemoryStream? _memory;
    private FileStream? _file;
    private long _position;
    private bool _disposed;

    public SpillToDiskStream(long thresholdBytes)
    {
        if (thresholdBytes < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(thresholdBytes));
        }
        _threshold = thresholdBytes;
        _memory = new MemoryStream();
    }

    public string? TempFilePath { get; private set; }

    public override bool CanRead => true;
    public override bool CanSeek => true;
    public override bool CanWrite => true;

    public override long Length => _file?.Length ?? _memory!.Length;

    public override long Position
    {
        get => _file?.Position ?? _memory!.Position;
        set
        {
            if (_file is not null)
            {
                _file.Position = value;
            }
            else
            {
                _memory!.Position = value;
            }
            _position = value;
        }
    }

    public override void Flush()
    {
        _file?.Flush();
        _memory?.Flush();
    }

    public override Task FlushAsync(CancellationToken cancellationToken)
    {
        if (_file is not null)
        {
            return _file.FlushAsync(cancellationToken);
        }
        return _memory!.FlushAsync(cancellationToken);
    }

    public override int Read(byte[] buffer, int offset, int count) =>
        _file is not null ? _file.Read(buffer, offset, count) : _memory!.Read(buffer, offset, count);

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
        _file is not null ? _file.ReadAsync(buffer, cancellationToken) : _memory!.ReadAsync(buffer, cancellationToken);

    public override long Seek(long offset, SeekOrigin origin) =>
        _file is not null ? _file.Seek(offset, origin) : _memory!.Seek(offset, origin);

    public override void SetLength(long value)
    {
        if (_file is not null)
        {
            _file.SetLength(value);
        }
        else
        {
            _memory!.SetLength(value);
        }
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        EnsureCapacity(count);
        if (_file is not null)
        {
            _file.Write(buffer, offset, count);
        }
        else
        {
            _memory!.Write(buffer, offset, count);
        }
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        await EnsureCapacityAsync(buffer.Length, cancellationToken).ConfigureAwait(false);
        if (_file is not null)
        {
            await _file.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            await _memory!.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
        }
    }

    private void EnsureCapacity(int incoming)
    {
        if (_file is not null) return;
        var projected = _memory!.Length + incoming;
        if (projected > _threshold)
        {
            SpillSync();
        }
    }

    private async ValueTask EnsureCapacityAsync(int incoming, CancellationToken ct)
    {
        if (_file is not null) return;
        var projected = _memory!.Length + incoming;
        if (projected > _threshold)
        {
            await SpillAsync(ct).ConfigureAwait(false);
        }
    }

    private void SpillSync()
    {
        var (file, path) = CreateSpillFile();
        var memBytes = _memory!.ToArray();
        file.Write(memBytes, 0, memBytes.Length);
        file.Position = _memory.Position;
        SecureZero.Clear(memBytes);
        _memory.Dispose();
        _memory = null;
        _file = file;
        TempFilePath = path;
    }

    private async Task SpillAsync(CancellationToken ct)
    {
        var (file, path) = CreateSpillFile();
        var memBytes = _memory!.ToArray();
        await file.WriteAsync(memBytes.AsMemory(), ct).ConfigureAwait(false);
        file.Position = _memory.Position;
        SecureZero.Clear(memBytes);
        await _memory.DisposeAsync().ConfigureAwait(false);
        _memory = null;
        _file = file;
        TempFilePath = path;
    }

    private static (FileStream file, string path) CreateSpillFile()
    {
        var path = Path.Combine(Path.GetTempPath(), $"pqf-auth-{Guid.NewGuid():N}.tmp");
        var options = new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.ReadWrite,
            Share = FileShare.None,
            BufferSize = 4096,
            Options = FileOptions.SequentialScan | FileOptions.DeleteOnClose,
        };
        if (!OperatingSystem.IsWindows())
        {
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        }
        var file = new FileStream(path, options);
        return (file, path);
    }

    protected override void Dispose(bool disposing)
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        if (disposing)
        {
            _memory?.Dispose();
            _file?.Dispose();
            TryDeleteTempFile();
        }
        base.Dispose(disposing);
    }

    public override async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        if (_memory is not null)
        {
            await _memory.DisposeAsync().ConfigureAwait(false);
        }
        if (_file is not null)
        {
            await _file.DisposeAsync().ConfigureAwait(false);
        }
        TryDeleteTempFile();
        await base.DisposeAsync().ConfigureAwait(false);
    }

    private void TryDeleteTempFile()
    {
        if (TempFilePath is null) return;
        try
        {
            System.IO.File.Delete(TempFilePath);
        }
        catch (FileNotFoundException)
        {
            // Expected: DeleteOnClose already removed it.
        }
        catch
        {
            // Best-effort cleanup.
        }
    }
}
