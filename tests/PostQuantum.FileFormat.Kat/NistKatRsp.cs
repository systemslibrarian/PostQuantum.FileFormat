namespace PostQuantum.FileFormat.Kat;

/// <summary>
/// Minimal parser for the NIST KAT .rsp file format used by the PQC
/// reference implementations. The format is a sequence of records
/// separated by blank lines; each record is `key = hexvalue` lines.
/// A leading `count =` line is the record's index.
/// </summary>
internal sealed class NistKatRsp
{
    public int Count { get; init; }
    public IReadOnlyDictionary<string, string> Fields { get; init; } = null!;

    public byte[] Hex(string key) => Convert.FromHexString(Fields[key]);

    public static IEnumerable<NistKatRsp> Parse(string path)
    {
        Dictionary<string, string>? current = null;
        int count = -1;

        foreach (var raw in File.ReadLines(path))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
            {
                if (current is not null && current.Count > 0)
                {
                    yield return new NistKatRsp { Count = count, Fields = current };
                    current = null;
                    count = -1;
                }
                continue;
            }

            var eq = line.IndexOf('=');
            if (eq <= 0) continue;
            var key = line[..eq].Trim();
            var value = line[(eq + 1)..].Trim();

            if (key.Equals("count", StringComparison.OrdinalIgnoreCase))
            {
                if (current is not null && current.Count > 0)
                {
                    yield return new NistKatRsp { Count = count, Fields = current };
                }
                current = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                count = int.Parse(value);
                continue;
            }

            current ??= new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            current[key] = value;
        }

        if (current is not null && current.Count > 0)
        {
            yield return new NistKatRsp { Count = count, Fields = current };
        }
    }
}
