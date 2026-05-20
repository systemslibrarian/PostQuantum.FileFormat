# Manual pages

`pqf.1` is the manual page for the `pqf` CLI, in mdoc / groff format.

## Preview locally

```bash
mandoc man/pqf.1 | less        # BSD-style; on macOS by default
groff -man -Tutf8 man/pqf.1 | less   # GNU-style; on Linux
```

## Why

A man page is a small but real signal that a project is meant to be
*used*, not just *demoed*. Distro packagers expect one; users
discovering the tool via `man pqf` after a homebrew install expect
one; the absence of one is a tell.

The page targets the same flag surface as `pqf --help` plus the
exit-code and security caveats that don't fit in CLI help.

## Installation (distro packagers)

`pqf.1` should land at `${prefix}/share/man/man1/pqf.1` for both
Homebrew and Debian-style packaging.
