# zip-audit

A single file, dependency free checker that reads a zip archive's central directory and reports the things that make extracting an untrusted archive dangerous: entries that climb out of the target directory, entries that are symlinks, duplicate and case colliding names, encrypted members and zip bombs.

It never decompresses anything, so it is safe to point at a hostile file and it finishes in milliseconds no matter how large the archive claims to be. That also means it cannot tell you whether the payload is corrupt, only whether the archive's structure is trying to trick your extractor.

## What it checks

- `path-traversal` (high) - an entry name contains a `..` segment, so a naive extractor writes outside the destination directory.
- `absolute-path` (high) - an entry name starts with `/`, `\`, or a drive letter such as `C:`.
- `symlink-entry` (high) - the entry's unix mode says symbolic link, which lets a two step extraction plant a link to `/etc/shadow` and then write through it.
- `compression-ratio` (high) - one entry expands more than the ratio limit (default 100x) from at least 1 MiB of claimed output, or claims output while its compressed size is zero.
- `total-size` (high) - the sum of every declared uncompressed size is over the limit (default 1 GiB).
- `duplicate-entry` and `case-collision` (medium) - the same name twice, or two names that differ only by case, which is how a file gets overwritten on a case insensitive filesystem.
- `entry-count` (medium) - more entries than the limit (default 20000), a cheap way to exhaust inodes.
- `encrypted-entry` (low) - the general purpose flag says the member is encrypted, so its real contents are opaque to any scan you run afterwards.
- `backslash-separator` and `directory-with-data` (low) - windows style separators and directory entries that also carry file data.

## Usage

```
python3 -m zip_audit archive.zip
python3 -m zip_audit downloads/*.zip --quiet
python3 -m zip_audit suspicious.zip --json
python3 -m zip_audit big.zip --max-ratio 50 --max-uncompressed-mib 256
```

There is nothing to install, the package is standard library only and runs on Python 3.8 and later from the repository root. A sample run against a deliberately hostile archive looks like this.

```
/tmp/demo-hostile.zip: 5 entries, 8236 compressed to 8388689 expanded bytes
  [HIGH] path-traversal ../../.ssh/authorized_keys: entry name climbs above the extraction root with ..
  [HIGH] absolute-path /etc/cron.d/persist: entry name starts at the filesystem root
  [HIGH] compression-ratio bomb.bin: expands 1028x (8157 to 8388608 bytes)
  [HIGH] symlink-entry innocent.txt: entry is a symlink and may escape the extraction directory
  totals: 4 high, 0 medium, 0 low
```

## Exit codes

- `0` - every archive was readable and clean.
- `1` - at least one finding was reported.
- `2` - at least one path could not be opened as a zip archive. Findings from the other paths are still printed.

The JSON mode prints a list of report objects with `path`, `entries`, `compressed_bytes`, `uncompressed_bytes`, `worst`, `counts` and a `findings` array, so it drops straight into a CI step or a pre-extraction hook.

## Deliberate limits

Only zip is supported. Tar, 7z and rar need their own parsers and pretending otherwise would be worse than saying no. The archive is examined through the central directory and members are never expanded, so the size and ratio numbers are the values the archive declares; a crafted file can lie about them, and a lying archive is itself a finding worth having. Overlapping entries that share byte ranges inside the file are not detected yet, and neither is a central directory that has been edited to hide a second set of entries.

## Tests

```
python3 -m unittest discover -s tests -v
```

Twenty three tests build every sample archive in a temporary directory, including a real zip bomb, a real symlink entry and a deliberately truncated file, so no fixture binaries live in the repository.
