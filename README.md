# libNeoAppleArchive
Bad unfinished cross-compat library for parsing Apple Archive

### What isn't finished:

- Any archive with a type other than directory, regular file or symlink.
- Most file attributes, ex CTM (creation time) will be ignored.
- Well written code, because this is extremely hard to read right now.
- LZFSE, LZMA, LZ4, ZLIB compressed `.aar`s; only RAW is currently supported.

### What is:

- Extremely limited functions for messing around with headers and extracting apple archives.

### Compatibility:

- macOS
- Linux
