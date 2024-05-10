# libNeoAppleArchive
Bad unfinished cross-compat library for parsing Apple Archive

### What isn't finished:

- Any archive with a type other than directory, regular file or symlink.
- Most file attributes, ex CTM (creation time) will be ignored.
- Well written code, because this is extremely hard to read right now.
- LZFSE, LZMA, LZ4, ZLIB compressed `.aar`s; only RAW is currently supported.
- Multi-Threadded support.

### What is:

- Extremely limited functions for messing around with headers and extracting apple archives. There are functions for manually creating apple archives (or modifying existing ones), however there currently is no functions for easy archiving of a directory from a file path.

### Compatibility:

- macOS
- Linux

# NOTE

This is not a reimplementation of libAppleArchive, rather it's own library, created from the ground up. It is not compatible with libAppleArchive APIs, look at the header and code for clues. There is also docs available at `docs/` for types and functions.
