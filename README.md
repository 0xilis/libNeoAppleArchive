# libNeoAppleArchive
Unfinished cross-compat library for parsing Apple Archive (and, by extension, YAA).

### What isn't finished:

- Any archive with a type other than directory, regular file or symlink. Be aware this is rare however.
- Readable code, the current version is stable but could be easier to read.
- LZMA, LZ4, ZLIB compressed `.aar`s; only `RAW` and `LZFSE` are currently supported.
- Multi-Threadded support.

### What is:

Limited functions for messing around with headers and extracting apple archives. There are functions for manually creating apple archives (or modifying existing ones), however there currently is no functions for easy archiving of a directory from a file path. Do be aware that it should be possible to do this though with the provided functions in the library. YAA is also supported, as it is just legacy Apple Archive, and all YAA files are just Apple Archives with a different header essentially.

### Compatibility:

- macOS
- Linux

# NOTE

This is not a reimplementation of libAppleArchive, rather it's own library, created from the ground up. It is not compatible with libAppleArchive APIs, look at the header and code for clues. There is also docs available at `docs/` for types and functions.

liblzfse is owned by Apple Inc. Find it here: [https://github.com/lzfse/lzfse](https://github.com/lzfse/lzfse).
