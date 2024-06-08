# libNeoAppleArchive
Unfinished cross-compat library for parsing Apple Archive (and, by extension, YAA).

### What isn't finished:

- Any archive with a type other than directory, regular file or symlink. Be aware this is rare however.
- Readable code, the current version is stable but could be easier to read.
- LZMA and LZ4 compressed `.aar`s; only `RAW`, `LZFSE`, and `ZLIB` are currently supported.
- Multi-Threadded support.

### What is:

Limited functions for messing around with headers and extracting apple archives. There are functions for manually creating apple archives (or modifying existing ones), however there currently is no functions for easy archiving of a directory from a file path. Do be aware that it should be possible to do this though with the provided functions in the library. YAA is also supported, as it is just legacy Apple Archive, and all YAA files are just Apple Archives with a different header essentially.

### Roadmap:

- Support all compression types for Apple Archive
- Support AEA, at least the `AEA_PROFILE__HKDF_SHA256_HMAC__NONE__ECDSA_P256` profile.
- Convienience functions for archiving / extracting files and directories.
- Making code more readable
- CLI for macOS/Linux (Will be on a seperate repo)
- GUI for Windows/macOS/Linux (If this happens, this won't be for a while, just an fyi)
- Native Windows support (While planned, do be aware this is at the bottom of the list of the roadmap).
  
### Compatibility:

- Most Darwin Operating Systems (macOS, iOS, watchOS, visionOS etc.) 
- Linux

# NOTE

This is not a reimplementation of libAppleArchive, rather it's own library, created from the ground up. It is not compatible with libAppleArchive APIs, look at the header and code for clues. There is also docs available at `docs/` for types and functions.

liblzfse is owned by Apple Inc. Find it here: [https://github.com/lzfse/lzfse](https://github.com/lzfse/lzfse). Currently a compiled version is statically linked at libNeoAppleArchive/compression/lzfse/lzfse.a for macOS, but you can just compile it yourself on Linux and replace it. In the future, it will be a submodule rather than pre-compiled.

ZLIB is not linked in the final executable line liblzfse but rather dynamically linked, as it is already on the OS itself.
