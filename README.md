# libNeoAppleArchive
Unfinished cross-compat library for parsing Apple Archive (and, by extension, YAA).

### What isn't finished
- Any archive with a type other than directory, regular file or symlink. Be aware this is rare however for user created `.aar`s
- LZMA and LZ4 compressed `.aar`s; only `RAW`, `LZFSE`, and `ZLIB` are currently supported
- Multi-Threadded support

### What is
Functions for messing around with headers and extracting apple archives. There are functions for manually creating apple archives (or modifying existing ones), however there currently is no functions for easy archiving of a directory from a file path. Do be aware that it should be possible to do this though with the provided functions in the library. YAA is also supported, as it is just legacy Apple Archive, and all YAA files are just Apple Archives with a different magic essentially.

### Roadmap
- [ ] Support all compression types for Apple Archive (partially complete)
- [x] Support AEA, at least the `AEA_PROFILE__HKDF_SHA256_HMAC__NONE__ECDSA_P256` and `AEA_PROFILE__HKDF_SHA256_AESCTR_HMAC__SYMMETRIC__NONE` profiles.
- [ ] An "IPSWDecrypt" CLI tool for Linux and Darwin platforms that can decrypt IPSW/OTA AEAs.
- [ ] Convienience functions for archiving / extracting files and directories.
- [ ] Making code more readable
- [ ] GUI for Windows/macOS/Linux

### Compatibility
- Most Darwin Operating Systems (macOS, iOS, watchOS, visionOS etc.) 
- Linux
- MinGW for Windows

# NOTE
This is not a reimplementation of libAppleArchive, rather its own library, created from the ground up. It is not compatible with libAppleArchive APIs, look at the header and code for clues. There is also docs available at `docs/` for types and functions.

# Libraries Used
[liblzfse](https://github.com/lzfse/lzfse) is owned by Apple Inc. It is added as a submodule in `libNeoAppleArchive/compression/lzfse`, and the Makefile builds it into `build/lzfse`.

[libzbitmap](https://github.com/eafer/libzbitmap) is owned by Corellium LLC, but is reversed engineered from Apple Inc's implementation. It is added as a submodule in `libNeoAppleArchive/compression/libzbitmap`, and the Makefile builds it into `build/libzbitmap`.

[zlib](https://zlib.net/) is not linked in the final library but is rather dynamically linked, as it is assumed to already be available on the OS itself.
