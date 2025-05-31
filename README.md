# libNeoAppleArchive
Cross-compat library for parsing Apple Archive and Apple Encrypted Archive.

### What isn't finished
- LZMA and LZ4 compressed `.aar`s; only `RAW`, `LZFSE`, `LZBITMAP` and `ZLIB` are currently supported
- Multi-Threadded support

### What is
Functions for messing around with headers, extracting, and archiving apple archives. There are functions for manually creating apple archives (or modifying existing ones), as well as convienience functions. YAA is also supported, as it is just legacy Apple Archive, and all YAA files are just Apple Archives with a different magic essentially.

### Roadmap
- [ ] Support all compression types for Apple Archive (partially complete)
- [x] Support AEA, at least the `AEA_PROFILE__HKDF_SHA256_HMAC__NONE__ECDSA_P256` and `AEA_PROFILE__HKDF_SHA256_AESCTR_HMAC__SYMMETRIC__NONE` profiles.
- [x] Convienience functions for archiving / extracting files and directories.
- [ ] Making code more readable
- [ ] GUI for Windows/macOS/Linux

### Compatibility
- Most Darwin Operating Systems (macOS, iOS, watchOS, visionOS etc.) 
- Linux
- MinGW for Windows (untested on latest, only old builds verified)

# NOTE
This is not a reimplementation of libAppleArchive, rather its own library, created from the ground up. It is not compatible with libAppleArchive APIs, look at the header and code for clues. There is also docs available at `docs/` for types and functions.

If the end result is compressed under ZLIB ends up having the same compressedSize and uncompressedSize, Apple's official tools will not uncompress it. This is not a libNeoAppleArchive bug but rather a bug with Apple's own implementation and will need to be fixed by them. Extracting under libNeoAppleArchive should work fine.

# Libraries Used
[liblzfse](https://github.com/lzfse/lzfse) is owned by Apple Inc. It is added as a submodule in `libNeoAppleArchive/compression/lzfse`, and the Makefile builds it into `build/lzfse`.

[libzbitmap](https://github.com/eafer/libzbitmap) is owned by Corellium LLC, but is reversed engineered from Apple Inc's implementation. It is added as a submodule in `libNeoAppleArchive/compression/libzbitmap`, and the Makefile builds it into `build/libzbitmap`.

[zlib](https://zlib.net/) is not linked in the final library but is rather dynamically linked, as it is assumed to already be available on the OS itself.

OS X and Linux are constantly tested to ensure they work, however mingw is not always tested on the latest commit. If you cannot get mingw to build libNeoAppleArchive, please report an issue and try seeing if an older commit works.
