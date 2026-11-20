# libNeoAppleArchive
Cross-compat library for parsing Apple Archive and Apple Encrypted Archive.

### What it features
Functions for messing around with headers, extracting, and archiving apple archives. There are functions for manually creating apple archives (or modifying existing ones), as well as convienience functions. YAA is also supported, as it is just legacy Apple Archive, and all YAA files are just Apple Archives with a different magic essentially.

### Roadmap
- [ ] Support all compression types for Apple Archive (partially complete)
- - Only LZ4 and LZMA are needed now.
- [x] Support AEA, at least the `AEA_PROFILE__HKDF_SHA256_HMAC__NONE__ECDSA_P256` and `AEA_PROFILE__HKDF_SHA256_AESCTR_HMAC__SYMMETRIC__NONE` profiles.
- [x] Convienience functions for archiving / extracting files and directories.
- [ ] Making code more readable
- [ ] Multi-threadded support
- [ ] GUI for Windows/macOS/Linux
- [ ] CommonCrypto variants for macOS to allow use without OpenSSL.
- [ ] Auto-include Swift Package Manager support (should not be too hard)

### Compatibility
- Most Darwin Operating Systems (macOS, iOS, watchOS, visionOS etc.) 
- Linux
- MinGW for Windows (untested on latest, only old builds verified)

# Contributing

Any/all contributions are welcome, no matter how small or large! 

If you are currently unsure of what to contribute, here are some easy targets:

- Implementing LZ4 and LZMA should be easy. Just keep in mind to maintain Linux support with this. I'll test on BSD myself so you don't need to worry too bad about it.
- Include Swift Package Manager support
- Some functions do not have docs or could use better documentation, as well as no good "welcome to the library!" doc which just generally shows how to use the library.
- The current Makefile isn't so great and only outputs builds for the current platform the user is running on. Rah! Bad! This should be changed.
- Another change to the Makefile being it should output dynamic libraries for OS X and Linux. Preferrably BSD and Windows too, but these aren't necessities. I can just add BSD support myself after your PR.
- Make build system output headers to /build/usr/include

Check out the [contributing page](https://github.com/0xilis/libNeoAppleArchive) learning how to style your code in a similar way to what is expected for libNeoAppleArchive.

# Issues

You have an issue with libNeoAppleArchive? Is it a feature suggestion / currently lacking feature? Feel free to report it in issues! Is it a bug? Feel free to report it also in issues! If this is triggered by any sample files please provide a sample .aar. Even if you cannot debug the root cause, just saying how to replicate your steps should be good for me to try and find out what's wrong.

# NOTE
This is not a reimplementation of libAppleArchive, rather its own library, created from the ground up. It is not compatible with libAppleArchive APIs, look at the header and code for clues. There is also docs available at `docs/` for types and functions.

If the end result is compressed under ZLIB ends up having the same compressedSize and uncompressedSize, Apple's official tools will not uncompress it. This is not a libNeoAppleArchive bug but rather a bug with Apple's own implementation and will need to be fixed by them. Extracting under libNeoAppleArchive should work fine.

# Libraries Used
[liblzfse](https://github.com/lzfse/lzfse) is owned by Apple Inc. It is added as a submodule in `libNeoAppleArchive/compression/lzfse`, and the Makefile builds it into `build/lzfse`.

[libzbitmap](https://github.com/eafer/libzbitmap) is owned by Corellium LLC. It is added as a submodule in `libNeoAppleArchive/compression/libzbitmap`, and the Makefile builds it into `build/libzbitmap`.

[zlib](https://zlib.net/) is not linked in the final library but is rather dynamically linked, as it is assumed to already be available on the OS itself.

[lzraven](https://github.com/retrowave3/apple-compressions) is an MIT-licensed open source reimplementation of LZRAVEN (formerly known as LZMAMMOTH). The license is placed in 'compression/lzraven/LICENSE' and the code is stored on this repository.

OS X and Linux are constantly tested to ensure they work, however mingw is not always tested on the latest commit. If you cannot get mingw to build libNeoAppleArchive, please report an issue and try seeing if an older commit works.
