# Contributing

Thank you for considering to contribute to libNeoAppleArchive!

Examples of contributions may include:

- Making the codebase more readable.
- Additions that while do not fix any security issue, may be a security risk if future code is added.
- Speed enhancements. However, please make sure that multi-threadding is optional if these are parts of your enhancements.
- Support for extra AAR/YAA features.
- Additional, improved documentation.
- Additional tests and examples of usage.

Please attempt to explain how your PR improves these, or a separate item not listed. Please also make sure your PR, if it adds new code, to be readable and well commented.

### General Code Style

While this is not required, one thing I would appreciate is using a similar code style as the library, including:

- Functions are made with snake_case, but variables are camelCase. This is to make differentiation among them more clear. Definitions are, of course, ALL_CAPS.
- Usage of `assert()` and `NEO_AA_NullParamAssert()` is heavily discouraged, for more information see [this page.](docs/code-quality/EndOfAssert.md).
- libNeoAppleArchive is intended to be supported on a variety of Unix systems, including OS X, Linux, FreeBSD and OpenBSD. Please make sure your code is cross-compatible if applicable.
- All if statements, while loops, for loops etc. should use curley braces.
- I personally code in a very odd C89-like style (I don't ever use single-line comments, if you see any here that code was written by someone else), but do noticably use size defined types from C99. I acknowledge is is a pretty strange choice so if you want to just do your own thing and use whatever C99 features you want, that's fine.
- While this is a bit hypocritical since a lot of functions here don't have explanations above them, one thing I would really like is a comment above them, explaining in few words what the function does, as well as explaining the return types and any extra notes someone who may want to use the function may want to know.
- If you're adding more functions, adding documentation for them in `docs/` would be really nice, but this is not an absolute need and I can just write the documentation later if you don't feel like writing it yourself.
- Please, avoid breaking changes!!! Changes that require people using our library to make changes to their code are REALLY not good.

If you break one or more of these rules but feel like you have a good reason, feel free to commit anyway.
