# NeoAAArchiveGeneric

NeoAAArchiveGeneric is a type that is for representing a generic Apple Archive. This means it can represent RAW, LZFSE, and ZLIB compressed Apple Archives. It is intended to support LZBITMAP, LZ4 and LZMA compression, however this has not yet been added to libNeoAppleArchive (although LZBITMAP is in the aea side). It holds the uncompressed, raw `NeoAAArchivePlain` in the `raw` field.

| Function      | Notes      |
| ------------- | ------------- |
| neo_aa_archive_generic_from_path() | Creates a new NeoAAArchiveGeneric with a filepath to the aar file, as well as decompresses it for storing in the NeoAAArchivePlain field. |
| neo_aa_archive_generic_from_encoded_data() | Creates a new NeoAAArchiveGeneric with a buffer of encoded data, as well as decompresses the NeoAAArchivePlain from it to store in the `raw` field. |