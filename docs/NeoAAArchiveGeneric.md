# NeoAAArchiveGeneric

NeoAAArchiveGeneric is a type that is for representing a generic Apple Archive. This means it can represent RAW, LZFSE, ZLIB, and LZBITMAP compressed Apple Archives. It is intended to support LZ4 and LZMA compression in the future, however this has not yet been added to libNeoAppleArchive. It holds the uncompressed, raw `NeoAAArchivePlain` in the `raw` field.

The [short name variant](ShortNameVariants.md) for this type is `NeoArchiveGeneric`.

| Function      | Notes      |
| ------------- | ------------- |
| [neo_aa_archive_generic_from_path()](func/neo_aa_archive_generic_from_path.md) | Creates a new NeoAAArchiveGeneric with a filepath to the aar file, as well as decompresses it for storing in the NeoAAArchivePlain field. |
| neo_aa_archive_generic_from_encoded_data() | Creates a new NeoAAArchiveGeneric with a buffer of encoded data, as well as decompresses the NeoAAArchivePlain from it to store in the `raw` field. |

## Converting to NeoAAArchivePlain

The `NeoAAArchivePlain` type should be used to work with Apple Archives. To convert a `NeoAAArchiveGeneric` to a `NeoAAArchivePlain`, simply access the `raw` element.

#### Code Sample

```c
NeoAAArchiveGeneric generic = neo_aa_archive_generic_from_path("compressed_aar.aar");
if (generic) {
    NeoAAArchivePlain raw = generic->raw;

    /*
     * Since we have gotten the raw element from our NeoAAArchiveGeneric,
     * we should free the NeoAAArchiveGeneric as we are no longer accessing it.
     */
    free(raw);

    // ... code using the NeoAAArchivePlain here.

    // After we are done with usage, destroy it.
    neo_aa_archive_plain_destroy(raw);
}
```
