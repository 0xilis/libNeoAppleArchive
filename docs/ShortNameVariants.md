# Short Name Variants

For simplicity and to make typing faster, libNeoAppleArchive also supplies short name variants for its types.

These can be used interchangeably with each other, ex. you can save a NeoHeader variable from a function that returns a NeoAAHeader, as these are the same type.

Short Name Variants also exist not just for types, but for definitions as well; for example, instead of typing `NEO_AA_FIELD_C`, someone can use the short name variant `NEO_FIELD_C` instead.

If you need to disable these for whatever reason, define NO_SHORTENED_NAMES.

The following short name definitions are:


#### Types

| Normal Type      | Short Variant      |
| ------------- | ------------- |
| NeoAAFieldType | NeoFieldType |
| NeoAAHeader | NeoHeader |
| NeoAAArchiveItem | NeoArchiveItem |
| NeoAAArchiveItemList | NeoArchiveItemList |
| NeoAAArchivePlain | NeoArchivePlain |
| NeoAAArchiveGeneric | NeoArchiveGeneric |
| NeoAEAArchive | NeoAEA |

#### Field Types

| Normal Field Type      | Short Variant      |
| ------------- | ------------- |
| NEO_AA_FIELD_TYPE_FLAG | NEO_FIELD_TYPE_FLAG |
| NEO_AA_FIELD_TYPE_UINT | NEO_FIELD_TYPE_UINT |
| NEO_AA_FIELD_TYPE_STRING | NEO_FIELD_TYPE_STRING |
| NEO_AA_FIELD_TYPE_HASH | NEO_FIELD_TYPE_HASH |
| NEO_AA_FIELD_TYPE_TIMESPEC | NEO_FIELD_TYPE_TIMESPEC |
| NEO_AA_FIELD_TYPE_BLOB | NEO_FIELD_TYPE_BLOB |

#### Macros

| Normal Macro      | Short Variant      |
| ------------- | ------------- |
| NEO_AA_FIELD_C | NEO_FIELD_C |
| NEO_AA_COMPRESSION_LZFSE| NEO_COMPRESSION_LZFSE |
| NEO_AA_COMPRESSION_NONE | NEO_COMPRESSION_NONE |
| NEO_AA_COMPRESSION_ZLIB | NEO_COMPRESSION_ZLIB |
