# NeoAAFieldType

NeoAAFieldType is a type that represents the type of a field key. The values correspond to ones defined in libAppleArchive's headers.

The [short name variant](ShortNameVariants.md) for this type is `NeoFieldType`.

| Name      | Value      |
| ------------- | ------------- |
| NEO_AA_FIELD_TYPE_FLAG | 0 |
| NEO_AA_FIELD_TYPE_UINT | 1 |
| NEO_AA_FIELD_TYPE_STRING | 2 |
| NEO_AA_FIELD_TYPE_HASH | 3 |
| NEO_AA_FIELD_TYPE_TIMESPEC | 4 |
| NEO_AA_FIELD_TYPE_BLOB | 5 |

### NEO_AA_FIELD_TYPE_FLAG

The field key will not have a value, it will just hold a field key and its subtype will be represented in binary form as '*'.

### NEO_AA_FIELD_TYPE_UINT

The value represents an unsigned integer. This can be 1, 2, 4, or 8 bytes. In binary form, the subtype for 1 byte is '1', 2 byte is '2', 4 byte is '4', and 8 byte is '8'.

### NEO_AA_FIELD_TYPE_STRING

The value represents a string with a maximum size of 64K bytes. In the binary data, this is represented with the 'P' subtype, followed by 2 bytes representing the size of the string. They will be flipped endian, ex if string size is 0x2a50, then the bytes will be `50 2a`. The size also takes into account any NULL end bytes of the string (albeit the string does not need to be NULL ended and often times is not). After the size is the string.

### NEO_AA_FIELD_TYPE_HASH

A value representing a hash. This can be 4, 20, 32, 48 or 64 bytes. In binary form, the subtype used to represent 4 byte hashes is 'F', 20 byte is 'G', 32 byte is 'H', 48 byte is 'I', and 64 byte is 'J'.

### NEO_AA_FIELD_TYPE_TIMESPEC

A value representing time. This can be 8 or 12 bytes. In binary form, the subtype used to represent 8 byte times is 'S', and 12 byte as 'T'.

### NEO_AA_FIELD_TYPE_BLOB

A value representing a blob. In the NeoAAHeader, this type is special in the fact that it does not represent the value but rather the size of the blob. The actual blob itself is stored outside the header, in a NeoAAArchiveItem. Due to this, blobs are not counted towards the header size. In binary form, 2 bytes (64KB blob size limit) to represent the size of the blob has subtype 'A', 4 bytes (4GB blob size limit) is subtype 'B', 8 bytes (16.8 million TB blob size limit) is subtype 'C'.
