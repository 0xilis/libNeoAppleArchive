# neo_aa_header_get_field_size
Retrieves the size of the field value at the index in the header in bytes. For example, a uint8_t field will return 1.

```c
size_t neo_aa_header_get_field_size(NeoAAHeader header, int index);
```

## Parameters

#### header

The NeoAAHeader representing the Apple Archive header.

#### index

The index of the field key in the header.

## Return Value

On success, this will return the index of the field key in the header. If it cannot find the field key in the header, this will return -1.

## Note

`NEO_AA_FIELD_TYPE_BLOB`s will not return the blob size. This is as the blob data is not on the header, but the header only contains the size of the blob. So, if the blob size is stored in a uint16_t, it will return 2, if it is stored in a uint32_t, it will return 4, etc. `NEO_AA_FIELD_TYPE_STRING`s are in the header, and thus will return the size of the string. The 2 bytes containing the string size will not be accounted for in the header.