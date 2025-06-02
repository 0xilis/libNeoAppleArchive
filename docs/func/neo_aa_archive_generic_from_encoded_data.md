# neo_aa_archive_generic_from_encoded_data
Creates a new NeoAAArchiveGeneric from a copy of the encoded data.

```c
NeoAAArchiveGeneric neo_aa_archive_generic_from_encoded_data(size_t encodedSize, uint8_t *data);
```

## Parameters

#### encodedSize

The size of the encoded data in bytes.

#### data

The encoded data of the Apple Archive to form the NeoAAArchiveGeneric from.

## Return Value

On success, this function will return the newly created NeoAAArchiveGenric. On failure, this function will return NULL.

## Note

For a version of the function that uses file paths, check out [neo_aa_archive_generic_from_path](neo_aa_archive_generic_from_path.md).
