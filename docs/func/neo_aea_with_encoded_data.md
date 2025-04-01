# neo_aea_with_encoded_data
Creates an Apple Encrypted Archive from a copy of the encoded data.

```c
NeoAEAArchive neo_aea_with_encoded_data(uint8_t *encodedData, size_t encodedDataSize);
```

## Parameters

#### encodedData

The encoded data to form the Apple Encrypted Archive from.

#### encodedDataSize

The size of the encoded data in bytes.

## Return Value

On success, this function will return the newly created NeoAEAArchive. On failure, this function will return NULL.

## Note

For a version of the function that does not copy the encoded data, check out [neo_aea_with_encoded_data_nocopy](neo_aea_with_encoded_data_nocopy.md).