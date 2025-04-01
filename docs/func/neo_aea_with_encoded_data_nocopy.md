# neo_aea_with_encoded_data_nocopy
Creates an Apple Encrypted Archive from the encoded data.

```c
NeoAEAArchive neo_aea_with_encoded_data_nocopy(uint8_t *encodedData, size_t encodedDataSize);
```

## Parameters

#### encodedData

The encoded data to form the Apple Encrypted Archive from.

#### encodedDataSize

The size of the encoded data in bytes.

## Return Value

On success, this function will return the newly created NeoAEAArchive. On failure, this function will return NULL.

## Note

For a version of the function that copies the encoded data, check out [neo_aea_with_encoded_data](neo_aea_with_encoded_data.md).