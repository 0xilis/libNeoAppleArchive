# neo_aa_header_create_with_encoded_data
Creates an Apple Archive header from a copy of the encoded data.

```c
NeoAAHeader neo_aa_header_create_with_encoded_data(size_t encodedSize, uint8_t *data);
```

## Parameters

#### encodedSize

The size of the encoded data in bytes.

#### data

The encoded data to form the Apple Archive header from.

## Return Value

On success, this function will return the newly created NeoAAHeader. On failure, this function will return NULL.
