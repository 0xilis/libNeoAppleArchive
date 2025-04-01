# neo_aea_auth_data
Retrieves the auth data from an Apple Encrypted Archive.

```c
uint8_t *neo_aea_auth_data(NeoAEAArchive aea, uint32_t *authDataSize);
```

## Parameters

#### aea

The NeoAEAArchive representing the Apple Encrypted Archive.

#### authDataSize

If this is not null, this parameter will be filled with the size of the auth data in bytes.

## Return Value

A pointer to the auth data on the NeoAEAArchive. This is used internally in the NeoAEAArchive, so it should not be modified.