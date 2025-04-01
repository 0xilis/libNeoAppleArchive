# neo_aea_extract_data
Decrypts the NeoAEAArchive if it is encrypted, and extracts the data from the Apple Encrypted Archive. Note that this does not verify signing.

```c
uint8_t *neo_aea_extract_data(NeoAEAArchive aea, size_t *size, EVP_PKEY* recPriv, EVP_PKEY* signaturePub, uint8_t* symmKey, size_t symmKeySize, uint8_t* password, size_t passwordSize);
```

## Parameters

#### aea

The NeoAEAArchive representing the Apple Encrypted Archive.

#### size

If this is not null, this parameter will be filled with the size of the extracted data in bytes.

# TODO: Finish docs on other params

## Return Value

On success, this returns the extracted data from the Apple Encrypted Archive. On failure, this function returns NULL.