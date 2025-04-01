# neo_aea_with_path
Creates a new NeoAEAArchive from the file at path.

```c
NeoAEAArchive neo_aea_with_path(const char *path);
```

## Parameters

#### path

A path containing an Apple Encrypted Archive

## Return Value

On success, this function will return the newly created NeoAEAArchive. On failure, this function will return NULL.

## Note

For a version of the function that uses buffers, check out [neo_aea_with_encoded_data_nocopy](neo_aea_with_encoded_data_nocopy.md).