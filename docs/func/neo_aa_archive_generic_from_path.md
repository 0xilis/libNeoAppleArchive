# neo_aa_archive_generic_from_path
Creates a new NeoAAArchiveGeneric from the file at path.

```c
NeoAAArchiveGeneric neo_aa_archive_generic_from_path(const char *path);
```

## Parameters

#### path

A path containing an Apple Archive.

## Return Value

On success, this function will return the newly created NeoAAArchiveGenric. On failure, this function will return NULL.

## Note

For a version of the function that uses buffers, check out [neo_aa_archive_generic_from_encoded_data](neo_aa_archive_generic_from_encoded_data.md).
