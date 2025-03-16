# neo_aa_archive_plain_with_neo_aea_archive
Retrieves the encoded data from an Apple Encrypted Archive, and creates a [NeoAAArchivePlain](https://github.com/0xilis/libNeoAppleArchive/blob/main/docs/NeoAAArchivePlain.md) from it.

```c
NeoAAArchivePlain neo_aa_archive_plain_with_neo_aea_archive(NeoAEAArchive aea);
```

## Parameters

#### aea

The NeoAEAArchive representing the Apple Encrypted Archive.

## Return Value

On success, this will return a NeoAAArchivePlain. On failure, this function will return NULL.