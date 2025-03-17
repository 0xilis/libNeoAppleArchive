# neo_aa_archive_item_create_with_header
Creates a new NeoAAArchiveItem with the NeoAAHeader for it. This does **not** copy the NeoAAHeader but stores the direct pointer for it in it. Do not free/destroy the NeoAAHeader while still using the item holding it for this reason.

```c
NeoAAArchiveItem neo_aa_archive_item_create_with_header(NeoAAHeader header);
```

## Return Value

This function will return the newly created NeoAAArchiveItem. On failure (such as the NeoAAHeader being passed in is already being used in another NeoAAArchiveItem), this will return a NULL pointer.
