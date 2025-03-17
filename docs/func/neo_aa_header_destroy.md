# neo_aa_header_destroy
Frees and 0's out all elements of a NeoAAHeader, as well as frees the NeoAAHeader itself.

```c
void neo_aa_header_destroy(NeoAAHeader header);
```

## Parameters

#### header

The NeoAAHeader representing the Apple Archive header.

## Note

For a version of the function that does not 0 data, check out [neo_aa_header_destroy_nozero](neo_aa_header_destroy_nozero.md). Please keep in mind that some systems implement free() in a way that automatically will 0 out data anyway.
