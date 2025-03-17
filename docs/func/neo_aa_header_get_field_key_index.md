# neo_aa_header_get_field_key_index
Retrieves the index of where the field key is on the Apple Archive header. (Indexed by 0).

```c
int neo_aa_header_get_field_key_index(NeoAAHeader header, uint32_t key);
```

## Parameters

#### header

The NeoAAHeader representing the Apple Archive header.

## Return Value

On success, this will return the index of the field key in the header. If it cannot find the field key in the header, this will return -1.
