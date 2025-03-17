# NeoAAArchiveItem

NeoAAArchiveItem is a type that is for representing a single item of the Apple Archive, ex one file or one directory. It holds the header as a NeoAAHeader, as well as the encoded blob data and encoded blob data size.

| Function      | Notes      |
| ------------- | ------------- |
| [neo_aa_archive_item_create_with_header()](func/neo_aa_archive_item_create_with_header.md) | Creates a new NeoAAArchiveItem with the NeoAAHeader for it. |
| [neo_aa_archive_item_create_with_header_copy()](func/neo_aa_archive_item_create_with_header_copy.md) | Creates a new NeoAAArchiveItem with a copy of the NeoAAHeader for it. |
| neo_aa_archive_item_add_blob_data() | Adds the encoded blob data and size. |
| neo_aa_archive_item_destroy() | Frees and 0's out the encoded data, 0's and neo_aa_header_destroy()'s out the NeoAAHeader, and frees the NeoAAArchiveItem itself. |
| neo_aa_archive_item_destroy_nozero() | Frees the encoded data, and neo_aa_header_destroy_nozero()'s out the NeoAAHeader, and frees the NeoAAArchiveItem itself. |
| neo_aa_archive_item_list_destroy() | Destroys an array of NeoAAArchiveItems. |
| neo_aa_archive_item_list_destroy_nozero() | Destroys an array of NeoAAArchiveItems. |
| neo_aa_archive_item_write_to_buffer() | Writes the encoded data and header to a buffer. This is how the item will be represented in the end raw `.aar` file. |
| neo_aa_archive_item_write_to_buffer() | Writes the encoded data and header to a buffer. This is how the item will be represented in the end raw `.aar` file. |
| neo_aa_archive_item_create_with_encoded_data() | Creates a NeoAAArchiveItem from encoded data (the binary data of an `.aar` file) |
