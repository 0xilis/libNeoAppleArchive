# NeoAAArchivePlain

NeoAAArchivePlain is a type that is for representing a plain, raw Apple Archive. It holds an item list (array of NeoAAArchiveItem), as well as the item count.

| Function      | Notes      |
| ------------- | ------------- |
| neo_aa_archive_plain_create_with_items() | Creates a new NeoAAArchivePlain with a copy of the item list (array of NeoAAArchiveItem) and item count. |
| neo_aa_archive_plain_create_with_items_nocopy() | Creates a new NeoAAArchivePlain with the item list (array of NeoAAArchiveItem) and item count. |
| neo_aa_archive_plain_destroy() | 0's out and neo_aa_archive_item_list_destroy()'s the items, as well as frees the NeoAAArchivePlain itself. |
| neo_aa_archive_plain_destroy_nozero() | neo_aa_archive_item_list_destroy_nozero()'s the items, as well as frees the NeoAAArchivePlain itself. |
| neo_aa_archive_plain_outfile_size() | Gets the size of the `.aar` file the NeoAAArchivePlain represents. |
| neo_aa_archive_plain_get_encoded_data() | Writes the Apple Archive for the NeoAAArchivePlain to a buffer and returns it. |
| neo_aa_archive_plain_writefd() | Writes the Apple Archive for the NeoAAArchivePlain to an open file descriptor. |
| neo_aa_archive_plain_write_path() | Opens the filepath and calls neo_aa_archive_plain_writefd() with the NeoAAArchivePlain. |
| neo_aa_archive_plain_create_with_encoded_data() | Creates a NeoAAArchivePlain from encoded data (the binary data of an `.aar` file) |
| neo_aa_archive_plain_create_with_aar_path() | Creates a NeoAAArchivePlain from a path to a raw, uncompressed `.aar` file. |
