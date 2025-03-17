# NeoAAHeader

NeoAAHeader is a type that is for representing the header of the Apple Archive. It holds the encoded data for the header, the header size, field keys, their sizes, and their values*.
(Note: NeoAAHeader does not directly store the value for field blobs as they don't count as being in the header; that is instead reserved to NeoAAArchiveItem, albeit NeoAAHeader will hold the size of the field blob).

| Function      | Notes      |
| ------------- | ------------- |
| [neo_aa_header_create()](func/neo_aa_header_create.md) | Creates a new, blank NeoAAHeader. |
| [neo_aa_header_destroy()](func/neo_aa_header_destroy.md) | Frees and 0's out all elements of a NeoAAHeader, as well as frees the NeoAAHeader itself. |
| [neo_aa_header_create_with_encoded_data()](func/neo_aa_header_create_with_encoded_data.md) | Creates a NeoAAHeader from encoded data (encoded data is how the header is represented in the actual .aar file). |
| [neo_aa_header_get_field_key_index()](func/neo_aa_header_get_field_key_index.md) | Returns the index to the field key in the NeoAAHeader. Getting the PAT field, you would use the first arg be the NeoAAHeader, and second be NEO_AA_FIELD_C("PAT"). |
| neo_aa_header_get_field_key_uint() | Returns the uint of the field key at the index in the header. |
| neo_aa_header_get_field_key_string() | Returns the string of the field key at the index in the header. |
| neo_aa_header_get_field_size() | Returns the size of the field key at the index in the header. |
| neo_aa_header_set_field_uint() | Sets the value of the uint in the header, or adds it if it is not present. |
| neo_aa_header_set_field_blob() | Sets the size of the blob in the header, or adds it if it is not present. |
| neo_aa_header_add_field_string() | Adds a string field key in the header. Will soon be deprecated for normal use by neo_aa_header_set_field_string(). |
| neo_aa_header_set_field_timespec() | Sets the value of the timespec in the header, or adds it if it is not present. |
| neo_aa_header_clone_header() | malloc()'s a new clone of the header, as well as all field keys and their values. |
| neo_aa_header_get_field_type() | Returns the NeoAAFieldType of the field key. |
