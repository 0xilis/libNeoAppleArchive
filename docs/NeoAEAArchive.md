# NeoAEAArchive

[ⓘ] **AEA support, while functional, is marked as work in progress and thus are considered private API. This means that API may be subject to change.**

NeoAEAArchive is a type for representing all types of AEA Archives. It can be used for decryption and extraction of AEA, and in the future, signing, verification, and creation.

| Function      | Notes      |
| ------------- | ------------- |
| neo_aea_archive_with_path() | Creates a new NeoAEAArchive from the file at path. |
| neo_aea_archive_with_encoded_data() | Copies over the encoded data and calls neo_aea_archive_with_encoded_data_nocopy. |
| neo_aea_archive_with_encoded_data_nocopy() | Creates a NeoAEAArchive from encoded data (encoded data is a buffer of the actual .aea file). |
| neo_aea_archive_extract_data() | Extract the NeoAEAArchive data, and decrypts it if it is a AEA using decryption. Does not validate signing info. |
| neo_aa_archive_plain_with_neo_aea_archive() | Extracts data using neo_aea_archive_extract_data() and makes a NeoAAArchivePlain from it. |
| neo_aea_archive_profile() | Get the profile ID of the AEA |
| neo_aea_archive_auth_data() | Get the auth data of the AEA (may need a call to extract_data first to decrypt it). This returns the raw internal pointer of the struct so it should not be modified. |
| neo_aea_archive_destroy() | Destroy / free the NeoAEAArchive and all fields in the object. |
