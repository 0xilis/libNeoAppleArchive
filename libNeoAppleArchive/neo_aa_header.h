/*
 *  neo_aa_header.h
 *  libNeoAppleArchive
 *
 *  Created by Snoolie Keffaber on 2024/04/24.
 */

#ifndef libNeoAppleArchive_h
#error Include libNeoAppleArchive.h instead of this file
#endif

#ifndef neo_aa_header_h
#define neo_aa_header_h

NeoAAHeader neo_aa_header_create(void);
void neo_aa_header_destroy(NeoAAHeader header);
NeoAAHeader neo_aa_header_create_with_encoded_data(size_t encodedSize, uint8_t *data);
int neo_aa_header_get_field_key_index(NeoAAHeader header, uint32_t key);
uint64_t neo_aa_header_get_field_key_uint(NeoAAHeader header, int index);
char *neo_aa_header_get_field_key_string(NeoAAHeader header, int index);
size_t neo_aa_header_get_field_size(NeoAAHeader header, int index);
void neo_aa_header_set_field_uint_or_blob(NeoAAHeader header, uint32_t key, size_t fieldSize, uint64_t value, NeoAAFieldType fieldType);
void neo_aa_header_set_field_uint(NeoAAHeader header, uint32_t key, size_t fieldSize, uint64_t value);
void neo_aa_header_set_field_blob(NeoAAHeader header, uint32_t key, size_t fieldSize, uint64_t blobSize);
void neo_aa_header_add_field_string(NeoAAHeader header, uint32_t key, size_t stringSize, char *s);
void neo_aa_header_set_field_string(NeoAAHeader header, uint32_t key, size_t stringSize, char *s);
NeoAAHeader neo_aa_header_clone_header(NeoAAHeader header);
NeoAAFieldType neo_aa_header_get_field_type(NeoAAHeader header, int index);

#endif /* neo_aa_header_h */
