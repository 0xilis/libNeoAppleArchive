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

#ifdef __cplusplus
extern "C" {
#endif

NeoAAHeader neo_aa_header_create(void);
void neo_aa_header_destroy(NeoAAHeader header);
void neo_aa_header_destroy_nozero(NeoAAHeader header);
NeoAAHeader neo_aa_header_create_with_encoded_data(size_t encodedSize, uint8_t *data);
int neo_aa_header_get_field_key_index(NeoAAHeader header, uint32_t key);
uint64_t neo_aa_header_get_field_key_uint(NeoAAHeader header, int index);
char *neo_aa_header_get_field_key_string(NeoAAHeader header, int index);
size_t neo_aa_header_get_field_size(NeoAAHeader header, int index);
void neo_aa_header_set_field_uint(NeoAAHeader header, uint32_t key, size_t fieldSize, uint64_t value);
void neo_aa_header_set_field_blob(NeoAAHeader header, uint32_t key, size_t fieldSize, uint64_t blobSize);
void __attribute__((deprecated)) neo_aa_header_add_field_string(NeoAAHeader header, uint32_t key, size_t stringSize, char *s); /* Please use neo_aa_header_set_field_string */
void neo_aa_header_set_field_string(NeoAAHeader header, uint32_t key, size_t stringSize, char *s);
void neo_aa_header_set_field_string(NeoAAHeader header, uint32_t key, size_t stringSize, char *s);
void neo_aa_header_set_field_timespec(NeoAAHeader header, uint32_t key, size_t fieldSize, time_t value);
void neo_aa_header_remove_field(NeoAAHeader header, uint32_t key);
void neo_aa_header_remove_field_at_index(NeoAAHeader header, int keyIndex);
NeoAAHeader neo_aa_header_clone_header(NeoAAHeader header);
NeoAAFieldType neo_aa_header_get_field_type(NeoAAHeader header, int index);

#ifdef __cplusplus
}
#endif

#endif /* neo_aa_header_h */
