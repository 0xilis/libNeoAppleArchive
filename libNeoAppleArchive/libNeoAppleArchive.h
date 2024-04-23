//
//  libNeoAppleArchive.h
//  libAppleArchive
//
//  Created by Snoolie Keffaber on 2024/04/22.
//

#ifndef libNeoAppleArchive_h
#define libNeoAppleArchive_h

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

struct neo_aa_header_impl {
    uint32_t fieldCount;
    char *encodedData;
    uint32_t *fieldKeys;
    char *fieldTypes;
    void **fieldValues;
    size_t *fieldKeySizes;
    size_t headerSize;
};

typedef uint32_t NeoAAFieldType;

typedef enum : uint32_t {
    NEO_AA_FIELD_TYPE_FLAG = 0,
    NEO_AA_FIELD_TYPE_UINT = 1,
    NEO_AA_FIELD_TYPE_STRING = 2,
    NEO_AA_FIELD_TYPE_HASH = 3,
    NEO_AA_FIELD_TYPE_TIMESPEC = 4,
    NEO_AA_FIELD_TYPE_BLOB = 5,
} NeoAAFieldTypes;

typedef struct neo_aa_header_impl * NeoAAHeader;

NeoAAHeader neo_aa_header_create(void);
NeoAAHeader neo_aa_header_create_with_encoded_data(size_t encodedSize, uint8_t *data);
void neo_aa_header_destroy(NeoAAHeader header);
int neo_aa_header_get_field_key_index(NeoAAHeader header, uint32_t key);
uint64_t neo_aa_header_get_field_key_uint(NeoAAHeader header, int index);
char *neo_aa_header_get_field_key_string(NeoAAHeader header, int index);
size_t neo_aa_header_get_field_size(NeoAAHeader header, int index);
void neo_aa_extract_aar_to_path(const char *archivePath, const char *outputPath);

__attribute__((always_inline)) static uint32_t internal_do_not_call_ez_make_field_key(char *buffer) {
    return (uint32_t)buffer[0] << 24 | (uint32_t)buffer[1] << 16 | (uint32_t)buffer[2] << 8  | (uint32_t)buffer[3];
}
#define NEO_AA_FIELD_C(s) internal_do_not_call_ez_make_field_key(s);

#endif
