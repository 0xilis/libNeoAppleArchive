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
#include <sys/xattr.h>
#include <time.h>

/*
 * Ugly warning:
 *
 * To help prevent heap overflows,
 * I integrate something into my structs
 * I'd like to refer to as "HSP".
 * Example, when a NeoAAArchiveItem is
 * created, it calls rand() to generate
 * a random 32bit integer for the
 * archiveItemIdentifier, the heap cookie.
 * We then fill the NeoAAHeaders with
 * the heap cookie, and when we have
 * the NeoAAArchiveItem mess with something,
 * it checks and ensures that the heap cookie
 * matches on the NeoAAArchiveItem and its
 * corresponding NeoAAHeader.
 */
struct neo_aa_header_impl {
    int archiveItemIdentifier_0;
    uint32_t fieldCount;
    char *encodedData;
    int archiveItemIdentifier_1;
    uint32_t *fieldKeys;
    int archiveItemIdentifier_2;
    char *fieldTypes;
    int archiveItemIdentifier_3;
    void **fieldValues;
    int archiveItemIdentifier_4;
    size_t *fieldKeySizes;
    int archiveItemIdentifier_5;
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

/* Do not manually access items of neo_aa_archive_item_impl !!! They are subject to change!!! */
struct neo_aa_archive_item_impl {
    int archivePlainIdentifier_0;
    NeoAAHeader header;
    int archivePlainIdentifier_1;
    char *encodedBlobData;
    int archivePlainIdentifier_2;
    size_t encodedBlobDataSize;
    int archivePlainIdentifier_3;
    int archiveItemIdentifier;
};

typedef struct neo_aa_archive_item_impl *NeoAAArchiveItem;

/* Do not manually access items of neo_aa_archive_plain_impl !!! They are subject to change!!! */
struct neo_aa_archive_plain_impl {
    int itemCount;
    NeoAAArchiveItem *items;
    int archivePlainIdentifier;
};

typedef struct neo_aa_archive_plain_impl *NeoAAArchivePlain;

void neo_aa_header_set_field_uint(NeoAAHeader header, uint32_t key, size_t fieldSize, uint64_t value);
void neo_aa_header_add_field_string(NeoAAHeader header, uint32_t key, size_t stringSize, char *s);
void neo_aa_header_set_field_blob(NeoAAHeader header, uint32_t key, size_t fieldSize, uint64_t blobSize);

NeoAAArchiveItem neo_aa_archive_item_create_with_header(NeoAAHeader header);
void neo_aa_archive_item_add_blob_data(NeoAAArchiveItem item, char *data, size_t dataSize);
NeoAAArchivePlain neo_aa_archive_plain_create_with_items(NeoAAArchiveItem *items, int itemCount);
void neo_aa_archive_item_list_destroy(NeoAAArchiveItem *items, int itemCount);
void neo_aa_archive_plain_destroy(NeoAAArchivePlain plainArchive);
void neo_aa_archive_item_write_to_buffer(NeoAAArchiveItem item, char *buffer);
void neo_aa_archive_plain_writefd(NeoAAArchivePlain plainArchive, int fd);
void neo_aa_archive_plain_write_path(NeoAAArchivePlain plainArchive, const char *filepath);
void neo_aa_archive_item_destroy(NeoAAArchiveItem item);

void neo_aa_extract_aar_to_path(const char *archivePath, const char *outputPath);

__attribute__((used, always_inline)) static uint32_t internal_do_not_call_ez_make_field_key(char *buffer) {
    return (uint32_t)buffer[0] << 24 | (uint32_t)buffer[1] << 16 | (uint32_t)buffer[2] << 8  | 0;
}
#define NEO_AA_FIELD_C(s) internal_do_not_call_ez_make_field_key(s)

/* My Arch Linux build system is bad and doesn't work if I include limits.h for some reason. Rather than fixing like I should, I define the limits here... */

#ifndef USHRT_MAX
#define USHRT_MAX 65535
#endif

#include "libNeoAppleArchive_internal.h"
#include "neo_aa_header.h"

#endif
