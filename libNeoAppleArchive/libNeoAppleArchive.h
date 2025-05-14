/*
 *  libNeoAppleArchive.h
 *  libNeoAppleArchive
 *
 *  Created by Snoolie Keffaber on 2024/04/22.
 */

#ifndef libNeoAppleArchive_h
#define libNeoAppleArchive_h

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#if defined(__APPLE__) || defined(__linux__)
#include <sys/xattr.h>
#endif
#include <time.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

struct neo_pbzx_archived_directory_header {
    uint32_t magic;
    uint32_t reserved_0;
    uint8_t reserved_1;
    uint8_t mystery; /* always 0x40 */
    uint16_t reserved_2;
    uint32_t reserved_3;
    uint32_t uncompressedSize;
    uint32_t reserved_4;
    uint32_t compressedSize;
};

struct neo_aa_header_impl {
    uint32_t fieldCount;
    char *encodedData;
    uint32_t *fieldKeys;
    char *fieldTypes;
    void **fieldValues;
    size_t *fieldKeySizes;
    size_t headerSize;
    void *archiveItem; /* The NeoAAArchiveItem associated with this header, having this pointer */
};

typedef uint32_t NeoAAFieldType;

typedef enum {
    NEO_AA_FIELD_TYPE_FLAG = (uint32_t)0,
    NEO_AA_FIELD_TYPE_UINT = (uint32_t)1,
    NEO_AA_FIELD_TYPE_STRING = (uint32_t)2,
    NEO_AA_FIELD_TYPE_HASH = (uint32_t)3,
    NEO_AA_FIELD_TYPE_TIMESPEC = (uint32_t)4,
    NEO_AA_FIELD_TYPE_BLOB = (uint32_t)5,
} NeoAAFieldTypes;

typedef struct neo_aa_header_impl * NeoAAHeader;

/* Do not manually access items of neo_aa_archive_item_impl !!! They are subject to change!!! */
struct neo_aa_archive_item_impl {
    NeoAAHeader header;
    char *encodedBlobData;
    size_t encodedBlobDataSize;
};

typedef struct neo_aa_archive_item_impl *NeoAAArchiveItem;
typedef NeoAAArchiveItem *NeoAAArchiveItemList;

/* Do not manually access items of neo_aa_archive_plain_impl !!! They are subject to change!!! */
struct neo_aa_archive_plain_impl {
    int itemCount;
    NeoAAArchiveItem *items;
};

typedef struct neo_aa_archive_plain_impl *NeoAAArchivePlain;

struct neo_aa_archive_generic_impl {
    NeoAAArchivePlain raw; /* the raw NeoAAArchivePlain */
    int compression; /* int representing algo, LZFSE/LZ4/etc */
    size_t uncompressedSize; /* size of RAW data */
    size_t compressedSize; /* size of compressed data */
};

typedef struct neo_aa_archive_generic_impl *NeoAAArchiveGeneric;

/* Shortened type names */
#ifndef NO_SHORTENED_NAMES
typedef NeoAAArchiveGeneric NeoArchiveGeneric;
typedef NeoAAArchivePlain NeoArchivePlain;
typedef NeoAAArchiveItemList NeoArchiveItemList;
typedef NeoAAArchiveItem NeoArchiveItem;
typedef NeoAAHeader NeoHeader;
typedef NeoAAFieldType NeoFieldType;
#endif

void neo_aa_header_set_field_uint(NeoAAHeader header, uint32_t key, size_t fieldSize, uint64_t value);
void neo_aa_header_add_field_string(NeoAAHeader header, uint32_t key, size_t stringSize, char *s);
void neo_aa_header_set_field_blob(NeoAAHeader header, uint32_t key, size_t fieldSize, uint64_t blobSize);

NeoAAArchiveItem neo_aa_archive_item_create_with_header(NeoAAHeader header);
NeoAAArchiveItem neo_aa_archive_item_create_with_header_copy(NeoAAHeader header);
void neo_aa_archive_item_add_blob_data(NeoAAArchiveItem item, char *data, size_t dataSize);
NeoAAArchivePlain neo_aa_archive_plain_create_with_items(NeoAAArchiveItem *items, int itemCount);
NeoAAArchivePlain neo_aa_archive_plain_create_with_items_nocopy(NeoAAArchiveItem *items, int itemCount);
void neo_aa_archive_item_list_destroy(NeoAAArchiveItem *items, int itemCount);
void neo_aa_archive_item_list_destroy_nozero(NeoAAArchiveItem *items, int itemCount);
void neo_aa_archive_plain_destroy(NeoAAArchivePlain plainArchive);
void neo_aa_archive_plain_destroy_nozero(NeoAAArchivePlain plainArchive);
void neo_aa_archive_item_write_to_buffer(NeoAAArchiveItem item, char *buffer);
uint8_t *neo_aa_archive_plain_get_encoded_data(NeoAAArchivePlain archive, size_t *encodedDataSize);
void neo_aa_archive_plain_writefd(NeoAAArchivePlain plainArchive, int fd);
void neo_aa_archive_plain_write_path(NeoAAArchivePlain plainArchive, const char *filepath);
void neo_aa_archive_item_destroy(NeoAAArchiveItem item);
void neo_aa_archive_item_destroy_nozero(NeoAAArchiveItem item);
NeoAAArchiveItem neo_aa_archive_item_create_with_encoded_data(size_t encodedSize, uint8_t *data);
NeoAAArchivePlain neo_aa_archive_plain_create_with_encoded_data(size_t encodedSize, uint8_t *data);
NeoAAArchiveGeneric neo_aa_archive_generic_from_path(const char *path);
int neo_aa_archive_plain_compress_writefd(NeoAAArchivePlain plain, int algorithm, int fd);
void neo_aa_archive_plain_compress_write_path(NeoAAArchivePlain plain, int algorithm, const char *path);

NeoAAArchivePlain neo_aa_archive_plain_from_directory(const char *dirPath);
void neo_aa_extract_aar_to_path(const char *archivePath, const char *outputPath);

__attribute__((used, always_inline)) static uint32_t internal_do_not_call_ez_make_field_key(char *buffer) {
    return (uint32_t)buffer[0] << 24 | (uint32_t)buffer[1] << 16 | (uint32_t)buffer[2] << 8  | 0;
}
#define NEO_AA_FIELD_C(s) internal_do_not_call_ez_make_field_key(s)

/* Compliant with the one defined in libAppleArchive, which is compliant with libcompression */
#ifndef NEO_AA_COMPRESSION_LZFSE
#define NEO_AA_COMPRESSION_LZFSE 0x801
#define NEO_AA_COMPRESSION_NONE 0
#define NEO_AA_COMPRESSION_ZLIB 0x505
#endif

/* Shortened names */

#ifndef NO_SHORTENED_NAMES
#define NEO_FIELD_C NEO_AA_FIELD_C
#define NEO_COMPRESSION_LZFSE NEO_AA_COMPRESSION_LZFSE
#define NEO_COMPRESSION_NONE NEO_AA_COMPRESSION_NONE
#define NEO_COMPRESSION_ZLIB NEO_AA_COMPRESSION_ZLIB
typedef enum {
    NEO_FIELD_TYPE_FLAG = (uint32_t)0,
    NEO_FIELD_TYPE_UINT = (uint32_t)1,
    NEO_FIELD_TYPE_STRING = (uint32_t)2,
    NEO_FIELD_TYPE_HASH = (uint32_t)3,
    NEO_FIELD_TYPE_TIMESPEC = (uint32_t)4,
    NEO_FIELD_TYPE_BLOB = (uint32_t)5,
} NeoFieldTypes;
#endif

#include "neo_aa_header.h"
#include "neo_aea_archive.h"

#ifdef __cplusplus
}
#endif

#endif
