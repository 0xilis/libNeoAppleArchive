/*
 *  libNeoAppleArchive_internal.c
 *  libNeoAppleArchive
 *
 *  Created by Snoolie Keffaber on 2024/04/22.
 */

#include "libNeoAppleArchive.h"
#include <zlib.h>

uint16_t internal_do_not_call_flip_edian_16(uint16_t num) {
    return ((num << 8)&0xff) | ((num >> 8) & 0xff);
}

uint32_t internal_do_not_call_flip_edian_32(uint32_t num) {
    return ((num>>24)&0xff) | ((num<<8)&0xff0000) | ((num>>8)&0xff00) | ((num<<24)&0xff000000);
}

size_t lastLoadedBinarySize_internal_do_not_use = 0;

char *internal_do_not_call_load_binary(const char *signedShortcutPath) {
    /* load AEA archive into memory */
    FILE *fp = fopen(signedShortcutPath,"r");
    if (!fp) {
        fprintf(stderr,"libNeoAppleArchive: failed to find path\n");
        return NULL;
    }
    fseek(fp, 0, SEEK_END);
    size_t binary_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    lastLoadedBinarySize_internal_do_not_use = binary_size;
    char *aeaShortcutArchive = malloc(binary_size * sizeof(char));
    memset(aeaShortcutArchive, 0, binary_size * sizeof(char));
    size_t bytesRead = fread(aeaShortcutArchive, binary_size, 1, fp);
    fclose(fp);
    if (bytesRead < binary_size) {
        free(aeaShortcutArchive);
        NEO_AA_LogError("failed to read the entire file.\n");
        return NULL;
    }
    return aeaShortcutArchive;
}


char *internal_do_not_call_memrchr(char *s, int c, size_t n) {
    uint64_t i = n;
internal_do_not_call_memrchr_fast_loop:
    i--;
    if (s[i] == c) {return (s+i);};
    if (i != 0) {goto internal_do_not_call_memrchr_fast_loop;};
    /* Error, return NULL */
    return NULL;
}

void internal_do_not_call_apply_xattr_blob_to_path(uint8_t *blob, size_t blobSize, const char *path) {
#if defined(__APPLE__) || defined(__linux__)
    uint32_t blobPosition = 0;
    while (blobPosition < blobSize) {
        uint8_t *currentXAT = blob + blobPosition;
        uint32_t *xatItemSizePtr = *(uint32_t **)&currentXAT;
        uint32_t xatItemSize = *xatItemSizePtr;
        if ((blobPosition + xatItemSize) > blobSize) {
            /* I'm not sure if libAppleArchive itself does this, but rather than erroring we attempt to fix it. */
            /* Some problems may arrive if XAT blob is over 4GB but that will probably never happen. */
            fprintf(stderr, "libNeoAppleArchive: xatItemSize (%d) reaches past size of XAT blob (%zu). Setting item size to blobSize and hoping for the best...\n",xatItemSize,blobSize);
            xatItemSize = (uint32_t)blobSize - blobPosition;
        }
        const char *xattrName = (const char *)currentXAT + 4;
        /* Name should be ended with NULL, so we can just use strnlen() for this */
        size_t xattrNameLen = strnlen(xattrName, xatItemSize - 4);
        if (xatItemSize < (4 + xattrNameLen + 1)) {
            /* Name + null byte reaches past xatItemSize, error :( */
            fprintf(stderr, "libNeoAppleArchive: (%lu) reaches past xatItemSize (%d).\n",(4 + xattrNameLen + 1), xatItemSize);
            return;
        }
        void *xattrValue = (void *)xattrName + xattrNameLen + 1;
        size_t xattrValueLen = xatItemSize - (4 + xattrNameLen + 1);
#if defined(__linux__)
        if (xattrValueLen) {
            setxattr(path, xattrName, xattrValue, xattrValueLen, 0);
        } else {
            /* xattr has no value ???; use 0 for the value */
            setxattr(path, xattrName, 0, 0, 0);
        }
#else
        /* macOS */
        if (xattrValueLen) {
            setxattr(path, xattrName, xattrValue, xattrValueLen, 0, 0);
        } else {
            /* xattr has no value ???; use 0 for the value */
            setxattr(path, xattrName, 0, 0, 0, 0);
        }
#endif
        blobPosition += xatItemSize;
    }
#else
    printf("libNeoAppleArchive does not support XAT parsing on non-macOS/Linux.\n");
#endif
}

void internal_do_not_call_is_field_key_available(uint32_t key) {
    /* These blobs have not yet been implemented */
    NEO_AA_AssertUnsupportedKey(key, "ACL");
    NEO_AA_AssertUnsupportedKey(key, "YAF");
}

int internal_do_not_call_is_field_type_supported_size(NeoAAFieldType fieldType, size_t fieldSize) {
    if (!fieldSize) {
        /* Only flags should be 0 in size */
        return (fieldType == NEO_AA_FIELD_TYPE_FLAG);
    }
    if (fieldSize == 1) {
        /* Only UINT can be 1 in size */
        return (fieldType == NEO_AA_FIELD_TYPE_UINT);
    }
    if (fieldSize == 2) {
        /* The size to store the string size in NEO_AA_FIELD_TYPE_STRING is 2 bytes btw */
        return ((fieldType == NEO_AA_FIELD_TYPE_UINT) || (fieldType == NEO_AA_FIELD_TYPE_BLOB) || (fieldType == NEO_AA_FIELD_TYPE_STRING));
    }
    if (fieldSize == 4) {
        return ((fieldType == NEO_AA_FIELD_TYPE_UINT) || (fieldType == NEO_AA_FIELD_TYPE_BLOB) || (fieldType == NEO_AA_FIELD_TYPE_HASH));
    }
    if (fieldSize == 8) {
        return ((fieldType == NEO_AA_FIELD_TYPE_UINT) || (fieldType == NEO_AA_FIELD_TYPE_BLOB) || (fieldType == NEO_AA_FIELD_TYPE_TIMESPEC));
    }
    if (fieldSize == 12) {
        return (fieldType == NEO_AA_FIELD_TYPE_TIMESPEC);
    }
    if (fieldType == NEO_AA_FIELD_TYPE_HASH) {
        return ((fieldSize == 20) || (fieldSize == 32) || (fieldSize == 48) || (fieldSize == 64));
    }
    return 0;
}

/* Unsafe since we are assuming that the type corresponds to size, and not taking future field types into account */
char internal_do_not_call_neo_aa_header_subtype_for_field_type_and_size(uint32_t fieldType, size_t fieldSize) {
    if (!fieldSize) {
        /* Assume NEO_AA_FIELD_TYPE_FLAG */
        return '*';
    }
    if (fieldType == NEO_AA_FIELD_TYPE_STRING) {
        /* Assume fieldSize is 2 */
        return 'P';
    }
    if (fieldType == NEO_AA_FIELD_TYPE_UINT) {
        /* Cool trick */
        return '0'+fieldSize;
    }
    if (fieldType == NEO_AA_FIELD_TYPE_BLOB) {
        /* Assume fieldSize is 2,4,8 */
        /* A,B,C evil hack */
        return 'A'+(fieldSize>>2);
    }
    if (fieldSize == 12) {
        /* Assume NEO_AA_FIELD_TYPE_TIMESPEC */
        return 'T';
    }
    if (fieldType == NEO_AA_FIELD_TYPE_TIMESPEC) {
        /* Since it wasn't 12, fieldSize must be 8 */
        return 'S';
    }
    /* Assume fieldType is NEO_AA_FIELD_TYPE_HASH */
    /* Evil hack */
    return 'F'+(fieldSize>>4);
}

uint64_t internal_do_not_call_neo_aa_archive_header_key_pos_in_encoded_data(NeoAAHeader header, int index) {
    NEO_AA_NullParamAssert(header);
    NEO_AA_NullParamAssert((index >= 0));
    size_t headerSize = header->headerSize;
    uint32_t fieldCount = header->fieldCount;
    NEO_AA_NullParamAssert(fieldCount);
    if (!index) {
        /* Index is 0; this is the first field key */
        return 6;
    }
    NEO_AA_NullParamAssert((index < fieldCount));
    size_t currentPos = 6;
    for (int i = 0; i < index; i++) {
        if (currentPos >= headerSize) {
            NEO_AA_LogError("reached past encodedData\n");
            return 0;
        }
        size_t fieldSize = neo_aa_header_get_field_size(header, i);
        NeoAAFieldType fieldType = neo_aa_header_get_field_type(header, i);
        /* Go past the fieldKey and subtype in encoded data */
        currentPos += 4;
        if (fieldType == NEO_AA_FIELD_TYPE_STRING) {
            /* NEO_AA_FIELD_TYPE_STRING */
            /* Go past string size, which is stored in 2 bytes, to the string itself */
            currentPos += 2;
        }
        /* Go past field value */
        currentPos += fieldSize;
        if (currentPos > headerSize) {
            NEO_AA_LogError("reached past encodedData\n");
            return 0;
        }
    }
    return (uint64_t)currentPos;
}

size_t internal_do_not_call_neo_aa_archive_item_encoded_data_size_for_encoded_data(size_t maxSize, uint8_t *data) {
    uint32_t *dumbHack = *(uint32_t **)&data;
    uint32_t headerMagic = dumbHack[0];
    if (headerMagic != AAR_MAGIC && headerMagic != YAA_MAGIC) { /* AA01/YAA1 */
        NEO_AA_LogError("data is not raw header (compression not yet supported)\n");
        return 0;
    }
    size_t encodedHeaderSize = (dumbHack[1] & 0xffff);
    size_t archiveItemSize = encodedHeaderSize;
    if (maxSize < encodedHeaderSize) {
        NEO_AA_LogError("header size is larger than maxSize\n");
        return 0;
    }
    NeoAAHeader header = neo_aa_header_create_with_encoded_data(encodedHeaderSize, data);
    if (!header) {
        NEO_AA_LogError("failed to create NeoAAHeader\n");
        return 0;
    }
    /* cycle all fields, add blobSize to item size */
    int fieldCount = header->fieldCount;
    for (int i = 0; i < fieldCount; i++) {
        if (neo_aa_header_get_field_type(header, i) == NEO_AA_FIELD_TYPE_BLOB) {
            archiveItemSize += neo_aa_header_get_field_key_uint(header, i);
        }
    }
    neo_aa_header_destroy(header);
    return archiveItemSize;
}

/*
 * internal_do_not_call_inflate
 *
 * Function used for zlib decompression from buffers.
 * src: the source buffer containing the compressed (gzip or zlib) data
 * srcLen: the length of the source buffer
 * dst: the destination buffer, into which the output will be written
 * dstLen: the length of the destination buffer
 *
 * Return values:
 * Z_BUF_ERROR: if dstLen is not large enough to fit the inflated data
 * Z_MEM_ERROR: if there's insufficient memory to perform the decompression
 * Z_DATA_ERROR: if the input data was corrupt
 */
int internal_do_not_call_inflate(const void *src, int srcLen, void *dst, int dstLen) {
    z_stream strm  = {0};
    strm.total_in  = strm.avail_in  = srcLen;
    strm.total_out = strm.avail_out = dstLen;
    strm.next_in   = (Bytef *) src;
    strm.next_out  = (Bytef *) dst;

    strm.zalloc = Z_NULL;
    strm.zfree  = Z_NULL;
    strm.opaque = Z_NULL;

    int err = -1;
    int ret = -1;

    err = inflateInit2(&strm, (15 + 32)); //15 window bits, and the +32 tells zlib to to detect if using gzip or zlib
    if (err == Z_OK) {
        err = inflate(&strm, Z_FINISH);
        if (err == Z_STREAM_END) {
            ret = (int)strm.total_out;
        }
        else {
             inflateEnd(&strm);
             return err;
        }
    }
    else {
        inflateEnd(&strm);
        return err;
    }

    inflateEnd(&strm);
    return ret;
}
