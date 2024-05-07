//
//  libNeoAppleArchive_internal.c
//  libAppleArchive
//
//  Created by Snoolie Keffaber on 2024/04/22.
//

#include "libNeoAppleArchive.h"

uint32_t internal_do_not_call_flip_edian_32(uint32_t num) {
    return ((num>>24)&0xff) | ((num<<8)&0xff0000) | ((num>>8)&0xff00) | ((num<<24)&0xff000000);
}

size_t lastLoadedBinarySize_internal_do_not_use = 0;

char *internal_do_not_call_load_binary(const char *signedShortcutPath) {
    /* load AEA archive into memory */
    FILE *fp = fopen(signedShortcutPath,"r");
    if (!fp) {
        fprintf(stderr,"libNeoAppleArchive: failed to find path\n");
        return 0;
    }
    fseek(fp, 0, SEEK_END);
    size_t binary_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    lastLoadedBinarySize_internal_do_not_use = binary_size;
    char *aeaShortcutArchive = malloc(binary_size * sizeof(char));
    /*
     * Explained better in comment below, but
     * a process may write to a file while
     * this is going on so binary_size would be
     * bigger than the bytes we copy,
     * making it hit EOF before binary_size
     * is hit. This means that potentially
     * other memory from the process may
     * be kept here. To prevent this,
     * we 0 out our buffer to make sure
     * it doesn't contain any leftover memory
     * left.
     */
    memset(aeaShortcutArchive, 0, binary_size * sizeof(char));
    /* copy bytes to binary, byte by byte... */
    int c;
    size_t n = 0;
    while ((c = fgetc(fp)) != EOF) {
        if (n > binary_size) {
            /*
             * If, at any point, a file is modified during / before copy,
             * ex it has a really small size, but another process
             * quickly modifies it after binary_size is saved but
             * before / during the bytes are copied to the buffer,
             * then it would go past the buffer, resulting
             * in a heap overflow from our race. Fixing this
             * problem by checking if n ever reaches past
             * the initial binary_size...
             */
            free(aeaShortcutArchive);
            fclose(fp);
            NEO_AA_LogError("reached past binarySize\n");
            return 0;
        }
        aeaShortcutArchive[n++] = (char) c;
    }
    fclose(fp);
    return aeaShortcutArchive;
}


char *internal_do_not_call_memrchr(char *s, int c, size_t n) {
    uint64_t i = n;
internal_do_not_call_memrchr_fast_loop:
    i--;
    if (s[i] == c) {return (s+i);};
    if (i != 0) {goto internal_do_not_call_memrchr_fast_loop;};
    /* Error, return 0 */
    return 0;
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
