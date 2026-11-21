/*
 *  neo_aa_header.c
 *  libNeoAppleArchive
 *
 *  Created by Snoolie Keffaber on 2024/04/24.
 */

#include "libNeoAppleArchive.h"
#include "libNeoAppleArchive_internal.h"
#include <limits.h>

NeoAAHeader neo_aa_header_create(void) {
    NeoAAHeader header = calloc(1, sizeof(struct neo_aa_header_impl)); /* [fuzz-triage] zero-init: 6-byte path left field ptrs uninit */
    if (!header) {
        NEO_AA_ErrorHeapAlloc();
        return NULL;
    }
    memset(header, 0, sizeof(struct neo_aa_header_impl));
    char *headerData = calloc(1, 7); /* 7 is the default header size (6) plus 1 */
    if (!headerData) {
        free(header);
        NEO_AA_ErrorHeapAlloc();
        return NULL;
    }
    strcpy(headerData, "AA01");
    headerData[4] = 6; /* 6 bytes long on creation */
    headerData[5] = 0;
    header->encodedData = headerData;
    header->headerSize = 6;
    return header;
}

void neo_aa_header_destroy(NeoAAHeader header) {
    if (!header) {
        return;
    }
    /*
     * If NeoAAHeader has a NeoAAArchiveItem on it, 0 us
     * out on the header. This protects against people
     * mis-using the library and calling neo_aa_header_destroy
     * but having the NeoAAArchiveItem be used for some
     * reason and still having the pointer for the freed header.
     */
    NeoAAArchiveItem item = header->archiveItem;
    if (item) {
        item->header = 0;
    }
    char *encodedData = header->encodedData;
    header->encodedData = 0;
    free(encodedData);
    size_t *fieldKeySizes = header->fieldKeySizes;
    header->fieldKeySizes = 0;
    free(fieldKeySizes);
    uint32_t *fieldKeys = header->fieldKeys;
    header->fieldKeys = 0;
    free(fieldKeys);
    char *fieldTypes = header->fieldTypes;
    header->fieldTypes = 0;
    free(fieldTypes);
    uint32_t fieldCount = header->fieldCount;
    void **fieldValues = header->fieldValues;
    header->fieldValues = 0;
    for (uint32_t i = 0; i < fieldCount; i++) {
        void *fieldValue = fieldValues[i];
        fieldValues[i] = 0;
        free(fieldValue);
    }
    free(fieldValues);
    memset(header, 0, sizeof(struct neo_aa_header_impl));
    free(header);
}

void neo_aa_header_destroy_nozero(NeoAAHeader header) {
    if (!header) {
        return;
    }
    free(header->encodedData);
    free(header->fieldKeySizes);
    free(header->fieldKeys);
    free(header->fieldTypes);
    uint32_t fieldCount = header->fieldCount;
    void **fieldValues = header->fieldValues;
    for (uint32_t i = 0; i < fieldCount; i++) {
        free(fieldValues[i]);
    }
    free(fieldValues);
    free(header);
}

NeoAAHeader neo_aa_header_create_with_encoded_data(size_t encodedSize, uint8_t *data) {
    uint32_t headerMagic;

    if (data == NULL || encodedSize < 6 || encodedSize > UINT16_MAX) {
        NEO_AA_LogError("invalid encoded header size\n");
        return NULL;
    }

    memcpy(&headerMagic, data, sizeof(headerMagic));

    if (headerMagic != AAR_MAGIC && headerMagic != YAA_MAGIC) { /* AA01/YAA1 */
        NEO_AA_LogError("data is not raw header\n");
        return NULL;
    }

    if ((size_t)((uint32_t)data[4] | ((uint32_t)data[5]<<8)) != encodedSize) {
        NEO_AA_LogError("encodedSize mismatch\n");
        return NULL;
    }

    /*
     * GHSA-chpv-g239-pp39: (C)
     *
     * We need to allocate with calloc to zero out other fields
     * since if a 6-byte header is inputted, it would have us return
     * uninitialized pointers. BAD!
     */
    NeoAAHeader header = calloc(1, sizeof(struct neo_aa_header_impl));
    if (!header) {
        NEO_AA_ErrorHeapAlloc();
        return NULL;
    }
    char *headerData = calloc(1, encodedSize);
    if (!headerData) {
        free(header);
        NEO_AA_ErrorHeapAlloc();
        return NULL;
    }
    memcpy(headerData, data, encodedSize);
    header->encodedData = headerData;
    header->headerSize = encodedSize;
    if (encodedSize == 6) {
        printf("neo_aa_header_create_with_encoded_data: no field keys (wtf?)\n");
        header->fieldCount = 0;
        return header;
    }
    uint32_t *fieldKeys = malloc(sizeof(uint32_t));
    char *fieldTypes = malloc(1);
    size_t *fieldKeySizes = malloc(sizeof(size_t));
    void **fieldKeyValues = malloc(sizeof(void *));
    /* now, fill with AAFieldKeys */
    uint32_t currentPos = 6;
    uint32_t fieldCount = 0;
    if (!fieldKeys || !fieldTypes || !fieldKeySizes || !fieldKeyValues) {
        goto free_all;
    }
    while (currentPos < encodedSize) {
        /*
         * GHSA-chpv-g239-pp39: (A/D)
         *
         * field keys are 4 bytes in size and we need to ensure
         * we have enough for the field key
         */
        if (encodedSize - currentPos < 4) {
            NEO_AA_LogError("incomplete field key\n");
            goto free_all;
        }

        fieldCount++;
        void *oldPtr = fieldKeys;
        fieldKeys = realloc(fieldKeys, sizeof(uint32_t) * fieldCount);
        if (!fieldKeys) {
            free(oldPtr);
            NEO_AA_ErrorHeapAlloc();
            goto free_all;
        }
        oldPtr = fieldTypes;
        fieldTypes = realloc(fieldTypes, fieldCount);
        if (!fieldTypes) {
            free(oldPtr);

            NEO_AA_ErrorHeapAlloc();
            goto free_all;
        }
        oldPtr = fieldKeySizes;
        fieldKeySizes = realloc(fieldKeySizes, sizeof(size_t) * fieldCount);
        if (!fieldKeySizes) {
            free(oldPtr);
            NEO_AA_ErrorHeapAlloc();
            goto free_all;
        }
        oldPtr = fieldKeyValues;
        fieldKeyValues = realloc(fieldKeyValues, sizeof(void *) * fieldCount);
        if (!fieldKeyValues) {
            free(oldPtr);
            NEO_AA_ErrorHeapAlloc();
            goto free_all;
        }
        
        char *currentPointer = headerData + currentPos;
        uint32_t fieldKeyPlusSubtype;
        memcpy(&fieldKeyPlusSubtype, currentPointer, sizeof(fieldKeyPlusSubtype));
        fieldKeyPlusSubtype = FLIP_32(fieldKeyPlusSubtype);
        uint32_t fieldKey = (fieldKeyPlusSubtype & 0xffffff00); /* first 3 bytes */
        char fieldKeySubtype = fieldKeyPlusSubtype & 0xff;
        char fieldKeyType;
        size_t fieldKeySize;
        currentPos += 4;
        
        switch (fieldKeySubtype) {
            case '*':
                fieldKeyType = NEO_AA_FIELD_TYPE_FLAG;
                fieldKeySize = 0;
                break;
                
            case '1':
                fieldKeyType = NEO_AA_FIELD_TYPE_UINT;
                fieldKeySize = 1;
                break;
                
            case '2':
                fieldKeyType = NEO_AA_FIELD_TYPE_UINT;
                fieldKeySize = 2;
                break;
                
            case '4':
                fieldKeyType = NEO_AA_FIELD_TYPE_UINT;
                fieldKeySize = 4;
                break;
                
            case '8':
                fieldKeyType = NEO_AA_FIELD_TYPE_UINT;
                fieldKeySize = 8;
                break;
                
            case 'A':
                fieldKeyType = NEO_AA_FIELD_TYPE_BLOB;
                fieldKeySize = 2;
                break;
                
            case 'B':
                fieldKeyType = NEO_AA_FIELD_TYPE_BLOB;
                fieldKeySize = 4;
                break;
                
            case 'C':
                fieldKeyType = NEO_AA_FIELD_TYPE_BLOB;
                fieldKeySize = 8;
                break;
                
            case 'F':
                fieldKeyType = NEO_AA_FIELD_TYPE_HASH;
                fieldKeySize = 4;
                break;
                
            case 'G':
                fieldKeyType = NEO_AA_FIELD_TYPE_HASH;
                fieldKeySize = 20;
                break;
                
            case 'H':
                fieldKeyType = NEO_AA_FIELD_TYPE_HASH;
                fieldKeySize = 32;
                break;
                
            case 'I':
                fieldKeyType = NEO_AA_FIELD_TYPE_HASH;
                fieldKeySize = 48;
                break;
                
            case 'J':
                fieldKeyType = NEO_AA_FIELD_TYPE_HASH;
                fieldKeySize = 64;
                break;
                
            case 'S':
                fieldKeyType = NEO_AA_FIELD_TYPE_TIMESPEC;
                fieldKeySize = 8;
                break;
                
            case 'T':
                fieldKeyType = NEO_AA_FIELD_TYPE_TIMESPEC;
                fieldKeySize = 12;
                break;
                
            case 'P':
                fieldKeyType = NEO_AA_FIELD_TYPE_STRING;
                if (currentPos + 6 > encodedSize) { /* [fuzz-triage] F4: bound string-size read */
                    NEO_AA_LogError("string size field reached past encodedData\n");
                    goto free_all;
                }
                uint16_t sizeShort; /* [fuzz-triage] F3: aligned read */
                memcpy(&sizeShort, currentPointer + 4, 2);
                fieldKeySize = sizeShort;
                if (encodedSize-currentPos < fieldKeySize) {
                    NEO_AA_LogError("string length reached past encodedData\n");
free_all:
                    free(fieldKeys);
                    free(fieldKeySizes);
                    free(fieldTypes);
                    free(headerData);
                    /*
                     * We need to check if fieldCount is not 0, as if
                     * it is, the fieldCount - 1 will underflow
                     */
                    if (fieldCount) {
                        for (unsigned int i = 0; i < fieldCount - 1; i++) {
                            free(fieldKeyValues[i]);
                        }
                    }
                    free(fieldKeyValues);
                    free(header);
                    return NULL;
                }
                currentPos += 2;
                break;
                
            default:
                NEO_AA_LogErrorF("invalid field subtype (%x)\n",fieldKeyPlusSubtype);
                goto free_all;
        }

        /*
         * GHSA-chpv-g239-pp39: (A)
         *
         * bounds check before allocation/copy
         */
        if (currentPos + fieldKeySize > encodedSize) {
            NEO_AA_LogError("field value reached past encodedData\n");
            goto free_all;
        }
        
        fieldKeys[fieldCount - 1] = fieldKey;
        fieldTypes[fieldCount - 1] = fieldKeyType;
        fieldKeySizes[fieldCount - 1] = fieldKeySize;
        
        /* make value */
        uint8_t *fieldKeyValue = malloc(fieldKeySize);
        if (!fieldKeyValue) {
            NEO_AA_ErrorHeapAlloc();
            goto free_all;
        }
        /* copy field key to fieldKeyValue */
        memcpy(fieldKeyValue, headerData + currentPos, fieldKeySize);
        fieldKeyValues[fieldCount - 1] = fieldKeyValue;
        
        currentPos += fieldKeySize;
    }
    header->fieldCount = fieldCount;
    header->fieldKeys = fieldKeys;
    header->fieldTypes = fieldTypes;
    header->fieldValues = fieldKeyValues;
    header->fieldKeySizes = fieldKeySizes;
    header->archiveItem = NULL;
    return header;
}

int neo_aa_header_get_field_key_index(NeoAAHeader header, uint32_t key) {
    uint32_t fieldCount = header->fieldCount;
    for (uint32_t i = 0; i < fieldCount; i++) {
        if (header->fieldKeys[i] == key) {
            return i;
        }
    }
    /* could not find key; error */
    return -1;
}

uint64_t neo_aa_header_get_field_key_uint(NeoAAHeader header, int index) {
    size_t fieldValueSize = header->fieldKeySizes[index];
    if (fieldValueSize == 1) {
        uint8_t *fieldValuePtr = header->fieldValues[index];
        return *fieldValuePtr;
    } else if (fieldValueSize == 2) {
        uint16_t *fieldValuePtr = header->fieldValues[index];
        return *fieldValuePtr;
    } else if (fieldValueSize == 4) {
        uint32_t *fieldValuePtr = header->fieldValues[index];
        return *fieldValuePtr;
    } else {
        uint64_t *fieldValuePtr = header->fieldValues[index];
        return *fieldValuePtr;
    }
}

char *neo_aa_header_get_field_key_string(NeoAAHeader header, int index) {
    size_t fieldValueSize = header->fieldKeySizes[index];
    char *newString = malloc(fieldValueSize + 1);
    if (!newString) {
        NEO_AA_ErrorHeapAlloc();
        return NULL;
    }
    char *fieldValuePtr = header->fieldValues[index];
    strncpy(newString, fieldValuePtr, fieldValueSize);
    newString[fieldValueSize] = '\0';
    return newString;
}

size_t neo_aa_header_get_field_size(NeoAAHeader header, int index) {
    return header->fieldKeySizes[index];
}

NEO_INTERNAL_API static int neo_aa_header_add_field_uint_or_blob(NeoAAHeader header, uint32_t key, size_t fieldSize, uint64_t value, NeoAAFieldType fieldType) {
    if (!header) {
        NEO_AA_LogError("header is NULL\n");
        return -1;
    }
    internal_do_not_call_is_field_key_available(key);
    if (internal_do_not_call_is_field_type_supported_size(fieldType, fieldSize) == 0) {
        NEO_AA_LogError("fieldSize not supported for specified fieldType\n");
        return -1;
    }

    if (fieldSize > sizeof(value) ||
        header->headerSize > UINT16_MAX - 4 - fieldSize ||
        header->fieldCount == UINT32_MAX) {
        NEO_AA_LogError("invalid field size or header exceeds maximum size\n");
        return -1;
    }

    size_t oldSize = header->headerSize;
    size_t newSize = oldSize + 4 + fieldSize;
    uint32_t fieldCount = header->fieldCount;

    if (!header->encodedData) {
        NEO_AA_LogError("header missing encoded data\n");
        return -1;
    }

    /* Allocate all replacement buffers independently. */
    char *newEncodedData = calloc(1, newSize);
    uint32_t *newFieldKeys = calloc(1, (fieldCount + 1) * sizeof(uint32_t));
    char *newFieldTypes = calloc(1, fieldCount + 1);
    void **newFieldValues = calloc(1, (fieldCount + 1) * sizeof(void *));
    size_t *newFieldKeySizes = calloc(1, (fieldCount + 1) * sizeof(size_t));
    uint64_t *newFieldValue = calloc(1, sizeof(uint64_t));

    if (!newEncodedData || !newFieldKeys || !newFieldTypes ||
        !newFieldValues || !newFieldKeySizes || !newFieldValue) {
        free(newEncodedData);
        free(newFieldKeys);
        free(newFieldTypes);
        free(newFieldValues);
        free(newFieldKeySizes);
        free(newFieldValue);
        NEO_AA_ErrorHeapAlloc();
        return -1;
    }

    /* Copy existing data. */
    memcpy(newEncodedData, header->encodedData, oldSize);

    if (fieldCount) {
        memcpy(newFieldKeys, header->fieldKeys, fieldCount * sizeof(uint32_t));
        memcpy(newFieldTypes, header->fieldTypes, fieldCount);
        memcpy(newFieldValues, header->fieldValues, fieldCount * sizeof(void *));
        memcpy(newFieldKeySizes, header->fieldKeySizes, fieldCount * sizeof(size_t));
    }

    /* encode the new field */
    uint16_t encodedSize = (uint16_t)newSize;
    memcpy(newEncodedData + 4, &encodedSize, sizeof(encodedSize));

    uint32_t encodedKey = FLIP_32(key);
    memcpy(newEncodedData + oldSize, &encodedKey, sizeof(encodedKey));

    newEncodedData[oldSize + 3] = internal_do_not_call_neo_aa_header_subtype_for_field_type_and_size(fieldType, fieldSize);

    memcpy(newEncodedData + oldSize + 4, &value, fieldSize);

    /* prepare the new field metadata */
    *newFieldValue = value;

    newFieldKeys[fieldCount] = key;
    newFieldTypes[fieldCount] = (char)fieldType;
    newFieldValues[fieldCount] = newFieldValue;
    newFieldKeySizes[fieldCount] = fieldSize;

    /* commit only after every allocation has succeeded */
    free(header->encodedData);
    free(header->fieldKeys);
    free(header->fieldTypes);
    free(header->fieldValues);
    free(header->fieldKeySizes);

    header->encodedData = newEncodedData;
    header->fieldKeys = newFieldKeys;
    header->fieldTypes = newFieldTypes;
    header->fieldValues = newFieldValues;
    header->fieldKeySizes = newFieldKeySizes;
    header->headerSize = newSize;
    header->fieldCount = fieldCount + 1;
    return 0;
}

NEO_INTERNAL_API static int neo_aa_header_set_field_uint_or_blob(NeoAAHeader header, uint32_t key, size_t fieldSize, uint64_t value, NeoAAFieldType fieldType) {
    /* TODO: Add support for fixing encodedData with keys that become larger */
    if (!header) {
        NEO_AA_LogError("header is NULL\n");
        return -1;
    }
    internal_do_not_call_is_field_key_available(key);
    if (internal_do_not_call_is_field_type_supported_size(fieldType, fieldSize) == 0) {
        NEO_AA_LogError("fieldSize not supported for specified fieldType\n");
        return -1;
    }
    int keyIndex = neo_aa_header_get_field_key_index(header, key);
    if (keyIndex == -1) {
        return neo_aa_header_add_field_uint_or_blob(header, key, fieldSize, value, fieldType);
    }
    size_t valueSize = neo_aa_header_get_field_size(header, keyIndex);
    if (valueSize != fieldSize) {
        /* TODO: This will probably be supported later but we need to reform the encodedData for this which is annoying */
        NEO_AA_LogError("setting field key with different size\n");
        return -1;
    }
    if (header->fieldTypes[keyIndex] != (char)fieldType) {
        NEO_AA_LogError("setting field key with different type\n");
        return -1;
    }
    void *encodedData = header->encodedData;
    if (!encodedData) {
        NEO_AA_LogError("header missing encoded data\n");
        return -1;
    }
    uint64_t encodedDataPos = internal_do_not_call_neo_aa_archive_header_key_pos_in_encoded_data(header, keyIndex);
    if (!encodedDataPos) {
        NEO_AA_LogError("failed to find position of key in encoded data\n");
        return -1;
    }
    void *valuePtr = header->fieldValues[keyIndex];
    switch (fieldSize) {
        case 1:
            *(uint8_t *)valuePtr = (uint8_t)value;
            break;
            
        case 2:
            *(uint16_t *)valuePtr = (uint16_t)value;
            break;
            
        case 4:
            *(uint32_t *)valuePtr = (uint32_t)value;
            break;
            
        case 8:
            *(uint64_t *)valuePtr = value;
            break;
            
        default:
            NEO_AA_LogError("bad fieldSize\n");
            return -1;
    }
    void *encodedValuePtr = (uint8_t *)encodedData + encodedDataPos + 4;
    memcpy(encodedValuePtr, &value, fieldSize);
    return 0;
}

void neo_aa_header_set_field_uint(NeoAAHeader header, uint32_t key, size_t fieldSize, uint64_t value) {
    neo_aa_header_set_field_uint_or_blob(header, key, fieldSize, value, NEO_AA_FIELD_TYPE_UINT);
}

void neo_aa_header_set_field_blob(NeoAAHeader header, uint32_t key, size_t fieldSize, uint64_t blobSize) {
    if (!fieldSize) {
        if (blobSize < UINT16_MAX) {
            fieldSize = 2;
        } else if (blobSize < UINT32_MAX) {
            fieldSize = 4;
        } else {
            fieldSize = 8;
        }
    }
    /* Blobs are not part of neo_aa_header, you will add the context to a neo_aa_archive_item later. */
    neo_aa_header_set_field_uint_or_blob(header, key, fieldSize, blobSize, NEO_AA_FIELD_TYPE_BLOB);
}

/* Currently marked as internal as they have not yet been added to the main library, but it is planned */
NEO_INTERNAL_API int neo_aa_header_set_field_uint_err(NeoAAHeader header, uint32_t key, size_t fieldSize, uint64_t value) {
    return neo_aa_header_set_field_uint_or_blob(header, key, fieldSize, value, NEO_AA_FIELD_TYPE_UINT);
}

/* Currently marked as internal as they have not yet been added to the main library, but it is planned */
NEO_INTERNAL_API int neo_aa_header_set_field_blob_err(NeoAAHeader header, uint32_t key, size_t fieldSize, uint64_t blobSize) {
    if (!fieldSize) {
        if (blobSize < UINT16_MAX) {
            fieldSize = 2;
        } else if (blobSize < UINT32_MAX) {
            fieldSize = 4;
        } else {
            fieldSize = 8;
        }
    }
    /* Blobs are not part of neo_aa_header, you will add the context to a neo_aa_archive_item later. */
    return neo_aa_header_set_field_uint_or_blob(header, key, fieldSize, blobSize, NEO_AA_FIELD_TYPE_BLOB);
}

int neo_aa_header_add_field_string(NeoAAHeader header, uint32_t key, size_t stringSize, char *s) {
    if (!header) {
        NEO_AA_LogError("header is NULL\n");
        return -1;
    }

    if (stringSize > USHRT_MAX || (stringSize > 0 && !s)) {
        NEO_AA_LogError("invalid string size or NULL string\n");
        return -1;
    }

    internal_do_not_call_is_field_key_available(key);

    if (header->headerSize > UINT16_MAX - 6 - stringSize ||
        header->fieldCount == UINT32_MAX) {
        NEO_AA_LogError("header exceeds maximum encoded size\n");
        return -1;
    }

    size_t oldSize = header->headerSize;
    size_t newSize = oldSize + 6 + stringSize;
    uint32_t fieldCount = header->fieldCount;

    if (!header->encodedData) {
        NEO_AA_LogError("header missing encoded data\n");
        return -1;
    }

    /* allocate all replacement buffers */
    char *newEncodedData = calloc(1, newSize);
    uint32_t *newFieldKeys = calloc(1, (fieldCount + 1) * sizeof(uint32_t));
    char *newFieldTypes = calloc(1, fieldCount + 1);
    void **newFieldValues = calloc(1, (fieldCount + 1) * sizeof(void *));
    size_t *newFieldKeySizes = calloc(1, (fieldCount + 1) * sizeof(size_t));

    char *newFieldValue = NULL;

    if (stringSize > 0) {
        newFieldValue = calloc(1, stringSize);
    }

    if (!newEncodedData || !newFieldKeys || !newFieldTypes || !newFieldValues || !newFieldKeySizes || (stringSize > 0 && !newFieldValue)) {

        free(newEncodedData);
        free(newFieldKeys);
        free(newFieldTypes);
        free(newFieldValues);
        free(newFieldKeySizes);
        free(newFieldValue);

        NEO_AA_ErrorHeapAlloc();
        return -1;
    }

    /* copy existing contents */
    memcpy(newEncodedData, header->encodedData, oldSize);

    if (fieldCount) {
        memcpy(newFieldKeys, header->fieldKeys, fieldCount * sizeof(uint32_t));
        memcpy(newFieldTypes, header->fieldTypes, fieldCount);
        memcpy(newFieldValues, header->fieldValues, fieldCount * sizeof(void *));
        memcpy(newFieldKeySizes, header->fieldKeySizes, fieldCount * sizeof(size_t));
    }

    /* encode the new string field */
    uint16_t encodedSize = (uint16_t)newSize;
    memcpy(newEncodedData + 4, &encodedSize, sizeof(encodedSize));

    uint32_t encodedKey = FLIP_32(key);
    memcpy(newEncodedData + oldSize, &encodedKey, sizeof(encodedKey));

    newEncodedData[oldSize + 3] = 'P';

    uint16_t encodedStringSize = (uint16_t)stringSize;
    memcpy(newEncodedData + oldSize + 4, &encodedStringSize, sizeof(encodedStringSize));

    if (stringSize > 0) {
        memcpy(newEncodedData + oldSize + 6, s, stringSize);
        memcpy(newFieldValue, s, stringSize);
    }

    /* prepare metadata */
    newFieldKeys[fieldCount] = key;
    newFieldTypes[fieldCount] = NEO_AA_FIELD_TYPE_STRING;
    newFieldValues[fieldCount] = newFieldValue;
    newFieldKeySizes[fieldCount] = stringSize;

    /* commit after all allocations and copies have succeeded */
    free(header->encodedData);
    free(header->fieldKeys);
    free(header->fieldTypes);
    free(header->fieldValues);
    free(header->fieldKeySizes);

    header->encodedData = newEncodedData;
    header->fieldKeys = newFieldKeys;
    header->fieldTypes = newFieldTypes;
    header->fieldValues = newFieldValues;
    header->fieldKeySizes = newFieldKeySizes;
    header->headerSize = newSize;
    header->fieldCount = fieldCount + 1;
    return 0;
}

/* Currently marked as internal as they have not yet been added to the main library, but it is planned */
NEO_INTERNAL_API int neo_aa_header_set_field_string_err(NeoAAHeader header, uint32_t key, size_t stringSize, char *s) {
    if (!header) {
        NEO_AA_LogError("header is NULL\n");
        return -1;
    }
    /* TODO: This function will call assert if fail! Bad! Make a new one later. */
    internal_do_not_call_is_field_key_available(key);

    if (stringSize > USHRT_MAX || (stringSize > 0 && !s)) {
        NEO_AA_LogError("invalid string size or NULL string\n");
        return -1;
    }

    int keyIndex = neo_aa_header_get_field_key_index(header, key);

    if (keyIndex == -1) {
        /*
         * We mark neo_aa_header_add_field_string deprecated for user
         * but we still want to use it internally
         * So turn off deprecations for just here
         */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        return neo_aa_header_add_field_string(header, key, stringSize, s);
#pragma GCC diagnostic pop
    }

    if (!header->encodedData) {
        NEO_AA_LogError("header missing encoded data\n");
        return -1;
    }

    size_t oldSize = header->headerSize;
    size_t oldValueSize = header->fieldKeySizes[keyIndex];

    /*
     * String fields contain:
     * 4 bytes: key and subtype
     * 2 bytes: string length
     * N bytes: string data
     *
     * Other field types contain:
     * 4 bytes: key and subtype
     * N bytes: field data
     */
    size_t oldPrefixSize = header->fieldTypes[keyIndex] == NEO_AA_FIELD_TYPE_STRING ? 2 : 0;

    size_t oldFieldSize = 4 + oldPrefixSize + oldValueSize;
    size_t newFieldSize = 6 + stringSize;

    /* Find the field's position in the encoded header. */
    uint64_t fieldPos = internal_do_not_call_neo_aa_archive_header_key_pos_in_encoded_data(header, keyIndex);

    if (!fieldPos) {
        NEO_AA_LogError("failed to find position of key in encoded data\n");
        return -1;
    }

    if (fieldPos > oldSize || oldFieldSize > oldSize - (size_t)fieldPos) {
        NEO_AA_LogError("invalid encoded field bounds\n");
        return -1;
    }

    /* calculate new header size */
    size_t remainingSize = oldSize - oldFieldSize;

    if (newFieldSize > UINT16_MAX - remainingSize) {
        NEO_AA_LogError("header exceeds maximum encoded size\n");
        return -1;
    }

    size_t newSize = remainingSize + newFieldSize;

    /*
     * Allocate replacement buffers independently.
     * Nothing in the original header is modified yet.
     */
    char *newEncodedData = malloc(newSize);

    char *newFieldValue = NULL;

    if (stringSize > 0) {
        newFieldValue = malloc(stringSize);
    }

    if (!newEncodedData || (stringSize > 0 && !newFieldValue)) {
        free(newEncodedData);
        free(newFieldValue);
        NEO_AA_ErrorHeapAlloc();
        return -1;
    }

    size_t position = (size_t)fieldPos;

    /*
     * Copy everything before the field, including its
     * four-byte key and subtype.
     */
    memcpy(newEncodedData, header->encodedData, position + 4);

    /* Update the field subtype to string */
    newEncodedData[position + 3] = 'P';

    /* Write the new 16-bit string length */
    uint16_t encodedStringSize = (uint16_t)stringSize;

    memcpy(newEncodedData + position + 4, &encodedStringSize, sizeof(encodedStringSize));

    /* Copy the replacement string */
    if (stringSize > 0) {
        memcpy(newEncodedData + position + 6, s, stringSize);
        memcpy(newFieldValue, s, stringSize);
    }

    /*
     * Move all subsequent encoded fields.
     *
     * This works for both growing and shrinking because
     * the destination is calculated from the new field size.
     */
    size_t oldTailPosition = position + oldFieldSize;
    size_t newTailPosition = position + newFieldSize;
    size_t tailSize = oldSize - oldTailPosition;

    if (tailSize > 0) {
        memmove(newEncodedData + newTailPosition, header->encodedData + oldTailPosition, tailSize);
    }

    /* update the encoded header size */
    uint16_t encodedHeaderSize = (uint16_t)newSize;

    memcpy(newEncodedData + 4, &encodedHeaderSize, sizeof(encodedHeaderSize));

    /*
     * Everything has succeeded.
     * We can now safely replace the original buffers.
     */
    free(header->encodedData);
    free(header->fieldValues[keyIndex]);

    header->encodedData = newEncodedData;
    header->headerSize = newSize;

    header->fieldValues[keyIndex] = newFieldValue;
    header->fieldKeySizes[keyIndex] = stringSize;
    header->fieldTypes[keyIndex] = NEO_AA_FIELD_TYPE_STRING;
    return 0;
}

void neo_aa_header_set_field_string(NeoAAHeader header, uint32_t key, size_t stringSize, char *s) {
    NEO_AA_NullParamAssert(header);
    neo_aa_header_set_field_string_err(header, key, stringSize, s);
}

NEO_INTERNAL_API static int neo_aa_header_add_field_timespec(NeoAAHeader header, uint32_t key, size_t fieldSize, time_t value) {
    if (!header) {
        NEO_AA_LogError("header is NULL\n");
        return -1;
    }
    internal_do_not_call_is_field_key_available(key);

    if (internal_do_not_call_is_field_type_supported_size(NEO_AA_FIELD_TYPE_TIMESPEC, fieldSize) == 0) {
        return -1;
    }

    if (header->headerSize > UINT16_MAX - 4 - fieldSize ||
        header->fieldCount == UINT32_MAX) {
        NEO_AA_LogError("header exceeds maximum encoded size\n");
        return -1;
    }

    size_t oldSize = header->headerSize;
    size_t newSize = oldSize + 4 + fieldSize;
    uint32_t fieldCount = header->fieldCount;

    if (!header->encodedData) {
        NEO_AA_LogError("header missing encoded data\n");
        return -1;
    }

    /* Allocate all replacement buffers. */
    char *newEncodedData = malloc(newSize);
    uint32_t *newFieldKeys = malloc((fieldCount + 1) * sizeof(uint32_t));
    char *newFieldTypes = malloc(fieldCount + 1);
    void **newFieldValues = malloc((fieldCount + 1) * sizeof(void *));
    size_t *newFieldKeySizes = malloc((fieldCount + 1) * sizeof(size_t));
    void *newFieldValue = calloc(1, fieldSize);

    if (!newEncodedData || !newFieldKeys || !newFieldTypes || !newFieldValues || !newFieldKeySizes || !newFieldValue) {

        free(newEncodedData);
        free(newFieldKeys);
        free(newFieldTypes);
        free(newFieldValues);
        free(newFieldKeySizes);
        free(newFieldValue);

        NEO_AA_ErrorHeapAlloc();
        return -1;
    }

    /* copy existing data */
    memcpy(newEncodedData, header->encodedData, oldSize);

    if (fieldCount) {
        memcpy(newFieldKeys, header->fieldKeys, fieldCount * sizeof(uint32_t));
        memcpy(newFieldTypes, header->fieldTypes, fieldCount);
        memcpy(newFieldValues, header->fieldValues, fieldCount * sizeof(void *));
        memcpy(newFieldKeySizes, header->fieldKeySizes, fieldCount * sizeof(size_t));
    }

    /* encode the new field */
    uint16_t encodedSize = (uint16_t)newSize;
    memcpy(newEncodedData + 4, &encodedSize, sizeof(encodedSize));

    uint32_t encodedKey = FLIP_32(key);
    memcpy(newEncodedData + oldSize, &encodedKey, sizeof(encodedKey));

    newEncodedData[oldSize + 3] = internal_do_not_call_neo_aa_header_subtype_for_field_type_and_size(NEO_AA_FIELD_TYPE_TIMESPEC, fieldSize);

    /*
     * avoid reading beyond time_t if fieldSize is larger
     * than sizeof(time_t).
     */
    size_t copySize = fieldSize < sizeof(value) ? fieldSize : sizeof(value);

    memcpy(newEncodedData + oldSize + 4, &value, copySize);
    memcpy(newFieldValue, &value, copySize);

    /* prepare metadata */
    newFieldKeys[fieldCount] = key;
    newFieldTypes[fieldCount] = NEO_AA_FIELD_TYPE_TIMESPEC;
    newFieldValues[fieldCount] = newFieldValue;
    newFieldKeySizes[fieldCount] = fieldSize;

    /* commit after all allocations have succeeded */
    free(header->encodedData);
    free(header->fieldKeys);
    free(header->fieldTypes);
    free(header->fieldValues);
    free(header->fieldKeySizes);

    header->encodedData = newEncodedData;
    header->fieldKeys = newFieldKeys;
    header->fieldTypes = newFieldTypes;
    header->fieldValues = newFieldValues;
    header->fieldKeySizes = newFieldKeySizes;
    header->headerSize = newSize;
    header->fieldCount = fieldCount + 1;
    return 0;
}

void neo_aa_header_set_field_timespec(NeoAAHeader header, uint32_t key, size_t fieldSize, time_t value) {
    /* TODO: Add support for fixing encodedData with keys that become larger */
    NEO_AA_NullParamAssert(header);
    internal_do_not_call_is_field_key_available(key);
    NEO_AA_NullParamAssert(internal_do_not_call_is_field_type_supported_size(NEO_AA_FIELD_TYPE_TIMESPEC, fieldSize));
    int keyIndex = neo_aa_header_get_field_key_index(header, key);
    if (keyIndex == -1) {
        neo_aa_header_add_field_timespec(header, key, fieldSize, value);
        return;
    }
    size_t valueSize = neo_aa_header_get_field_size(header, keyIndex);
    if (valueSize != fieldSize) {
        /* TODO: This will probably be supported later but we need to reform the encodedData for this which is annoying */
        NEO_AA_LogError("setting field key with different size\n");
        return;
    }
    if (header->fieldTypes[keyIndex] != NEO_AA_FIELD_TYPE_TIMESPEC) {
        NEO_AA_LogError("setting field key with different type\n");
        return;
    }
    if (header->fieldKeySizes[keyIndex] != fieldSize) {
        NEO_AA_LogError("setting field key with same type but different size, this is not yet supported but in the future it will be\n");
        return;
    }
    void *encodedData = header->encodedData;
    if (!encodedData) {
        NEO_AA_LogError("header missing encoded data\n");
        return;
    }
    uint64_t encodedDataPos = internal_do_not_call_neo_aa_archive_header_key_pos_in_encoded_data(header, keyIndex);
    if (!encodedDataPos) {
        NEO_AA_LogError("failed to find position of key in encoded data\n");
        return;
    }
    void *valuePtr = header->fieldValues[keyIndex];
    switch (fieldSize) {
        case 8:
            *(uint64_t *)valuePtr = value;
            break;

        case 12:
            *(time_t *)valuePtr = value;
            break;
            
        default:
            NEO_AA_LogError("bad fieldSize\n");
            return;
    }
    void *encodedValuePtr = (uint8_t *)encodedData + encodedDataPos + 4;
    memcpy(encodedValuePtr, &value, fieldSize);
}

void neo_aa_header_remove_field(NeoAAHeader header, uint32_t key) {
    /* TODO: Test function more */
    NEO_AA_NullParamAssert(header);

    int keyIndex = neo_aa_header_get_field_key_index(header, key);
    if (keyIndex == -1) {
        NEO_AA_LogError("field key not found\n");
        return;
    }
    neo_aa_header_remove_field_at_index(header, keyIndex);
}

void neo_aa_header_remove_field_at_index(NeoAAHeader header, int keyIndex) {

    /* Get the size of the field to remove */
    size_t fieldSize = header->fieldKeySizes[keyIndex];
    size_t encodedFieldSize = fieldSize + 4; /* 4 bytes for the key and subtype */

    /* Calculate the position of the field in the encoded data */
    uint64_t fieldKeyEncodedDataPos = internal_do_not_call_neo_aa_archive_header_key_pos_in_encoded_data(header, keyIndex);
    if (!fieldKeyEncodedDataPos) {
        NEO_AA_LogError("failed to find position of key in encoded data\n");
        return;
    }

    /* Remove the field from the encoded data */
    char *encodedData = header->encodedData;
    size_t oldSize = header->headerSize;
    size_t newSize = oldSize - encodedFieldSize;

    /* Shift the remaining data in encodedData to overwrite the removed field */
    memmove(encodedData + fieldKeyEncodedDataPos,
            encodedData + fieldKeyEncodedDataPos + encodedFieldSize,
            oldSize - (fieldKeyEncodedDataPos + encodedFieldSize));

    /* Reallocate encodedData to the new size */
    char *newEncodedData = realloc(encodedData, newSize);
    if (!newEncodedData) {
        NEO_AA_ErrorHeapAlloc();
        return;
    }
    header->encodedData = newEncodedData;
    header->headerSize = newSize;

    /* Free the field value if it exists */
    free(header->fieldValues[keyIndex]);

    /* Shift the remaining fields in the arrays to fill the gap */
    uint32_t fieldCount = header->fieldCount;
    for (unsigned int i = keyIndex; i < fieldCount - 1; i++) {
        header->fieldKeys[i] = header->fieldKeys[i + 1];
        header->fieldTypes[i] = header->fieldTypes[i + 1];
        header->fieldValues[i] = header->fieldValues[i + 1];
        header->fieldKeySizes[i] = header->fieldKeySizes[i + 1];
    }

    /* Reallocate the arrays to the new size */
    /* TODO: Handle realloc() failure */
    uint32_t *newFieldKeys = realloc(header->fieldKeys, (fieldCount - 1) * sizeof(uint32_t));
    char *newFieldTypes = realloc(header->fieldTypes, fieldCount - 1);
    void **newFieldValues = realloc(header->fieldValues, (fieldCount - 1) * sizeof(void *));
    size_t *newFieldKeySizes = realloc(header->fieldKeySizes, (fieldCount - 1) * sizeof(size_t));

    if (!newFieldKeys || !newFieldTypes || !newFieldValues || !newFieldKeySizes) {
        NEO_AA_ErrorHeapAlloc();
        return;
    }

    /* Update the header fields */
    header->fieldKeys = newFieldKeys;
    header->fieldTypes = newFieldTypes;
    header->fieldValues = newFieldValues;
    header->fieldKeySizes = newFieldKeySizes;
    header->fieldCount = fieldCount - 1;
}

NeoAAHeader neo_aa_header_clone_header(NeoAAHeader header) {
    if (!header) {
        NEO_AA_LogError("header is NULL\n");
        return NULL;
    }
    char *encodedData = header->encodedData;
    size_t encodedDataSize = header->headerSize;
    int fieldCount = header->fieldCount;
    size_t *fieldKeySizes = header->fieldKeySizes;
    uint32_t *fieldKeys = header->fieldKeys;
    char *fieldTypes = header->fieldTypes;
    void **fieldValues = header->fieldValues;
    NeoAAHeader clonedHeader = malloc(sizeof(struct neo_aa_header_impl));
    if (!clonedHeader) {
        NEO_AA_ErrorHeapAlloc();
        return NULL;
    }
    size_t *copiedFieldKeySizes = malloc(fieldCount * sizeof(size_t));
    if (!copiedFieldKeySizes) {
        free(clonedHeader);
        NEO_AA_ErrorHeapAlloc();
        return NULL;
    }
    char *copiedEncodedData = malloc(encodedDataSize);
    if (!copiedEncodedData) {
        free(copiedFieldKeySizes);
        free(clonedHeader);
        NEO_AA_ErrorHeapAlloc();
        return NULL;
    }
    uint32_t *copiedFieldKeys = malloc(fieldCount * sizeof(uint32_t));
    if (!copiedFieldKeys) {
        free(copiedEncodedData);
        free(copiedFieldKeySizes);
        free(clonedHeader);
        NEO_AA_ErrorHeapAlloc();
        return NULL;
    }
    char *copiedFieldTypes = malloc(fieldCount);
    if (!copiedFieldTypes) {
        free(copiedFieldKeys);
        free(copiedEncodedData);
        free(copiedFieldKeySizes);
        free(clonedHeader);
        NEO_AA_ErrorHeapAlloc();
        return NULL;
    }
    void **copiedFieldValues = malloc(fieldCount * sizeof(void*));
    if (!copiedFieldValues) {
        free(copiedFieldTypes);
        free(copiedFieldKeys);
        free(copiedEncodedData);
        free(copiedFieldKeySizes);
        free(clonedHeader);
        NEO_AA_ErrorHeapAlloc();
        return NULL;
    }
    for (size_t i = 0; i < encodedDataSize; i++) {
        copiedEncodedData[i] = encodedData[i];
    }
    for (int i = 0; i < fieldCount; i++) {
        size_t fieldKeySize = fieldKeySizes[i];
        uint8_t *fieldValue = fieldValues[i];
        uint8_t *copiedFieldValue = malloc(fieldKeySize);
        if (!copiedFieldValue) {
            if (i) {
                for (int j = 0; j < i; j++) {
                    free(copiedFieldValues[j]);
                }
            }
            free(copiedFieldTypes);
            free(copiedFieldKeys);
            free(copiedEncodedData);
            free(copiedFieldKeySizes);
            free(clonedHeader);
            NEO_AA_ErrorHeapAlloc();
            return NULL;
        }
        for (size_t j = 0; j < fieldKeySize; j++) {
            copiedFieldValue[j] = fieldValue[j];
        }
        copiedFieldKeys[i] = fieldKeys[i];
        copiedFieldKeySizes[i] = fieldKeySize;
        copiedFieldTypes[i] = fieldTypes[i];
        copiedFieldValues[i] = copiedFieldValue;
    }
    clonedHeader->fieldCount = fieldCount;
    clonedHeader->encodedData = copiedEncodedData;
    clonedHeader->fieldKeys = copiedFieldKeys;
    clonedHeader->fieldTypes = copiedFieldTypes;
    clonedHeader->fieldValues = copiedFieldValues;
    clonedHeader->fieldKeySizes = copiedFieldKeySizes;
    clonedHeader->headerSize = encodedDataSize;
    clonedHeader->archiveItem = NULL;
    return clonedHeader;
}

NeoAAFieldType neo_aa_header_get_field_type(NeoAAHeader header, int index) {
    return header->fieldTypes[index];
}
