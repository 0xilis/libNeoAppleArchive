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
    NeoAAHeader header = malloc(sizeof(struct neo_aa_header_impl));
    if (!header) {
        fprintf(stderr,"neo_aa_header_create: malloc\n");
        return NULL;
    }
    memset(header, 0, sizeof(struct neo_aa_header_impl));
    size_t default_header_size = 6;
    char *headerData = malloc(default_header_size + 1);
    strcpy(headerData, "AA01");
    headerData[4] = 6; /* 6 bytes long on creation */
    headerData[5] = 0;
    header->encodedData = headerData;
    header->headerSize = default_header_size;
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
    uint32_t *dumbHack = *(uint32_t **)&data;
    uint32_t headerMagic = dumbHack[0];
    if (headerMagic != AAR_MAGIC && headerMagic != YAA_MAGIC) { /* AA01/YAA1 */
        fprintf(stderr,"neo_aa_header_create_with_encoded_data: data is not raw header (compression not yet supported)\n");
        return NULL;
    }
    if ((dumbHack[1] & 0xffff) != encodedSize) {
        fprintf(stderr,"neo_aa_header_create_with_encoded_data: encodedSize mismatch\n");
        return NULL;
    }
    if (encodedSize < 6) {
        fprintf(stderr,"neo_aa_header_create_with_encoded_data: encodedSize too small\n");
        return NULL;
    }
    NeoAAHeader header = malloc(sizeof(struct neo_aa_header_impl));
    if (!header) {
        fprintf(stderr,"neo_aa_header_create_with_encoded_data: malloc\n");
        return NULL;
    }
    char *headerData = malloc(encodedSize);
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
    while (currentPos < encodedSize) {
        fieldCount++;
        fieldKeys = realloc(fieldKeys, sizeof(uint32_t) * fieldCount);
        fieldTypes = realloc(fieldTypes, fieldCount);
        fieldKeySizes = realloc(fieldKeySizes, sizeof(size_t) * fieldCount);
        fieldKeyValues = realloc(fieldKeyValues, sizeof(void *) * fieldCount);
        
        char *currentPointer = headerData + currentPos;
        dumbHack = *(uint32_t **)&currentPointer;
        uint32_t fieldKeyPlusSubtype = dumbHack[0];
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
                char *sizeCharPtr = currentPointer + 4;
                uint16_t *sizeShortPtr = *(uint16_t **)&sizeCharPtr;
                fieldKeySize = sizeShortPtr[0];
                if (encodedSize-currentPos < fieldKeySize) {
                    free(fieldKeys);
                    free(fieldKeySizes);
                    free(fieldTypes);
                    free(headerData);
                    for (unsigned int i = 0; i < fieldCount - 1; i++) {
                        free(fieldKeyValues[i]);
                    }
                    free(fieldKeyValues);
                    free(header);
                    NEO_AA_LogError("string length reached past encodedData\n");
                    return NULL;
                }
                currentPos += 2;
                break;
                
            default:
                free(fieldKeys);
                free(fieldKeySizes);
                free(fieldTypes);
                free(headerData);
                for (unsigned int i = 0; i < fieldCount - 1; i++) {
                    free(fieldKeyValues[i]);
                }
                free(fieldKeyValues);
                free(header);
                fprintf(stderr, "neo_aa_header_create_with_encoded_data: invalid field subtype (%x)\n",fieldKeyPlusSubtype);
                return NULL;
        }
        
        fieldKeys[fieldCount - 1] = fieldKey;
        fieldTypes[fieldCount - 1] = fieldKeyType;
        fieldKeySizes[fieldCount - 1] = fieldKeySize;
        
        /* make value */
        uint8_t *fieldKeyValue = malloc(fieldKeySize);
        /* copy field key to fieldKeyValue */
        for (size_t i = 0; i < fieldKeySize; i++) {
            fieldKeyValue[i] = headerData[currentPos + i];
        }
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

NEO_INTERNAL_API static void neo_aa_header_add_field_uint_or_blob(NeoAAHeader header, uint32_t key, size_t fieldSize, uint64_t value, NeoAAFieldType fieldType) {
    NEO_AA_NullParamAssert(header);
    internal_do_not_call_is_field_key_available(key);
    NEO_AA_NullParamAssert(internal_do_not_call_is_field_type_supported_size(fieldType, fieldSize));
    size_t oldSize = header->headerSize;
    size_t newSize = oldSize + 4 + fieldSize;
    char *encodedData = header->encodedData;
    uint32_t fieldCount = header->fieldCount;
    char *newEncodedData = realloc(encodedData, newSize);
    if (!newEncodedData) {
        NEO_AA_ErrorHeapAlloc();
        return;
    }
    uint32_t *newFieldKeys = realloc(header->fieldKeys, (fieldCount + 1) * sizeof(uint32_t));
    if (!newFieldKeys) {
        NEO_AA_ErrorHeapAlloc();
        return;
    }
    char *newFieldTypes = realloc(header->fieldTypes, fieldCount + 1);
    if (!newFieldTypes) {
        NEO_AA_ErrorHeapAlloc();
        return;
    }
    void **newFieldValues = realloc(header->fieldValues, (fieldCount + 1) * sizeof(void*));
    if (!newFieldValues) {
        NEO_AA_ErrorHeapAlloc();
        return;
    }
    size_t *fieldKeySizes = realloc(header->fieldKeySizes, (fieldCount + 1) * sizeof(size_t));
    if (!fieldKeySizes) {
        NEO_AA_ErrorHeapAlloc();
        return;
    }
    uint16_t newSizeDowncast = (uint16_t)newSize;
    /* Update encodedData with new size */
    memcpy(newEncodedData + 4, &newSizeDowncast, 2);
    uint32_t dumbPatchworkFix = FLIP_32(key);
    memcpy(newEncodedData + oldSize, &dumbPatchworkFix, 4);
    newEncodedData[oldSize + 3] = internal_do_not_call_neo_aa_header_subtype_for_field_type_and_size(fieldType, fieldSize);
    memcpy(newEncodedData + oldSize + 4, &value, fieldSize);
    header->encodedData = newEncodedData;
    header->headerSize = newSize;
    fieldKeySizes[fieldCount] = fieldSize;
    uint64_t *fieldValue = malloc(sizeof(uint64_t));
    *fieldValue = value;
    newFieldValues[fieldCount] = fieldValue;
    newFieldTypes[fieldCount] = fieldType;
    newFieldKeys[fieldCount] = key;
    header->fieldCount = fieldCount + 1;
    header->fieldValues = newFieldValues;
    header->fieldKeys = newFieldKeys;
    header->fieldTypes = newFieldTypes;
    header->fieldKeySizes = fieldKeySizes;
}

NEO_INTERNAL_API static void neo_aa_header_set_field_uint_or_blob(NeoAAHeader header, uint32_t key, size_t fieldSize, uint64_t value, NeoAAFieldType fieldType) {
    /* TODO: Add support for fixing encodedData with keys that become larger */
    NEO_AA_NullParamAssert(header);
    internal_do_not_call_is_field_key_available(key);
    NEO_AA_NullParamAssert(internal_do_not_call_is_field_type_supported_size(fieldType, fieldSize));
    int keyIndex = neo_aa_header_get_field_key_index(header, key);
    if (keyIndex == -1) {
        neo_aa_header_add_field_uint_or_blob(header, key, fieldSize, value, fieldType);
        return;
    }
    size_t valueSize = neo_aa_header_get_field_size(header, keyIndex);
    if (valueSize != fieldSize) {
        /* TODO: This will probably be supported later but we need to reform the encodedData for this which is annoying */
        NEO_AA_LogError("setting field key with different size\n");
        return;
    }
    if (header->fieldTypes[keyIndex] != (char)fieldType) {
        NEO_AA_LogError("setting field key with different type\n");
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
            return;
    }
    void *encodedValuePtr = (uint8_t *)encodedData + encodedDataPos + 4;
    memcpy(encodedValuePtr, &value, fieldSize);
}

void neo_aa_header_set_field_uint(NeoAAHeader header, uint32_t key, size_t fieldSize, uint64_t value) {
    neo_aa_header_set_field_uint_or_blob(header, key, fieldSize, value, NEO_AA_FIELD_TYPE_UINT);
}

void neo_aa_header_set_field_blob(NeoAAHeader header, uint32_t key, size_t fieldSize, uint64_t blobSize) {
    if (!fieldSize) {
        if (blobSize < 0xFFFF) {
            fieldSize = 2;
        } else if (blobSize < 0xFFFFFFFF) {
            fieldSize = 4;
        } else {
            fieldSize = 8;
        }
    }
    /* Blobs are not part of neo_aa_header, you will add the context to a neo_aa_archive_item later. */
    neo_aa_header_set_field_uint_or_blob(header, key, fieldSize, blobSize, NEO_AA_FIELD_TYPE_BLOB);
}

void neo_aa_header_add_field_string(NeoAAHeader header, uint32_t key, size_t stringSize, char *s) {
    NEO_AA_NullParamAssert(header);
    if (stringSize > USHRT_MAX) {
        NEO_AA_LogErrorF("libNeoAppleArchive: stringSize %zu larger than USHRT_MAX\n",stringSize);
        return;
    }
    internal_do_not_call_is_field_key_available(key);
    size_t oldSize = header->headerSize;
    size_t newSize = oldSize + 6 + stringSize;
    if (newSize > USHRT_MAX) {
        NEO_AA_LogErrorF("libNeoAppleArchive: headerSize grew past USHRT_MAX with newSize %zu\n",newSize);
        return;
    }
    char *encodedData = header->encodedData;
    uint32_t fieldCount = header->fieldCount;
    char *newEncodedData = realloc(encodedData, newSize);
    if (!newEncodedData) {
        NEO_AA_ErrorHeapAlloc();
        return;
    }
    uint32_t *newFieldKeys = realloc(header->fieldKeys, (fieldCount + 1) * sizeof(uint32_t));
    if (!newFieldKeys) {
        NEO_AA_ErrorHeapAlloc();
        return;
    }
    char *newFieldTypes = realloc(header->fieldTypes, fieldCount + 1);
    if (!newFieldTypes) {
        NEO_AA_ErrorHeapAlloc();
        return;
    }
    void **newFieldValues = realloc(header->fieldValues, (fieldCount + 1) * sizeof(void*));
    if (!newFieldValues) {
        NEO_AA_ErrorHeapAlloc();
        return;
    }
    size_t *fieldKeySizes = realloc(header->fieldKeySizes, (fieldCount + 1) * sizeof(size_t));
    if (!fieldKeySizes) {
        NEO_AA_ErrorHeapAlloc();
        return;
    }
    uint16_t newSizeDowncast = (uint16_t)newSize;
    /* Update encodedData with new size */
    memcpy(newEncodedData + 4, &newSizeDowncast, 2);
    uint32_t dumbPatchworkFix = FLIP_32(key);
    memcpy(newEncodedData + oldSize, &dumbPatchworkFix, 4);
    newEncodedData[oldSize + 3] = 'P';
    memcpy(newEncodedData + oldSize + 4, &stringSize, 2);

    /* Only copy string if it has a size */
    if (stringSize) {
        strncpy(newEncodedData + oldSize + 6, s, stringSize);
    }

    header->encodedData = newEncodedData;
    header->headerSize = newSize;
    fieldKeySizes[fieldCount] = stringSize;

    char *fieldValue;
    if (stringSize) {
        fieldValue = malloc(stringSize + 1);
        strncpy(fieldValue, s, stringSize);
    } else {
        /* If stringSize is 0, string is NULL */
        fieldValue = 0;
    }
    newFieldValues[fieldCount] = fieldValue;
    newFieldTypes[fieldCount] = NEO_AA_FIELD_TYPE_STRING;
    newFieldKeys[fieldCount] = key;
    header->fieldCount = fieldCount + 1;
    header->fieldValues = newFieldValues;
    header->fieldKeys = newFieldKeys;
    header->fieldTypes = newFieldTypes;
    header->fieldKeySizes = fieldKeySizes;
}

void neo_aa_header_set_field_string(NeoAAHeader header, uint32_t key, size_t stringSize, char *s) {
    NEO_AA_NullParamAssert(header);
    internal_do_not_call_is_field_key_available(key);

    int keyIndex = neo_aa_header_get_field_key_index(header, key);
    if (keyIndex == -1) {
        /*
         * We mark neo_aa_header_add_field_string deprecated for user
         * but we still want to use it internally
         * So turn off deprecations for just here
         */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        neo_aa_header_add_field_string(header, key, stringSize, s);
#pragma GCC diagnostic pop
        return;
    }

    size_t oldStringSize = neo_aa_header_get_field_size(header, keyIndex);
    size_t oldAllocationSize = oldStringSize;
    if (NEO_AA_FIELD_TYPE_STRING == header->fieldTypes[keyIndex]) {
        oldAllocationSize += 2;
    }

    size_t newAllocationSize = stringSize + 2;

    uint64_t fieldKeyEncodedDataPos = internal_do_not_call_neo_aa_archive_header_key_pos_in_encoded_data(header, keyIndex);
    if (!fieldKeyEncodedDataPos) {
        NEO_AA_LogError("failed to find position of key in encoded data\n");
        return;
    }

    char *encodedData = header->encodedData;

    /* Check for overflow */
    if (newAllocationSize > oldAllocationSize) {
        /* Need to reallocate the encodedData to fit the new string size */
        size_t oldSize = header->headerSize;
        size_t newSize = oldSize + (newAllocationSize - oldAllocationSize);

        char *newEncodedData = realloc(encodedData, newSize);
        if (!newEncodedData) {
            NEO_AA_ErrorHeapAlloc();
            return;
        }

        header->encodedData = newEncodedData;
        header->headerSize = newSize;

        /* Ensure that the moveSize is non-negative before calling memmove */
        size_t moveSize = oldSize - (fieldKeyEncodedDataPos + 4 + oldAllocationSize);

        if (moveSize > 0) {
            memmove(newEncodedData + fieldKeyEncodedDataPos + 4 + newAllocationSize,
                newEncodedData + fieldKeyEncodedDataPos + 4 + oldAllocationSize,
                moveSize);
        }

        encodedData = newEncodedData;
    }

    uint16_t stringSizeDowncast = (uint16_t)stringSize;
    memcpy(encodedData + fieldKeyEncodedDataPos + 4, &stringSizeDowncast, 2);

    if (stringSize > 0) {
        memcpy(encodedData + fieldKeyEncodedDataPos + 6, s, stringSize);
    }

    header->fieldKeySizes[keyIndex] = stringSize;

    free(header->fieldValues[keyIndex]);

    char *newFieldValue = NULL;
    if (stringSize > 0) {
        newFieldValue = malloc(stringSize);
        if (!newFieldValue) {
            NEO_AA_ErrorHeapAlloc();
            return;
        }
        strncpy(newFieldValue, s, stringSize);
        /* libAppleArchive doesn't NULL terminate the string so I won't here */
    }

    header->fieldValues[keyIndex] = newFieldValue;

    if (header->fieldTypes[keyIndex] != NEO_AA_FIELD_TYPE_STRING) {
        header->fieldTypes[keyIndex] = NEO_AA_FIELD_TYPE_STRING;
    }
}

NEO_INTERNAL_API static void neo_aa_header_add_field_timespec(NeoAAHeader header, uint32_t key, size_t fieldSize, time_t value) {
    NEO_AA_NullParamAssert(header);
    internal_do_not_call_is_field_key_available(key);
    NEO_AA_NullParamAssert(internal_do_not_call_is_field_type_supported_size(NEO_AA_FIELD_TYPE_TIMESPEC, fieldSize));
    size_t oldSize = header->headerSize;
    size_t newSize = oldSize + 4 + fieldSize;
    char *encodedData = header->encodedData;
    uint32_t fieldCount = header->fieldCount;
    char *newEncodedData = realloc(encodedData, newSize);
    if (!newEncodedData) {
        NEO_AA_ErrorHeapAlloc();
        return;
    }
    uint32_t *newFieldKeys = realloc(header->fieldKeys, (fieldCount + 1) * sizeof(uint32_t));
    if (!newFieldKeys) {
        NEO_AA_ErrorHeapAlloc();
        return;
    }
    char *newFieldTypes = realloc(header->fieldTypes, fieldCount + 1);
    if (!newFieldTypes) {
        NEO_AA_ErrorHeapAlloc();
        return;
    }
    void **newFieldValues = realloc(header->fieldValues, (fieldCount + 1) * sizeof(void*));
    if (!newFieldValues) {
        NEO_AA_ErrorHeapAlloc();
        return;
    }
    size_t *fieldKeySizes = realloc(header->fieldKeySizes, (fieldCount + 1) * sizeof(size_t));
    if (!fieldKeySizes) {
        NEO_AA_ErrorHeapAlloc();
        return;
    }
    uint16_t newSizeDowncast = (uint16_t)newSize;
    /* Update encodedData with new size */
    memcpy(newEncodedData + 4, &newSizeDowncast, 2);
    uint32_t dumbPatchworkFix = FLIP_32(key);
    memcpy(newEncodedData + oldSize, &dumbPatchworkFix, 4);
    newEncodedData[oldSize + 3] = internal_do_not_call_neo_aa_header_subtype_for_field_type_and_size(NEO_AA_FIELD_TYPE_TIMESPEC, fieldSize);
    memcpy(newEncodedData + oldSize + 4, &value, fieldSize);
    header->encodedData = newEncodedData;
    header->headerSize = newSize;
    fieldKeySizes[fieldCount] = fieldSize;
    uint64_t *fieldValue = malloc(sizeof(time_t));
    *fieldValue = value;
    newFieldValues[fieldCount] = fieldValue;
    newFieldTypes[fieldCount] = NEO_AA_FIELD_TYPE_TIMESPEC;
    newFieldKeys[fieldCount] = key;
    header->fieldCount = fieldCount + 1;
    header->fieldValues = newFieldValues;
    header->fieldKeys = newFieldKeys;
    header->fieldTypes = newFieldTypes;
    header->fieldKeySizes = fieldKeySizes;
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
    NEO_AA_NullParamAssert(header);
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
