//
//  libNeoAppleArchive.c
//  libAppleArchive
//
//  Created by Snoolie Keffaber on 2024/04/22.
//

#include "libNeoAppleArchive.h"

uint32_t internal_do_not_call_flip_edian_32(uint32_t num) {
    return ((num>>24)&0xff) | ((num<<8)&0xff0000) | ((num>>8)&0xff00) | ((num<<24)&0xff000000);
}

#define FLIP_32(x) internal_do_not_call_flip_edian_32(x)

NeoAAHeader neo_aa_header_create(void) {
    NeoAAHeader header = malloc(sizeof(struct neo_aa_header_impl));
    if (!header) {
        fprintf(stderr,"neo_aa_header_create: malloc\n");
        return 0;
    }
    memset(header, 0, sizeof(struct neo_aa_header_impl));
    char *headerData = malloc(6);
    strcpy(headerData, "AA01");
    headerData[4] = 6; /* 6 bytes long on creation */
    header->encodedData = headerData;
    header->fieldCount = 0;
    header->headerSize = 6;
    return header;
}

void neo_aa_header_destroy(NeoAAHeader header) {
    free(header->encodedData);
    free(header->fieldKeySizes);
    free(header->fieldKeys);
    free(header->fieldTypes);
    uint32_t fieldCount = header->fieldCount;
    void **fieldValues = header->fieldValues;
    for (int i = 0; i < fieldCount; i++) {
        free(fieldValues[i]);
    }
    free(fieldValues);
}

NeoAAHeader neo_aa_header_create_with_encoded_data(size_t encodedSize, uint8_t *data) {
    uint32_t *dumbHack = *(uint32_t **)&data;
    if (dumbHack[0] != 0x31304141) { /* AA01 */
        fprintf(stderr,"neo_aa_header_create_with_encoded_data: data is not raw header (compression not yet supported)\n");
        return 0;
    }
    if ((dumbHack[1] & 0xffff) != encodedSize) {
        fprintf(stderr,"neo_aa_header_create_with_encoded_data: encodedSize mismatch\n");
        return 0;
    }
    if (encodedSize < 6) {
        fprintf(stderr,"neo_aa_header_create_with_encoded_data: encodedSize too small\n");
        return 0;
    }
    NeoAAHeader header = malloc(sizeof(struct neo_aa_header_impl));
    if (!header) {
        fprintf(stderr,"neo_aa_header_create_with_encoded_data: malloc\n");
        return 0;
    }
    memset(header, 0, sizeof(struct neo_aa_header_impl));
    char *headerData = malloc(encodedSize);
    memcpy(headerData, data, encodedSize);
    header->encodedData = headerData;
    header->headerSize = encodedSize;
    if (encodedSize == 6) {
        printf("neo_aa_header_create_with_encoded_data: no field keys (wtf?)\n");
        header->fieldCount = 0;
        return header;
    }
    uint32_t *fieldKeys = malloc(sizeof(uint32_t) * 1);
    char *fieldTypes = malloc(1);
    size_t *fieldKeySizes = malloc(sizeof(size_t) * 1);
    void **fieldKeyValues = malloc(sizeof(void *) * 1);
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
                currentPos += 2;
                break;
                
            default:
                free(fieldKeys);
                free(fieldKeySizes);
                free(fieldTypes);
                free(headerData);
                for (int i = 0; i < fieldCount - 1; i++) {
                    free(fieldKeyValues[i]);
                }
                free(fieldKeyValues);
                free(header);
                fprintf(stderr, "neo_aa_header_create_with_encoded_data: invalid field subtype (%x)\n",fieldKeyPlusSubtype);
                return 0;
        }
        
        /*printf("fieldKey: %x\n",fieldKey);
        printf("fieldKeySubtype: %c\n",fieldKeySubtype);
        printf("fieldKeySize: %zx\n",fieldKeySize);*/
        
        fieldKeys[fieldCount - 1] = fieldKey;
        fieldTypes[fieldCount - 1] = fieldKeyType;
        fieldKeySizes[fieldCount - 1] = fieldKeySize;
        
        /* make value */
        uint8_t *fieldKeyValue = malloc(fieldKeySize);
        /* copy field key to fieldKeyValue */
        for (int i = 0; i < fieldKeySize; i++) {
            fieldKeyValue[i] = headerData[currentPos + i];
        }
        fieldKeyValues[fieldCount - 1] = fieldKeyValue;
        
        currentPos += fieldKeySize;
    }
    header->fieldCount = fieldCount;
    header->fieldKeys = fieldKeys;
    header->fieldValues = fieldKeyValues;
    header->fieldKeySizes = fieldKeySizes;
    header->fieldTypes = fieldTypes;
    return header;
}

int neo_aa_header_get_field_key_index(NeoAAHeader header, uint32_t key) {
    uint32_t fieldCount = header->fieldCount;
    for (int i = 0; i < fieldCount; i++) {
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
    char *fieldValuePtr = header->fieldValues[index];
    strncpy(newString, fieldValuePtr, fieldValueSize);
    newString[fieldValueSize] = '\0';
    return newString;
}

size_t neo_aa_header_get_field_size(NeoAAHeader header, int index) {
    return header->fieldKeySizes[index];
}

size_t lastLoadedBinarySize_internal_do_not_use = 0;

char *internal_do_not_call_load_binary(const char *signedShortcutPath) {
    /* load AEA archive into memory */
    FILE *fp = fopen(signedShortcutPath,"r");
    if (!fp) {
        fprintf(stderr,"libshortcutsign: extract_signed_shortcut failed to find path\n");
        return 0;
    }
    fseek(fp, 0, SEEK_END);
    size_t binary_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    lastLoadedBinarySize_internal_do_not_use = binary_size;
    char *aeaShortcutArchive = malloc(binary_size * sizeof(char));
    /* copy bytes to binary, byte by byte... */
    int c;
    size_t n = 0;
    while ((c = fgetc(fp)) != EOF) {
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

void neo_aa_extract_aar_buffer_to_path(uint8_t *appleArchive, size_t appleArchiveSize, const char *outputPath) {
    char *oldWorkingDir = getcwd(NULL, 0);
    uint32_t *dirtyUglyHack = *(uint32_t **)&appleArchive;
    if (dirtyUglyHack[0] != 0x31304141) {
        fprintf(stderr, "neo_aa_extract_aar_buffer_to_path: magic not AA01. (compressed aar not yet supported, needs to be raw)\n");
        return;
    }
    uint8_t *currentHeader = appleArchive;
    int extracting = 1;
    char *slashEndOfPath = internal_do_not_call_memrchr((char *)outputPath, '/', strlen(outputPath));
    char *newPath;
    if (slashEndOfPath) {
        size_t sizeOfNewPath = slashEndOfPath - outputPath;
        newPath = malloc(sizeOfNewPath + 1);
        strncpy(newPath, outputPath, sizeOfNewPath);
        chdir(newPath);
        printf("chdir to: %s\n",newPath);
        free(newPath);
    } else {
        /* BAD! change this later. */
        newPath = (char *)outputPath;
        chdir(outputPath);
    }
    while (extracting) {
        dirtyUglyHack = *(uint32_t **)&currentHeader;
        if (dirtyUglyHack[0] != 0x31304141) {
            fprintf(stderr, "neo_aa_extract_aar_to_path: magic not AA01. (compressed aar not yet supported, needs to be raw)\n");
            return;
        }
        uint16_t headerSize = (dirtyUglyHack[1] & 0xffff);
        NeoAAHeader header = neo_aa_header_create_with_encoded_data(headerSize, currentHeader);
        if (!header) {
            fprintf(stderr, "neo_aa_extract_aar_to_path: header creation fail\n");
            return;
        }
        uint32_t typKey = NEO_AA_FIELD_C("TYP");
        int typIndex = neo_aa_header_get_field_key_index(header, typKey);
        if (typIndex == -1) {
            fprintf(stderr, "neo_aa_extract_aar_to_path: no TYP field\n");
            return;
        }
        uint32_t patKey = NEO_AA_FIELD_C("PAT");
        int patIndex = neo_aa_header_get_field_key_index(header, patKey);
        if (patIndex == -1) {
            fprintf(stderr, "neo_aa_extract_aar_to_path: no PAT field\n");
            return;
        }
        uint32_t modKey = NEO_AA_FIELD_C("MOD");
        int modIndex = neo_aa_header_get_field_key_index(header, modKey);
        if (modIndex == -1) {
            fprintf(stderr, "neo_aa_extract_aar_to_path: no MOD field\n");
            return;
        }
        uint32_t ctmKey = NEO_AA_FIELD_C("CTM");
        int ctmIndex = neo_aa_header_get_field_key_index(header, ctmKey);
        uint32_t mtmKey = NEO_AA_FIELD_C("MTM");
        int mtmIndex = neo_aa_header_get_field_key_index(header, mtmKey);
        uint32_t uidKey = NEO_AA_FIELD_C("UID");
        int uidIndex = neo_aa_header_get_field_key_index(header, uidKey);
        uint32_t gidKey = NEO_AA_FIELD_C("GID");
        int gidIndex = neo_aa_header_get_field_key_index(header, gidKey);
        uint32_t xatKey = NEO_AA_FIELD_C("XAT");
        int xatIndex = neo_aa_header_get_field_key_index(header, xatKey);
        uint64_t accessMode = neo_aa_header_get_field_key_uint(header, modIndex);
        size_t pathSize = neo_aa_header_get_field_size(header, patIndex);
        uint8_t typEntryType = neo_aa_header_get_field_key_uint(header, typIndex);
        struct stat st;
        char *pathName;
        size_t xatSize = 0;
        if (!pathSize) {
            /* directory has empty name, this is only for creating outputPath */
            size_t dirNameSize = strlen(outputPath);
            pathName = malloc(dirNameSize + 1);
            strncpy(pathName, outputPath, dirNameSize);
        } else {
            pathName = neo_aa_header_get_field_key_string(header, patIndex);
        }
        if (typEntryType == 'D') {
            /* Header for directory */
            mkdir(pathName, accessMode);
            stat(pathName, &st);
            uid_t fileUid = st.st_uid;
            gid_t fileGid = st.st_gid;
            if (uidIndex != -1) {
                fileUid = (uid_t)neo_aa_header_get_field_key_uint(header, uidIndex);
            }
            if (gidIndex != -1) {
                fileGid = (gid_t)neo_aa_header_get_field_key_uint(header, gidIndex);
            }
            chown(pathName, fileUid, fileGid);
            if (xatIndex != -1) {
                xatSize = neo_aa_header_get_field_key_uint(header, xatIndex);
            }
            currentHeader += (headerSize + xatSize);
        } else if (typEntryType == 'F') {
            /* Header for file */
            uint32_t datKey = NEO_AA_FIELD_C("DAT");
            int datIndex = neo_aa_header_get_field_key_index(header, datKey);
            if (datIndex == -1) {
                free(pathName);
                fprintf(stderr, "neo_aa_extract_aar_to_path: no DAT field\n");
                return;
            }
            uint64_t dataSize = neo_aa_header_get_field_key_uint(header, datIndex);
            /* make sure we don't overflow and leak data in output */
            uint64_t endOfFile = appleArchiveSize - ((currentHeader - appleArchive) + headerSize);
            if (dataSize > endOfFile) {
                free(pathName);
                free(appleArchive);
                fprintf(stderr, "neo_aa_extract_aar_to_path: dataSize overflow\n");
                return;
            }
            FILE *fp = fopen(pathName, "w");
            if (!fp) {
                free(pathName);
                fprintf(stderr, "neo_aa_extract_aar_to_path: could not open pathName: %s\n",pathName);
                return;
            }
            uint8_t *fileData = currentHeader + headerSize;
            /* copy file data to buffer */
            fwrite(fileData, dataSize, 1, fp);
            fclose(fp);
            stat(pathName, &st);
            uid_t fileUid = st.st_uid;
            gid_t fileGid = st.st_gid;
            if (uidIndex != -1) {
                fileUid = (uid_t)neo_aa_header_get_field_key_uint(header, uidIndex);
            }
            if (gidIndex != -1) {
                fileGid = (gid_t)neo_aa_header_get_field_key_uint(header, gidIndex);
            }
            chown(pathName, fileUid, fileGid);
            if (modIndex != -1) {
                chmod(pathName, accessMode);
            }
            size_t xatSize = 0;
            if (xatIndex != -1) {
                xatSize = neo_aa_header_get_field_key_uint(header, xatIndex);
            }
            currentHeader += (headerSize + dataSize + xatSize);
        } else if (typEntryType == 'L') {
            /* Symlink for file */
            uint32_t lnkKey = NEO_AA_FIELD_C("LNK");
            int lnkIndex = neo_aa_header_get_field_key_index(header, lnkKey);
            if (lnkIndex == -1) {
                free(pathName);
                fprintf(stderr, "neo_aa_extract_aar_to_path: no LNK field\n");
                return;
            }
            char *lnkPath = neo_aa_header_get_field_key_string(header, lnkIndex);
            uint8_t *slashEndOfPathName = (uint8_t *)internal_do_not_call_memrchr(pathName, '/', strlen(pathName));
            if (slashEndOfPathName) {
                /* I'm not even sure if this works */
                char *symlinkPath = malloc(strlen(lnkPath) + strlen((char *)slashEndOfPathName) + 1);
                strncpy(symlinkPath, pathName, (slashEndOfPathName - appleArchive));
                sprintf(symlinkPath + (slashEndOfPathName - appleArchive), "/%s", lnkPath);
                symlink(symlinkPath, pathName);
                free(symlinkPath);
            } else {
                symlink(lnkPath, pathName);
            }
            free(lnkPath);
        } else {
            free(pathName);
            fprintf(stderr, "neo_aa_extract_aar_to_path: AAEntryType %c not supported yet, only D and F currently are\n",typEntryType);
            return;
        }
        free(pathName);
        size_t currentHeader_IndexOfArchive = (currentHeader - appleArchive);
        if (currentHeader_IndexOfArchive >= appleArchiveSize) {
            /* reached end of file */
            extracting = 0;
        }
    }
    /* Restore original working dir */
    chdir(oldWorkingDir);
}

void neo_aa_extract_aar_to_path(const char *archivePath, const char *outputPath) {
    char *oldWorkingDir = getcwd(NULL, 0);
    uint8_t *appleArchive = (uint8_t *)internal_do_not_call_load_binary(archivePath);
    /* dirty ugly hack */
    uint32_t *dirtyUglyHack = *(uint32_t **)&appleArchive;
    if (dirtyUglyHack[0] != 0x31304141) {
        fprintf(stderr, "neo_aa_extract_aar_to_path: magic not AA01. (compressed aar not yet supported, needs to be raw)\n");
        return;
    }
    size_t appleArchiveSize = lastLoadedBinarySize_internal_do_not_use;
    uint8_t *currentHeader = appleArchive;
    int extracting = 1;
    char *slashEndOfPath = internal_do_not_call_memrchr((char *)outputPath, '/', strlen(outputPath));
    char *newPath;
    if (slashEndOfPath) {
        size_t sizeOfNewPath = slashEndOfPath - outputPath;
        newPath = malloc(sizeOfNewPath + 1);
        strncpy(newPath, outputPath, sizeOfNewPath);
        chdir(newPath);
        printf("chdir to: %s\n",newPath);
        free(newPath);
    } else {
        /* BAD! change this later. */
        newPath = (char *)outputPath;
        chdir(outputPath);
    }
    while (extracting) {
        dirtyUglyHack = *(uint32_t **)&currentHeader;
        if (dirtyUglyHack[0] != 0x31304141) {
            free(appleArchive);
            fprintf(stderr, "neo_aa_extract_aar_to_path: magic not AA01. (compressed aar not yet supported, needs to be raw)\n");
            return;
        }
        uint16_t headerSize = (dirtyUglyHack[1] & 0xffff);
        NeoAAHeader header = neo_aa_header_create_with_encoded_data(headerSize, currentHeader);
        if (!header) {
            free(appleArchive);
            fprintf(stderr, "neo_aa_extract_aar_to_path: header creation fail\n");
            return;
        }
        uint32_t typKey = NEO_AA_FIELD_C("TYP");
        int typIndex = neo_aa_header_get_field_key_index(header, typKey);
        if (typIndex == -1) {
            free(appleArchive);
            fprintf(stderr, "neo_aa_extract_aar_to_path: no TYP field\n");
            return;
        }
        uint32_t patKey = NEO_AA_FIELD_C("PAT");
        int patIndex = neo_aa_header_get_field_key_index(header, patKey);
        if (patIndex == -1) {
            free(appleArchive);
            fprintf(stderr, "neo_aa_extract_aar_to_path: no PAT field\n");
            return;
        }
        uint32_t modKey = NEO_AA_FIELD_C("MOD");
        int modIndex = neo_aa_header_get_field_key_index(header, modKey);
        if (modIndex == -1) {
            free(appleArchive);
            fprintf(stderr, "neo_aa_extract_aar_to_path: no MOD field\n");
            return;
        }
        uint32_t ctmKey = NEO_AA_FIELD_C("CTM");
        int ctmIndex = neo_aa_header_get_field_key_index(header, ctmKey);
        uint32_t mtmKey = NEO_AA_FIELD_C("MTM");
        int mtmIndex = neo_aa_header_get_field_key_index(header, mtmKey);
        uint32_t uidKey = NEO_AA_FIELD_C("UID");
        int uidIndex = neo_aa_header_get_field_key_index(header, uidKey);
        uint32_t gidKey = NEO_AA_FIELD_C("GID");
        int gidIndex = neo_aa_header_get_field_key_index(header, gidKey);
        uint32_t xatKey = NEO_AA_FIELD_C("XAT");
        int xatIndex = neo_aa_header_get_field_key_index(header, xatKey);
        uint64_t accessMode = neo_aa_header_get_field_key_uint(header, modIndex);
        size_t pathSize = neo_aa_header_get_field_size(header, patIndex);
        uint8_t typEntryType = neo_aa_header_get_field_key_uint(header, typIndex);
        struct stat st;
        char *pathName;
        size_t xatSize = 0;
        if (!pathSize) {
            /* directory has empty name, this is only for creating outputPath */
            size_t dirNameSize = strlen(outputPath);
            pathName = malloc(dirNameSize + 1);
            strncpy(pathName, outputPath, dirNameSize);
        } else {
            pathName = neo_aa_header_get_field_key_string(header, patIndex);
        }
        if (typEntryType == 'D') {
            /* Header for directory */
            mkdir(pathName, accessMode);
            stat(pathName, &st);
            uid_t fileUid = st.st_uid;
            gid_t fileGid = st.st_gid;
            if (uidIndex != -1) {
                fileUid = (uid_t)neo_aa_header_get_field_key_uint(header, uidIndex);
            }
            if (gidIndex != -1) {
                fileGid = (gid_t)neo_aa_header_get_field_key_uint(header, gidIndex);
            }
            chown(pathName, fileUid, fileGid);
            if (xatIndex != -1) {
                xatSize = neo_aa_header_get_field_key_uint(header, xatIndex);
            }
            currentHeader += (headerSize + xatSize);
        } else if (typEntryType == 'F') {
            /* Header for file */
            uint32_t datKey = NEO_AA_FIELD_C("DAT");
            int datIndex = neo_aa_header_get_field_key_index(header, datKey);
            if (datIndex == -1) {
                free(pathName);
                free(appleArchive);
                fprintf(stderr, "neo_aa_extract_aar_to_path: no DAT field\n");
                return;
            }
            uint64_t dataSize = neo_aa_header_get_field_key_uint(header, datIndex);
            /* make sure we don't overflow and leak data in output */
            uint64_t endOfFile = appleArchiveSize - ((currentHeader - appleArchive) + headerSize);
            if (dataSize > endOfFile) {
                free(pathName);
                free(appleArchive);
                fprintf(stderr, "neo_aa_extract_aar_to_path: dataSize overflow\n");
                return;
            }
            FILE *fp = fopen(pathName, "w");
            if (!fp) {
                free(pathName);
                free(appleArchive);
                fprintf(stderr, "neo_aa_extract_aar_to_path: could not open pathName: %s\n",pathName);
                return;
            }
            uint8_t *fileData = currentHeader + headerSize;
            /* copy file data to buffer */
            fwrite(fileData, dataSize, 1, fp);
            fclose(fp);
            stat(pathName, &st);
            uid_t fileUid = st.st_uid;
            gid_t fileGid = st.st_gid;
            if (uidIndex != -1) {
                fileUid = (uid_t)neo_aa_header_get_field_key_uint(header, uidIndex);
            }
            if (gidIndex != -1) {
                fileGid = (gid_t)neo_aa_header_get_field_key_uint(header, gidIndex);
            }
            chown(pathName, fileUid, fileGid);
            if (modIndex != -1) {
                chmod(pathName, accessMode);
            }
            size_t xatSize = 0;
            if (xatIndex != -1) {
                xatSize = neo_aa_header_get_field_key_uint(header, xatIndex);
            }
            currentHeader += (headerSize + dataSize + xatSize);
        } else if (typEntryType == 'L') {
            /* Symlink for file */
            uint32_t lnkKey = NEO_AA_FIELD_C("LNK");
            int lnkIndex = neo_aa_header_get_field_key_index(header, lnkKey);
            if (lnkIndex == -1) {
                free(pathName);
                free(appleArchive);
                fprintf(stderr, "neo_aa_extract_aar_to_path: no LNK field\n");
                return;
            }
            char *lnkPath = neo_aa_header_get_field_key_string(header, lnkIndex);
            uint8_t *slashEndOfPathName = (uint8_t *)internal_do_not_call_memrchr(pathName, '/', strlen(pathName));
            if (slashEndOfPathName) {
                /* I'm not even sure if this works */
                char *symlinkPath = malloc(strlen(lnkPath) + strlen((char *)slashEndOfPathName) + 1);
                strncpy(symlinkPath, pathName, (slashEndOfPathName - appleArchive));
                sprintf(symlinkPath + (slashEndOfPathName - appleArchive), "/%s", lnkPath);
                symlink(symlinkPath, pathName);
                free(symlinkPath);
            } else {
                symlink(lnkPath, pathName);
            }
            free(lnkPath);
        } else {
            free(pathName);
            free(appleArchive);
            fprintf(stderr, "neo_aa_extract_aar_to_path: AAEntryType %c not supported yet, only D and F currently are\n",typEntryType);
            return;
        }
        free(pathName);
        size_t currentHeader_IndexOfArchive = (currentHeader - appleArchive);
        if (currentHeader_IndexOfArchive >= appleArchiveSize) {
            /* reached end of file */
            extracting = 0;
        }
    }
    free(appleArchive);
    /* Restore original working dir */
    chdir(oldWorkingDir);
}
