//
//  libNeoAppleArchive.c
//  libAppleArchive
//
//  Created by Snoolie Keffaber on 2024/04/22.
//

#include "libNeoAppleArchive.h"
#include "libNeoAppleArchive_internal.h"

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
                uint8_t *xattrBlob = currentHeader + headerSize;
                internal_do_not_call_apply_xattr_blob_to_path(xattrBlob, xatSize, pathName);
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
                uint8_t *xattrBlob = currentHeader + headerSize + dataSize;
                internal_do_not_call_apply_xattr_blob_to_path(xattrBlob, xatSize, pathName);
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

/* Unfinished. */
NeoAAArchiveItem neo_aa_archive_item_create_with_header(NeoAAHeader header) {
    NEO_AA_NullParamAssert(header);
    NeoAAArchiveItem archiveItem = malloc(sizeof(struct neo_aa_archive_item_impl));
    if (!archiveItem) {
        NEO_AA_ErrorHeapAlloc();
        return 0;
    }
    memset(archiveItem, 0, sizeof(struct neo_aa_archive_item_impl));
    archiveItem->header = header;
    srand((unsigned int)time(NULL));
    int heapCookie = rand();
    internal_do_not_call_neo_aa_header_fill_heap_cookies(header, heapCookie);
    archiveItem->archiveItemIdentifier = heapCookie;
    return archiveItem;
}

/* Unfinished. */
void neo_aa_archive_item_add_blob_data(NeoAAArchiveItem item, char *data, size_t dataSize) {
    NEO_AA_NullParamAssert(item);
    NEO_AA_NullParamAssert(data);
    NEO_AA_NullParamAssert(dataSize);
    internal_do_not_call_neo_aa_archive_item_assert_heap_cookie(item);
    char *encodedBlobData = item->encodedBlobData;
    if (encodedBlobData) {
        /* Zero out item->encodedBlobData BEFORE we free it to prevent weird UaF race threading issues */
        item->encodedBlobData = 0;
        free(encodedBlobData);
    }
    encodedBlobData = malloc(dataSize);
    for (size_t i = 0; i < dataSize; i++) {
        encodedBlobData[i] = data[i];
    }
    item->encodedBlobData = encodedBlobData;
    item->encodedBlobDataSize = dataSize;
}

NeoAAArchivePlain neo_aa_archive_plain_create_with_items(NeoAAArchiveItem *items, int itemCount) {
    NEO_AA_NullParamAssert(items);
    NEO_AA_NullParamAssert(itemCount);
    srand((unsigned int)time(NULL));
    int heapCookie = rand();
    NeoAAArchivePlain plainArchive = malloc(sizeof(struct neo_aa_archive_plain_impl));
    if (!plainArchive) {
        NEO_AA_ErrorHeapAlloc();
        return 0;
    }
    memset(plainArchive, 0, sizeof(struct neo_aa_archive_plain_impl));
    plainArchive->archivePlainIdentifier = heapCookie;
    NeoAAArchiveItem *copiedItems = malloc(sizeof(NeoAAArchiveItem) * itemCount);
    for (int i = 0; i < itemCount; i++) {
        NeoAAArchiveItem archiveItem = items[i];
        internal_do_not_call_neo_aa_archive_item_assert_heap_cookie(archiveItem);
        char *encodedBlobData = archiveItem->encodedBlobData;
        size_t encodedBlobDataSize = archiveItem->encodedBlobDataSize;
        int archiveItemIdentifier = archiveItem->archiveItemIdentifier;
        NeoAAArchiveItem copiedArchiveItem = malloc(sizeof(struct neo_aa_archive_item_impl));
        if (!copiedArchiveItem) {
            free(plainArchive);
            NEO_AA_ErrorHeapAlloc();
            return 0;
        }
        memset(copiedArchiveItem, 0, sizeof(struct neo_aa_archive_item_impl));
        NeoAAHeader copiedHeader = neo_aa_header_clone_header(archiveItem->header);
        if (!copiedHeader) {
            free(copiedArchiveItem);
            free(plainArchive);
            NEO_AA_LogError("cloning header in list failed\n");
            return 0;
        }
        internal_do_not_call_neo_aa_header_fill_heap_cookies(copiedHeader, archiveItemIdentifier);
        copiedArchiveItem->header = copiedHeader;
        if (encodedBlobDataSize) {
            char *copiedEncodedBlobData = malloc(encodedBlobDataSize);
            if (!copiedEncodedBlobData) {
                free(copiedArchiveItem);
                free(plainArchive);
                NEO_AA_ErrorHeapAlloc();
                return 0;
            }
            for (size_t j = 0; j < encodedBlobDataSize; j++) {
                copiedEncodedBlobData[j] = encodedBlobData[j];
            }
            copiedArchiveItem->encodedBlobData = copiedEncodedBlobData;
            copiedArchiveItem->encodedBlobDataSize = encodedBlobDataSize;
        }
        copiedArchiveItem->archiveItemIdentifier = archiveItemIdentifier;
        internal_do_not_call_neo_aa_archive_item_fill_heap_cookies(copiedArchiveItem, heapCookie);
        copiedItems[i] = copiedArchiveItem;
    }
    plainArchive->items = copiedItems;
    plainArchive->itemCount = itemCount;
    return plainArchive;
}

void neo_aa_archive_item_list_destroy(NeoAAArchiveItem *items, int itemCount) {
    NEO_AA_NullParamAssert(items);
    for (int i = 0; i < itemCount; i++) {
        NeoAAArchiveItem archiveItem = items[i];
        items[i] = 0;
        NeoAAHeader header = archiveItem->header;
        archiveItem->header = 0;
        neo_aa_header_destroy(header);
        char *encodedBlobData = archiveItem->encodedBlobData;
        archiveItem->encodedBlobData = 0;
        free(encodedBlobData);
        memset(archiveItem, 0, sizeof(struct neo_aa_archive_item_impl));
        free(archiveItem);
    }
    free(items);
}

void neo_aa_archive_plain_destroy(NeoAAArchivePlain plainArchive) {
    NEO_AA_NullParamAssert(plainArchive);
    NeoAAArchiveItem *items = plainArchive->items;
    int itemCount = plainArchive->itemCount;
    plainArchive->items = 0;
    neo_aa_archive_item_list_destroy(items, itemCount);
    memset(plainArchive, 0, sizeof(struct neo_aa_archive_plain_impl));
    free(plainArchive);
}

size_t neo_aa_archive_plain_outfile_size(NeoAAArchivePlain plainArchive) {
    size_t outfileSize = 0;
    int itemCount = plainArchive->itemCount;
    NeoAAArchiveItem *items = plainArchive->items;
    for (int i = 0; i < itemCount; i++) {
        NeoAAArchiveItem item = items[i];
        NeoAAHeader header = item->header;
        outfileSize += (header->headerSize + item->encodedBlobDataSize);
    }
    return outfileSize;
}

void neo_aa_archive_item_write_to_buffer(NeoAAArchiveItem item, char *buffer) {
    NeoAAHeader header = item->header;
    char *encodedHeaderData = header->encodedData;
    size_t encodedHeaderSize = header->headerSize;
    for (size_t i = 0; i < encodedHeaderSize; i++) {
        buffer[i] = encodedHeaderData[i];
    }
    size_t encodedBlobDataSize = item->encodedBlobDataSize;
    if (encodedBlobDataSize) {
        char *encodedBlobData = item->encodedBlobData;
        for (size_t i = 0; i < encodedBlobDataSize; i++) {
            buffer[i+encodedHeaderSize] = encodedBlobData[i];
        }
    }
}

void neo_aa_archive_plain_writefd(NeoAAArchivePlain plainArchive, int fd) {
    NEO_AA_NullParamAssert(plainArchive);
    internal_do_not_call_neo_aa_archive_plain_assert_heap_cookie(plainArchive);
    /* Ugly slow */
    size_t archiveSize = neo_aa_archive_plain_outfile_size(plainArchive);
    /* Now we know what the archive size will be, create it. */
    char *buffer = malloc(archiveSize); /* buffer to write to fd */
    size_t offset = 0;
    int itemCount = plainArchive->itemCount;
    NeoAAArchiveItem *items = plainArchive->items;
    for (int i = 0; i < itemCount; i++) {
        NeoAAArchiveItem item = items[i];
        NeoAAHeader header = item->header;
        neo_aa_archive_item_write_to_buffer(item, buffer + offset);
        offset += (header->headerSize + item->encodedBlobDataSize);
    }
    write(fd, buffer, archiveSize);
    free(buffer);
}

void neo_aa_archive_plain_write_path(NeoAAArchivePlain plainArchive, const char *filepath) {
    NEO_AA_NullParamAssert(plainArchive);
    NEO_AA_NullParamAssert(filepath);
    internal_do_not_call_neo_aa_archive_plain_assert_heap_cookie(plainArchive);
    return;
    FILE *fp = fopen(filepath, "w");
    if (!fp) {
        NEO_AA_LogError("failed to open filepath\n");
        return;
    }
    int fd = fp->_file;
    neo_aa_archive_plain_writefd(plainArchive, fd);
    fclose(fp);
}

void neo_aa_archive_item_destroy(NeoAAArchiveItem item) {
    NeoAAHeader header = item->header;
    item->header = 0;
    neo_aa_header_destroy(header);
    char *encodedBlobData = item->encodedBlobData;
    if (encodedBlobData) {
        item->encodedBlobData = 0;
        free(encodedBlobData);
    }
    memset(item, 0, sizeof(struct neo_aa_archive_item_impl));
    free(item);
}
