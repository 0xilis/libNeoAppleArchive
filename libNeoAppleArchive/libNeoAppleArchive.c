/*
 *  libNeoAppleArchive.c
 *  libNeoAppleArchive
 *
 *  Created by Snoolie Keffaber on 2024/04/22.
 */

#include "libNeoAppleArchive.h"
#include "libNeoAppleArchive_internal.h"
#include "../build/lzfse/include/lzfse.h"
#include <zlib.h>

void neo_aa_extract_aar_buffer_to_path(uint8_t *appleArchive, size_t appleArchiveSize, const char *outputPath) {
    printf("This function does not exist. Sorry!\n");
    return;
}

void neo_aa_extract_aar_to_path(const char *archivePath, const char *outputPath) {
    /* TODO: Redo this entire function. This and the one above it are by far the worst coded functions in this whole library. */
    char *oldWorkingDir = getcwd(NULL, 0);
    uint8_t *appleArchive = (uint8_t *)internal_do_not_call_load_binary(archivePath);
    /* dirty ugly hack */
    uint32_t *dirtyUglyHack = *(uint32_t **)&appleArchive;
    uint32_t headerMagic = dirtyUglyHack[0];
    if (headerMagic != AAR_MAGIC && headerMagic != YAA_MAGIC) {
        NEO_AA_LogError("magic not AA01/YAA1.\n");
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
        headerMagic = dirtyUglyHack[0];
        if (headerMagic != AAR_MAGIC && headerMagic != YAA_MAGIC) {
            free(appleArchive);
            NEO_AA_LogError("neo_aa_extract_aar_to_path: magic not AA01/YAA1.\n");
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
#if defined(_WIN32) || defined(WIN32)
            mkdir(pathName);
#else
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
#endif
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
                free(appleArchive);
                fprintf(stderr, "neo_aa_extract_aar_to_path: could not open pathName: %s\n",pathName);
                free(pathName);
                return;
            }
            uint8_t *fileData = currentHeader + headerSize;
            /* copy file data to buffer */
            fwrite(fileData, dataSize, 1, fp);
            fclose(fp);
#if defined(_WIN32) || defined(WIN32)
            /* Windows does not implement unix uid_t/gid_t */
#else
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
#endif
            size_t xatSize = 0;
            if (xatIndex != -1) {
                xatSize = neo_aa_header_get_field_key_uint(header, xatIndex);
                uint8_t *xattrBlob = currentHeader + headerSize + dataSize;
                internal_do_not_call_apply_xattr_blob_to_path(xattrBlob, xatSize, pathName);
            }
            currentHeader += (headerSize + dataSize + xatSize);
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

NeoAAArchiveItem neo_aa_archive_item_create_with_header(NeoAAHeader header) {
    NEO_AA_NullParamAssert(header);
    NeoAAArchiveItem archiveItem = malloc(sizeof(struct neo_aa_archive_item_impl));
    if (!archiveItem) {
        NEO_AA_ErrorHeapAlloc();
        return NULL;
    }
    memset(archiveItem, 0, sizeof(struct neo_aa_archive_item_impl));
    if (header->archiveItem) {
        /*
         * This header was already used in an existing archive item.
         * This means two NeoAAArchiveItems would be holding the same
         * pointer, ruh-oh! It's easy for someone who does this to
         * run into heap issues, hence we prevent this from happening.
         * If you want to re-use a header for an archive item, please
         * use neo_aa_header_clone_header to clone it.
         */
        free(archiveItem);
        NEO_AA_LogError("header already has an archiveItem holding it\n");
        return NULL;
    }
    header->archiveItem = archiveItem;
    archiveItem->header = header;
    return archiveItem;
}

void neo_aa_archive_item_add_blob_data(NeoAAArchiveItem item, char *data, size_t dataSize) {
    NEO_AA_NullParamAssert(item);
    NEO_AA_NullParamAssert(data);
    NEO_AA_NullParamAssert(dataSize);
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
    NeoAAArchivePlain plainArchive = malloc(sizeof(struct neo_aa_archive_plain_impl));
    if (!plainArchive) {
        NEO_AA_ErrorHeapAlloc();
        return NULL;
    }
    memset(plainArchive, 0, sizeof(struct neo_aa_archive_plain_impl));
    NeoAAArchiveItem *copiedItems = malloc(sizeof(NeoAAArchiveItem) * itemCount);
    for (int i = 0; i < itemCount; i++) {
        /* We copy the item list (array of NeoAAArchiveItem) here */
        NeoAAArchiveItem archiveItem = items[i];
        char *encodedBlobData = archiveItem->encodedBlobData;
        size_t encodedBlobDataSize = archiveItem->encodedBlobDataSize;
        NeoAAArchiveItem copiedArchiveItem = malloc(sizeof(struct neo_aa_archive_item_impl));
        if (!copiedArchiveItem) {
            free(plainArchive);
            NEO_AA_ErrorHeapAlloc();
            return NULL;
        }
        memset(copiedArchiveItem, 0, sizeof(struct neo_aa_archive_item_impl));
        NeoAAHeader copiedHeader = neo_aa_header_clone_header(archiveItem->header);
        if (!copiedHeader) {
            free(copiedArchiveItem);
            free(plainArchive);
            NEO_AA_LogError("cloning header in list failed\n");
            return NULL;
        }
        copiedHeader->archiveItem = copiedArchiveItem;
        copiedArchiveItem->header = copiedHeader;
        if (encodedBlobDataSize) {
            char *copiedEncodedBlobData = malloc(encodedBlobDataSize);
            if (!copiedEncodedBlobData) {
                free(copiedArchiveItem);
                free(plainArchive);
                NEO_AA_ErrorHeapAlloc();
                return NULL;
            }
            for (size_t j = 0; j < encodedBlobDataSize; j++) {
                copiedEncodedBlobData[j] = encodedBlobData[j];
            }
            copiedArchiveItem->encodedBlobData = copiedEncodedBlobData;
            copiedArchiveItem->encodedBlobDataSize = encodedBlobDataSize;
        }
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
        if (!header) {
            NEO_AA_LogError("item does not have header\n");
            return 0;
        }
        outfileSize += (header->headerSize + item->encodedBlobDataSize);
    }
    return outfileSize;
}

void neo_aa_archive_item_write_to_buffer(NeoAAArchiveItem item, char *buffer) {
    NeoAAHeader header = item->header;
    if (!header) {
        NEO_AA_LogError("item does not hold a header\n");
        return;
    }
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
    /* Ugly slow */
    size_t archiveSize = neo_aa_archive_plain_outfile_size(plainArchive);
    if (!archiveSize) {
        NEO_AA_LogError("failed to get outfile size\n");
        return;
    }
    /* Now we know what the archive size will be, create it. */
    char *buffer = malloc(archiveSize); /* buffer to write to fd */
    size_t offset = 0;
    int itemCount = plainArchive->itemCount;
    NeoAAArchiveItem *items = plainArchive->items;
    for (int i = 0; i < itemCount; i++) {
        NeoAAArchiveItem item = items[i];
        NeoAAHeader header = item->header;
        if (!header) {
            NEO_AA_LogError("item does not hold a header\n");
            return;
        }
        neo_aa_archive_item_write_to_buffer(item, buffer + offset);
        offset += (header->headerSize + item->encodedBlobDataSize);
    }
    write(fd, buffer, archiveSize);
    free(buffer);
}

uint8_t *neo_aa_archive_plain_get_encoded_data(NeoAAArchivePlain archive, size_t *encodedDataSize) {
    NEO_AA_NullParamAssert(archive);
    /* Ugly slow */
    size_t archiveSize = neo_aa_archive_plain_outfile_size(archive);
    if (!archiveSize) {
        NEO_AA_LogError("failed to get outfile size\n");
        return 0;
    }
    /* Now we know what the archive size will be, create it. */
    char *buffer = malloc(archiveSize); /* buffer to return */
    if (!buffer) {
        NEO_AA_LogError("out of memory!\n");
        return 0;
    }
    size_t offset = 0;
    int itemCount = archive->itemCount;
    NeoAAArchiveItem *items = archive->items;
    for (int i = 0; i < itemCount; i++) {
        NeoAAArchiveItem item = items[i];
        NeoAAHeader header = item->header;
        if (!header) {
            NEO_AA_LogError("item does not hold a header\n");
            return 0;
        }
        neo_aa_archive_item_write_to_buffer(item, buffer + offset);
        offset += (header->headerSize + item->encodedBlobDataSize);
    }

    if (encodedDataSize) {
        /* Only do this after we know nothing failed */
        *encodedDataSize = archiveSize;
    }
    return (uint8_t *)buffer;
}

void neo_aa_archive_plain_write_path(NeoAAArchivePlain plainArchive, const char *filepath) {
    NEO_AA_NullParamAssert(plainArchive);
    NEO_AA_NullParamAssert(filepath);
    FILE *fp = fopen(filepath, "w");
    if (!fp) {
        NEO_AA_LogError("failed to open filepath\n");
        return;
    }
#if defined(__APPLE__)
    int fd = fp->_file;
#else
    int fd = fileno(fp);
#endif
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

NeoAAArchiveItem neo_aa_archive_item_create_with_encoded_data(size_t encodedSize, uint8_t *data) {
    /* Get the header size */
    uint32_t *dumbHack = *(uint32_t **)&data;
    uint32_t headerMagic = dumbHack[0];
    if (headerMagic != AAR_MAGIC && headerMagic != YAA_MAGIC) { /* AA01/YAA1 */
        NEO_AA_LogError("data is not raw header (compression not yet supported)\n");
        return NULL;
    }
    size_t encodedHeaderSize = (dumbHack[1] & 0xffff);
    if (encodedSize < encodedHeaderSize) {
        NEO_AA_LogError("header size is larger than encoded item size\n");
        return NULL;
    }
    NeoAAHeader header = neo_aa_header_create_with_encoded_data(encodedHeaderSize, data);
    if (!header) {
        NEO_AA_LogError("failed to create header\n");
        return NULL;
    }
    NeoAAArchiveItem item = neo_aa_archive_item_create_with_header(header);
    if (!item) {
        NEO_AA_LogError("failed to create item\n");
        return NULL;
    }
    if (encodedSize == encodedHeaderSize) {
        /* The header is the entire item (no blob data) */
        return item;
    }
    /* archive item contains some blob data, add it */
    uint8_t *blobData = data + encodedHeaderSize;
    size_t blobDataSize = encodedSize - encodedHeaderSize;
    neo_aa_archive_item_add_blob_data(item, (char *)blobData, blobDataSize);
    return item;
}

NeoAAArchivePlain neo_aa_archive_plain_create_with_encoded_data(size_t encodedSize, uint8_t *data) {
    NeoAAArchiveItem *itemList = 0;
    int itemCount = 0;
    size_t maxSize = encodedSize;
    uint64_t position = 0;
    while (position < encodedSize) {
        itemCount++;
        NeoAAArchiveItem *itemListNewPtr = realloc(itemList, sizeof(NeoAAArchiveItem) * itemCount);
        if (!itemListNewPtr) {
            free(itemList);
            NEO_AA_ErrorHeapAlloc();
            return NULL;
        }
        itemList = itemListNewPtr;
        size_t currentHeaderSize = internal_do_not_call_neo_aa_archive_item_encoded_data_size_for_encoded_data(maxSize, data + position);
        if (!currentHeaderSize) {
            free(itemList);
            NEO_AA_LogError("failed to get header size\n");
            return NULL;
        }
        NeoAAArchiveItem item = neo_aa_archive_item_create_with_encoded_data(currentHeaderSize, data + position);
        itemList[itemCount - 1] = item;
        position += currentHeaderSize;
        maxSize = encodedSize - position;
    }
    NeoAAArchivePlain plainArchive = neo_aa_archive_plain_create_with_items(itemList, itemCount);
    free(itemList);
    return plainArchive;
}

NeoAAArchivePlain neo_aa_archive_plain_create_with_aar_path(const char *path) {
    NEO_AA_NullParamAssert(path);
    FILE *fp = fopen(path, "w");
    if (!fp) {
        NEO_AA_LogError("failed to open filepath\n");
        return NULL;
    }
    fseek(fp, 0, SEEK_END);
    size_t binary_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
#if defined(__APPLE__)
    int fd = fp->_file;
#else
    int fd = fileno(fp);
#endif
    if (binary_size > (UINT32_MAX-6) || binary_size < 12) {
        fclose(fp);
        NEO_AA_LogError("AEA over 4GB or under 12 bytes\n");
        return NULL;
    }
    uint8_t *data = malloc(binary_size);
    if (!data) {
        fclose(fp);
        NEO_AA_ErrorHeapAlloc();
        return NULL;
    }
    memset(data, 0, binary_size);
    ssize_t bytesRead = read(fd, data, binary_size);
    if (bytesRead < binary_size) {
        fclose(fp);
        free(data);
        NEO_AA_LogError("failed to read entire file\n");
        return NULL;
    }
    fclose(fp);
    NeoAAArchivePlain plainArchive = neo_aa_archive_plain_create_with_encoded_data(binary_size, data);
    free(data);
    return plainArchive;
}

/*
 * neo_aa_archive_generic_from_encoded_data
 *
 * Feed this encoded data.
 * This converts it to NeoAAArchiveGeneric,
 * which handles all compression types of
 * .aar, including uncompressed.
 * Well, it *will*... currently it only
 * supports ZLIB/LZFSE/RAW at the moment.
 *
 * On succession, returns a NeoAAArchiveGeneric.
 * On fail, returns 0.
 */
NeoAAArchiveGeneric neo_aa_archive_generic_from_encoded_data(size_t encodedSize, uint8_t *data) {
    /* get the first 4 bytes from data, to use as magic. */
    uint32_t magic = ((uint32_t *)data)[0];
    if (magic == AAR_MAGIC || magic == YAA_MAGIC) {
        /* If magic is AA01 or YAA1, then this is a RAW archive. */
        /* Create the plain archive. */
        NeoAAArchivePlain plainArchive = neo_aa_archive_plain_create_with_encoded_data(encodedSize, data);
        if (!plainArchive) {
            /* Failed to create plain archive, return NULL. */
            return NULL;
        }
        NeoAAArchiveGeneric genericArchive = malloc(sizeof(struct neo_aa_archive_generic_impl));
        if (!genericArchive) {
            /* Not enough space to create the generic archive. */
            neo_aa_archive_plain_destroy(plainArchive);
            NEO_AA_LogError("not enough space to create NeoAAArchiveGeneric\n");
            return NULL;
        }
        /* 0-fill struct */
        memset(genericArchive, 0, sizeof(struct neo_aa_archive_generic_impl));
        genericArchive->raw = plainArchive;
        genericArchive->compression = NEO_AA_COMPRESSION_NONE;
        genericArchive->compressedSize = encodedSize;
        genericArchive->uncompressedSize = encodedSize;
        return genericArchive;
    }
    if ((magic & 0x00FFFFFF) == PBZ__MAGIC) {
        /* pbz* type, so must be compressed archive */
        char compressionType = magic >> 24;
        if (compressionType == 'e') {
            /* type is LZFSE */
            /* compressed size of aar is stored at 0x18 in binary */
            size_t compressedSize = FLIP_32(*((uint32_t *)(data + 0x18)));
            /* uncompressed size of aar is stored at 0x10 in binary */
            size_t uncompressedSize = FLIP_32(*((uint32_t *)(data + 0x10)));
            uint8_t *encodedRAWData = malloc(uncompressedSize);
            if (!encodedRAWData) {
                NEO_AA_ErrorHeapAlloc();
                return NULL;
            }
            memset(encodedRAWData, 0, uncompressedSize);
            size_t decompressedBytes = lzfse_decode_buffer(encodedRAWData, uncompressedSize, data + 0x1C, compressedSize, 0);
            if (decompressedBytes != uncompressedSize) {
                free(encodedRAWData);
                NEO_AA_LogError("failed to decompress LZFSE data\n");
                return NULL;
            }
            NeoAAArchivePlain plainArchive = neo_aa_archive_plain_create_with_encoded_data(uncompressedSize, encodedRAWData);
            free(encodedRAWData);
            if (!plainArchive) {
                /* Failed to create plain archive, return NULL. */
                return NULL;
            }
            NeoAAArchiveGeneric genericArchive = malloc(sizeof(struct neo_aa_archive_generic_impl));
            if (!genericArchive) {
                /* Not enough space to create the generic archive. */
                neo_aa_archive_plain_destroy(plainArchive);
                NEO_AA_LogError("not enough space to create NeoAAArchiveGeneric\n");
                return NULL;
            }
            /* 0-fill struct */
            memset(genericArchive, 0, sizeof(struct neo_aa_archive_generic_impl));
            genericArchive->raw = plainArchive;
            genericArchive->compression = NEO_AA_COMPRESSION_LZFSE;
            genericArchive->compressedSize = compressedSize;
            genericArchive->uncompressedSize = uncompressedSize;
            return genericArchive;
        } else if (compressionType == 'z') {
            /* type is ZLIB */
            /* compressed size of aar is stored at 0x18 in binary */
            size_t compressedSize = FLIP_32(*((uint32_t *)(data + 0x18)));
            /* uncompressed size of aar is stored at 0x10 in binary */
            size_t uncompressedSize = FLIP_32(*((uint32_t *)(data + 0x10)));
            uint8_t *encodedRAWData = malloc(uncompressedSize);
            if (!encodedRAWData) {
                NEO_AA_ErrorHeapAlloc();
                return NULL;
            }
            memset(encodedRAWData, 0, uncompressedSize);
            /* check for error codes later */
            internal_do_not_call_inflate(data + 0x1C, (int)compressedSize, encodedRAWData, (int)uncompressedSize);
            NeoAAArchivePlain plainArchive = neo_aa_archive_plain_create_with_encoded_data(uncompressedSize, encodedRAWData);
            free(encodedRAWData);
            if (!plainArchive) {
                /* Failed to create plain archive, return NULL. */
                return NULL;
            }
            NeoAAArchiveGeneric genericArchive = malloc(sizeof(struct neo_aa_archive_generic_impl));
            if (!genericArchive) {
                /* Not enough space to create the generic archive. */
                neo_aa_archive_plain_destroy(plainArchive);
                NEO_AA_LogError("not enough space to create NeoAAArchiveGeneric\n");
                return NULL;
            }
            /* 0-fill struct */
            memset(genericArchive, 0, sizeof(struct neo_aa_archive_generic_impl));
            genericArchive->raw = plainArchive;
            genericArchive->compression = NEO_AA_COMPRESSION_ZLIB;
            genericArchive->compressedSize = compressedSize;
            genericArchive->uncompressedSize = uncompressedSize;
            return genericArchive;
        } else {
            /* We currently don't support non ZLIB/LZFSE/RAW apple archives, sorry! */
            NEO_AA_LogError("We currently don't support non ZLIB/LZFSE/RAW apple archives, sorry!\n");
            return NULL;
        }
    }
    NEO_AA_LogError("Data does not appear to be apple archive or compressed.\n");
    return NULL;
}

/*
 * neo_aa_archive_generic_from_path
 *
 * Feed this a .aar file.
 * This converts it to NeoAAArchiveGeneric,
 * which handles all compression types of
 * .aar, including uncompressed.
 * Well, it *will*... currently it only
 * supports ZLIB/LZFSE/RAW at the moment.
 */
NeoAAArchiveGeneric neo_aa_archive_generic_from_path(const char *path) {
    NEO_AA_NullParamAssert(path);
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        NEO_AA_LogError("failed to open filepath\n");
        return NULL;
    }
    fseek(fp, 0, SEEK_END);
    size_t binary_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (binary_size < 6) {
        /* Compressed or uncompressed, a .aar *cannot* be less than 6 bytes. */
        fclose(fp);
        NEO_AA_LogError("AAR is less than 6 bytes \n");
        return NULL;
    }
    /* malloc our data */
    uint8_t *data = malloc(binary_size);
    if (!data) {
        fclose(fp);
        NEO_AA_ErrorHeapAlloc();
        return NULL;
    }
    /* 0-fill buffer */
    memset(data, 0, binary_size);
    /* copy bytes from file to buffer */
    ssize_t bytesRead = fread(data, 1, binary_size, fp);
    if (bytesRead < binary_size) {
        fclose(fp);
        free(data);
        NEO_AA_LogError("failed to read entire file\n");
        return NULL;
    }
    fclose(fp);
    NeoAAArchiveGeneric genericArchive = neo_aa_archive_generic_from_encoded_data(binary_size, data);
    free(data);
    return genericArchive;
}

int neo_aa_archive_plain_compress_writefd(NeoAAArchivePlain plain, int algorithm, int fd) {
    if (NEO_AA_COMPRESSION_NONE == algorithm) {
        neo_aa_archive_plain_writefd(plain, fd);
        return 1;
    }
    /* Ugly slow */
    size_t archiveSize = neo_aa_archive_plain_outfile_size(plain);
    if (!archiveSize) {
        NEO_AA_LogError("failed to get outfile size\n");
        return 0;
    }
    /* Now we know what the archive size will be, create it. */
    char *buffer = malloc(archiveSize); /* buffer to write to fd */
    if (!buffer) {
        NEO_AA_LogError("not enough memory to parse buffer\n");
        return 0;
    }
    size_t offset = 0;
    int itemCount = plain->itemCount;
    NeoAAArchiveItem *items = plain->items;
    for (int i = 0; i < itemCount; i++) {
        NeoAAArchiveItem item = items[i];
        NeoAAHeader header = item->header;
        if (!header) {
            NEO_AA_LogError("item does not hold a header\n");
            return 0;
        }
        neo_aa_archive_item_write_to_buffer(item, buffer + offset);
        offset += (header->headerSize + item->encodedBlobDataSize);
    }
    if (NEO_AA_COMPRESSION_LZFSE == algorithm) {
        /* TODO: This code sucks. */
        uint8_t *compressed = malloc(archiveSize + 100);
        if (!compressed) {
            NEO_AA_LogError("not enough memory to compress\n");
            return 0;
        }
        memset(compressed, 0, archiveSize + 100);
        struct neo_pbzx_archived_directory_header *ptr = (struct neo_pbzx_archived_directory_header *)compressed;
        ptr->magic = AAR_MAGIC;
        ptr->mystery = 0x40;
        ptr->uncompressedSize = FLIP_32((uint32_t)archiveSize);
        /* Skip past header */
        compressed += sizeof(struct neo_pbzx_archived_directory_header);
        size_t compressedSize = lzfse_encode_buffer(compressed, archiveSize + 100, (uint8_t *)buffer, archiveSize, 0);
        ptr->compressedSize = FLIP_32((uint32_t)compressedSize);
        free(buffer);
        write(fd, compressed - sizeof(struct neo_pbzx_archived_directory_header), compressedSize + sizeof(struct neo_pbzx_archived_directory_header));
        /* Go back to header since this is the pointer malloc gave us */
        free(compressed - sizeof(struct neo_pbzx_archived_directory_header));
        return 1;
    }
    NEO_AA_LogError("this algorithm is currently not supported\n");
    return 0;
}

void neo_aa_archive_plain_compress_write_path(NeoAAArchivePlain plain, int algorithm, const char *path) {
    NEO_AA_NullParamAssert(plain);
    NEO_AA_NullParamAssert(path);
    FILE *fp = fopen(path, "w");
    if (!fp) {
        NEO_AA_LogError("failed to open path\n");
        return;
    }
#if defined(__APPLE__)
    int fd = fp->_file;
#else
    int fd = fileno(fp);
#endif
    neo_aa_archive_plain_compress_writefd(plain, algorithm, fd);
    fclose(fp);
}

