/*
 *  libNeoAppleArchive.c
 *  libNeoAppleArchive
 *
 *  Created by Snoolie Keffaber on 2024/04/22.
 */

#include "libNeoAppleArchive.h"
#include "libNeoAppleArchive_internal.h"
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wstrict-prototypes"
#include <lzfse.h>
#pragma clang diagnostic pop
#include <libzbitmap.h>
#include <zlib.h>
#include <fcntl.h>
#include <dirent.h>
#include <libgen.h>

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

NeoAAArchiveItem neo_aa_archive_item_create_with_header_copy(NeoAAHeader header) {
    NeoAAHeader headerCopy = neo_aa_header_clone_header(header);
    return neo_aa_archive_item_create_with_header(headerCopy);
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

NeoAAArchivePlain neo_aa_archive_plain_create_with_items_nocopy(NeoAAArchiveItem *items, int itemCount) {
    NEO_AA_NullParamAssert(items);
    NEO_AA_NullParamAssert(itemCount);
    NeoAAArchivePlain plainArchive = malloc(sizeof(struct neo_aa_archive_plain_impl));
    if (!plainArchive) {
        NEO_AA_ErrorHeapAlloc();
        return NULL;
    }
    plainArchive->items = items;
    plainArchive->itemCount = itemCount;
    return plainArchive;
}

NeoAAArchivePlain neo_aa_archive_plain_create_with_items(NeoAAArchiveItem *items, int itemCount) {
    NEO_AA_NullParamAssert(items);
    NEO_AA_NullParamAssert(itemCount);
    NeoAAArchiveItem *copiedItems = malloc(sizeof(NeoAAArchiveItem) * itemCount);
    if (!copiedItems) {
        NEO_AA_ErrorHeapAlloc();
        return NULL;
    }
    for (int i = 0; i < itemCount; i++) {
        /* We copy the item list (array of NeoAAArchiveItem) here */
        NeoAAArchiveItem archiveItem = items[i];
        char *encodedBlobData = archiveItem->encodedBlobData;
        size_t encodedBlobDataSize = archiveItem->encodedBlobDataSize;
        NeoAAArchiveItem copiedArchiveItem = malloc(sizeof(struct neo_aa_archive_item_impl));
        if (!copiedArchiveItem) {
            free(copiedItems);
            NEO_AA_ErrorHeapAlloc();
            return NULL;
        }
        memset(copiedArchiveItem, 0, sizeof(struct neo_aa_archive_item_impl));
        NeoAAHeader copiedHeader = neo_aa_header_clone_header(archiveItem->header);
        if (!copiedHeader) {
            free(copiedArchiveItem);
            free(copiedItems);
            NEO_AA_LogError("cloning header in list failed\n");
            return NULL;
        }
        copiedHeader->archiveItem = copiedArchiveItem;
        copiedArchiveItem->header = copiedHeader;
        if (encodedBlobDataSize) {
            char *copiedEncodedBlobData = malloc(encodedBlobDataSize);
            if (!copiedEncodedBlobData) {
                free(copiedArchiveItem);
                free(copiedItems);
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
    return neo_aa_archive_plain_create_with_items_nocopy(copiedItems, itemCount);
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

void neo_aa_archive_item_list_destroy_nozero(NeoAAArchiveItem *items, int itemCount) {
    NEO_AA_NullParamAssert(items);
    for (int i = 0; i < itemCount; i++) {
        NeoAAArchiveItem archiveItem = items[i];
        neo_aa_header_destroy_nozero(archiveItem->header);
        free(archiveItem->encodedBlobData);
        free(archiveItem);
    }
    free(items);
}

void neo_aa_archive_plain_destroy_nozero(NeoAAArchivePlain plainArchive) {
    NEO_AA_NullParamAssert(plainArchive);
    neo_aa_archive_item_list_destroy(plainArchive->items, plainArchive->itemCount);
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

int neo_aa_archive_plain_write_buffer(NeoAAArchivePlain plainArchive, uint8_t *buffer) {
    size_t offset = 0;
    int itemCount = plainArchive->itemCount;
    NeoAAArchiveItem *items = plainArchive->items;
    for (int i = 0; i < itemCount; i++) {
        NeoAAArchiveItem item = items[i];
        NeoAAHeader header = item->header;
        if (!header) {
            NEO_AA_LogError("item does not hold a header\n");
            return -1;
        }
        char *_buffer = (char *)buffer;
        neo_aa_archive_item_write_to_buffer(item, _buffer + offset);
        offset += (header->headerSize + item->encodedBlobDataSize);
    }
    return 0;
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
    uint8_t *buffer = malloc(archiveSize); /* buffer to write to fd */
    if (neo_aa_archive_plain_write_buffer(plainArchive, buffer)) {
        NEO_AA_LogError("neo_aa_archive_plain_write_buffer failed\n");
        return;
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

void neo_aa_archive_item_destroy_nozero(NeoAAArchiveItem item) {
    neo_aa_header_destroy_nozero(item->header);
    free(item->encodedBlobData);
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
    NeoAAArchivePlain plainArchive = neo_aa_archive_plain_create_with_items_nocopy(itemList, itemCount);
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
    size_t binarySize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
#if defined(__APPLE__)
    int fd = fp->_file;
#else
    int fd = fileno(fp);
#endif
    if (binarySize > (UINT32_MAX-6) || binarySize < 12) {
        fclose(fp);
        NEO_AA_LogError("AEA over 4GB or under 12 bytes\n");
        return NULL;
    }
    uint8_t *data = malloc(binarySize);
    if (!data) {
        fclose(fp);
        NEO_AA_ErrorHeapAlloc();
        return NULL;
    }
    ssize_t bytesRead = read(fd, data, binarySize);
    if ((size_t)bytesRead < binarySize) {
        fclose(fp);
        free(data);
        NEO_AA_LogError("failed to read entire file\n");
        return NULL;
    }
    fclose(fp);
    NeoAAArchivePlain plainArchive = neo_aa_archive_plain_create_with_encoded_data(binarySize, data);
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
 * supports ZLIB/LZFSE/LZBITMAP/RAW at the moment.
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
            neo_aa_archive_plain_destroy_nozero(plainArchive);
            NEO_AA_LogError("not enough space to create NeoAAArchiveGeneric\n");
            return NULL;
        }
        genericArchive->raw = plainArchive;
        genericArchive->compression = NEO_AA_COMPRESSION_NONE;
        genericArchive->uncompressedSize = encodedSize;
        genericArchive->compressedSize = encodedSize;
        return genericArchive;
    }
    if ((magic & 0x00FFFFFF) == PBZ__MAGIC) {
        /* pbz* type, so must be compressed archive */
        char compressionType = magic >> 24;
        if (compressionType == 'e') {
            size_t fileHeaderMagic = 0xC;
            size_t blockHeaderSize = 0x10;
            uint8_t *current = data + fileHeaderMagic;
            size_t remaining = encodedSize - fileHeaderMagic;
            size_t totalUncompressedSize = 0;
            size_t totalCompressedSize = 0;
            uint8_t *encodedRAWData = NULL;
            uint8_t *currentUncompressedPos = NULL;
            
            while (remaining > 0) {
                if (remaining < blockHeaderSize) {
                    NEO_AA_LogError("corrupted data: header too short\n");
                    return NULL;
                }
                size_t blockUncompressedSize = FLIP_32(*((uint32_t *)(current + 0x4)));
                size_t blockCompressedSize = FLIP_32(*((uint32_t *)(current + 0xC)));
                size_t blockTotalSize = blockHeaderSize + blockCompressedSize;
                if (remaining < blockTotalSize) {
                    NEO_AA_LogError("corrupted data: block exceeds buffer\n");
                    return NULL;
                }

                totalUncompressedSize += blockUncompressedSize;
                totalCompressedSize += blockCompressedSize;  /* Only compressed data portion */
                current += blockTotalSize;
                remaining -= blockTotalSize;
            }

            encodedRAWData = malloc(totalUncompressedSize);
            if (!encodedRAWData) {
                NEO_AA_ErrorHeapAlloc();
                return NULL;
            }

            current = data + fileHeaderMagic;
            remaining = encodedSize - fileHeaderMagic;
            currentUncompressedPos = encodedRAWData;
            while (remaining > 0) {
                size_t blockUncompressedSize = FLIP_32(*((uint32_t *)(current + 0x4)));
                size_t blockCompressedSize = FLIP_32(*((uint32_t *)(current + 0xC)));
                size_t blockTotalSize = blockHeaderSize + blockCompressedSize;
                size_t decompressedBytes = lzfse_decode_buffer(
                    currentUncompressedPos,
                    blockUncompressedSize,
                    current + blockHeaderSize,
                    blockCompressedSize,
                    0
                );
                
                if (decompressedBytes != blockUncompressedSize) {
                    free(encodedRAWData);
                    NEO_AA_LogError("failed to decompress LZFSE data\n");
                    return NULL;
                }
                
                currentUncompressedPos += blockUncompressedSize;
                current += blockTotalSize;
                remaining -= blockTotalSize;
            }

            NeoAAArchivePlain plainArchive = neo_aa_archive_plain_create_with_encoded_data(
                totalUncompressedSize,
                encodedRAWData
            );
            free(encodedRAWData);

            if (!plainArchive) {
                return NULL;
            }

            NeoAAArchiveGeneric genericArchive = malloc(sizeof(struct neo_aa_archive_generic_impl));
            if (!genericArchive) {
                neo_aa_archive_plain_destroy_nozero(plainArchive);
                NEO_AA_LogError("not enough space to create NeoAAArchiveGeneric\n");
                return NULL;
            }

            genericArchive->raw = plainArchive;
            genericArchive->compression = NEO_AA_COMPRESSION_LZFSE;
            genericArchive->uncompressedSize = totalUncompressedSize;
            genericArchive->compressedSize = totalCompressedSize;
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
                neo_aa_archive_plain_destroy_nozero(plainArchive);
                NEO_AA_LogError("not enough space to create NeoAAArchiveGeneric\n");
                return NULL;
            }
            genericArchive->raw = plainArchive;
            genericArchive->compression = NEO_AA_COMPRESSION_ZLIB;
            genericArchive->uncompressedSize = uncompressedSize;
            genericArchive->compressedSize = compressedSize;
            return genericArchive;
        } else if (compressionType == 'b') {
            /* type is LZBIPMAP */
            /* compressed size of aar is stored at 0x18 in binary */
            size_t compressedSize = FLIP_32(*((uint32_t *)(data + 0x18)));
            /* uncompressed size of aar is stored at 0x10 in binary */
            size_t uncompressedSize = FLIP_32(*((uint32_t *)(data + 0x10)));
            uint8_t *encodedRAWData = malloc(uncompressedSize);
            if (!encodedRAWData) {
                NEO_AA_ErrorHeapAlloc();
                return NULL;
            }

            size_t decompressedBytes = 0;
            int failed = zbm_decompress(encodedRAWData, uncompressedSize, data + 0x1C, compressedSize, &decompressedBytes);
            if (decompressedBytes != uncompressedSize || failed) {
                free(encodedRAWData);
                NEO_AA_LogError("failed to decompress LZBITMAP data\n");
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
                neo_aa_archive_plain_destroy_nozero(plainArchive);
                NEO_AA_LogError("not enough space to create NeoAAArchiveGeneric\n");
                return NULL;
            }
            genericArchive->raw = plainArchive;
            genericArchive->compression = NEO_AA_COMPRESSION_LZBITMAP;
            genericArchive->uncompressedSize = uncompressedSize;
            genericArchive->compressedSize = compressedSize;
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
    size_t binarySize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (binarySize < 6) {
        /* Compressed or uncompressed, a .aar *cannot* be less than 6 bytes. */
        fclose(fp);
        NEO_AA_LogError("AAR is less than 6 bytes \n");
        return NULL;
    }
    /* malloc our data */
    uint8_t *data = malloc(binarySize);
    if (!data) {
        fclose(fp);
        NEO_AA_ErrorHeapAlloc();
        return NULL;
    }
    /* copy bytes from file to buffer */
    ssize_t bytesRead = fread(data, 1, binarySize, fp);
    if ((size_t)bytesRead < binarySize) {
        fclose(fp);
        free(data);
        NEO_AA_LogError("failed to read entire file\n");
        return NULL;
    }
    fclose(fp);
    NeoAAArchiveGeneric genericArchive = neo_aa_archive_generic_from_encoded_data(binarySize, data);
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
        ptr->magic = PBZE_MAGIC;
        ptr->mystery = 0x40;
        ptr->uncompressedSize = FLIP_32((uint32_t)archiveSize);

        /* Skip past header */
        compressed += sizeof(struct neo_pbzx_archived_directory_header);

        size_t compressedSize = lzfse_encode_buffer(compressed, (archiveSize + 100) - sizeof(struct neo_pbzx_archived_directory_header), (uint8_t *)buffer, archiveSize, 0);

        ptr->compressedSize = FLIP_32((uint32_t)compressedSize);
        free(buffer);

        write(fd, compressed - sizeof(struct neo_pbzx_archived_directory_header), compressedSize + sizeof(struct neo_pbzx_archived_directory_header));
        /* Go back to header since this is the pointer malloc gave us */
        free(compressed - sizeof(struct neo_pbzx_archived_directory_header));
        return 1;
    } else if (NEO_AA_COMPRESSION_ZLIB == algorithm) {
        uint8_t *compressed = malloc(archiveSize + 100);
        if (!compressed) {
            NEO_AA_LogError("not enough memory to compress\n");
            return 0;
        }
        memset(compressed, 0, archiveSize + 100);

        struct neo_pbzx_archived_directory_header *ptr = (struct neo_pbzx_archived_directory_header *)compressed;
        ptr->magic = PBZZ_MAGIC;
        ptr->mystery = 0x40;
        ptr->uncompressedSize = FLIP_32((uint32_t)archiveSize);

        /* Skip past header */
        compressed += sizeof(struct neo_pbzx_archived_directory_header);

        size_t compressedSize = archiveSize + 100 - sizeof(struct neo_pbzx_archived_directory_header);
        int ret = compress2(compressed, &compressedSize, (const Bytef *)buffer, archiveSize, Z_BEST_COMPRESSION);
        if (ret != Z_OK) {
            NEO_AA_LogErrorF("zlib compression failed with error code %d\n", ret);
            free(buffer);
            free(compressed - sizeof(struct neo_pbzx_archived_directory_header));
            return 0;
        }

        ptr->compressedSize = FLIP_32((uint32_t)compressedSize);
        free(buffer);

        write(fd, compressed - sizeof(struct neo_pbzx_archived_directory_header), compressedSize + sizeof(struct neo_pbzx_archived_directory_header));
        /* Go back to header since this is the pointer malloc gave us */
        free(compressed - sizeof(struct neo_pbzx_archived_directory_header));
        return 1;
    } else if (NEO_AA_COMPRESSION_LZBITMAP == algorithm) {
        /* TODO: This code sucks. */
        uint8_t *compressed = malloc(archiveSize + 100);
        if (!compressed) {
            NEO_AA_LogError("not enough memory to compress\n");
            return 0;
        }
        memset(compressed, 0, archiveSize + 100);

        struct neo_pbzx_archived_directory_header *ptr = (struct neo_pbzx_archived_directory_header *)compressed;
        ptr->magic = PBZB_MAGIC;
        ptr->mystery = 0x40;
        ptr->uncompressedSize = FLIP_32((uint32_t)archiveSize);

        /* Skip past header */
        compressed += sizeof(struct neo_pbzx_archived_directory_header);

        size_t compressedSize;
        int errorCode = zbm_compress(compressed, (archiveSize + 100) - sizeof(struct neo_pbzx_archived_directory_header), (uint8_t *)buffer, archiveSize, &compressedSize);
        if (errorCode) {
            NEO_AA_LogErrorF("lzbitmap compression failed with error code %d\n", errorCode);
            free(buffer);
            free(compressed - sizeof(struct neo_pbzx_archived_directory_header));
            return 0;
        }

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

/* TODO: Experimental */
/* Recursively archive directory contents */
NEO_INTERNAL_API static int add_directory_contents_to_archive(const char *dirPath, NeoAAArchiveItem *items, 
                                          size_t *itemsCount, size_t *itemsMalloc,
                                          const char *basePath) {
    DIR *dir = opendir(dirPath);
    if (!dir) {
        NEO_AA_LogErrorF("Failed to open directory: %s\n", dirPath);
        return -1;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;  /* Skip "." and ".." */
        }

        char fullPath[1024];
        snprintf(fullPath, sizeof(fullPath), "%s/%s", dirPath, entry->d_name);

        /* Build relative path for PAT field */
        char relativePath[2048] = {0};
        if (basePath && basePath[0] != '\0') {
            snprintf(relativePath, sizeof(relativePath), "%s/%s", basePath, entry->d_name);
        } else {
            strncpy(relativePath, entry->d_name, sizeof(relativePath));
        }

        /* Check if we need to grow our items array */
        if (*itemsCount == *itemsMalloc) {
            *itemsMalloc *= 2;
            NeoAAArchiveItem *newItems = (NeoAAArchiveItem *)realloc(items, sizeof(NeoAAArchiveItem) * (*itemsMalloc));
            if (!newItems) {
                NEO_AA_LogError("Failed to realloc items array\n");
                closedir(dir);
                return -1;
            }
            items = newItems;
        }

#ifdef O_SYMLINK
        /* On macOS but not Linux, O_SYMLINK behaves like O_NOFOLLOW,
         *  O_NOFOLLOW makes open() fail on symlinks...
         */
        int fd = open(fullPath, O_RDONLY | O_SYMLINK);
#else
        int fd = open(fullPath, O_RDONLY | O_NOFOLLOW);
#endif

        struct stat fileStat;
        if (fstat(fd, &fileStat) < 0) {
            perror("Failed to get file info");
            continue;
        }

        NeoAAHeader header = neo_aa_header_create();
        if (!header) {
            NEO_AA_LogErrorF("Failed to create header for %s\n", fullPath);
            continue;
        }

#if !(defined(_WIN32) || defined(WIN32))
        /* Set UID/GID on Unix-like systems */
        if (fileStat.st_uid != (uid_t)-1) {
            neo_aa_header_set_field_uint(header, NEO_AA_FIELD_C("UID"), 2, (unsigned short)fileStat.st_uid);
        }
        if (fileStat.st_gid != (gid_t)-1) {
            neo_aa_header_set_field_uint(header, NEO_AA_FIELD_C("GID"), 1, (unsigned char)fileStat.st_gid);
        }
#endif

        if (S_ISDIR(fileStat.st_mode)) {
            close(fd);
            /* Handle directory */
            neo_aa_header_set_field_string(header, NEO_AA_FIELD_C("PAT"), strlen(relativePath), relativePath);
            neo_aa_header_set_field_uint(header, NEO_AA_FIELD_C("TYP"), 1, 'D');
            
            NeoAAArchiveItem item = neo_aa_archive_item_create_with_header(header);
            if (!item) {
                NEO_AA_LogErrorF("Failed to create item for directory: %s\n", fullPath);
                neo_aa_header_destroy_nozero(header);
                continue;
            }
            
            items[(*itemsCount)++] = item;
            
            /* Recursively process subdirectory */
            int result = add_directory_contents_to_archive(fullPath, items, itemsCount, itemsMalloc, relativePath);
            if (result != 0) {
                closedir(dir);
                return result;
            }
        } else if (S_ISLNK(fileStat.st_mode)) {
            close(fd);
#if !(defined(_WIN32) || defined(WIN32))
            /* Handle symlink */
            char symlinkTarget[1024];
            ssize_t len = readlink(fullPath, symlinkTarget, sizeof(symlinkTarget) - 1);
            if (len < 0) {
                perror("readlink failed");
                neo_aa_header_destroy_nozero(header);
                continue;
            }
            symlinkTarget[len] = '\0';
            
            neo_aa_header_set_field_string(header, NEO_AA_FIELD_C("PAT"), strlen(relativePath), relativePath);
            neo_aa_header_set_field_string(header, NEO_AA_FIELD_C("LNK"), len, symlinkTarget);
            neo_aa_header_set_field_uint(header, NEO_AA_FIELD_C("TYP"), 1, 'L');
            
            NeoAAArchiveItem item = neo_aa_archive_item_create_with_header(header);
            if (!item) {
                NEO_AA_LogErrorF("Failed to create item for symlink: %s\n", fullPath);
                neo_aa_header_destroy_nozero(header);
                continue;
            }
            
            items[(*itemsCount)++] = item;
#endif
        } else if (S_ISREG(fileStat.st_mode)) {
            /* Handle regular file */
            if (fd < 0) {
                perror("Failed to open file");
                neo_aa_header_destroy_nozero(header);
                continue;
            }
            
            size_t fileSize = fileStat.st_size;
            unsigned char *fileData = (unsigned char *)malloc(fileSize);
            if (!fileData) {
                NEO_AA_LogErrorF("Memory allocation failed for file: %s\n", fullPath);
                close(fd);
                neo_aa_header_destroy_nozero(header);
                continue;
            }
            
            ssize_t bytesRead = read(fd, fileData, fileSize);
            close(fd);
            
            if (bytesRead < (ssize_t)fileSize) {
                NEO_AA_LogErrorF("Failed to read entire file: %s\n", fullPath);
                free(fileData);
                neo_aa_header_destroy_nozero(header);
                continue;
            }
            
            neo_aa_header_set_field_string(header, NEO_AA_FIELD_C("PAT"), strlen(relativePath), relativePath);
            neo_aa_header_set_field_uint(header, NEO_AA_FIELD_C("TYP"), 1, 'F');
            neo_aa_header_set_field_blob(header, NEO_AA_FIELD_C("DAT"), 0, fileSize);
            
            NeoAAArchiveItem item = neo_aa_archive_item_create_with_header(header);
            if (!item) {
                NEO_AA_LogErrorF("Failed to create item for file: %s\n", fullPath);
                free(fileData);
                neo_aa_header_destroy_nozero(header);
                continue;
            }
            
            neo_aa_archive_item_add_blob_data(item, (char *)fileData, fileSize);
            items[(*itemsCount)++] = item;
            free(fileData);
        }
    }
    
    closedir(dir);
    return 0;
}

NEO_INTERNAL_API static NeoAAArchivePlain internal_do_not_call_wrap_file_in_neo_aa(const char *inputPath) {
    NeoAAHeader header = neo_aa_header_create();
    if (!header) {
        NEO_AA_LogError("Failed to create header\n");
        return NULL;
    }
    char *fileName = basename((char *)inputPath);
    /* Declare our file as, well, a file */
    neo_aa_header_set_field_uint(header, NEO_AA_FIELD_C("TYP"), 1, 'F');
    /* Declare our PAT to be our file name */
    neo_aa_header_set_field_string(header, NEO_AA_FIELD_C("PAT"), strlen(fileName), fileName);
    /* Crete the NeoAAArchiveItem item */
    NeoAAArchiveItem item = neo_aa_archive_item_create_with_header(header);
    if (!item) {
        neo_aa_header_destroy_nozero(header);
        NEO_AA_LogError("Failed to create item\n");
        return NULL;
    }
    FILE *fp = fopen(inputPath, "r");
    if (!fp) {
        neo_aa_archive_item_destroy_nozero(item);
        NEO_AA_LogError("Failed to open input path\n");
        return NULL;
    }
    fseek(fp, 0, SEEK_END);
    size_t binarySize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    /* allocate our uncompressed data */
    uint8_t *data = malloc(binarySize);
    if (!data) {
        fclose(fp);
        neo_aa_archive_item_destroy_nozero(item);
        NEO_AA_LogError("Not enough memory to allocate file into memory\n");
        return NULL;
    }
    size_t bytesRead = fread(data, 1, binarySize, fp);
    fclose(fp);
    if (bytesRead < binarySize) {
        neo_aa_archive_item_destroy_nozero(item);
        NEO_AA_LogError("Failed to read the entire file\n");
        return NULL;
    }
    
    /* Handle other than RAW later */
    neo_aa_header_set_field_blob(header, NEO_AA_FIELD_C("DAT"), 0, binarySize);
    neo_aa_archive_item_add_blob_data(item, (char *)data, binarySize);
    free(data);
    NeoAAArchiveItem *itemList = &item;
    NeoAAArchivePlain archive = neo_aa_archive_plain_create_with_items_nocopy(itemList, 1);
    if (!archive) {
        NEO_AA_LogError("Failed to create NeoAAArchivePlain\n");
        return NULL;
    }
    return archive;
}

/*
 * TODO: Needs more support for more types,
 * ex. aar with a socket
 */
NeoAAArchivePlain neo_aa_archive_plain_from_directory(const char *dirPath) {
    /* Check if dirPath is a directory path or path to a singular file */
    struct stat statbuf;

    if (stat(dirPath, &statbuf)) {
        NEO_AA_LogError("stat() failed for dirPath\n");
        return NULL;
    }

    if (S_ISREG(statbuf.st_mode)) {
        return internal_do_not_call_wrap_file_in_neo_aa(dirPath);
    }
    /* Assume dirPath is directory if not regular file */

    size_t itemsCount = 0;
    size_t itemsMalloc = 100;
    NeoAAArchiveItemList items = (NeoAAArchiveItemList)malloc(sizeof(NeoAAArchiveItem) * itemsMalloc);
    if (!items) {
        NEO_AA_LogError("Failed to allocate initial items array\n");
        return NULL;
    }
    
    /* Process directory recursively */
    int result = add_directory_contents_to_archive(dirPath, items, &itemsCount, &itemsMalloc, "");
    if (result != 0) {
        NEO_AA_LogErrorF("add_directory_contents_to_archive returned %d\n",result);
        neo_aa_archive_item_list_destroy_nozero(items, itemsCount);
        return NULL;
    }
    
    /* Create archive if we found any items */
    if (itemsCount > 0) {
        NeoAAArchivePlain archive = neo_aa_archive_plain_create_with_items_nocopy(items, itemsCount);
        if (!archive) {
            NEO_AA_LogError("Failed to create archive from items\n");
            neo_aa_archive_item_list_destroy_nozero(items, itemsCount);
            return NULL;
        }
        
        /* Return the archive */
        return archive;
    } else {
        free(items);
        NEO_AA_LogError("No items found to archive\n");
        return NULL;
    }
    
    return NULL;
}

int neo_aa_extract_aar_to_path_err(const char *archivePath, const char *outputPath) {
    /* 
     * TODO: Redo this entire function.
     * This is by far the worst coded function in this whole library.
     */
    char *oldWorkingDir = getcwd(NULL, 0);
    /* load binary into memory */
    FILE *fp = fopen(archivePath,"rb");
    if (!fp) {
        NEO_AA_LogError("failed to find path\n");
        return -1;
    }
    fseek(fp, 0, SEEK_END);
    size_t appleArchiveSize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    uint8_t *appleArchive = malloc(appleArchiveSize);
    if (!appleArchive) {
        NEO_AA_LogError("failed to load appleArchive into memory\n");
        return -3;
    }
    size_t bytesRead = fread(appleArchive, 1, appleArchiveSize, fp);
    fclose(fp);
    if (bytesRead < appleArchiveSize) {
        free(appleArchive);
        NEO_AA_LogErrorF("failed to read the entire file (read %zu bytes, expected %zu).\n",bytesRead, appleArchiveSize);
        return -2;
    }
    uint32_t headerMagic;
    memcpy(&headerMagic, appleArchive, 4);
    if (headerMagic != AAR_MAGIC && headerMagic != YAA_MAGIC) {
        /* May be PBZE, if so uncompress it... */
        NeoAAArchiveGeneric generic = neo_aa_archive_generic_from_encoded_data(appleArchiveSize, appleArchive);
        if (!generic) {
            /* assume NeoAAArchiveGeneric failed because it was not compressed */
            NEO_AA_LogError("magic not AA01/YAA1.\n");
            return -4;
        }
        NeoAAArchivePlain raw = generic->raw;
        free(generic);
        free(appleArchive);
        /* Ugly slow */
        size_t archiveSize = neo_aa_archive_plain_outfile_size(raw);
        if (!archiveSize) {
            NEO_AA_LogError("failed to get outfile size\n");
            return -5;
        }
        /* Now we know what the archive size will be, create it. */
        appleArchive = malloc(archiveSize); /* buffer to write to fd */
        if (neo_aa_archive_plain_write_buffer(raw, appleArchive)) {
            NEO_AA_LogError("neo_aa_archive_plain_write_buffer failed\n");
            return -6;
        }
        neo_aa_archive_plain_destroy_nozero(raw);
        appleArchiveSize = archiveSize;
    }
    uint8_t *currentHeader = appleArchive;
    int extracting = 1;
    size_t outputPathLen = strlen(outputPath);
    char *slashEndOfPath = internal_do_not_call_memrchr((char *)outputPath, '/', outputPathLen);
    char *newPath;
    if (outputPath[outputPathLen - 1] == '/') {
        size_t sizeOfNewPath = slashEndOfPath - outputPath;
        newPath = malloc(sizeOfNewPath + 1);
        strncpy(newPath, outputPath, sizeOfNewPath);
        newPath[sizeOfNewPath + 1] = 0;
        if (chdir(newPath)) {
            NEO_AA_LogErrorF("chdir(newPath) failed for %s, trying anyway...\n",newPath);
        }
        free(newPath);
    } else {
        /* BAD! change this later. */
        newPath = (char *)outputPath;
        if (chdir(outputPath)) {
            NEO_AA_LogErrorF("chdir(outputPath) failed for %s, trying anyway...\n", outputPath);
            mkdir(outputPath, 0755);
            chdir(outputPath);
        }
    }
    while (extracting) {
        memcpy(&headerMagic, currentHeader, 4);
        if (headerMagic != AAR_MAGIC && headerMagic != YAA_MAGIC) {
            free(appleArchive);
            NEO_AA_LogError("magic not AA01/YAA1.\n");
            return -7;
        }
        uint16_t headerSize;
        memcpy(&headerSize, currentHeader + 4, 2);
        NeoAAHeader header = neo_aa_header_create_with_encoded_data(headerSize, currentHeader);
        if (!header) {
            free(appleArchive);
            NEO_AA_LogError("header creation fail\n");
            return -8;
        }
        uint32_t typKey = NEO_AA_FIELD_C("TYP");
        int typIndex = neo_aa_header_get_field_key_index(header, typKey);
        if (typIndex == -1) {
            free(appleArchive);
            NEO_AA_LogError("no TYP field\n");
            return -9;
        }
        uint32_t patKey = NEO_AA_FIELD_C("PAT");
        int patIndex = neo_aa_header_get_field_key_index(header, patKey);
        if (patIndex == -1) {
            free(appleArchive);
            NEO_AA_LogError("no PAT field\n");
            return -10;
        }
        uint32_t modKey = NEO_AA_FIELD_C("MOD");
        int modIndex = neo_aa_header_get_field_key_index(header, modKey);
        uint32_t uidKey = NEO_AA_FIELD_C("UID");
        int uidIndex = neo_aa_header_get_field_key_index(header, uidKey);
        uint32_t gidKey = NEO_AA_FIELD_C("GID");
        int gidIndex = neo_aa_header_get_field_key_index(header, gidKey);
        uint32_t xatKey = NEO_AA_FIELD_C("XAT");
        int xatIndex = neo_aa_header_get_field_key_index(header, xatKey);
        size_t pathSize = neo_aa_header_get_field_size(header, patIndex);
        uint8_t typEntryType = neo_aa_header_get_field_key_uint(header, typIndex);
        struct stat st;
        char *pathName;
        size_t xatSize = 0;
        if (!pathSize) {
            /* directory has empty name, this is only for creating outputPath */
            if (xatIndex != -1) {
                /* Somehow the outputPath has its own XAT??? Just skip it... */
                xatSize = neo_aa_header_get_field_key_uint(header, xatIndex);
            }
            currentHeader += (headerSize + xatSize);
            continue;
        } else {
            pathName = neo_aa_header_get_field_key_string(header, patIndex);
        }
        if (typEntryType == 'D') {
            /* Header for directory */
#if defined(_WIN32) || defined(WIN32)
            mkdir(pathName);
#else
            uint64_t accessMode;
            if (modIndex != -1) {
                accessMode = neo_aa_header_get_field_key_uint(header, modIndex);
                mkdir(pathName, accessMode);
            } else {
                mkdir(pathName, 0755);
            }
            int fd = open(pathName, O_RDWR | O_NOFOLLOW);
            if (fd != -1) {
                fstat(fd, &st);
                uid_t fileUid = st.st_uid;
                gid_t fileGid = st.st_gid;
                if (uidIndex != -1) {
                    fileUid = (uid_t)neo_aa_header_get_field_key_uint(header, uidIndex);
                }
                if (gidIndex != -1) {
                    fileGid = (gid_t)neo_aa_header_get_field_key_uint(header, gidIndex);
                }
                fchown(fd, fileUid, fileGid);
                if (xatIndex != -1) {
                    xatSize = neo_aa_header_get_field_key_uint(header, xatIndex);
                    uint8_t *xattrBlob = currentHeader + headerSize;
                    internal_do_not_call_apply_xattr_blob_to_fd(xattrBlob, xatSize, fd);
                }
                close(fd);
            }
#endif
            currentHeader += (headerSize + xatSize);
        } else if (typEntryType == 'F') {
            /* Header for file */
            uint32_t datKey = NEO_AA_FIELD_C("DAT");
            int datIndex = neo_aa_header_get_field_key_index(header, datKey);
            if (datIndex == -1) {
                free(pathName);
                free(appleArchive);
                NEO_AA_LogError("no DAT field\n");
                return -12;
            }
            uint64_t dataSize = neo_aa_header_get_field_key_uint(header, datIndex);
            /* make sure we don't overflow and leak data in output */
            uint64_t endOfFile = appleArchiveSize - ((currentHeader - appleArchive) + headerSize);
            if (dataSize > endOfFile) {
                free(pathName);
                free(appleArchive);
                NEO_AA_LogError("dataSize overflow\n");
                return -13;
            }

            FILE *fp = fopen(pathName, "w+");
            if (!fp) {
                NEO_AA_LogErrorF("could not open pathName: %s, trying to open fullPath instead as last resort...\n",pathName);
                char fullPath[1024];
                snprintf(fullPath, sizeof(fullPath), "%s/%s", newPath, pathName);
                free(pathName);
                fp = fopen(fullPath, "w+");
                if (!fp) {
                    free(appleArchive);
                    NEO_AA_LogErrorF("could not open fullPath: %s\n", fullPath);
                    return -14;
                }
            }
#if defined(_WIN32) || defined(WIN32)
            /* Windows does not implement unix uid_t/gid_t */
#else
            int fd = fileno(fp);
            if (fd != -1) {
                fstat(fd, &st);
                if (S_ISLNK(st.st_mode)) {
                    /* prevent arbitrary file write */
                    fclose(fp);
                    free(appleArchive);
                    NEO_AA_LogErrorF("tried to open normal file, instead opened symlink at %s\n", pathName);
                    free(pathName);
                    return -16;
                }
                uid_t fileUid = st.st_uid;
                gid_t fileGid = st.st_gid;
                if (uidIndex != -1) {
                    fileUid = (uid_t)neo_aa_header_get_field_key_uint(header, uidIndex);
                }
                if (gidIndex != -1) {
                    fileGid = (gid_t)neo_aa_header_get_field_key_uint(header, gidIndex);
                }
                fchown(fd, fileUid, fileGid);
                if (modIndex != -1) {
                    uint64_t accessMode = neo_aa_header_get_field_key_uint(header, modIndex);
                    fchmod(fd, accessMode);
                }
            }
#endif
            uint8_t *fileData = currentHeader + headerSize;
            /* copy file data to buffer */
            fwrite(fileData, dataSize, 1, fp);
            xatSize = 0;
            if (xatIndex != -1) {
                xatSize = neo_aa_header_get_field_key_uint(header, xatIndex);
                uint8_t *xattrBlob = currentHeader + headerSize + dataSize;
                internal_do_not_call_apply_xattr_blob_to_fd(xattrBlob, xatSize, fd);
            }
            fclose(fp);
            currentHeader += (headerSize + dataSize + xatSize);
        } else if (typEntryType == 'L') {
            /* Symlink for file */
            uint32_t lnkKey = NEO_AA_FIELD_C("LNK");
            int lnkIndex = neo_aa_header_get_field_key_index(header, lnkKey);
            if (lnkIndex == -1) {
                free(pathName);
                free(appleArchive);
                fprintf(stderr, "neo_aa_extract_aar_to_path: no LNK field\n");
                return -17;
            }
            char *lnkPath = neo_aa_header_get_field_key_string(header, lnkIndex);
            symlink(lnkPath, pathName);
            free(lnkPath);
            currentHeader += headerSize;
        } else {
            free(pathName);
            free(appleArchive);
            NEO_AA_LogErrorF("AAEntryType %c not supported yet, only D, F, and L currently are\n",typEntryType);
            return -15;
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
    return 0;
}

void neo_aa_extract_aar_to_path(const char *archivePath, const char *outputPath) {
    neo_aa_extract_aar_to_path_err(archivePath, outputPath);
}
