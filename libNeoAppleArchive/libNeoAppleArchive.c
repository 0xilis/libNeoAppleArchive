/*
 *  libNeoAppleArchive.c
 *  libNeoAppleArchive
 *
 *  Created by Snoolie Keffaber on 2024/04/22.
 */

#include "libNeoAppleArchive.h"
#include "libNeoAppleArchive_internal.h"
#include "neo_aa_stream.h"
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wstrict-prototypes"
#include <lzfse.h>
#pragma clang diagnostic pop
#include <libzbitmap.h>
#include <zlib.h>
#include <fcntl.h>
#include <dirent.h>
#include <libgen.h>
#include "compression/lzraven/lzraven.h"
#include <errno.h>

NeoAAArchiveItem neo_aa_archive_item_create_with_header(NeoAAHeader header) {
    if (!header) {
        NEO_AA_LogError("header is NULL\n");
        return NULL;
    }
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
        item->encodedBlobData = NULL;
        free(encodedBlobData);
    }
    encodedBlobData = malloc(dataSize);
    if (!encodedBlobData) {
        NEO_AA_ErrorHeapAlloc();
        return;
    }
    for (size_t i = 0; i < dataSize; i++) {
        encodedBlobData[i] = data[i];
    }
    item->encodedBlobData = encodedBlobData;
    item->encodedBlobDataSize = dataSize;
}

NeoAAArchivePlain neo_aa_archive_plain_create_with_items_nocopy(NeoAAArchiveItem *items, int itemCount) {
    if (!items || !itemCount) {
        NEO_AA_LogError("items empty");
        return NULL;
    }
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
    if (!items || !itemCount) {
        NEO_AA_LogError("items empty");
        return NULL;
    }
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
            neo_aa_archive_item_list_destroy_nozero(copiedItems, i);
            NEO_AA_ErrorHeapAlloc();
            return NULL;
        }
        memset(copiedArchiveItem, 0, sizeof(struct neo_aa_archive_item_impl));
        NeoAAHeader copiedHeader = neo_aa_header_clone_header(archiveItem->header);
        if (!copiedHeader) {
            /*
             * We have not yet changed copiedArchiveItem->encodedBlobData,
             * or copiedArchiveItem->header so we need to just free() rather
             * than calling neo_aa_archive_item_destroy_nozero()
             */
            free(copiedArchiveItem);
            neo_aa_archive_item_list_destroy_nozero(copiedItems, i);
            NEO_AA_LogError("cloning header in list failed\n");
            return NULL;
        }
        copiedHeader->archiveItem = copiedArchiveItem;
        copiedArchiveItem->header = copiedHeader;
        if (encodedBlobDataSize) {
            char *copiedEncodedBlobData = malloc(encodedBlobDataSize);
            if (!copiedEncodedBlobData) {
                free(copiedHeader);
                free(copiedArchiveItem);
                neo_aa_archive_item_list_destroy_nozero(copiedItems, i);
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
    if (!items) {
        return;
    }
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
    if (!plainArchive) {
        return;
    }
    NeoAAArchiveItem *items = plainArchive->items;
    int itemCount = plainArchive->itemCount;
    plainArchive->items = 0;
    neo_aa_archive_item_list_destroy(items, itemCount);
    memset(plainArchive, 0, sizeof(struct neo_aa_archive_plain_impl));
    free(plainArchive);
}

void neo_aa_archive_item_list_destroy_nozero(NeoAAArchiveItem *items, int itemCount) {
    if (!items) {
        return;
    }
    for (int i = 0; i < itemCount; i++) {
        NeoAAArchiveItem archiveItem = items[i];
        neo_aa_header_destroy_nozero(archiveItem->header);
        free(archiveItem->encodedBlobData);
        free(archiveItem);
    }
    free(items);
}

void neo_aa_archive_plain_destroy_nozero(NeoAAArchivePlain plainArchive) {
    if (!plainArchive) {
        return;
    }
    neo_aa_archive_item_list_destroy_nozero(plainArchive->items, plainArchive->itemCount);
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

#if 0 /* TODO: Not yet complete */
uint64_t neo_aa_archive_plain_outfile_size64(NeoAAArchivePlain plainArchive) {
    uint64_t outfileSize = 0;
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
#endif

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

NEO_INTERNAL_API int neo_aa_archive_plain_writefd_err(NeoAAArchivePlain plainArchive, int fd) {
    if (!plainArchive) {
        NEO_AA_LogError("plainArchive is NULL\n");
        return -1;
    }
    /* Ugly slow */
    size_t archiveSize = neo_aa_archive_plain_outfile_size(plainArchive);
    if (!archiveSize) {
        NEO_AA_LogError("failed to get outfile size\n");
        return -1;
    }
    /* Now we know what the archive size will be, create it. */
    uint8_t *buffer = malloc(archiveSize); /* buffer to write to fd */
    if (neo_aa_archive_plain_write_buffer(plainArchive, buffer)) {
        NEO_AA_LogError("neo_aa_archive_plain_write_buffer failed\n");
        free(buffer);
        return -1;
    }
    write(fd, buffer, archiveSize);
    free(buffer);
    return 0;
}

void neo_aa_archive_plain_writefd(NeoAAArchivePlain plainArchive, int fd) {
    NEO_AA_NullParamAssert(plainArchive);
    neo_aa_archive_plain_writefd_err(plainArchive, fd);
}

uint8_t *neo_aa_archive_plain_get_encoded_data(NeoAAArchivePlain archive, size_t *encodedDataSize) {
    if (!archive) {
        NEO_AA_LogError("archive is NULL\n");
        return 0;
    }
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
            free(buffer);
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
    if (!plainArchive) {
        NEO_AA_LogError("plainArchive is NULL\n");
        return;
    }
    if (!filepath) {
        NEO_AA_LogError("filepath is NULL\n");
        return;
    }
    FILE *fp = fopen(filepath, "w");
    if (!fp) {
        NEO_AA_LogError("failed to open filepath\n");
        return;
    }
    int fd = fileno(fp);
    neo_aa_archive_plain_writefd(plainArchive, fd);
    fclose(fp);
}

void neo_aa_archive_item_destroy(NeoAAArchiveItem item) {
    if (!item) {
        return;
    }
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
    if (!item) {
        return;
    }
    neo_aa_header_destroy_nozero(item->header);
    free(item->encodedBlobData);
    free(item);
}

NeoAAArchiveItem neo_aa_archive_item_create_with_encoded_data(size_t encodedSize, uint8_t *data) {
    if (data == NULL || encodedSize < 6) {
        NEO_AA_LogError("encoded item too small\n");
        return NULL;
    }

    uint32_t headerMagic;
    memcpy(&headerMagic, data, sizeof(headerMagic));
    if (headerMagic != AAR_MAGIC && headerMagic != YAA_MAGIC) { /* AA01/YAA1 */
        NEO_AA_LogError("data is not raw header (compression not yet supported)\n");
        return NULL;
    }

    /* Get the header size */
    size_t encodedHeaderSize = (size_t)((uint32_t)data[4] | ((uint32_t)data[5]<<8)); /* [fuzz-triage] 2-byte read */
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
            /*
             * GHSA-chpv-g239-pp39: Make sure to free remaining items in itemList
             */
            if (itemList) {
                neo_aa_archive_item_list_destroy_nozero(itemList, itemCount - 1);
            }
            NEO_AA_ErrorHeapAlloc();
            return NULL;
        }
        itemList = itemListNewPtr;
        size_t currentHeaderSize = internal_do_not_call_neo_aa_archive_item_encoded_data_size_for_encoded_data(maxSize, data + position);
        if (!currentHeaderSize) {
            /*
             * GHSA-chpv-g239-pp39: Make sure to free remaining items in itemList
             */
            neo_aa_archive_item_list_destroy_nozero(itemList, itemCount - 1);
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
    if (!path) {
        NEO_AA_LogError("path is NULL\n");
        return NULL;
    }
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        NEO_AA_LogError("failed to open filepath\n");
        return NULL;
    }
    if (fseeko(fp, 0, SEEK_END) != 0) {
        NEO_AA_LogError("reached SEEK_END\n");
        fclose(fp);
        return NULL;
    }

    off_t fileSize = ftello(fp);

    if (fileSize < 0 || fseeko(fp, 0, SEEK_SET) != 0) {
        NEO_AA_LogError("file size is smaller\n");
        fclose(fp);
        return NULL;
    }

    uint64_t binarySize = (uint64_t)fileSize;
    int fd = fileno(fp);
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
    fclose(fp);
    if ((size_t)bytesRead < binarySize) {
        free(data);
        NEO_AA_LogError("failed to read entire file\n");
        return NULL;
    }
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
            uint8_t *encodedRAWData = calloc(1, uncompressedSize);
            if (!encodedRAWData) {
                NEO_AA_ErrorHeapAlloc();
                return NULL;
            }
            int totalOut = internal_do_not_call_inflate(data + 0x1C, (int)compressedSize, encodedRAWData, (int)uncompressedSize);
            if ((size_t)totalOut != uncompressedSize || totalOut == -1) {
                free(encodedRAWData);
                NEO_AA_LogError("failed to decompress ZLIB data\n");
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
        } else if (compressionType == 'm') {
            /* type is LZRAVEN (formerly known as LZMAMMOTH */
            /* compressed size of aar is stored at 0x18 in binary */
            size_t compressedSize = FLIP_32(*((uint32_t *)(data + 0x18)));
            /* uncompressed size of aar is stored at 0x10 in binary */
            size_t uncompressedSize = FLIP_32(*((uint32_t *)(data + 0x10)));
            uint8_t *encodedRAWData = calloc(1, uncompressedSize);
            if (!encodedRAWData) {
                NEO_AA_ErrorHeapAlloc();
                return NULL;
            }
            size_t totalOut = lzraven_decode_buffer(encodedRAWData, (size_t)uncompressedSize, data + 0x1C, (size_t)compressedSize);
            if (totalOut != uncompressedSize || !totalOut) {
                free(encodedRAWData);
                NEO_AA_LogError("failed to decompress LZRAVEN data\n");
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
            genericArchive->compression = NEO_AA_COMPRESSION_LZRAVEN;
            genericArchive->uncompressedSize = uncompressedSize;
            genericArchive->compressedSize = compressedSize;
            return genericArchive;
        } else {
            /* We currently don't support non ZLIB/LZFSE/LZBITMAP/LZRAVEN/RAW apple archives, sorry! */
            NEO_AA_LogError("We currently don't support non ZLIB/LZFSE/LZBITMAP/LZRAVEN/RAW apple archives, sorry!\n");
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
 * Well, it *will*... currently it only supports
 * ZLIB/LZFSE/LZBITMAP/LZRAVEN/RAW at the moment.
 */
NeoAAArchiveGeneric neo_aa_archive_generic_from_path(const char *path) {
    if (!path) {
        NEO_AA_LogError("path is NULL\n");
        return NULL;
    }
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        NEO_AA_LogError("failed to open filepath\n");
        return NULL;
    }
    if (fseeko(fp, 0, SEEK_END) != 0) {
        NEO_AA_LogError("reached SEEK_END\n");
        fclose(fp);
        return NULL;
    }
    off_t fileSize = ftello(fp);
    if (fileSize < 0 || fseeko(fp, 0, SEEK_SET) != 0) {
        NEO_AA_LogError("file size is smaller\n");
        fclose(fp);
        return NULL;
    }
    uint64_t binarySize = (uint64_t)fileSize;
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
            free(buffer);
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
            free(buffer);
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
            free(buffer);
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
            free(buffer);
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
    } else if (NEO_AA_COMPRESSION_LZRAVEN == algorithm) {
        /* TODO: This code sucks. */
        uint8_t *compressed = malloc(archiveSize + 100);
        if (!compressed) {
            NEO_AA_LogError("not enough memory to compress\n");
            free(buffer);
            return 0;
        }
        memset(compressed, 0, archiveSize + 100);

        struct neo_pbzx_archived_directory_header *ptr = (struct neo_pbzx_archived_directory_header *)compressed;
        ptr->magic = PBZM_MAGIC;
        ptr->mystery = 0x40;
        ptr->uncompressedSize = FLIP_32((uint32_t)archiveSize);

        /* Skip past header */
        compressed += sizeof(struct neo_pbzx_archived_directory_header);

        size_t compressedSize = lzraven_encode_buffer(compressed, (archiveSize + 100) - sizeof(struct neo_pbzx_archived_directory_header), (uint8_t *)buffer, archiveSize);
        if (!compressedSize) {
            NEO_AA_LogError("compressedSize==0\n");
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
    if (!plain) {
        NEO_AA_LogError("plain is NULL\n");
        return;
    }
    if (!path) {
        NEO_AA_LogError("path is NULL\n");
        return;
    }
    FILE *fp = fopen(path, "w");
    if (!fp) {
        NEO_AA_LogError("failed to open path\n");
        return;
    }
    int fd = fileno(fp);
    neo_aa_archive_plain_compress_writefd(plain, algorithm, fd);
    fclose(fp);
}

/* TODO: Experimental */
/* Recursively archive directory contents */
NEO_INTERNAL_API static int add_directory_contents_to_archive(const char *dirPath, NeoAAArchiveItem *items, size_t *itemsCount, size_t *itemsMalloc, const char *basePath) {
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
            if (neo_aa_header_set_field_uint_err(header, NEO_AA_FIELD_C("UID"), 2, (unsigned short)fileStat.st_uid)) {
                NEO_AA_LogError("failed to set uid field\n");
                continue;
            }
        }
        if (fileStat.st_gid != (gid_t)-1) {
            if (neo_aa_header_set_field_uint_err(header, NEO_AA_FIELD_C("GID"), 1, (unsigned char)fileStat.st_gid)) {
                NEO_AA_LogError("failed to set gid field\n");
                continue;
            }
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
    if (fseeko(fp, 0, SEEK_END) != 0) {
        NEO_AA_LogError("reached SEEK_END\n");
        fclose(fp);
        return NULL;
    }
    off_t fileSize = ftello(fp);
    if (fileSize < 0 || fseeko(fp, 0, SEEK_SET) != 0) {
        NEO_AA_LogError("file size is smaller\n");
        fclose(fp);
        return NULL;
    }
    uint64_t binarySize = (uint64_t)fileSize;
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

NEO_INTERNAL_API static int neo_aa_extract_raw_aar_to_path_err(const char *archivePath, const char *outputPath) {
    if (!archivePath || !outputPath || !outputPath[0]) {
        NEO_AA_LogError("invalid path\n");
        return -1;
    }

    FILE *archive = fopen(archivePath, "rb");
    if (!archive) {
        NEO_AA_LogError("failed to open archive\n");
        return -1;
    }

    /* get archive size */
    if (fseeko(archive, 0, SEEK_END) != 0) {
        fclose(archive);
        return -1;
    }

    off_t archiveSize = ftello(archive);

    if (archiveSize < 6 || fseeko(archive, 0, SEEK_SET) != 0) {
        fclose(archive);
        NEO_AA_LogError("invalid archive size\n");
        return -1;
    }

    /* check archive magic */
    uint8_t magicBytes[4];

    if (neo_aa_read_exact(archive, magicBytes, sizeof(magicBytes))) {
        fclose(archive);
        return -1;
    }

    uint32_t magic;
    memcpy(&magic, magicBytes, sizeof(magic));

    if (magic != AAR_MAGIC && magic != YAA_MAGIC) {
        fclose(archive);
        NEO_AA_LogError("compressed archives require a streaming decoder\n");
        return -4;
    }

    if (fseeko(archive, 0, SEEK_SET) != 0) {
        fclose(archive);
        return -1;
    }

    /* create output directory if it doesn't already exist */
    if (mkdir(outputPath, 0755) < 0 && errno != EEXIST) {
        fclose(archive);
        NEO_AA_LogError("failed to create output directory\n");
        return -1;
    }

    struct stat outputStat;

    if (stat(outputPath, &outputStat) < 0 || !S_ISDIR(outputStat.st_mode)) {
        fclose(archive);
        NEO_AA_LogError("output path is not a directory\n");
        return -1;
    }

    /* extract entries sequentially */
    int result = 0;

    while (1) {
        off_t currentPosition = ftello(archive);

        if (currentPosition < 0) {
            result = -1;
            break;
        }

        if (currentPosition == archiveSize) {
            break;
        }

        if (currentPosition > archiveSize ||
            archiveSize - currentPosition < 6) {
            NEO_AA_LogError("truncated archive header\n");
            result = -1;
            break;
        }

        uint8_t prefix[6];

        if (neo_aa_read_exact(archive, prefix, sizeof(prefix))) {
            result = -1;
            break;
        }

        memcpy(&magic, prefix, 4);

        if (magic != AAR_MAGIC && magic != YAA_MAGIC) {
            NEO_AA_LogError("invalid entry magic\n");
            result = -1;
            break;
        }

        uint16_t headerSize = (uint16_t)prefix[4] | ((uint16_t)prefix[5] << 8);

        if (headerSize < 6 || (uint64_t)headerSize > (uint64_t)(archiveSize - currentPosition)) {
            NEO_AA_LogError("invalid header size\n");
            result = -1;
            break;
        }

        uint8_t *headerData = malloc(headerSize);

        if (!headerData) {
            result = -1;
            break;
        }

        memcpy(headerData, prefix, sizeof(prefix));

        if (neo_aa_read_exact(archive, headerData + sizeof(prefix), headerSize - sizeof(prefix))) {
            free(headerData);
            result = -1;
            break;
        }

        NeoAAHeader header = neo_aa_header_create_with_encoded_data(headerSize, headerData);

        free(headerData);

        if (!header) {
            NEO_AA_LogError("failed to parse header\n");
            result = -1;
            break;
        }

        int typIndex = neo_aa_header_get_field_key_index(header, NEO_AA_FIELD_C("TYP"));

        int patIndex = neo_aa_header_get_field_key_index(header, NEO_AA_FIELD_C("PAT"));

        int modIndex = neo_aa_header_get_field_key_index(header, NEO_AA_FIELD_C("MOD"));

        int uidIndex = neo_aa_header_get_field_key_index(header, NEO_AA_FIELD_C("UID"));

        int gidIndex = neo_aa_header_get_field_key_index(header, NEO_AA_FIELD_C("GID"));

        int datIndex = neo_aa_header_get_field_key_index(header, NEO_AA_FIELD_C("DAT"));

        int xatIndex = neo_aa_header_get_field_key_index(header, NEO_AA_FIELD_C("XAT"));

        int lnkIndex = neo_aa_header_get_field_key_index(header, NEO_AA_FIELD_C("LNK"));

        if (typIndex < 0 || patIndex < 0) {
            neo_aa_header_destroy_nozero(header);
            NEO_AA_LogError("missing TYP or PAT field\n");
            result = -1;
            break;
        }

        uint8_t entryType = neo_aa_header_get_field_key_uint(header, typIndex);

        char *pathName = neo_aa_header_get_field_key_string(header, patIndex);

        if (!pathName) {
            neo_aa_header_destroy_nozero(header);
            result = -1;
            break;
        }

        /*
         * Empty PAT entries are permitted for archive-root
         * metadata. They have no filesystem output.
         */
        if (!pathName[0]) {
            uint64_t xatSize = xatIndex >= 0 ? neo_aa_header_get_field_key_uint(header, xatIndex) : 0;

            neo_aa_header_destroy_nozero(header);
            free(pathName);

            if (xatSize) {
                if (neo_aa_skip_stream(archive, xatSize)) {
                    result = -1;
                    break;
                }
            }

            continue;
        }

        if (neo_aa_validate_archive_path(pathName)) {
            NEO_AA_LogError("unsafe archive path\n");
            free(pathName);
            neo_aa_header_destroy_nozero(header);
            result = -1;
            break;
        }

        if (neo_aa_make_parent_directories(outputPath, pathName)) {
            free(pathName);
            neo_aa_header_destroy_nozero(header);
            result = -1;
            break;
        }

        char fullPath[PATH_MAX];

        int pathLength = snprintf(fullPath, sizeof(fullPath), "%s/%s", outputPath, pathName);

        if (pathLength < 0 ||
            (size_t)pathLength >= sizeof(fullPath)) {
            free(pathName);
            neo_aa_header_destroy_nozero(header);
            result = -1;
            break;
        }

        uint64_t xatSize = xatIndex >= 0 ? neo_aa_header_get_field_key_uint(header, xatIndex) : 0;

        if (entryType == 'D') {
            /* directory */
            uint64_t mode = modIndex >= 0 ? neo_aa_header_get_field_key_uint(header, modIndex) : 0755;

            if (mkdir(fullPath, (mode_t)mode) < 0 &&
                errno != EEXIST) {
                result = -1;
            }

            int fd = -1;

            if (!result) {
                fd = open(
                    fullPath,
                    O_RDONLY
#ifdef O_DIRECTORY
                    | O_DIRECTORY
#endif
#ifdef O_NOFOLLOW
                    | O_NOFOLLOW
#endif
                );

                if (fd < 0) {
                    result = -1;
                }
            }

#if !defined(_WIN32) && !defined(WIN32)
            if (fd >= 0) {
                struct stat st;

                if (fstat(fd, &st) == 0 && S_ISDIR(st.st_mode)) {
                    if (uidIndex >= 0 || gidIndex >= 0) {
                        uid_t uid = uidIndex >= 0 ? (uid_t)neo_aa_header_get_field_key_uint(header, uidIndex) : st.st_uid;

                        gid_t gid = gidIndex >= 0 ? (gid_t)neo_aa_header_get_field_key_uint(header, gidIndex) : st.st_gid;

                        fchown(fd, uid, gid);
                    }

                    fchmod(fd, (mode_t)mode);

                    if (xatSize && neo_aa_read_apply_xattrs(archive, xatSize, fd)) {
                        result = -1;
                    }
                } else {
                    result = -1;
                }

                close(fd);
            }
#else
            if (xatSize && neo_aa_skip_stream(archive, xatSize)) {
                result = -1;
            }
#endif
        } else if (entryType == 'F') {
            /* file */
            if (datIndex < 0) {
                NEO_AA_LogError("missing DAT field\n");
                result = -1;
            } else {
                uint64_t dataSize = neo_aa_header_get_field_key_uint(header, datIndex);

                off_t dataPosition = ftello(archive);

                if (dataPosition < 0 || (uint64_t)dataPosition > (uint64_t)archiveSize || dataSize > (uint64_t)(archiveSize - dataPosition) || xatSize > (uint64_t)(archiveSize - dataPosition) - dataSize) {
                    NEO_AA_LogError("file data exceeds archive bounds\n");
                    result = -1;
                } else {
#ifdef O_NOFOLLOW
                    int fd = open(fullPath, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
#else
                    int fd = open(fullPath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
#endif

                    if (fd < 0) {
                        result = -1;
                    } else {
                        FILE *output = fdopen(fd, "wb");

                        if (!output) {
                            close(fd);
                            result = -1;
                        } else {
                            /*
                             * Copy DAT directly to disk.
                             * Memory consumption is independent
                             * of the file's size.
                             */
                            if (neo_aa_copy_stream(archive, output, dataSize)) {
                                result = -1;
                            }

                            if (!result && fflush(output) != 0) {
                                result = -1;
                            }

#if !defined(_WIN32) && !defined(WIN32)
                            if (!result) {
                                struct stat st;

                                if (fstat(fd, &st) == 0) {
                                    uid_t uid = uidIndex >= 0 ? (uid_t)neo_aa_header_get_field_key_uint(header, uidIndex) : st.st_uid;

                                    gid_t gid = gidIndex >= 0 ? (gid_t)neo_aa_header_get_field_key_uint(header, gidIndex) : st.st_gid;

                                    if (uidIndex >= 0 || gidIndex >= 0) {
                                        fchown(fd, uid, gid);
                                    }

                                    if (modIndex >= 0) {
                                        fchmod(fd, (mode_t)neo_aa_header_get_field_key_uint(header, modIndex));
                                    }
                                } else {
                                    result = -1;
                                }
                            }

                            if (!result && xatSize &&
                                neo_aa_read_apply_xattrs(archive, xatSize, fd)) {
                                result = -1;
                            }
#else
                            if (!result && xatSize &&
                                neo_aa_skip_stream(archive, xatSize)) {
                                result = -1;
                            }
#endif
                            fclose(output);
                        }
                    }
                }
            }
        } else if (entryType == 'L') {
            /* symlink */
            if (lnkIndex < 0) {
                result = -1;
            } else {
                char *target = neo_aa_header_get_field_key_string(header, lnkIndex);

                if (!target) {
                    result = -1;
                } else {
                    if (symlink(target, fullPath) < 0) {
                        result = -1;
                    }

                    free(target);
                }

                if (!result && xatSize &&
                    neo_aa_skip_stream(archive, xatSize)) {
                    result = -1;
                }
            }
        } else {
            NEO_AA_LogErrorF("unsupported archive entry type: %c\n", entryType);
            result = -1;
        }

        free(pathName);
        neo_aa_header_destroy_nozero(header);

        if (result) {
            break;
        }
    }

    fclose(archive);

    if (result) {
        NEO_AA_LogError("archive extraction failed\n");
        return -1;
    }

    return 0;
}

/*
 * neo_aa_extract_aar_to_path_err
 *
 * Extracts an Apple Archive to the specified destination path.
 *
 * Supports RAW (AA01/YAA1) archives, as well as compressed PBZZ
 * (ZLIB), PBZE (LZFSE), PBZB (LZBITMAP), and PBZM (LZRAVEN) archives.
 *
 * RAW and PBZZ archives are extracted using streaming operations to
 * minimize memory usage. PBZE, PBZB, and PBZM archives are currently
 * decompressed in memory due to the lack of streaming decompression
 * implementations for these types.
 *
 * If the function was successful, it will return 0.
 * If not, it will return a negative error code.
*/
int neo_aa_extract_aar_to_path_err(const char *archivePath, const char *outputPath) {
    if (!archivePath || !outputPath || !outputPath[0]) {
        NEO_AA_LogError("invalid path\n");
        return -1;
    }

    FILE *archive = fopen(archivePath, "rb");
    if (!archive) {
        NEO_AA_LogError("failed to open archive\n");
        return -1;
    }

    if (fseeko(archive, 0, SEEK_END) != 0) {
        fclose(archive);
        return -1;
    }

    off_t archiveSize = ftello(archive);

    if (archiveSize < 6 || fseeko(archive, 0, SEEK_SET) != 0) {
        fclose(archive);
        NEO_AA_LogError("invalid archive size\n");
        return -1;
    }

    uint8_t magicBytes[4];

    if (neo_aa_read_exact(archive, magicBytes, sizeof(magicBytes))) {
        fclose(archive);
        NEO_AA_LogError("failed to read magic of top header");
        return -1;
    }

    uint32_t magic;
    memcpy(&magic, magicBytes, sizeof(magic));

    if (magic == AAR_MAGIC || magic == YAA_MAGIC) {
        fclose(archive);
        return neo_aa_extract_raw_aar_to_path_err(archivePath, outputPath);
    }

    if ((magic & 0x00FFFFFF) != PBZ__MAGIC) {
        fclose(archive);
        NEO_AA_LogError("magic is not AA01/YAA1 or PBZE\n");
        return -1;
    }

    char compressionType = (char)(magic >> 24);

    /* use a private temporary directory to store the decompressed archive */
    const char *tempDir = getenv("TMPDIR");

    if (!tempDir || !tempDir[0]) {
        tempDir = "/tmp";
    }

    char tempDirectory[PATH_MAX];

    int tempDirectoryLength = snprintf(tempDirectory, sizeof(tempDirectory), "%s/neo_aa_extract_XXXXXX", tempDir);

    if (tempDirectoryLength < 0 || (size_t)tempDirectoryLength >= sizeof(tempDirectory)) {
        fclose(archive);
        NEO_AA_LogError("temporary directory path too long\n");
        return -1;
    }

    if (!mkdtemp(tempDirectory)) {
        fclose(archive);
        NEO_AA_LogError("failed to create temporary directory\n");
        return -1;
    }

    char tempPath[PATH_MAX];

    int tempPathLength = snprintf(tempPath, sizeof(tempPath), "%s/archive.raw", tempDirectory);

    if (tempPathLength < 0 || (size_t)tempPathLength >= sizeof(tempPath)) {
        fclose(archive);
        rmdir(tempDirectory);
        NEO_AA_LogError("tempPathLength < 0 || (size_t)tempPathLength >= sizeof(tempPath))\n");
        return -1;
    }

    int result = -1;

    if (compressionType == 'z') {
        /* ZLIB */
        if (archiveSize < 0x1C) {
            NEO_AA_LogError("invalid PBZZ header\n");
            goto cleanup;
        }

        uint8_t header[0x1C];

        if (fseeko(archive, 0, SEEK_SET) != 0 ||
            neo_aa_read_exact(archive, header, sizeof(header))) {
            NEO_AA_LogError("failed to read PBZZ header\n");
            goto cleanup;
        }

        uint32_t uncompressedSize = ((uint32_t)header[0x10] << 24) | ((uint32_t)header[0x11] << 16) | ((uint32_t)header[0x12] << 8) | ((uint32_t)header[0x13]);

        uint32_t compressedSize = ((uint32_t)header[0x18] << 24) | ((uint32_t)header[0x19] << 16) | ((uint32_t)header[0x1A] << 8) | ((uint32_t)header[0x1B]);

        if ((uint64_t)compressedSize > (uint64_t)(archiveSize - 0x1C)) {
            NEO_AA_LogError("compressed data exceeds archive bounds\n");
            goto cleanup;
        }

        if (fseeko(archive, 0x1C, SEEK_SET) != 0) {
            NEO_AA_LogError("(fseeko(archive, 0x1C, SEEK_SET) != 0)\n");
            goto cleanup;
        }

        int tempFD = open(tempPath, O_RDWR | O_CREAT | O_EXCL, 0600);

        if (tempFD < 0) {
            NEO_AA_LogError("failed to create temporary archive\n");
            goto cleanup;
        }

        FILE *tempFile = fdopen(tempFD, "w+b");

        if (!tempFile) {
            close(tempFD);
            unlink(tempPath);
            NEO_AA_LogError("fdopen(tempFD, \"w+b\") failed\n");
            goto cleanup;
        }

        if (internal_do_not_call_inflate_stream(archive, tempFile, compressedSize)) {
            NEO_AA_LogError("failed to decompress ZLIB data\n");
            fclose(tempFile);
            goto cleanup;
        }

        if (fflush(tempFile) != 0) {
            fclose(tempFile);
            NEO_AA_LogError("failed to flush tempFile\n");
            goto cleanup;
        }

        if (fseeko(tempFile, 0, SEEK_END) != 0) {
            fclose(tempFile);
            NEO_AA_LogError("(fseeko(tempFile, 0, SEEK_END)\n");
            goto cleanup;
        }

        off_t actualSize = ftello(tempFile);

        if (actualSize < 0 || (uint64_t)actualSize != (uint64_t)uncompressedSize) {
            NEO_AA_LogError("incorrect decompressed size\n");
            fclose(tempFile);
            goto cleanup;
        }

        if (fseeko(tempFile, 0, SEEK_SET) != 0) {
            fclose(tempFile);
            NEO_AA_LogError("(fseeko(tempFile, 0, SEEK_SET) != 0)\n");
            goto cleanup;
        }

        uint8_t rawMagicBytes[4];

        if (neo_aa_read_exact(tempFile, rawMagicBytes, sizeof(rawMagicBytes))) {
            fclose(tempFile);
            NEO_AA_LogError("failed to read magic\n");
            goto cleanup;
        }

        uint32_t rawMagic;
        memcpy(&rawMagic, rawMagicBytes, sizeof(rawMagic));

        if (rawMagic != AAR_MAGIC && rawMagic != YAA_MAGIC) {
            NEO_AA_LogError("decompressed data is not a RAW archive\n");
            fclose(tempFile);
            goto cleanup;
        }

        fclose(tempFile);
    } else {
        /*
         * PBZE / LZFSE
         * PBZB / LZBITMAP
         * PBZM / LZRAVEN
         *
         * These formats still require the generic in-memory decoder.
         */
        if ((uint64_t)archiveSize > SIZE_MAX) {
            NEO_AA_LogError("archive too large for memory decoder\n");
            goto cleanup;
        }

        size_t encodedSize = (size_t)archiveSize;

        uint8_t *encodedData = malloc(encodedSize);

        if (!encodedData) {
            NEO_AA_ErrorHeapAlloc();
            goto cleanup;
        }

        if (fseeko(archive, 0, SEEK_SET) != 0 || neo_aa_read_exact(archive, encodedData, encodedSize)) {
            free(encodedData);
            NEO_AA_LogError("failed to read compressed archive\n");
            goto cleanup;
        }

        NeoAAArchiveGeneric genericArchive = neo_aa_archive_generic_from_encoded_data(encodedSize, encodedData);

        free(encodedData);

        if (!genericArchive) {
            NEO_AA_LogError("failed to decode compressed archive\n");
            goto cleanup;
        }

        int tempFD = open(tempPath, O_WRONLY | O_CREAT | O_EXCL, 0600);

        if (tempFD < 0) {
            neo_aa_archive_plain_destroy_nozero(genericArchive->raw);
            free(genericArchive);
            NEO_AA_LogError("failed to create temporary archive\n");
            goto cleanup;
        }

        if (neo_aa_archive_plain_writefd_err(genericArchive->raw, tempFD)) {
            close(tempFD);
            unlink(tempPath);

            neo_aa_archive_plain_destroy_nozero(genericArchive->raw);
            free(genericArchive);

            NEO_AA_LogError("failed to write decoded RAW archive\n");
            goto cleanup;
        }

        if (close(tempFD) != 0) {
            unlink(tempPath);

            neo_aa_archive_plain_destroy_nozero(genericArchive->raw);
            free(genericArchive);

            goto cleanup;
        }

        neo_aa_archive_plain_destroy_nozero(genericArchive->raw);
        free(genericArchive);
    }

    /* extract the raw, decompressed aar now that we decompressed it */
    result = neo_aa_extract_raw_aar_to_path_err(tempPath, outputPath);

cleanup:
    fclose(archive);

    unlink(tempPath);
    rmdir(tempDirectory);

    return result;
}

void neo_aa_extract_aar_to_path(const char *archivePath, const char *outputPath) {
    neo_aa_extract_aar_to_path_err(archivePath, outputPath);
}
