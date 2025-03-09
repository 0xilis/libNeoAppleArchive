/*
 *  neo_aea_archive.c
 *  libNeoAppleArchive
 *
 *  Created by Snoolie Keffaber on 2024/05/07.
 */

/*
 * NOTE THAT THIS CODE IS WIP.
 * Do not use in public programs,
 * as calls are likely to change.
 */

#include "libNeoAppleArchive.h"
#include "libNeoAppleArchive_internal.h"
#include "neo_aea_archive.h"
#include "../build/lzfse/include/lzfse.h"

#define HMacSHA256Size 32

NeoAEAArchive neo_aea_archive_with_path(const char *path) {
    NEO_AA_NullParamAssert(path);
    if (strlen(path) > 1024) {
        NEO_AA_LogError("path should not exceed 1024 characters\n");
        return 0;
    }
    NeoAEAArchive aeaArchive = malloc(sizeof(struct neo_aea_archive_impl));
    if (!aeaArchive) {
        NEO_AA_ErrorHeapAlloc();
        return 0;
    }
    /* fill struct with 0 */
    memset(aeaArchive, 0, sizeof(struct neo_aea_archive_impl));
    FILE *fp = fopen(path, "r");
    if (!fp) {
        free(aeaArchive);
        NEO_AA_LogError("failed to open path\n");
        return 0;
    }
    fseek(fp, 0, SEEK_END);
    size_t binary_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    aeaArchive->encodedDataSize = binary_size;
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
    /* copy bytes to buffer */
    size_t bytesRead = fread(aeaShortcutArchive, binary_size, 1, fp);
    if (bytesRead < binary_size) {
        fclose(fp);
        free(aeaShortcutArchive);
        free(aeaArchive);
        NEO_AA_LogError("failed to read the file\n");
        return 0;
    }
    fclose(fp);
    aeaArchive->encodedData = (uint8_t *)aeaShortcutArchive;
    aeaArchive->profile = (NeoAEAProfile)(*((uint8_t*)(aeaShortcutArchive + 4)));
    return aeaArchive;
}

NeoAEAArchive neo_aea_archive_with_encoded_data(uint8_t *encodedData, size_t encodedDataSize) {
    NEO_AA_NullParamAssert(encodedData);
    NeoAEAArchive aeaArchive = malloc(sizeof(struct neo_aea_archive_impl));
    if (!aeaArchive) {
        NEO_AA_ErrorHeapAlloc();
        return 0;
    }
    /* fill struct with 0 */
    memset(aeaArchive, 0, sizeof(struct neo_aea_archive_impl));
    aeaArchive->encodedDataSize = encodedDataSize;
    uint8_t *encodedDataCopy = malloc(encodedDataSize);
    if (!encodedDataCopy) {
        free(aeaArchive);
        NEO_AA_ErrorHeapAlloc();
        return 0;
    }
    for (int i = 0; i < encodedDataSize; i++) {
        encodedDataCopy[i] = encodedData[i];
    }
    aeaArchive->encodedData = (uint8_t *)encodedDataCopy;
    aeaArchive->profile = (NeoAEAProfile)(*((uint8_t *)encodedDataCopy + 4));
    return aeaArchive;
}

/*
 * neo_aea_archive_extract_data
 *
 * Extracts data from the AEA.
 * This does not validate signing.
 */
uint8_t *neo_aea_archive_extract_data(NeoAEAArchive aea, size_t *size) {
    /* TODO: Support more than 1 cluster, but this is only for >100mb files */
    NEO_AA_NullParamAssert(aea);
    if (aea->profile) {
        NEO_AA_LogError("neo_aa_archive_plain_with_neo_aea_archive should only be called on Profile 0 unencrypted profiles\n");
        return 0;
    }
    uint8_t *encodedData = (uint8_t *)aea->encodedData;
    NEO_AA_NullParamAssert(encodedData);
    size_t encodedDataSize = aea->encodedDataSize;
    if (encodedDataSize <= 12) {
        NEO_AA_LogError("size should be bigger than 12\n");
        return 0;
    }
    uint32_t authDataSize = 0;
    memcpy(&authDataSize, encodedData + 0x8, 4);

    size_t archivedDirSize = 0; /* size of uncompressed LZFSE data of the Apple Archive */

    /* copy struct from encoded data */
    struct aea_profile0_post_authData postAuthData = {0};
    /* 
     * We don't copy the final default cluster,
     * since we aren't 100% sure this aea will
     * have the default 256 segments per cluster
     */
    memcpy(&postAuthData, encodedData + authDataSize + 12, sizeof(struct aea_profile0_post_authData));
    /* Check root header */
    struct aea_root_header rootHeader = postAuthData.prerootHeader.rootHeader;
    char compressionAlgo = rootHeader.compressionAlgorithm;
    if (rootHeader.checksumAlgorithm != 2) {
        NEO_AA_LogError("non sha256 checksum not yet supported\n");
        return 0;
    }
    /* Calculate where segment data is */
    struct aea_segment_header *segment0Header = (struct aea_segment_header *)(encodedData + (sizeof(struct aea_profile0_post_authData)) + HMacSHA256Size);
    int segments = 0;
    uint32_t i;
    struct aea_segment_header *segmentHeader = segment0Header;
    /* Count segments and calculate archivedDirSize */
    for (i = 0; i < rootHeader.segmentsPerCluster; i++) {
        struct aea_segment_header _segmentHeader = *segmentHeader;
        if (_segmentHeader.originalSize == 0 && _segmentHeader.compressedSize == 0) {
            /* Empty segment */
            break;
        }
        size_t archivedDirSizeOld = archivedDirSize;
        archivedDirSize += _segmentHeader.originalSize;
        if (archivedDirSize < archivedDirSizeOld) {
            NEO_AA_LogError("archivedDirSize underflow\n");
            return 0;
        }
        segments++;
        segmentHeader += sizeof(struct aea_segment_header);
    }
    if (!segments) {
        NEO_AA_LogError("aea cluster has 0 segments\n");
        return 0;
    }
    int segmentOffset = (sizeof(struct aea_segment_header) * rootHeader.segmentsPerCluster);
    if (segmentOffset < 0) {
        NEO_AA_LogError("integer underflow in segmentOffset calculation\n");
        return 0;
    }
    int clusterDataStart = (sizeof(struct aea_profile0_post_authData)) + HMacSHA256Size + segmentOffset;
    if (clusterDataStart < 0) {
        NEO_AA_LogError("integer underflow in clusterDataStart calculation\n");
        return 0;
    }
    clusterDataStart += HMacSHA256Size + (rootHeader.segmentsPerCluster * HMacSHA256Size);
    if (clusterDataStart < 0) {
        NEO_AA_LogError("integer underflow in clusterDataStart calculation\n");
        return 0;
    }
    uint8_t *encodedAppleArchive = malloc(archivedDirSize);
    if (!encodedAppleArchive) {
        NEO_AA_ErrorHeapAlloc();
        return 0;
    }
    /* Get data (uncompressed segment 0 data append segment 1 data etc...) */
    i = 0;
    segmentHeader = segment0Header;
    uint8_t *segmentPtr = encodedData + clusterDataStart;
    size_t aarSize = 0;
    for (i = 0; i < segments; i++) {
        struct aea_segment_header _segmentHeader = *segmentHeader;
        /*
         * - = None
         * 4 = LZ4
         * b = LZBITMAP
         * e = LZFSE
         * f = LZVN
         * x = LZMA
         * z = ZLIB
         */
        size_t decompressedBytes;
        /* 
         * uncompressed data is either - or 0
         * i forgot which one it is so im doing both
         * however, even if the cluster follows a specific
         * compression algorithm, segments over the specified
         * segmentSize do not seem to be compressed.
         */
        int dataOffset = 0;
        if ((compressionAlgo == '-') || (compressionAlgo == 0) || (_segmentHeader.compressedSize > rootHeader.segmentSize && _segmentHeader.compressedSize == _segmentHeader.originalSize)) {
            /* No compression */
            decompressedBytes = _segmentHeader.compressedSize;
            /* copy entire aaLZFSEPtr buffer to encodedAppleArchive */
            memcpy(encodedAppleArchive + dataOffset, segmentPtr, _segmentHeader.compressedSize);
        } else if (compressionAlgo == 'e') {
            /* LZFSE compressed */
            decompressedBytes = lzfse_decode_buffer(encodedAppleArchive + dataOffset, archivedDirSize - dataOffset, segmentPtr, _segmentHeader.compressedSize, 0);
            if (decompressedBytes != archivedDirSize) {
                NEO_AA_LogError("failed to decompress LZFSE data\n");
                free(encodedAppleArchive);
                return 0;
            }
        } else {
            /* Not yet supported */
            NEO_AA_LogErrorF("compression algorithm %02x not yet supported\n", compressionAlgo);
            free(encodedAppleArchive);
            return 0;
        }
        segmentPtr += _segmentHeader.compressedSize;
        segmentHeader += sizeof(struct aea_segment_header);
        dataOffset += _segmentHeader.compressedSize;
        aarSize += decompressedBytes;
    }
    if (size) {
        *size = aarSize;
    }
    return encodedAppleArchive;
}

/*
 * neo_aa_archive_plain_with_neo_aea_archive
 *
 * Gets the NeoAAArchivePlain from the NeoAEAArchive.
 * This does not validate signing. For this, use
 * neo_aa_archive_plain_with_neo_aea_archive_verify
 */
NeoAAArchivePlain neo_aa_archive_plain_with_neo_aea_archive(NeoAEAArchive aea) {
    size_t aarSize;
    uint8_t *encodedAppleArchive = neo_aea_archive_extract_data(aea, &aarSize);
    if (encodedAppleArchive) {
        NEO_AA_LogError("could not extract data from aea\n");
        return 0;
    }
    return neo_aa_archive_plain_create_with_encoded_data(aarSize, encodedAppleArchive);
}