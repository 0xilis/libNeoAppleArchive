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
    aeaArchive->encodedData = aeaShortcutArchive;
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
 * neo_aa_archive_plain_with_neo_aea_archive
 *
 * Gets the NeoAAArchivePlain from the NeoAEAArchive.
 * This does not validate signing. For this, use
 * neo_aa_archive_plain_with_neo_aea_archive_verify
 */
NeoAAArchivePlain neo_aa_archive_plain_with_neo_aea_archive(NeoAEAArchive aea) {
    NEO_AA_NullParamAssert(aea);
    uint8_t *encodedData = (uint8_t *)aea->encodedData;
    NEO_AA_NullParamAssert(encodedData);
    size_t encodedDataSize = aea->encodedDataSize;
    if (encodedDataSize <= 12) {
        NEO_AA_LogError("size should be bigger than 12\n");
        return 0;
    }
    uint32_t authDataSize = 0;
    memcpy(&authDataSize, encodedData + 0x8, 4);
    uint32_t aaLzfseOffset = authDataSize + 0x495c;
    if (aaLzfseOffset > encodedDataSize) {
        NEO_AA_LogError("reached past encodedDataSize\n");
        return 0;
    }
    /* Make sure that +0x495c didn't result in a integer overflow */
    if (aaLzfseOffset < authDataSize) {
        NEO_AA_LogError("aaLzfseOffset overflow\n");
        return 0;
    }
    uint8_t *aaLZFSEPtr = encodedData + aaLzfseOffset;
    /* Make sure we didn't overflow aaLZFSEPtr */
    if (aaLZFSEPtr < encodedData) {
        NEO_AA_LogError("aaLZFSEPtr overflow\n");
        return 0;
    }
    size_t archivedDirSize = 0; /* size of uncompressed LZFSE data of the Apple Archive */
    size_t compressedSize = 0; /* size of the LZFSE compressed Apple Archive */
    size_t encodedDataSize2 = 0; /* should be equal to encodedDataSize */
    memcpy(&compressedSize, encodedData + authDataSize + 0x13c + 4, 4);
    memcpy(&encodedDataSize2, encodedData + authDataSize + 0xec + 8, 4);
    memcpy(&archivedDirSize, encodedData + authDataSize + 0xec, 4);
    /* doing this check instead of only compressedSize+aaLzfseOffset in case integer overflow */
    if (compressedSize > encodedDataSize) {
        NEO_AA_LogError("compressedSize reaches past encodedData\n");
        return 0;
    }
    if ((compressedSize + aaLzfseOffset) > encodedDataSize) {
        NEO_AA_LogError("compressedSize+offset reaches past encodedData\n");
        return 0;
    }
    uint8_t *encodedAppleArchive = malloc(archivedDirSize);
    if (!encodedAppleArchive) {
        NEO_AA_ErrorHeapAlloc();
        return 0;
    }
    size_t decompressedBytes = compression_decode_buffer(encodedAppleArchive, archivedDirSize, aaLZFSEPtr, compressedSize, 0, COMPRESSION_LZFSE);
    if (decompressedBytes != archivedDirSize) {
        free(encodedAppleArchive);
        NEO_AA_LogError("failed to decompress LZFSE data\n");
        return 0;
    }
    return neo_aa_archive_plain_create_with_encoded_data(decompressedBytes, encodedAppleArchive);
}