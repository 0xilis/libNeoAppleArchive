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
#include <openssl/aes.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>

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
    size_t binarySize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    aeaArchive->encodedDataSize = binarySize;
    uint8_t *aeaShortcutArchive = malloc(binarySize);
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
    memset(aeaShortcutArchive, 0, binarySize);
    /* copy bytes to buffer */
    size_t bytesRead = fread(aeaShortcutArchive, binarySize, 1, fp);
    if (bytesRead < binarySize) {
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
    memcpy(encodedDataCopy, encodedData, encodedDataSize);
    aeaArchive->encodedData = encodedDataCopy;
    aeaArchive->profile = (NeoAEAProfile)(*((uint8_t *)encodedDataCopy + 4));
    return aeaArchive;
}

NeoAEAArchive neo_aea_archive_with_encoded_data_nocopy(uint8_t *encodedData, size_t encodedDataSize) {
    NEO_AA_NullParamAssert(encodedData);
    NeoAEAArchive aeaArchive = malloc(sizeof(struct neo_aea_archive_impl));
    if (!aeaArchive) {
        NEO_AA_ErrorHeapAlloc();
        return 0;
    }
    /* fill struct with 0 */
    memset(aeaArchive, 0, sizeof(struct neo_aea_archive_impl));
    aeaArchive->encodedDataSize = encodedDataSize;
    aeaArchive->encodedData = encodedData;
    aeaArchive->profile = (NeoAEAProfile)(*((uint8_t *)encodedData + 4));
    return aeaArchive;
}


__attribute__((visibility ("hidden"))) static void *hmac_derive(void *hkdf_key, void *data1, size_t data1Len, void *data2, size_t data2Len) {
    uint8_t *hmac = malloc(HMacSHA256Size);
    OSSL_PARAM params[4];

    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!mac) {
        fprintf(stderr, "Failed to fetch EVP MAC\n");
        return NULL;
    }

    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    if (!ctx) {
        fprintf(stderr, "Failed to create EVP MAC context\n");
        return NULL;
    }
    
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, OSSL_DIGEST_NAME_SHA2_256, sizeof(OSSL_DIGEST_NAME_SHA2_256));
    params[1] = OSSL_PARAM_construct_end();

    /* Initialize HMAC with SHA-256 */
    if (!EVP_MAC_init(ctx, hkdf_key, HMacSHA256Size, params)) {
        fprintf(stderr, "Failed to initialize EVP MAC\n");
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return NULL;
    }

    /* Update HMAC with data */
    if (data2 && data2Len > 0) {
        if (!EVP_MAC_update(ctx, data2, data2Len)) {
            fprintf(stderr, "Failed to update HMAC\n");
            EVP_MAC_CTX_free(ctx);
            EVP_MAC_free(mac);
            return NULL;
        }
    }
    if (data1 && data1Len > 0) {
        if (!EVP_MAC_update(ctx, data1, data1Len)) {
            fprintf(stderr, "Failed to update HMAC\n");
            EVP_MAC_CTX_free(ctx);
            EVP_MAC_free(mac);
            return NULL;
        }
    }
    if (!EVP_MAC_update(ctx, (const uint8_t *)&data2Len, 8)) {
        fprintf(stderr, "Failed to update HMAC\n");
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return NULL;
    }

    /* Finalize HMAC */
    if (!EVP_MAC_final(ctx, hmac, NULL, HMacSHA256Size)) {
        fprintf(stderr, "Failed to finalize HMAC\n");
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return NULL;
    }
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);

    return hmac;
}

__attribute__((visibility ("hidden"))) static void *do_hkdf(void *context, size_t contextLen, void *key) {
    void *derivedKey = malloc(512);
    if (!derivedKey) {
        return NULL;
    }
    EVP_KDF* kdf;
    if ((kdf = EVP_KDF_fetch(NULL, "hkdf", NULL)) == NULL) {
        return NULL;
    }
    EVP_KDF_CTX* ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (ctx == NULL) {
        return NULL;
    }
    OSSL_PARAM params[4] = {
        OSSL_PARAM_construct_utf8_string("digest", "sha256", sizeof("sha256")),
        OSSL_PARAM_construct_octet_string("key", key, 32),
        OSSL_PARAM_construct_octet_string("info", context, contextLen),
        OSSL_PARAM_construct_end()
    };
    if (EVP_KDF_CTX_set_params(ctx, params) <= 0) {
        return NULL;
    }
    if (EVP_KDF_derive(ctx, derivedKey, 32, NULL) <= 0) {
        return NULL;
    }
    EVP_KDF_CTX_free(ctx);
    return derivedKey;
}

/* Helper function to perform HKDF using OpenSSL */
__attribute__((visibility ("hidden"))) static int hkdf_extract_and_expand_helper(const uint8_t *salt, size_t salt_len,
                            const uint8_t *key, size_t key_len,
                            const uint8_t *info, size_t info_len,
                            uint8_t *out, size_t out_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!ctx) {
        fprintf(stderr, "Failed to create HKDF context\n");
        return 0;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        fprintf(stderr, "Failed to initialize HKDF context\n");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0) {
        fprintf(stderr, "Failed to set HKDF hash function\n");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    if (salt && EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, salt_len) <= 0) {
        fprintf(stderr, "Failed to set HKDF salt\n");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(ctx, key, key_len) <= 0) {
        fprintf(stderr, "Failed to set HKDF key\n");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    if (EVP_PKEY_CTX_add1_hkdf_info(ctx, info, info_len) <= 0) {
        fprintf(stderr, "Failed to set HKDF info\n");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    if (EVP_PKEY_derive(ctx, out, &out_len) <= 0) {
        fprintf(stderr, "Failed to derive HKDF output\n");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    EVP_PKEY_CTX_free(ctx);
    return 1;
}

int get_encoded_size(EVP_PKEY* pkey) {
    size_t tmp;
    if (!pkey || !EVP_PKEY_get_raw_public_key(pkey, NULL, &tmp)) {
        return 0;
    }
    return tmp;
}

int serialize_pubkey(EVP_PKEY* pkey, uint8_t* buf, size_t len) {
    if (!pkey) {
        return 0;
    }
    size_t tmp = len;
    if (!pkey || !EVP_PKEY_get_raw_public_key(pkey, buf, &tmp)) {
        return 0;
    }
    return 1;
}

uint8_t* calculate_hmac(
    uint8_t* key, size_t keySize,
    uint8_t* data, size_t dataSize,
    uint8_t* salt, size_t saltSize
) {
    size_t bufSize = saltSize + dataSize + sizeof(uint64_t);
    uint8_t* buf = malloc(bufSize);
    if (!buf) {
        NEO_AA_ErrorHeapAlloc();
        return NULL;
    }
    memcpy(buf, salt, saltSize);
    memcpy(&buf[saltSize], data, dataSize);
    memcpy(&buf[saltSize + dataSize], &saltSize, sizeof(uint64_t));
    return hmac_derive(key, buf, bufSize, NULL, 0);
}

uint8_t* decrypt_AES_256_CTR(uint8_t* key, uint8_t* data, size_t dataSize) {
    const EVP_CIPHER* cipher = EVP_aes_256_ctr();
    uint8_t* decrypted = malloc(dataSize + EVP_CIPHER_block_size(cipher));
    if (!decrypted) {
        NEO_AA_ErrorHeapAlloc();
        return NULL;
    }
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, cipher, NULL, &key[32], &key[64]);
    int outl = dataSize + EVP_CIPHER_block_size(cipher);
    EVP_DecryptUpdate(ctx, decrypted, &outl, data, dataSize);
    outl = dataSize + EVP_CIPHER_block_size(cipher) - outl;
    EVP_DecryptFinal(ctx, decrypted, &outl);
    return decrypted;
}

uint8_t* get_password_key(
    uint8_t* password, size_t passwordLen, 
    uint8_t* salt, size_t saltLen,
    int hardness
) {
    uint8_t* out = malloc(64);
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "SCRYPT", NULL);
    if (!out || !kdf) {
        NEO_AA_ErrorHeapAlloc();
        return NULL;
    }
    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    uint32_t r = 8, p = 1;
    OSSL_PARAM params[6] = {
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, password, passwordLen),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt, saltLen),
        OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_N, (uint64_t *)&hardness),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_SCRYPT_R, &r),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_SCRYPT_P, &p),
        OSSL_PARAM_construct_end()
    };
    if (EVP_KDF_derive(ctx, out, 64, params) <= 0) {
        return NULL;
    }
    return out;
}

void* main_key(
    NewNeoAEAArchive aea, 
    EVP_PKEY* senderPub, 
    EVP_PKEY* recPriv, 
    EVP_PKEY* sigPub, 
    uint8_t* symmKey, size_t symmKeySize
) {
    size_t len = 12 
                + get_encoded_size(senderPub) 
                + get_encoded_size(recPriv) 
                + get_encoded_size(sigPub), 
           tmp, off = 12;
    uint8_t *context = malloc(len),
            *mainKey = malloc(32);
    if (!context || !mainKey) {
        NEO_AA_ErrorHeapAlloc();
        return NULL;
    }
    strcpy((char *)context, "AEA_AMK");
    *(uint32_t *)&context[8] = aea->profileID; // is actually an uint24_t
    context[11] = aea->scryptStrength;
    off += serialize_pubkey(senderPub, &context[off], len - off);
    off += serialize_pubkey(recPriv, &context[off], len - off);
    off += serialize_pubkey(sigPub, &context[off], len - off);
    if (!hkdf_extract_and_expand_helper(aea->keyDerivationSalt, 0x20, (uint8_t *)symmKey, symmKeySize, (uint8_t *)context, 0x4c, mainKey, 32)) {
        return NULL;
    }
    return mainKey;
}

void* password_key(uint8_t* mainKey) {
    return do_hkdf("AEA_SCRYPT", 10, mainKey);
}

void* signature_encryption_key(uint8_t* mainKey) {
    void* derivationKey = do_hkdf("AEA_SEK", 7, mainKey);
    return do_hkdf("AEA_SEK2", 8, derivationKey);
}

void* root_header_key(uint8_t* mainKey) {
    return do_hkdf("AEA_RHEK", 8, mainKey);
}

void* cluster_key(uint8_t* mainKey, int idx) {
    char context[10];
    strcpy(context, "AEA_CK");
    *(int *)&context[5] = idx;
    return do_hkdf(context, 10, mainKey);
}

void* cluster_header_key(uint8_t* clusterKey) {
    return do_hkdf("AEA_CHEK", 9, cluster_key);
}

void* segment_key(uint8_t* clusterKey, int idx) {
    char context[10];
    strcpy(context, "AEA_SK");
    *(int *)&context[5] = idx;
    return do_hkdf(context, 10, clusterKey);
}

struct aea_segment_header new_partial_segment(uint8_t* decryptedSegment, int checksumAlgorithm) {
    size_t checksumSize = checksumSizes[checksumAlgorithm];
    struct aea_old_segment_header* tmp = (struct aea_old_segment_header*)decryptedSegment;
    struct aea_segment_header segment = {
        .originalSize = tmp->originalSize,
        .compressedSize = tmp->compressedSize
    };
    
    segment.hash = malloc(checksumSize);
    if (!segment.hash) {
        NEO_AA_ErrorHeapAlloc();
        return (struct aea_segment_header){};
    }
    memcpy(segment.hash, &decryptedSegment[8], checksumSize);

    // to be initialized later
    segment.segmentData = NULL;
    bzero(segment.segmentHMAC, 0x20);

    // all fields initialized, return the segment
    return segment;
}

struct aea_cluster_header new_partial_cluster(uint8_t* decryptedCluster, int numSegments, int checksumAlgorithm) {
    struct aea_cluster_header cluster = (struct aea_cluster_header){0},
        errorCluster = cluster;
    size_t segmentHeaderSize = checksumSizes[checksumAlgorithm] + 8;
    cluster.segments = malloc(numSegments * segmentHeaderSize);
    if (!cluster.segments) {
        NEO_AA_ErrorHeapAlloc();
        return errorCluster;
    }
    struct aea_segment_header emptySegment = (struct aea_segment_header){};
    for (size_t i = 0; i < numSegments; i++) {
        struct aea_segment_header segment = new_partial_segment(decryptedCluster, checksumAlgorithm);
        if (!memcmp(&segment, &emptySegment, sizeof(struct aea_segment_header))) {
            return errorCluster;
        }
        decryptedCluster += segmentHeaderSize;
        cluster.segments[i] = segment;
    }
    memcpy(cluster.nextClusterHMAC, decryptedCluster, 0x20);
    decryptedCluster += 0x20;
    for (size_t i = 0; i < numSegments; i++) {
        struct aea_segment_header* segment = &cluster.segments[i];
        memcpy(segment->segmentHMAC, decryptedCluster, 0x20);
        decryptedCluster += 0x20;
    }
    // all field initialized, return cluster
    return cluster;
}

/*
 * neo_aea_archive_extract_data
 *
 * Extracts data from the AEA.
 * This does not validate signing.
 */
uint8_t *neo_aea_archive_extract_data(
    NewNeoAEAArchive aea, 
    size_t *size, 
    EVP_PKEY* recPriv,
    EVP_PKEY* signaturePub,
    uint8_t* symmKey, size_t symmKeySize,
    uint8_t* password, size_t passwordSize
) {
    /* TODO:
       * support other compression algorithms (lz4, lzbitmap, lzvn, lzma, zlib)
       * unit tests for all of these functions to make sure they work
       * 
     */
    NEO_AA_NullParamAssert(aea);
    size_t aeaDataSize = 0; /* size of the AEA's (uncompressed) data */

    if (aea->profileID == NEO_AEA_PROFILE_HKDF_SHA256_HMAC_NONE_ECDSA_P256) {
        symmKey = aea->profileDependent;
    } else if (HAS_SYMMETRIC_ENCRYPTION(aea->profileID)) {
        if (!symmKey || symmKeySize != 32) {
            return NULL;
        }
    }

    EVP_PKEY* senderPub = NULL;
    if (HAS_ASYMMETRIC_ENCRYPTION(aea->profileID)) {
        senderPub = EVP_PKEY_new_raw_public_key(NID_X9_62_prime256v1, NULL, aea->profileDependent, 65);
        if (!senderPub) {
            return NULL;
        }
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(recPriv, NULL);
        symmKey = malloc(32);
        symmKeySize = 32;
        if ((!ctx) || (!symmKey)
          || (EVP_PKEY_derive_init(ctx) <= 0)
          || (EVP_PKEY_derive_set_peer(ctx, senderPub) <= 0)
          || (EVP_PKEY_derive(ctx, symmKey, &symmKeySize) <= 0)) {
            return NULL;
        }
    }

    if (HAS_PASSWORD_ENCRYPTION(aea->profileID)) {
        if (!password || !passwordSize) {
            return NULL;
        }
        void* scryptCTX = malloc(10);
        if (!scryptCTX) {
            return NULL;
        }
        uint8_t* extendedSalt = password_key(aea->keyDerivationSalt);
        memcpy(aea->keyDerivationSalt, &extendedSalt[32], 0x20);
        symmKey = get_password_key(password, passwordSize, extendedSalt, 32, aea->scryptStrength);
    }

    if (!IS_SIGNED(aea->profileID)) {
        signaturePub = NULL;
    }

    /* Calculate Main Key (AEA_AMK) */
    uint8_t* mainKey = main_key(aea, senderPub, recPriv, signaturePub, symmKey, symmKeySize);
    if (IS_ENCRYPTED(aea->profileID)) {
        uint8_t* rootHeaderKey = root_header_key(mainKey);
        memcpy(
            aea->encryptedRootHeader, 
            decrypt_AES_256_CTR(rootHeaderKey, aea->encryptedRootHeader, 0x30), 
            0x30
        );
    }

    /* Check root header */
    struct aea_root_header* rootHeader = &aea->rootHeader;
    char compressionAlgo = rootHeader->compressionAlgorithm;
    if (rootHeader->checksumAlgorithm != 2) {
        NEO_AA_LogError("non sha256 checksum not yet supported\n");
        return 0;
    }
    size_t outBufferSize = 0;
    uint8_t *aeaData = malloc(aeaDataSize);
    if (!aeaData) {
        NEO_AA_ErrorHeapAlloc();
        return 0;
    }
    size_t numClusters = 0,
           clusterIndex = 0,
           segmentHeaderSize = 8 + checksumSizes[rootHeader->checksumAlgorithm];

    // Cluster Decryption Routine
    /* 
        During the execution of this function,
        There is a possibility to use memory that is ~2x the file size
        (one copy of the encrypted data, another of the decrypted)
        Parallelization of decryption is possible given segment sizes
            are precomputed beforehand.
    */
    if (IS_ENCRYPTED(aea->profileID)) {
        uint8_t* encryptedClusters = aea->encryptedClusters;
        size_t off = 0, clusterSize = sizeof(struct aea_cluster_header) * 10;
        int i = 0;
        aea->clusters = malloc(clusterSize);
        if (!aea->clusters) {
            NEO_AA_ErrorHeapAlloc();
            return 0;
        }
        // no known number of clusters, so iterate until we reach the end
        while (off < aea->clusterLen) {
            uint8_t* clusterKey = cluster_key(mainKey, clusterIndex);

            // decrypt current cluster
            uint8_t* clusterHeaderKey = cluster_header_key(clusterKey);
            uint8_t* decryptedCluster = decrypt_AES_256_CTR(
                clusterHeaderKey, 
                &encryptedClusters[off], 
                segmentHeaderSize * rootHeader->segmentsPerCluster
            );

            // make new cluster struct (data field in segments not filled in)
            struct aea_cluster_header cluster = new_partial_cluster(
                decryptedCluster, 
                rootHeader->segmentsPerCluster, 
                rootHeader->checksumAlgorithm
            );
            off += segmentHeaderSize * rootHeader->segmentsPerCluster  // segment headers
                +  0x20 * (1 + rootHeader->segmentsPerCluster); // HMACs
            free(decryptedCluster); // already copied into the cluster struct, no longer required
            
            for (size_t i = 0; i < rootHeader->segmentsPerCluster; i++) {
                struct aea_segment_header* segment = &cluster.segments[i];
                uint8_t* segmentKey = segment_key(clusterKey, i);
                // EXPENSIVE -- up to 1 MB copied and decrypted per segment!
                uint8_t* decryptedSegment = decrypt_AES_256_CTR(
                    segmentKey, 
                    &encryptedClusters[off], 
                    segment->compressedSize
                );
                if (!decryptedSegment) {
                    return 0;
                }
                // direct assignment because the whole decrypted memory belongs to this single segment
                segment->segmentData = decryptedSegment;
                // all fields in segment are now fully setup, we can move to next segment
                off += segment->compressedSize; // segment data
            }
            aea->clusters[i++] = cluster;
            if (i == (clusterSize / sizeof(struct aea_cluster_header))) {
                clusterSize *= 2;
                aea->clusters = realloc(aea->clusters, clusterSize);
                if (!aea->clusters) {
                    NEO_AA_ErrorHeapAlloc();
                    return 0;
                }
            }
            // off == next cluster header offset
        }
        free(encryptedClusters); // free encrypted clusters to not waste any more memory holding it
        // now we should only be using memory that's the same size as the file size
    }
    // use aea->clusters from now on, as they are now decrypted

    while (1) {
        int numSegments = 0;
        struct aea_segment_header *segmentHeaders = aea->clusters[clusterIndex].segments;
        /* Count number of non-empty segments and calculate aeaDataSize */
        for (uint32_t i = 0; i < rootHeader->segmentsPerCluster; i++) {
            struct aea_segment_header* curSegmentHeader = &segmentHeaders[i];
            if (curSegmentHeader->compressedSize == 0) {
                /* Empty segment */
                break;
            }
            
            // https://stackoverflow.com/a/33948556
            if ((aeaDataSize + curSegmentHeader->originalSize) < aeaDataSize) {
                NEO_AA_LogError("aeaDataSize overflow\n");
                return 0;
            }
            aeaDataSize += curSegmentHeader->originalSize;
            numSegments++;
        }
        if (!numSegments) {
            NEO_AA_LogError("AEA cluster only has empty segments\n");
            return 0;
        }
        /* Get data (uncompressed segment 0 data append segment 1 data etc...) */
        int dataOffset = 0;
        for (uint32_t i = 0; i < numSegments; i++) {
            struct aea_segment_header* curSegmentHeader = &segmentHeaders[i];
            size_t decompressedBytes = 0;
            /*
             * - = None
             * 4 = LZ4
             * b = LZBITMAP
             * e = LZFSE
             * f = LZVN
             * x = LZMA
             * z = ZLIB
             */

            /* 
             * Uncompressed data is -
             * However, even if the cluster follows a specific
             * compression algorithm, segments that have a 
             * larger size when compressed are stored uncompressed.
             */
            if ((compressionAlgo == NEO_AEA_COMPRESSION_NONE) || curSegmentHeader->compressedSize == curSegmentHeader->originalSize) {
                /* No compression */
                decompressedBytes = curSegmentHeader->compressedSize;
                /* copy entire aaLZFSEPtr buffer to aeaData */
                memcpy(&aeaData[dataOffset], curSegmentHeader->segmentData, curSegmentHeader->compressedSize);
            } else if (compressionAlgo == NEO_AEA_COMPRESSION_LZFSE) {
                /* LZFSE compressed */
                decompressedBytes = lzfse_decode_buffer(
                    &aeaData[dataOffset], 
                    curSegmentHeader->originalSize, 
                    curSegmentHeader->segmentData, 
                    curSegmentHeader->compressedSize, 
                    0
                );
                if (decompressedBytes != curSegmentHeader->originalSize) {
                    NEO_AA_LogError("failed to decompress LZFSE data\n");
                    free(aeaData);
                    return 0;
                }
            } else {
                /* Not yet supported */
                NEO_AA_LogErrorF("compression algorithm %02x not yet supported\n", compressionAlgo);
                free(aeaData);
                return 0;
            }
            dataOffset += curSegmentHeader->originalSize;
            outBufferSize += decompressedBytes;
        }

        if (numSegments != rootHeader->segmentsPerCluster) {
            // there were empty segments, end of cluster
            break;
        }
    }   
    if (size) {
        *size = outBufferSize;
    }
    return aeaData;
}

int alloc_memcpy(void** dst, void* src, size_t n) {
    *dst = malloc(n);
    if (!*dst) {
        return 0;
    }
    memcpy(*dst, src, n);
    return 1;
}

NewNeoAEAArchive convertFromOld(NeoAEAArchive aea) {
    NewNeoAEAArchive newaea = calloc(1, sizeof(struct aea_archive));
    if (!newaea) {
        return NULL;
    }
    uint8_t* buf = aea->encodedData;
    // magic, profileID, scryptStrength, authDataSize
    memcpy(newaea, buf, 12);
    buf += 12;
    void *data = NULL;
    if (!alloc_memcpy(&data, buf, newaea->authDataSize)) {
        return NULL;
    }
    newaea->authData = data;
    buf += newaea->authDataSize;
    size_t size;
    switch (aea->profile) {
        case NEO_AEA_PROFILE_HKDF_SHA256_HMAC_NONE_ECDSA_P256:
            size = 128;
            break;
        case NEO_AEA_PROFILE_HKDF_SHA256_AESCTR_HMAC_SYMMETRIC_ECDSA_P256:
        case NEO_AEA_PROFILE_HKDF_SHA256_AESCTR_HMAC_ECDHE_P256_ECDSA_P256:
            size = 160;
            break;
        default:
            size = 0;
            break;
    }
    if (!alloc_memcpy(&data, buf, size)) {
        return NULL;
    }
    newaea->signature = data;
    buf += size;
    switch (aea->profile) {
        case NEO_AEA_PROFILE_HKDF_SHA256_HMAC_NONE_ECDSA_P256:
            size = 32;
            break;
        case NEO_AEA_PROFILE_HKDF_SHA256_AESCTR_HMAC_ECDHE_P256_NONE:
        case NEO_AEA_PROFILE_HKDF_SHA256_AESCTR_HMAC_ECDHE_P256_ECDSA_P256:
            size = 65;
            break;
        default:
            size = 0;
            break;
    }
    if (!alloc_memcpy(&data, buf, size)) {
        return NULL;
    };
    newaea->profileDependent = data;
    buf += size;
    memcpy((char *)newaea + 12 + 3 * sizeof(uint8_t *), buf, 0x90);
    buf += 0x90;
    newaea->clusterLen = aea->encodedDataSize - (buf - aea->encodedData);
    // EXPENSIVE: copies all clusters
    if (!alloc_memcpy(&data, buf, newaea->clusterLen)) {
        return NULL;
    }
    newaea->encryptedClusters = data;
    return newaea;
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
    NewNeoAEAArchive newaea = convertFromOld(aea);
    uint8_t *encodedAppleArchive = neo_aea_archive_extract_data(newaea, &aarSize, NULL, 0, NULL, 0, NULL, 0);
    if (encodedAppleArchive) {
        NEO_AA_LogError("could not extract data from aea\n");
        return 0;
    }
    return neo_aa_archive_plain_create_with_encoded_data(aarSize, encodedAppleArchive);
}

void neo_aea_archive_destroy(NeoAEAArchive aea) {
    NEO_AA_NullParamAssert(aea);
    if (aea->encodedData) {
        free(aea->encodedData);
    }
    free(aea);
}
