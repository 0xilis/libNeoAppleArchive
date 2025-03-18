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
// can't do anything about imported submodules
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wstrict-prototypes"
#include <lzfse.h>
#pragma clang diagnostic pop
#include <libzbitmap.h>
#include <zlib.h>
#include <assert.h>
#include <openssl/aes.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include "asn1parse.h"

#define HMacSHA256Size 32

#ifdef DEBUG
void DumpHex(const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			printf(" ");
			if ((i+1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}
#endif

__attribute__((visibility ("hidden"))) int alloc_memcpy(void** dst, void* src, size_t n) {
    *dst = malloc(n);
    if (!*dst) {
        return 0;
    }
    memcpy(*dst, src, n);
    return 1;
}

__attribute__((visibility ("hidden"))) static void *hmac_derive(void *hkdf_key, void *data1, size_t data1Len, void *data2, size_t data2Len) {
    uint8_t *hmac = malloc(HMacSHA256Size);
    if (!hmac) {
        NEO_AA_ErrorHeapAlloc();
        return NULL;
    }

    OSSL_PARAM params[4];

    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!mac) {
        NEO_AA_LogError("Failed to fetch EVP MAC\n");
        OPENSSL_ERR_PRINT();
        free(hmac);
        return NULL;
    }

    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    if (!ctx) {
        NEO_AA_LogError("Failed to create EVP MAC context\n");
        OPENSSL_ERR_PRINT();
        free(hmac);
        return NULL;
    }
    
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, OSSL_DIGEST_NAME_SHA2_256, sizeof(OSSL_DIGEST_NAME_SHA2_256));
    params[1] = OSSL_PARAM_construct_end();

    /* Initialize HMAC with SHA-256 */
    if (!EVP_MAC_init(ctx, hkdf_key, HMacSHA256Size, params)) {
        NEO_AA_LogError("Failed to initialize EVP MAC\n");
        OPENSSL_ERR_PRINT();
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        free(hmac);
        return NULL;
    }

    /* Update HMAC with data */
    if (data2 && data2Len > 0) {
        if (!EVP_MAC_update(ctx, data2, data2Len)) {
            NEO_AA_LogError("Failed to update HMAC\n");
            OPENSSL_ERR_PRINT();
            EVP_MAC_CTX_free(ctx);
            EVP_MAC_free(mac);
            free(hmac);
            return NULL;
        }
    }
    if (data1 && data1Len > 0) {
        if (!EVP_MAC_update(ctx, data1, data1Len)) {
            NEO_AA_LogError("Failed to update HMAC\n");
            OPENSSL_ERR_PRINT();
            EVP_MAC_CTX_free(ctx);
            EVP_MAC_free(mac);
            free(hmac);
            return NULL;
        }
    }
    if (!EVP_MAC_update(ctx, (const uint8_t *)&data2Len, 8)) {
        NEO_AA_LogError("Failed to update HMAC\n");
        OPENSSL_ERR_PRINT();
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        free(hmac);
        return NULL;
    }

    /* Finalize HMAC */
    if (!EVP_MAC_final(ctx, hmac, NULL, HMacSHA256Size)) {
        NEO_AA_LogError("Failed to finalize HMAC\n");
        OPENSSL_ERR_PRINT();
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        free(hmac);
        return NULL;
    }
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);

    return hmac;
}

__attribute__((visibility ("hidden"))) static int hmac_verify(void *hkdf_key, void *data1, size_t data1Len, void *data2, size_t data2Len, uint8_t *hmac) {
    void *hmac2 = hmac_derive(hkdf_key, data1, data1Len, data2, data2Len);
    if (!hmac) {
        return -1;
    }
    int isInvalid = memcmp(hmac, hmac2, 32);
#ifdef DEBUG
    printf("hmac:\n");
    DumpHex(hmac, 32);
#endif
#ifdef DEBUG
    printf("hmac2:\n");
    DumpHex(hmac2, 32);
#endif
    free(hmac2);
    return isInvalid;
}

__attribute__((visibility ("hidden"))) static void *do_hkdf(void *context, size_t contextLen, void *key, size_t outSize) {
    void *derivedKey = malloc(outSize);
    if (!derivedKey) {
        return NULL;
    }
    EVP_KDF* kdf;
    if ((kdf = EVP_KDF_fetch(NULL, "hkdf", NULL)) == NULL) {
        free(derivedKey);
        return NULL;
    }
    EVP_KDF_CTX* ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (ctx == NULL) {
        free(derivedKey);
        return NULL;
    }
    OSSL_PARAM params[4] = {
        OSSL_PARAM_construct_utf8_string("digest", "sha256", sizeof("sha256")),
        OSSL_PARAM_construct_octet_string("key", key, 32),
        OSSL_PARAM_construct_octet_string("info", context, contextLen),
        OSSL_PARAM_construct_end()
    };
    if (EVP_KDF_CTX_set_params(ctx, params) <= 0) {
        free(derivedKey);
        EVP_KDF_CTX_free(ctx);
        return NULL;
    }
    if (EVP_KDF_derive(ctx, derivedKey, outSize, NULL) <= 0) {
        free(derivedKey);
        EVP_KDF_CTX_free(ctx);
        return NULL;
    }
    EVP_KDF_CTX_free(ctx);
    return derivedKey;
}

/* Helper function to perform HKDF using OpenSSL */
__attribute__((visibility ("hidden"))) static int hkdf_extract_and_expand_helper(
    const uint8_t *salt, size_t salt_len,
    const uint8_t *key, size_t key_len,
    const uint8_t *info, size_t info_len,
    uint8_t *out, size_t out_len
) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!ctx) {
        NEO_AA_LogError("Failed to create HKDF context\n");
        OPENSSL_ERR_PRINT();
        return 0;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        NEO_AA_LogError("Failed to initialize HKDF context\n");
        OPENSSL_ERR_PRINT();
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0) {
        NEO_AA_LogError("Failed to set HKDF hash function\n");
        OPENSSL_ERR_PRINT();
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    if (salt && EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, salt_len) <= 0) {
        NEO_AA_LogError("Failed to set HKDF salt\n");
        OPENSSL_ERR_PRINT();
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(ctx, key, key_len) <= 0) {
        NEO_AA_LogError("Failed to set HKDF key\n");
        OPENSSL_ERR_PRINT();
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    if (EVP_PKEY_CTX_add1_hkdf_info(ctx, info, info_len) <= 0) {
        NEO_AA_LogError("Failed to set HKDF info\n");
        OPENSSL_ERR_PRINT();
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    if (EVP_PKEY_derive(ctx, out, &out_len) <= 0) {
        NEO_AA_LogError("Failed to derive HKDF output\n");
        OPENSSL_ERR_PRINT();
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    EVP_PKEY_CTX_free(ctx);
    return 1;
}

__attribute__((visibility ("hidden"))) int get_encoded_size(EVP_PKEY* pkey) {
    if (!pkey) {
        return 0;
    }
    OSSL_PARAM* params;
    if (!EVP_PKEY_todata(pkey, EVP_PKEY_PUBLIC_KEY, &params)) {
        OPENSSL_ERR_PRINT();
        return 0;
    }
    OSSL_PARAM* param = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (!param) {
        OPENSSL_ERR_PRINT();
        OSSL_PARAM_free(params);
        return 0;
    }
    size_t used;
    if (!OSSL_PARAM_get_octet_string(param, NULL, 0, &used)) {
        OPENSSL_ERR_PRINT();
        OSSL_PARAM_free(params);
        return 0;
    }
    OSSL_PARAM_free(params);
    return used;
}

__attribute__((visibility ("hidden"))) int serialize_pubkey(EVP_PKEY* pkey, uint8_t* buf, size_t len) {
    if (!pkey) {
        return 0;
    }
    OSSL_PARAM* params;
    if (!EVP_PKEY_todata(pkey, EVP_PKEY_PUBLIC_KEY, &params)) {
        OPENSSL_ERR_PRINT();
        return 0;
    }
    OSSL_PARAM* param = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (!param) {
        OPENSSL_ERR_PRINT();
        OSSL_PARAM_free(params);
        return 0;
    }
    size_t used;
    if (!OSSL_PARAM_get_octet_string(param, (void **)&buf, len, &used)) {
        OPENSSL_ERR_PRINT();
        OSSL_PARAM_free(params);
        return 0;
    }
    OSSL_PARAM_free(params);
    return used;
}

__attribute__((visibility ("hidden"))) uint8_t* calculate_hmac(
    uint8_t* key,
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
    void* hmac = hmac_derive(key, buf, bufSize, NULL, 0);
    free(buf);
    return hmac;
}

__attribute__((visibility ("hidden"))) uint8_t* decrypt_AES_256_CTR(uint8_t* key, uint8_t* data, size_t dataSize) {
    const EVP_CIPHER* cipher = EVP_aes_256_ctr();
    uint8_t* decrypted = malloc(dataSize);
    if (!decrypted) {
        NEO_AA_ErrorHeapAlloc();
        return NULL;
    }
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!EVP_DecryptInit_ex(ctx, cipher, NULL, &key[32], &key[64])) {
        OPENSSL_ERR_PRINT();
        EVP_CIPHER_CTX_free(ctx);
        free(decrypted);
        return 0;
    }
    int outl = dataSize;
    if (!EVP_DecryptUpdate(ctx, decrypted, &outl, data, dataSize)) {
        OPENSSL_ERR_PRINT();
        EVP_CIPHER_CTX_free(ctx);
        free(decrypted);
        return 0;
    }
    outl = dataSize - outl;
    if (!EVP_DecryptFinal(ctx, decrypted, &outl)) {
        OPENSSL_ERR_PRINT();
        EVP_CIPHER_CTX_free(ctx);
        free(decrypted);
        return 0;
    }
    EVP_CIPHER_CTX_free(ctx);
    return decrypted;
}

__attribute__((visibility ("hidden"))) uint8_t* get_password_key(
    uint8_t* password, size_t passwordLen, 
    uint8_t* salt, size_t saltLen,
    uint64_t hardness
) {
    uint8_t* out = malloc(32);
    if (!out) {
        NEO_AA_ErrorHeapAlloc();
        return NULL;
    }
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "SCRYPT", NULL);
    if (!kdf) {
        OPENSSL_ERR_PRINT();
        free(out);
        return NULL;
    }
    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!ctx) {
        OPENSSL_ERR_PRINT();
        free(out);
        return NULL;
    }
    uint32_t r = 8, p = 1;
    uint64_t n = hardness;
    OSSL_PARAM params[6] = {
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_PASSWORD, password, passwordLen),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, salt, saltLen),
        OSSL_PARAM_uint64(OSSL_KDF_PARAM_SCRYPT_N, &n),
        OSSL_PARAM_uint32(OSSL_KDF_PARAM_SCRYPT_R, &r),
        OSSL_PARAM_uint32(OSSL_KDF_PARAM_SCRYPT_P, &p),
        OSSL_PARAM_END
    };
    if (EVP_KDF_derive(ctx, out, 32, params) <= 0) {
        OPENSSL_ERR_PRINT();
        EVP_KDF_CTX_free(ctx);
        free(out);
        return NULL;
    }
    EVP_KDF_CTX_free(ctx);
    return out;
}

__attribute__((visibility ("hidden"))) void* main_key(
    NeoAEAArchive aea, 
    EVP_PKEY* senderPub, EVP_PKEY* recPriv, EVP_PKEY* sigPub, 
    uint8_t* symmKey, size_t symmKeySize
) {
    size_t len = 11 
                + get_encoded_size(senderPub) 
                + get_encoded_size(recPriv) 
                + get_encoded_size(sigPub), 
           off = 11;
    uint8_t *context = malloc(len),
            *mainKey = malloc(32);
    if (!context || !mainKey) {
        NEO_AA_ErrorHeapAlloc();
        return NULL;
    }
    strcpy((char *)context, MAIN_KEY_INFO);
    *(uint32_t *)&context[7] = aea->profileID; /* is actually an uint24_t */
    context[10] = aea->scryptStrength;
    if (senderPub) {
        int res = serialize_pubkey(senderPub, &context[off], len - off);
        if (!res) {
            NEO_AA_LogError("serialize_pubkey failed!\n");
            return NULL;
        }
        off += res;
    }
    if (recPriv) {
        int res = serialize_pubkey(recPriv, &context[off], len - off);
        if (!res) {
            NEO_AA_LogError("serialize_pubkey failed!\n");
            return NULL;
        }
        off += res;
    }
    if (sigPub) {
        int res = serialize_pubkey(sigPub, &context[off], len - off);
        if (!res) {
            NEO_AA_LogError("serialize_pubkey failed!\n");
            return NULL;
        }
        off += res;
    }
    if (!hkdf_extract_and_expand_helper(
            aea->keyDerivationSalt,  0x20, 
            (uint8_t *)symmKey, symmKeySize, 
            (uint8_t *)context, len, 
            mainKey, 32
        )) {
        free(context);
        free(mainKey);
        return NULL;
    }
    free(context);
    return mainKey;
}

__attribute__((visibility ("hidden"))) void* password_key(uint8_t* mainKey, size_t keySize) {
    return do_hkdf(SCRYPT_KEY_INFO, 10, mainKey, keySize);
}

__attribute__((visibility ("hidden"))) void* signature_encryption_key(uint8_t* mainKey, size_t keySize) {
    void* derivationKey = do_hkdf(SIGNATURE_ENCRYPTION_DERIVATION_KEY_INFO, 7, mainKey, 32);
    void* res = do_hkdf(SIGNATURE_ENCRYPTION_KEY_INFO, 8, derivationKey, keySize);
    free(derivationKey);
    return res;
}

__attribute__((visibility ("hidden"))) void* root_header_key(uint8_t* mainKey, size_t keySize) {
    return do_hkdf(ROOT_HEADER_ENCRYPTED_KEY_INFO, 8, mainKey, keySize);
}

__attribute__((visibility ("hidden"))) void* cluster_key(uint8_t* mainKey, int idx) {
    char context[10];
    strcpy(context, CLUSTER_KEY_INFO);
    *(int *)&context[6] = idx;
    return do_hkdf(context, 10, mainKey, 32);
}

__attribute__((visibility ("hidden"))) void* cluster_header_key(uint8_t* clusterKey, size_t keySize) {
    return do_hkdf(CLUSTER_KEY_MATERIAL_INFO, 8, clusterKey, keySize);
}

__attribute__((visibility ("hidden"))) void* segment_key(uint8_t* clusterKey, int idx, size_t keySize) {
    char context[10];
    strcpy(context, SEGMENT_KEY_INFO);
    *(int *)&context[6] = idx;
    return do_hkdf(context, 10, clusterKey, keySize);
}

__attribute__((visibility ("hidden"))) struct aea_segment_header new_partial_segment(uint8_t* decryptedSegment, int checksumAlgorithm) {
    size_t checksumSize = checksumSizes[checksumAlgorithm];
    struct aea_old_segment_header* tmp = (struct aea_old_segment_header*)decryptedSegment;
    struct aea_segment_header segment = {
        .originalSize = tmp->originalSize,
        .compressedSize = tmp->compressedSize
    };
    
    void *tmpBuf;
    if (!alloc_memcpy(&tmpBuf, &decryptedSegment[8], checksumSize)) {
        NEO_AA_ErrorHeapAlloc();
        return (struct aea_segment_header){0};
    }
    segment.hash = tmpBuf;

    /* to be initialized later */
    segment.segmentData = NULL;
    bzero(segment.segmentHMAC, 0x20);

    /* all fields initialized, return the segment */
    return segment;
}

__attribute__((visibility ("hidden"))) struct aea_cluster_header new_partial_cluster(uint8_t* decryptedCluster, uint8_t* segmentMACs, int numSegments, int checksumAlgorithm) {
    struct aea_cluster_header cluster = (struct aea_cluster_header){0},
        errorCluster = cluster;
    size_t segmentHeaderSize = checksumSizes[checksumAlgorithm] + 8;
    cluster.segments = malloc(numSegments * sizeof(struct aea_segment_header));
    if (!cluster.segments) {
        NEO_AA_ErrorHeapAlloc();
        return errorCluster;
    }
    struct aea_segment_header emptySegment = (struct aea_segment_header){0};
    for (int i = 0; i < numSegments; i++) {
        struct aea_segment_header segment = new_partial_segment(decryptedCluster, checksumAlgorithm);
        if (!memcmp(&segment, &emptySegment, sizeof(struct aea_segment_header))) {
            // TODO: MEMORY LEAK: free segment
            return errorCluster;
        }
        decryptedCluster += segmentHeaderSize;
        cluster.segments[i] = segment;
    }
    memcpy(cluster.nextClusterHMAC, segmentMACs, 0x20);
    segmentMACs += 0x20;
    for (int i = 0; i < numSegments; i++) {
        struct aea_segment_header* segment = &cluster.segments[i];
        memcpy(segment->segmentHMAC, segmentMACs, 0x20);
        segmentMACs += 0x20;
    }
    // all field initialized, return cluster
    return cluster;
}

NeoAEAArchive neo_aea_archive_with_encoded_data_nocopy(uint8_t *encodedData, size_t encodedDataSize) {
    NEO_AA_NullParamAssert(encodedData);
    NeoAEAArchive aea = calloc(1, sizeof(struct aea_archive));
    if (!aea) {
        NEO_AA_ErrorHeapAlloc();
        return 0;
    }
    memcpy(aea, encodedData, 12);
    uint8_t *buf = encodedData + 12;
    void *data = NULL;
    if (!alloc_memcpy(&data, buf, aea->authDataSize)) {
	    free(aea);
        return NULL;
    }
    aea->authData = data;
    buf += aea->authDataSize;
    size_t size;
    switch (aea->profileID) {
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
        free(aea);
        return NULL;
    }
    aea->signature = data;
    buf += size;
    switch (aea->profileID) {
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
        free(aea);
        return NULL;
    };
    aea->profileDependent = data;
    buf += size;
    memcpy((char *)aea + offsetof(struct aea_archive, keyDerivationSalt), buf, 0x90);
    buf += 0x90;
    aea->clusterDataLen = encodedDataSize - (buf - encodedData);
    // EXPENSIVE: copies all clusters
    if (IS_ENCRYPTED(aea->profileID)) {
        if (!alloc_memcpy(&data, buf, aea->clusterDataLen)) {
            free(aea);
            return NULL;
        }
        aea->encryptedClusters = data;
        aea->isEncrypted = true;
    } else {
        aea->isEncrypted = false;
        struct aea_root_header* rootHeader = &aea->rootHeader;
        size_t off = 0, 
               clusterSize = sizeof(struct aea_cluster_header) * 10, 
               segmentHeaderSize = 8 + checksumSizes[rootHeader->checksumAlgorithm];
        int i = 0;
        aea->clusters = malloc(clusterSize);
        if (!aea->clusters) {
            NEO_AA_ErrorHeapAlloc();
            free(aea);
            return NULL;
        }
        aea->innerDataLen = 0;
        // no known number of clusters, so iterate until we reach the end
        while (off < aea->clusterDataLen) {
            // make new cluster struct (data field in segments not filled in)
            struct aea_cluster_header cluster = new_partial_cluster(
                &buf[off], 
                &buf[off + (segmentHeaderSize * rootHeader->segmentsPerCluster)], 
                rootHeader->segmentsPerCluster, 
                rootHeader->checksumAlgorithm
            );
            off += segmentHeaderSize * rootHeader->segmentsPerCluster  // segment headers
                +  0x20 * (1 + rootHeader->segmentsPerCluster); // HMACs
            
            for (size_t j = 0; j < rootHeader->segmentsPerCluster; j++) {
                struct aea_segment_header* segment = &cluster.segments[j];
                // EXPENSIVE -- up to 1 MB copied per segment!
                void* tmp;
                alloc_memcpy(&tmp, &buf[off], segment->compressedSize);
                segment->segmentData = tmp;
                // all fields in segment are now fully setup, we can move to next segment
                off += segment->compressedSize; // segment data
                aea->innerDataLen += segment->originalSize;
            }
            aea->clusters[i++] = cluster;
            if (i == (clusterSize / sizeof(struct aea_cluster_header))) {
                clusterSize *= 2;
                aea->clusters = realloc(aea->clusters, clusterSize);
                if (!aea->clusters) {
                    NEO_AA_ErrorHeapAlloc();
                    free(aea);
                    return NULL;
                }
            }
            // off == next cluster header offset
        }
        aea->numClusters = i;
    }
    return aea;
}

NeoAEAArchive neo_aea_archive_with_encoded_data(uint8_t *encodedData, size_t encodedDataSize) {
    NEO_AA_NullParamAssert(encodedData);
    uint8_t *encodedDataCopy = malloc(encodedDataSize);
    if (!encodedDataCopy) {
        NEO_AA_ErrorHeapAlloc();
        return 0;
    }
    memcpy(encodedDataCopy, encodedData, encodedDataSize);
    NeoAEAArchive aea = neo_aea_archive_with_encoded_data_nocopy(encodedDataCopy, encodedDataSize);
    if (!aea) {
        free(encodedDataCopy);
        return NULL;
    }
    return aea;
}

NeoAEAArchive neo_aea_archive_with_path(const char *path) {
    NEO_AA_NullParamAssert(path);
    if (strlen(path) > 1024) {
        NEO_AA_LogError("path should not exceed 1024 characters\n");
        return 0;
    }
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        NEO_AA_LogError("failed to open path\n");
        return 0;
    }
    fseek(fp, 0, SEEK_END);
    size_t encodedDataSize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    uint8_t *encodedData = malloc(encodedDataSize);
    /* copy bytes to buffer */
    size_t bytesRead = fread(encodedData, 1, encodedDataSize, fp);
    if (bytesRead < encodedDataSize) {
        fclose(fp);
        free(encodedData);
        NEO_AA_LogError("failed to read the file\n");
        return 0;
    }
    fclose(fp);
    NeoAEAArchive aea = neo_aea_archive_with_encoded_data_nocopy(encodedData, encodedDataSize);
    if (!aea) {
        free(encodedData);
        return NULL;
    }
    return aea;
}

// Cluster Decryption Routine
/* 
    During the execution of this function,
    There is a possibility to use memory that is ~2x the file size
    (one copy of the encrypted data, another of the decrypted)
    Parallelization of decryption is possible given segment sizes
        are precomputed beforehand.
*/
__attribute__((visibility ("hidden"))) int decrypt_clusters(NeoAEAArchive aea, uint8_t* mainKey, struct aea_root_header* rootHeader, size_t segmentHeaderSize) {
    uint8_t* encryptedClusters = aea->encryptedClusters;
    size_t keySize = aea->profileID == NEO_AEA_PROFILE_HKDF_SHA256_HMAC_NONE_ECDSA_P256 ? 32 : 80;
    size_t off = 0, 
           clusterSize = sizeof(struct aea_cluster_header) * 10,
           clusterDataLen = aea->clusterDataLen;
    int i = 0, isFinal = 0;
    aea->clusters = malloc(clusterSize);
    if (!aea->clusters) {
        NEO_AA_ErrorHeapAlloc();
        return 0;
    }
    aea->innerDataLen = 0;
    // no known number of clusters, so iterate until we reach the end
    while (off < clusterDataLen) {
        uint8_t* clusterKey = cluster_key(mainKey, i);

#ifdef DEBUG
        printf("clusterKey %d:\n", i);
        DumpHex(clusterKey, 32);
#endif

        // decrypt current cluster
        uint8_t* clusterHeaderKey = cluster_header_key(clusterKey, keySize);
#ifdef DEBUG
        printf("clusterHeaderKey %d:\n", i);
        DumpHex(clusterHeaderKey, keySize);
#endif
        uint8_t* decryptedCluster = decrypt_AES_256_CTR(
            clusterHeaderKey, 
            &encryptedClusters[off], 
            segmentHeaderSize * rootHeader->segmentsPerCluster
        );
        free(clusterHeaderKey);

        // make new cluster struct (data field in segments not filled in)
        struct aea_cluster_header cluster = new_partial_cluster(
            decryptedCluster, 
            &encryptedClusters[off + (segmentHeaderSize * rootHeader->segmentsPerCluster)], 
            rootHeader->segmentsPerCluster, 
            rootHeader->checksumAlgorithm
        );
        off += segmentHeaderSize * rootHeader->segmentsPerCluster  // segment headers
            +  0x20 * (1 + rootHeader->segmentsPerCluster); // HMACs
        free(decryptedCluster); // already copied into the cluster struct, no longer required
        
        for (size_t j = 0; j < rootHeader->segmentsPerCluster; j++) {
            struct aea_segment_header *segment = &cluster.segments[j];
            if (!segment->compressedSize) {
                isFinal = 1;
                break;
            }
            uint8_t *segmentKey = segment_key(clusterKey, j, keySize);
#ifdef DEBUG
            printf("segmentKey %zu:\n", j);
            DumpHex(segmentKey, keySize);
#endif
            // EXPENSIVE -- up to 1 MB copied and decrypted per segment!
            uint8_t *decryptedSegment = decrypt_AES_256_CTR(
                segmentKey, 
                &encryptedClusters[off], 
                segment->compressedSize
            );
            free(segmentKey);
            if (!decryptedSegment) {
                free(aea->clusters); // TODO: MEMORY LEAK: free all other segments too
                aea->encryptedClusters = encryptedClusters;
                return 0;
            }
            // direct assignment because the whole decrypted memory belongs to this single segment
            segment->segmentData = decryptedSegment;
            // all fields in segment are now fully setup, we can move to next segment
            off += segment->compressedSize; // segment data
            aea->innerDataLen += segment->originalSize;
        }
        free(clusterKey);
        aea->clusters[i++] = cluster;
        if (isFinal) {
            break;
        }
        if (i == (clusterSize / sizeof(struct aea_cluster_header))) {
            clusterSize *= 2;
            void *tmp = realloc(aea->clusters, clusterSize);
            if (!tmp) {
                NEO_AA_ErrorHeapAlloc();
                free(aea->clusters); // TODO: MEMORY LEAK: free all other segments too
                aea->encryptedClusters = encryptedClusters;
                return 0;
            }
            aea->clusters = tmp;
        }
        // off == next cluster header offset
    }
    aea->numClusters = i;
    free(encryptedClusters); // free encrypted clusters to not waste any more memory holding it
    // now we should only be using memory that's the same size as the file size
    aea->isEncrypted = false;
    return 1;
}

/*
 * neo_aea_archive_extract_data
 *
 * Extracts data from the AEA.
 * This does not validate signing.
 */
uint8_t *neo_aea_archive_extract_data(
    NeoAEAArchive aea, 
    size_t *size, 
    EVP_PKEY* recPriv,
    EVP_PKEY* signaturePub,
    uint8_t* symmKey, size_t symmKeySize,
    uint8_t* password, size_t passwordSize
) {
    /* TODO:
       * support other compression algorithms (lz4, lzvn, lzma)
       * unit tests for all of these functions to make sure they work
       * more abstraction to make it easier to understand
       * etc...
     */
    NEO_AA_NullParamAssert(aea);

    size_t keySize = aea->profileID == NEO_AEA_PROFILE_HKDF_SHA256_HMAC_NONE_ECDSA_P256 ? 32 : 80;
    EVP_PKEY* senderPub = NULL;
    if (aea->profileID == NEO_AEA_PROFILE_HKDF_SHA256_HMAC_NONE_ECDSA_P256) {
        symmKey = aea->profileDependent;
        if (!symmKey) {
            NEO_AA_LogError("No symmKey in AEA file\n");
            return NULL;
        }
    } else if (HAS_SYMMETRIC_ENCRYPTION(aea->profileID)) {
        if (!symmKey || symmKeySize != 32) {
            NEO_AA_LogError("Invalid symmKey specified\n");
            return NULL;
        }
    } else if (HAS_ASYMMETRIC_ENCRYPTION(aea->profileID)) {
        if (!recPriv) {
            NEO_AA_LogError("Recipient private key not specified\n");
            return NULL;
        }
        /* parse the X9.63 ECDSA-P256 key */
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	    if (ctx == NULL) {
	    	NEO_AA_LogError("failed to create EVP_PKEY_CTX object\n");
            OPENSSL_ERR_PRINT();
            return NULL;
	    }
    
        if (!EVP_PKEY_fromdata_init(ctx)) {
            NEO_AA_LogError("failed to initialize context\n");
            OPENSSL_ERR_PRINT();
            EVP_PKEY_CTX_free(ctx);
            return NULL;
        }
    
        OSSL_PARAM params[3] = {
            OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, SN_X9_62_prime256v1, 0),
            OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, aea->profileDependent, 1 + 64),
            OSSL_PARAM_END
        };
    
        if (EVP_PKEY_fromdata(ctx, &senderPub, EVP_PKEY_KEYPAIR, params) <= 0) { // TODO: MEMORY LEAK
            NEO_AA_LogError("failed to create EVP_PKEY object\n");
            OPENSSL_ERR_PRINT();
            EVP_PKEY_CTX_free(ctx);
            return NULL;
        }

        EVP_PKEY_CTX_free(ctx);
        ctx = EVP_PKEY_CTX_new(recPriv, NULL);
        if (!ctx) {
            OPENSSL_ERR_PRINT();
            return NULL;
        }
        symmKey = malloc(32); // TODO: MEMORY LEAK
        symmKeySize = 0x20;
        if (!symmKey) {
            NEO_AA_ErrorHeapAlloc();
            EVP_PKEY_CTX_free(ctx);
            return NULL;
        }
        if ((EVP_PKEY_derive_init(ctx) <= 0)
          || (EVP_PKEY_derive_set_peer(ctx, senderPub) <= 0)
          || (EVP_PKEY_derive(ctx, symmKey, &symmKeySize) <= 0)) {
            NEO_AA_LogError("Cannot derive symmKey\n");
            OPENSSL_ERR_PRINT();
            free(symmKey);
            EVP_PKEY_free(senderPub);
            EVP_PKEY_CTX_free(ctx);
            return NULL;
        }
        EVP_PKEY_CTX_free(ctx);
    } else if (HAS_PASSWORD_ENCRYPTION(aea->profileID)) {
        if (!password || !passwordSize) {
            NEO_AA_LogError("Password not specified\n");
            return NULL;
        }
        uint8_t* extendedSalt = password_key(aea->keyDerivationSalt, keySize);
        if (!extendedSalt) {
            NEO_AA_LogError("Could not get extendedSalt\n");
            return NULL;
        }
#ifdef DEBUG
        printf("extendedSalt:\n");
        DumpHex(extendedSalt, 0x40);
#endif
        memcpy(aea->keyDerivationSalt, &extendedSalt[32], 0x20);
        symmKey = get_password_key(password, passwordSize, extendedSalt, 32, (uint64_t)0x4000 << (aea->scryptStrength << 1));
        if (!symmKey) {
            NEO_AA_LogError("Could not derive symmKey from password\n");
            free(extendedSalt);
            return NULL;
        }
        free(extendedSalt);
    }

    symmKeySize = 0x20;
#ifdef DEBUG
    printf("symmKey:\n");
    DumpHex(symmKey, symmKeySize);
#endif

    if (!IS_SIGNED(aea->profileID)) {
        // have to do this to not mess with mainKey
        signaturePub = NULL;
    } else if (!signaturePub && aea->profileID != NEO_AEA_PROFILE_HKDF_SHA256_HMAC_NONE_ECDSA_P256) {
        // TODO: explain why exactly profile 0 doesn't need the signaturePub to derive the mainKey
        NEO_AA_LogError("Signing public key not specified\n");
        if (HAS_ASYMMETRIC_ENCRYPTION(aea->profileID)) {
            free(symmKey);
        }
        if (senderPub) {
            EVP_PKEY_free(senderPub);
        }
        return NULL;
    }

    uint8_t *mainKey = NULL;

    /* Calculate Root Header Key (AEA_RHEK) */
    if (aea->isEncrypted) {
        /* Calculate Main Key (AEA_AMK) */
        mainKey = main_key(
            aea, 
            senderPub, recPriv, signaturePub, 
            symmKey, symmKeySize
        );
        if (senderPub) {
            EVP_PKEY_free(senderPub);
        }
        if (!mainKey) {
            return NULL;
        }
#ifdef DEBUG
        printf("mainKey:\n");
        DumpHex(mainKey, 32);
#endif

        uint8_t* rootHeaderKey = root_header_key(mainKey, keySize);
        if (!rootHeaderKey) {
            if (HAS_ASYMMETRIC_ENCRYPTION(aea->profileID)) {
                free(symmKey);
            }
            return NULL;
        }
#ifdef DEBUG
        printf("rootHeaderKey:\n");
        DumpHex(rootHeaderKey, keySize);
#endif
        uint8_t* decrypted = decrypt_AES_256_CTR(rootHeaderKey, aea->encryptedRootHeader, 0x30);
        memcpy(
            &aea->encryptedRootHeader[0], 
            decrypted,
            0x30
        );
        free(rootHeaderKey);
        free(decrypted);
    }

    /* Check Root Header */
    struct aea_root_header* rootHeader = &aea->rootHeader;
    char compressionAlgo = rootHeader->compressionAlgorithm;
    if (rootHeader->checksumAlgorithm != 2) {
        NEO_AA_LogError("Non-SHA256 checksum not yet supported\n");
        if (HAS_ASYMMETRIC_ENCRYPTION(aea->profileID)) {
            free(symmKey);
        }
        return NULL;
    }

    if (aea->isEncrypted) {
        /* EXPENSIVE:
         * Decrypts every cluster and segment in the file and
         * creates new structs for each of them in order to
         * parse them in the right format
         */
        if (!decrypt_clusters(aea, mainKey, rootHeader, 8 + checksumSizes[rootHeader->checksumAlgorithm])) {
            NEO_AA_LogError("Failed to decrypt clusters\n");
            if (HAS_ASYMMETRIC_ENCRYPTION(aea->profileID)) {
                free(symmKey);
            }
            free(mainKey);
            return NULL;
        }
        free(mainKey);
    }

    if (HAS_ASYMMETRIC_ENCRYPTION(aea->profileID)) {
        free(symmKey);
    }
    // use aea->clusters, aea->numClusters and aea->innerDataLen from now on, as they are now decrypted and set

    uint8_t *aeaData = malloc(aea->innerDataLen); // TODO: MEMORY LEAK
    if (!aeaData) {
        NEO_AA_ErrorHeapAlloc();
        return NULL;
    }
    size_t dataOffset = 0, outBufferSize = 0;
    for (size_t i = 0; i < aea->numClusters; i++) {
        struct aea_segment_header *segmentHeaders = aea->clusters[i].segments;
        /* Get data (segment 0 decompressed data + segment 1 decompressed data + etc...) */
        for (uint32_t j = 0; j < rootHeader->segmentsPerCluster; j++) {
            struct aea_segment_header* curSegmentHeader = &segmentHeaders[j];
            if (curSegmentHeader->compressedSize == 0) {
                // empty segments, no more data to decompress
                goto end;
            }
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
             * Uncompressed data is '-'
             * However, even if the cluster follows a specific
             * compression algorithm, segments that have a 
             * larger size when compressed are stored uncompressed.
             */
            if ((compressionAlgo == NEO_AEA_COMPRESSION_NONE) || curSegmentHeader->compressedSize == curSegmentHeader->originalSize) {
                /* No compression */
                decompressedBytes = curSegmentHeader->compressedSize;
                /* copy entire segment data buffer to aeaData */
                memcpy(
                    &aeaData[dataOffset], 
                    curSegmentHeader->segmentData, 
                    curSegmentHeader->compressedSize
                );
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
                    NEO_AA_LogError("Failed to decompress LZFSE data\n");
                    free(aeaData);
                    return NULL;
                }
            } else if (compressionAlgo == NEO_AEA_COMPRESSION_LZBITMAP) {
                size_t unused;
                (void)unused;
                if (zbm_decompress(
                    &aeaData[dataOffset],
                    curSegmentHeader->originalSize, 
                    curSegmentHeader->segmentData,
                    curSegmentHeader->compressedSize,
                    &unused
                ) < 0) {
                    NEO_AA_LogError("Failed to decompress LZBITMAP data\n");
                    free(aeaData);
                    return NULL;
                }
            } else if (compressionAlgo == NEO_AEA_COMPRESSION_ZLIB) {
                size_t originalSize = curSegmentHeader->originalSize;
                if (uncompress(
                    &aeaData[dataOffset],
                    &originalSize,
                    curSegmentHeader->segmentData,
                    curSegmentHeader->compressedSize
                )) {
                    NEO_AA_LogError("Failed to decompress ZLIB data\n");
                    free(aeaData);
                    return NULL;
                }
            } else {
                /* Not yet supported */
                NEO_AA_LogErrorF("Compression algorithm '%c' not yet supported\n", compressionAlgo);
                free(aeaData);
                return NULL;
            }
            dataOffset += curSegmentHeader->originalSize;
            outBufferSize += decompressedBytes;
        }
    }   
end:
    if (size) {
        *size = outBufferSize;
    }
    return aeaData;
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
    uint8_t *encodedAppleArchive = neo_aea_archive_extract_data(aea, &aarSize, NULL, 0, NULL, 0, NULL, 0);
    if (encodedAppleArchive) {
        NEO_AA_LogError("could not extract data from aea\n");
        return 0;
    }
    return neo_aa_archive_plain_create_with_encoded_data(aarSize, encodedAppleArchive);
}

uint32_t neo_aea_archive_profile(NeoAEAArchive aea) {
    NEO_AA_NullParamAssert(aea);
    return aea->profileID;
}

uint8_t *neo_aea_archive_auth_data(NeoAEAArchive aea, uint32_t *authDataSize) {
    NEO_AA_NullParamAssert(aea);
    if (authDataSize) {
        *authDataSize = aea->authDataSize;
    }
    return aea->authData;
}

void neo_aea_archive_destroy(NeoAEAArchive aea) {
    NEO_AA_NullParamAssert(aea);
    if (aea->authData) {
        free(aea->authData);
    }
    if (aea->signature) {
        free(aea->signature);
    }
    if (aea->profileDependent) {
        free(aea->profileDependent);
    }
    if (aea->isEncrypted) {
        if (aea->encryptedClusters) {
            free(aea->encryptedClusters);
            aea->encryptedClusters = NULL;
        }
    } else if (aea->clusters) {
        for (size_t i = 0; i < aea->numClusters; i++) {
            struct aea_cluster_header cluster = aea->clusters[i];
            struct aea_root_header rootHeader = aea->rootHeader;
            for (uint32_t j = 0; j < rootHeader.segmentsPerCluster; j++) {
                struct aea_segment_header segment = cluster.segments[j];
                if (segment.hash) {
                    free(segment.hash);
                }
                if (segment.segmentData) {
                    free(segment.segmentData);
                }
            }
            free(cluster.segments);
        }
        free(aea->clusters);
    }
    free(aea);
}

/*
 * neo_aea_archive_verify
 *
 * Verifies the ECDSA-P256 signature, as well as
 * HKDF / HMAC verification. If valid, it will
 * return 0. If not or an error occours, it returns -1.
 *
 * TODO: HKDF / HMAC verification not yet done.
 * TODO: Only supports profile 0.
 */
int neo_aea_archive_verify(NeoAEAArchive aea, uint8_t *publicKey) {
    NEO_AA_NullParamAssert(aea);

    if (aea->profileID != NEO_AEA_PROFILE_HKDF_SHA256_HMAC_NONE_ECDSA_P256) {
        NEO_AA_LogError("Verification only supported for profile 0 (ECDSA-P256)\n");
        return 0;
    }

    if (aea->authDataSize == 0 || aea->signature == NULL) {
        NEO_AA_LogError("Invalid authDataSize or signature\n");
        return 0;
    }

    /* Verify public key format */
    if (!publicKey || publicKey[0] != 0x04) {
        NEO_AA_LogError("Invalid public key format: must be uncompressed X9.63 (65 bytes, starting with 0x04)\n");
        return 0;
    }

    /* Create an EVP_PKEY context for the public key */
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!ctx) {
        OPENSSL_ERR_PRINT();
        return 0;
    }

    /* Initialize the context for key creation */
    if (EVP_PKEY_fromdata_init(ctx) <= 0) {
        OPENSSL_ERR_PRINT();
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    /* Build the parameters for the public key */
    OSSL_PARAM_BLD *param_bld = OSSL_PARAM_BLD_new();
    if (!param_bld) {
        OPENSSL_ERR_PRINT();
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    /* Set the curve name (secp256r1) */
    if (!OSSL_PARAM_BLD_push_utf8_string(param_bld, OSSL_PKEY_PARAM_GROUP_NAME, SN_X9_62_prime256v1, 0)) {
        OPENSSL_ERR_PRINT();
        OSSL_PARAM_BLD_free(param_bld);
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    /* Set the public key */
    if (!OSSL_PARAM_BLD_push_octet_string(param_bld, OSSL_PKEY_PARAM_PUB_KEY, publicKey, 65)) {
        OPENSSL_ERR_PRINT();
        OSSL_PARAM_BLD_free(param_bld);
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    /* Convert the parameter builder to parameters */
    OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(param_bld);
    if (!params) {
        OPENSSL_ERR_PRINT();
        OSSL_PARAM_BLD_free(param_bld);
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    /* Create the EVP_PKEY object from the parameters */
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        OPENSSL_ERR_PRINT();
        OSSL_PARAM_free(params);
        OSSL_PARAM_BLD_free(param_bld);
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    /* Free the parameter builder and parameters */
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(param_bld);
    EVP_PKEY_CTX_free(ctx);

    /* Create a digest context for verification */
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        OPENSSL_ERR_PRINT();
        EVP_PKEY_free(pkey);
        return 0;
    }

    /* Initialize the digest context for verification */
    if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
        OPENSSL_ERR_PRINT();
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return 0;
    }

    /* Create prologue copy to check */
    size_t prologueSize = 0x13c + aea->authDataSize;
    uint8_t *prologueCopy = malloc(prologueSize);
    memcpy(prologueCopy, aea, 12);
    memcpy(prologueCopy + 12, aea->authData, aea->authDataSize);
    /* Prologue copy should have 0'd out signature */
    memset(prologueCopy + 12 + aea->authDataSize, 0, 128);
    memcpy(prologueCopy + 12 + aea->authDataSize + 128, aea->profileDependent, 32);
    memcpy(prologueCopy + 12 + aea->authDataSize + 128 + 32, (uint8_t *)aea + offsetof(struct aea_archive, keyDerivationSalt), 0x90);

    /* Update the digest context with the prologue data */
    if (EVP_DigestVerifyUpdate(md_ctx, prologueCopy, prologueSize) <= 0) {
        OPENSSL_ERR_PRINT();
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        free(prologueCopy);
        return 0;
    }

    /* Parse asn1 signature */
    int asn1len = ecdsa_p256_signature_asn1_len(aea->signature, 128);
    if (!asn1len) {
        NEO_AA_LogError("Failed to parse ASN.1");
        return 0;
    }

    /* Finalize the verification */
    int result = EVP_DigestVerifyFinal(md_ctx, aea->signature, asn1len);

    /* Clean up */
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    free(prologueCopy);

    if (result != 1) {
        if (result == 0) {
            return -1;
        } else {
            OPENSSL_ERR_PRINT();
            return -1;
        }
    }

    /* TODO: This code sucks ass. */
    size_t keySize = aea->profileID == NEO_AEA_PROFILE_HKDF_SHA256_HMAC_NONE_ECDSA_P256 ? 32 : 80;

    /* Prepare HKDF context */
    const uint8_t *salt = (uint8_t *)aea + offsetof(struct aea_archive, keyDerivationSalt);
    const uint8_t *keyDerivationKey = aea->profileDependent; /* 32-byte key, 65 on profile 3/4 */
    size_t keyDerivationKeySize;
    if (aea->profileID == NEO_AEA_PROFILE_HKDF_SHA256_HMAC_NONE_ECDSA_P256) {
        keyDerivationKeySize = 32;
    } else if (aea->profileID == NEO_AEA_PROFILE_HKDF_SHA256_AESCTR_HMAC_ECDHE_P256_NONE) {
        keyDerivationKeySize = 65;
    } else if (aea->profileID == NEO_AEA_PROFILE_HKDF_SHA256_AESCTR_HMAC_ECDHE_P256_ECDSA_P256) {
        keyDerivationKeySize = 65;
    } else {
        keyDerivationKeySize = 0;
    }
    uint8_t context[0x4c] = {0};
    memcpy(context, "AEA_AMK", 7);
    memcpy(context + 11, publicKey, 0x41); 

    /* Derive key using OpenSSL HKDF */
    uint8_t mainKey[32];
    if (!hkdf_extract_and_expand_helper(salt, 32, keyDerivationKey, keyDerivationKeySize, context, sizeof(context), mainKey, 32)) {
        fprintf(stderr, "HKDF derivation failed\n");
        return -1;
    }

    void *aea_rhek_ctx[8];
    memcpy(aea_rhek_ctx, "AEA_RHEK", 8);
    void *rhekKey = do_hkdf(aea_rhek_ctx, 8, mainKey, keySize);
    if (!rhekKey) {
        NEO_AA_LogError("malloc failed\n");
        return -1;
    }
    size_t authDataSize = aea->authDataSize;
    uint8_t *chekPlusAuthData = malloc(authDataSize + 32);
    memcpy(chekPlusAuthData, (uint8_t *)aea + offsetof(struct aea_archive, cluster0HeaderHMAC), 32);
    memcpy(chekPlusAuthData + 32, aea->authData, authDataSize);

    if (hmac_verify(rhekKey, (uint8_t *)aea + offsetof(struct aea_archive, rootHeader), 0x30, chekPlusAuthData, authDataSize + 32, (uint8_t *)aea + offsetof(struct aea_archive, rootHeaderHMAC))) {
        free(rhekKey);
        free(chekPlusAuthData);
        NEO_AA_LogError("AEA_RHEK hmac failed\n");
        return -1;
    }
    free(rhekKey);
    free(chekPlusAuthData);
    /*
     * AEA_RHEK hmac is valid!
     * We are past the validation that libAppleArchive's
     * AEADecryptionInputStreamOpen does. However, now we
     * need to replicate the rest of the checks, which are
     * done when AAArchiveStreamProcess is called.
     */
    return 0;
}

/*
 * neo_aa_archive_plain_with_neo_aea_archive_verify
 *
 * Verifies the ECDSA-P256 signature, as well as
 * HKDF / HMAC verification. If valid, it will
 * get the NeoAAArchivePlain from the NeoAEAArchive.
 * If you want to extract without validation, use
 * neo_aa_archive_plain_with_neo_aea_archive. If
 * You only want to verify, use neo_aea_archive_verify.
 */
NeoAAArchivePlain neo_aa_archive_plain_with_neo_aea_archive_verify(NeoAEAArchive aea, uint8_t *publicKey) {
    if (neo_aea_archive_verify(aea, publicKey)) {
        return neo_aa_archive_plain_with_neo_aea_archive(aea);
    }
    return 0;
}
