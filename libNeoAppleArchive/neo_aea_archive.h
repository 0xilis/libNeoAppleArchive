
/*
 *  neo_aea_archive.h
 *  libNeoAppleArchive
 *
 *  Created by Snoolie Keffaber on 2024/05/07.
 */

#ifndef libNeoAppleArchive_h
#error Include libNeoAppleArchive.h instead of this file
#endif

/*
 * Only NEO_AEA_PROFILE_HKDF_SHA256_HMAC_NONE_ECDSA_P256 is supported ATM.
 * NEO_AEA_PROFILE_HKDF_SHA256_AESCTR_HMAC_SYMMETRIC_NONE has plans to be
 * supported in the future as OTA/IPSWs use it.
 */

#ifndef neo_aea_archive_h
#define neo_aea_archive_h

#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdbool.h>

#define OPENSSL_ERR_PRINT() fprintf(stderr, "OpenSSL Error at %s in %s:%d: \n", __func__, __FILE__, __LINE__); ERR_print_errors_fp(stderr)

/* Different types of AEA, should be same as AEAProfiles definition */
typedef enum {
    NEO_AEA_PROFILE_HKDF_SHA256_HMAC_NONE_ECDSA_P256 = 0,
    NEO_AEA_PROFILE_HKDF_SHA256_AESCTR_HMAC_SYMMETRIC_NONE = 1,
    NEO_AEA_PROFILE_HKDF_SHA256_AESCTR_HMAC_SYMMETRIC_ECDSA_P256 = 2,
    NEO_AEA_PROFILE_HKDF_SHA256_AESCTR_HMAC_ECDHE_P256_NONE = 3,
    NEO_AEA_PROFILE_HKDF_SHA256_AESCTR_HMAC_ECDHE_P256_ECDSA_P256 = 4,
    NEO_AEA_PROFILE_HKDF_SHA256_AESCTR_HMAC_SCRYPT_NONE = 5,
} NeoAEAProfile;

typedef enum {
    NEO_AEA_COMPRESSION_NONE = '-',
    NEO_AEA_COMPRESSION_LZ4 = '4',
    NEO_AEA_COMPRESSION_LZBITMAP = 'b',
    NEO_AEA_COMPRESSION_LZFSE = 'e',
    NEO_AEA_COMPRESSION_LZVN = 'f',
    NEO_AEA_COMPRESSION_LZMA = 'x',
    NEO_AEA_COMPRESSION_ZLIB = 'z',
} NeoAEACompressionTypes;

#define MAIN_KEY_INFO                            "AEA_AMK"
#define ROOT_HEADER_ENCRYPTED_KEY_INFO           "AEA_RHEK"
#define CLUSTER_KEY_INFO                         "AEA_CK"
#define CLUSTER_KEY_MATERIAL_INFO                "AEA_CHEK"
#define SCRYPT_KEY_INFO                          "AEA_SCRYPT"
#define SEGMENT_KEY_INFO                         "AEA_SK"
#define SIGNATURE_ENCRYPTION_DERIVATION_KEY_INFO "AEA_SEK"
#define SIGNATURE_ENCRYPTION_KEY_INFO            "AEA_SEK2"
#define PADDING_KEY_INFO                         "AEA_PAK"

static int checksumSizes[3] = {
    0, // None
    8, // Murmur64
    0x20 // SHA-256
};

#define IS_ENCRYPTED(x) (x != NEO_AEA_PROFILE_HKDF_SHA256_HMAC_NONE_ECDSA_P256)
#define IS_SIGNED(x) ((x == NEO_AEA_PROFILE_HKDF_SHA256_HMAC_NONE_ECDSA_P256) \
                   || (x == NEO_AEA_PROFILE_HKDF_SHA256_AESCTR_HMAC_SYMMETRIC_ECDSA_P256) \
                   || (x == NEO_AEA_PROFILE_HKDF_SHA256_AESCTR_HMAC_ECDHE_P256_ECDSA_P256))
#define HAS_SYMMETRIC_ENCRYPTION(x) ((x == NEO_AEA_PROFILE_HKDF_SHA256_AESCTR_HMAC_SYMMETRIC_NONE) \
                                  || (x == NEO_AEA_PROFILE_HKDF_SHA256_AESCTR_HMAC_SYMMETRIC_ECDSA_P256))
#define HAS_ASYMMETRIC_ENCRYPTION(x) ((x == NEO_AEA_PROFILE_HKDF_SHA256_AESCTR_HMAC_ECDHE_P256_NONE) \
                                   || (x == NEO_AEA_PROFILE_HKDF_SHA256_AESCTR_HMAC_ECDHE_P256_ECDSA_P256))
#define HAS_PASSWORD_ENCRYPTION(x) (x == NEO_AEA_PROFILE_HKDF_SHA256_AESCTR_HMAC_SCRYPT_NONE)

struct __attribute__((packed)) aea_root_header {
    uint64_t originalFileSize;
    uint64_t encryptedFileSize;
    uint32_t segmentSize;
    uint32_t segmentsPerCluster;
    uint8_t compressionAlgorithm;
    uint8_t checksumAlgorithm;
    uint8_t reserved[22];
};

struct aea_cluster_header {
    // size: rootHeader->segmentsPerCluster
    struct aea_segment_header* segments;
    uint8_t nextClusterHMAC[0x20];
};

struct aea_segment_header {
    uint32_t originalSize;
    uint32_t compressedSize;
    /* size: based on rootHeader.checksumAlgorithm
       0 for checksumAlgorithm 0
       8 for checksumAlgorithm 1 (Murmur64 Hash)
       32 for checksumAlgorithm 2 (SHA-256)
     */
    uint8_t* hash;
    uint8_t segmentHMAC[0x20];
    // size: compressedSize
    uint8_t* segmentData;
};



/* Do not manually access items of aea_archive !!! They are subject to change!!! */

struct __attribute__((packed)) aea_archive {
    uint32_t magic;
    uint32_t profileID: 24; // actually an uint24_t
    uint8_t scryptStrength;
    uint32_t authDataSize;
    // size: authDataSize
    uint8_t* authData;
    /* size: 
     * 128 for profile 0 (ECDSA-P256)
     * 160 for profile 2 or 4
     * 0 otherwise
     */
    uint8_t* signature;
    /* size:
     * 32 for profile 0 (Key Derivation Seed)
     * 65 for profile 3 or 4 (Sender Public Key)
     * 0 otherwise
     */
    uint8_t* profileDependent;
    uint8_t keyDerivationSalt[0x20];
    uint8_t rootHeaderHMAC[0x20];
    // size: 0x30
    union {
        struct aea_root_header rootHeader;
        uint8_t encryptedRootHeader[0x30];
    };
    uint8_t cluster0HeaderHMAC[0x20];
    bool isEncrypted;
    union {
        struct {
            size_t clusterDataLen; // data length of clusters for encrypted
            // size: clusterDataLen
            uint8_t* encryptedClusters;
        };
        // size: TBD at runtime
        struct {
            size_t numClusters, // number of clusters that follow for decrypted
                   innerDataLen; // length of data that is actually contained in the clusters -> segments
            struct aea_cluster_header* clusters;
        };
    };
};

typedef struct aea_archive *NeoAEAArchive;






// ======== starting from here: old struct definitions kept for compatibility reasons ========

struct aea_old_segment_header {
    uint32_t originalSize;
    uint32_t compressedSize;
    /* size: based on rootHeader.checksumAlgorithm
       0 for checksumAlgorithm 0
       8 for checksumAlgorithm 1 (Murmur64 Hash)
       32 for checksumAlgorithm 2 (SHA-256)
     */
    uint8_t hash[0x20];
};

struct aea_header {
    uint32_t magic;
     /*
      * TODO:
      * This is actually a uint24_t for profile
      * followed by a uint8_t for scriptSize.
      * However, scriptSize is always 0 in non-profile 5,
      * and lnaa does not support profile 5...
      * so this is fine *for now*.
      */
    uint32_t profile;
    uint32_t authDataSize;
};

/* Prior to aea_root_header in AEAProfile 0/1 */
struct aea_preroot_header {
    uint8_t keyDeriviationSalt[32];
    uint8_t rootHeaderHMACSHA256[32];
    struct aea_root_header rootHeader;
};

/* In AEAProfile 0, prior to aea_preroot_header */
struct aea_sig_info {
    uint8_t ecdsaP256[128];
    uint8_t keyDeriviationSeed[32];
};

/* NOTE: Not all headers are 256 segments, but default is */
struct aea_default_cluster {
    uint8_t headerHMACSHA256[32];
    struct aea_segment_header segmentHeaders[256];
};

struct aea_profile0_default_post_authData {
    struct aea_sig_info sigInfo;
    struct aea_preroot_header prerootHeader;
    struct aea_default_cluster cluster0header;
};

struct aea_profile0_post_authData {
    struct aea_sig_info sigInfo;
    struct aea_preroot_header prerootHeader;
};

NeoAEAArchive neo_aea_archive_with_path(const char *path);
NeoAEAArchive neo_aea_archive_with_encoded_data(uint8_t *encodedData, size_t encodedDataSize);
NeoAEAArchive neo_aea_archive_with_encoded_data_nocopy(uint8_t *encodedData, size_t encodedDataSize);
uint8_t *neo_aea_archive_extract_data(
    NeoAEAArchive aea, 
    size_t *size, 
    EVP_PKEY* recPriv,
    EVP_PKEY* signaturePub,
    uint8_t* symmKey, size_t symmKeySize,
    uint8_t* password, size_t passwordSize
);
NeoAAArchivePlain neo_aa_archive_plain_with_neo_aea_archive(NeoAEAArchive aea);
uint32_t neo_aea_archive_profile(NeoAEAArchive aea);
uint8_t *neo_aea_archive_auth_data(NeoAEAArchive aea, uint32_t *authDataSize);
void neo_aea_archive_destroy(NeoAEAArchive aea);

#endif /* neo_aea_archive_h */
