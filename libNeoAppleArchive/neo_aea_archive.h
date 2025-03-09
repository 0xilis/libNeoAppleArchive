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

/* Different types of AEA, should be same as AEAProfiles definition */
typedef enum {
    NEO_AEA_PROFILE_HKDF_SHA256_HMAC_NONE_ECDSA_P256 = 0,
    NEO_AEA_PROFILE_HKDF_SHA256_AESCTR_HMAC_SYMMETRIC_NONE = 1,
    NEO_AEA_PROFILE_HKDF_SHA256_AESCTR_HMAC_SYMMETRIC_ECDSA_P256 = 2,
    NEO_AEA_PROFILE_HKDF_SHA256_AESCTR_HMAC_ECDHE_P256_NONE = 3,
    NEO_AEA_PROFILE_HKDF_SHA256_AESCTR_HMAC_ECDHE_P256_ECDSA_P256 = 4,
    NEO_AEA_PROFILE_HKDF_SHA256_AESCTR_HMAC_SCRYPT_NONE = 5,
} NeoAEAProfile;

/* Do not manually access items of neo_aea_archive_impl !!! They are subject to change!!! */
struct neo_aea_archive_impl {
    size_t encodedDataSize;
    uint8_t *encodedData;
    /*
     * In the future for public use,
     * We should probably implement field keys into
     * NeoAEAArchive, but for now I'm only
     * using this for AEAProfile 0 extraction
     * so I'll only implement the public key
     * for now...
     */
    uint8_t *publicSigningKey; /* buffer containing ECDSA-P256 public signing key */
    size_t publicSigningKeySize; /* should always be 65 */
    NeoAEAProfile profile;
};

typedef struct neo_aea_archive_impl *NeoAEAArchive;



struct aea_root_header {
    uint64_t originalFileSize;
    uint64_t encryptedFileSize;
    uint32_t segmentSize;
    uint32_t segmentsPerCluster;
    char compressionAlgorithm;
    uint8_t checksumAlgorithm;
    uint8_t reserved;
};

struct aea_segment_header {
    uint32_t originalSize;
    uint32_t compressedSize;
    uint8_t sha256[32];
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
uint8_t *neo_aea_archive_extract_data(NeoAEAArchive aea, size_t *size);
NeoAAArchivePlain neo_aa_archive_plain_with_neo_aea_archive(NeoAEAArchive aea);
NeoAEAProfile neo_aea_archive_profile(NeoAEAArchive aea);

#endif /* neo_aea_archive_h */
