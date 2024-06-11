//
//  neo_aea_archive.c
//  libAppleArchive
//
//  Created by Snoolie Keffaber on 2024/05/07.
//

#include "libNeoAppleArchive.h"
#include "libNeoAppleArchive_internal.h"
#include "crypto/sha256.h"
#include "crypto/ecdsa/tinyp256.h"
#include "crypto/asn1parse.h"

/*
 * Note: Using libcompression is temporary.
 * libcompression is not on Linux platforms,
 * so in the future swap out the LZFSE with
 * liblzfse, which is available at
 * https://github.com/lzfse/lzfse
 */
#include <compression.h>

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
    return aeaArchive;
}

/* similar to my libshortcutsign function for this */
uint8_t *neo_aea_archive_copy_auth_data(NeoAEAArchive aea) {
    /* TODO: Finish */
    NEO_AA_NullParamAssert(aea);
    fprintf(stderr,"FINISH LATER\n");
    exit(1);
    return 0;
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

/*
 * DO NOT ADD THIS FUNCTION TO PUBLIC
 */
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonHMAC.h>
#import <CommonCrypto/CommonDigest.h>
const char *getHashFromDigestSHA256Call(char *encodedAppleArchive, uint32_t len) {
    CC_SHA256_CTX *context = malloc(sizeof(CC_SHA256_CTX));
    CC_SHA256_Init(context);
    CC_SHA256_Update(context, encodedAppleArchive, len);
    unsigned char *md = malloc(CC_SHA256_DIGEST_LENGTH);
    CC_SHA256_Final(md, context);
    free(context);
    return (const char *)md;
}
/* External CommonCrypto headers */
/* available macOS 10.15, iOS 13.0+ */
#ifndef _CC_RSACRYPTOR_H_
enum {
    kCCDigestNone = 0,
    kCCDigestSHA1 = 8,
    kCCDigestSHA224 = 9,
    kCCDigestSHA256 = 10,
    kCCDigestSHA384 = 11,
    kCCDigestSHA512 = 12,
};
typedef uint32_t CCDigestAlgorithm;
typedef struct CCKDFParameters *CCKDFParametersRef;
#endif
/*
 * DO NOT ADD THIS FUNCTION TO PUBLIC
 */
typedef uint32_t CCKDFAlgorithm;
CCStatus CCKDFParametersCreateHkdf(CCKDFParametersRef *params,const void *salt, size_t saltLen,const void *context, size_t contextLen);
CCStatus CCDeriveKey(const CCKDFParametersRef params, CCDigestAlgorithm digest,const void *keyDerivationKey, size_t keyDerivationKeyLen,void *derivedKey, size_t derivedKeyLen);
void CCKDFParametersDestroy(CCKDFParametersRef params);
void *do_hkdf(void *context, size_t contextLen, const void *key) {
    void *derivedKey = malloc(512);
    if (!derivedKey) {
        return 0;
    }
    CCKDFParametersRef p;
    CCKDFParametersCreateHkdf(&p, 0, 0, context, contextLen);
    CCDeriveKey(p, kCCDigestSHA256, key, 32, derivedKey, 32);
    CCKDFParametersDestroy(p);
    return derivedKey;
}
/*
 * DO NOT ADD THIS FUNCTION TO PUBLIC
 */
void *hmac_derive(void *hkdf_key, void *data1, size_t data1Len, void *data2, size_t data2Len) {
    void *hmac = malloc(1024);
    if (!hmac) {
        return 0;
    }
    CCHmacContext context;
    CCHmacInit(&context, kCCHmacAlgSHA256, hkdf_key, 32);
    CCHmacUpdate(&context, data2, data2Len);
    CCHmacUpdate(&context, data1, data1Len);
    CCHmacUpdate(&context, &data2Len, 8);
    CCHmacFinal(&context, hmac);
    return hmac;
}
int hmac_verify(void *hkdf_key, void *data1, size_t data1Len, void *data2, size_t data2Len, uint8_t *hmac) {
    void *hmac2 = hmac_derive(hkdf_key, data1, data1Len, data2, data2Len);
    if (!hmac) {
        return -1;
    }
    int isInvalid = memcmp(hmac, hmac2, 32);
    free(hmac2);
    return isInvalid;
}

/*
 * neo_aea_archive_verify
 *
 * Verifies the ECDSA-P256 signature, as well as
 * HKDF / HMAC verification. If valid, it will
 * return 1. If not or an error occours, it returns 0.
 */
int neo_aea_archive_verify(NeoAEAArchive aea) {
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
    /*
     * First things first, we need to verify the
     * ECDSA signature. While I don't think the
     * Apple Archive documentation or headers gives
     * this a clear name anywhere, judging by the logs
     * and symbols in libApleArchive, I'm pretty sure
     * the area that is signature checked is called the
     * prologue. The ECDSA signature signs the first
     * (auth_data_size+0x13c) of the binary. Albeit,
     * it is stored in that data at auth_data_size+0xc,
     * and since we obviously don't know the signature
     * before signing it, libAppleArchive 0's it out
     * and hashes it. This hash is signature checked.
     * The ASN.1 encoded ECDSA signature also is
     * represented by 128 bytes in the file, but since
     * it is usually smaller, 0'd are at the bytes that
     * the signature doesn't occupy in the 128 byte section.
     *
     * The actual regular Apple Archive not in this
     * region, so someone can change it and still pass
     * ECDSA verification, but this is not an issue as
     * the prologue contains HDKF keys and HMAC context
     * that will be checked later, and changing the
     * regular Apple Archive will make you fail HMAC
     * verification, which you cannot just simply change
     * to be verified since that *is* protected by the
     * prologue signature.
     *
     * (Also, if anyone knows what this field of the
     * AEA archive is called and it's not actually
     * called the prologue, correct me and show me
     * a source; pretty sure that the only people
     * that actually know what it's called would be
     * libAppleArchive engineers which I doubt would
     * see this and read this comment for this other,
     * much much worse library for Apple Archive)
     */
    /*
     * Here, we create a copy of our prologue in the
     * encodedData for our archive, then 0 out the
     * copy and hash it, just like regular libAppleArchive.
     */
    if (encodedDataSize >= aaLzfseOffset) {
        NEO_AA_LogError("aaLzfseOffset reaches past encodedData\n");
        return 0;
    }
    uint8_t *publicSigningKey = aea->publicSigningKey;
    if (!publicSigningKey) {
        NEO_AA_LogError("no publicSigningKey on aea\n");
        return 0;
    }
    uint8_t *prologueSignature = encodedData + authDataSize + 0xc;
    uint8_t prologueSignatureRaw[64];
    if (raw_ecdsa_p256_signature_from_asn1(prologueSignature, 128, prologueSignatureRaw)) {
        NEO_AA_LogError("invalid ASN1 encoding for signature\n");
        return 0;
    }
    size_t prologueSize = authDataSize + 0x13c;
    uint8_t *prologue = malloc(prologueSize);
    if (!prologue) {
        NEO_AA_ErrorHeapAlloc();
        return 0;
    }
    memcpy(prologue, encodedData, prologueSize);
    /* 0 out the signature from the prologue */
    memset(prologue + authDataSize + 0xc, 0, 128);
    /* hash it */
    BYTE buf[SHA256_BLOCK_SIZE];
    LNAA_SHA256_CTX ctx;
    lnaa_sha256_init(&ctx);
    lnaa_sha256_update(&ctx, prologue, prologueSize);
    lnaa_sha256_final(&ctx, buf);
    free(prologue);
    /* verify signature (we skip the 04 byte of public signing key) */
    size_t publicSigningKeySize = aea->publicSigningKeySize;
    if (lnaa_tinyp256_verify(publicSigningKey + 1, publicSigningKeySize - 1, buf, 32, prologueSignatureRaw, 64) != LNAA_TINYP256_OK) {
        /* Signature is bad */
        NEO_AA_LogError("prologue signature verification fail\n");
        return 0;
    }
    /*
     * Now, we do HKDF/HMAC verification
     */
    size_t contextLen = 7+4+publicSigningKeySize;
    void *context = malloc(contextLen);
    memcpy(context, "AEA_AMK", 7);
    memset(context + 7, 0, 4);
    memcpy(context + 11, publicSigningKey, publicSigningKeySize);
    CCKDFParametersRef p;
    const void *salt = encodedData + authDataSize + 0xac;
    CCStatus hkdfCreateError = CCKDFParametersCreateHkdf(&p, salt, 32, context, contextLen);
    free(context);
    if (hkdfCreateError) {
        CCKDFParametersDestroy(p);
        NEO_AA_LogError("failed AEA_AMK context create\n");
        return 0;
    }
    const void *keyDerivationKeyAMK = encodedData + authDataSize + 0x8c;
    /* derivedKey will be filled */
    uint8_t aeaAmkKey[0x100];
    memset(aeaAmkKey, 0, 0x100);
    CCStatus deriveKeyError = CCDeriveKey(p, kCCDigestSHA256, keyDerivationKeyAMK, 32, aeaAmkKey, 32);
    CCKDFParametersDestroy(p);
    if (deriveKeyError) {
        NEO_AA_LogError("failed deriving AEA_AMK key\n");
        return 0;
    }
    void *aea_rhek_ctx[8];
    memcpy(aea_rhek_ctx, "AEA_RHEK", 8);
    void *rhekKey = do_hkdf(aea_rhek_ctx, 8, keyDerivationKeyAMK);
    if (!rhekKey) {
        NEO_AA_LogError("malloc failed\n");
        return 0;
    }
    void *chekPlusAuthData = malloc(authDataSize + 32);
    memcpy(chekPlusAuthData, encodedData + authDataSize + 0x11c, 32);
    memcpy(chekPlusAuthData + 32, encodedData + 0xc, authDataSize);
    if (hmac_verify(rhekKey, encodedData + authDataSize + 0xec, 0x30, chekPlusAuthData, authDataSize + 32, encodedData + authDataSize + 0xcc)) {
        free(rhekKey);
        free(chekPlusAuthData);
        NEO_AA_LogError("AEA_RHEK hmac failed\n");
        return 0;
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
    void *aea_ck_ctx[10];
    memcpy(aea_ck_ctx, "AEA_CK", 6);
    memset(aea_ck_ctx + 6, 0, 4);
    void *ckKey = do_hkdf(aea_ck_ctx, 10, aeaAmkKey);
    if (!ckKey) {
        NEO_AA_LogError("malloc failed\n");
        return 0;
    }
    void *aea_chek_ctx[8];
    memcpy(aea_chek_ctx, "AEA_CHEK", 8);
    void *chekKey = do_hkdf(aea_chek_ctx, 8, ckKey);
    if (!chekKey) {
        free(ckKey);
        NEO_AA_LogError("malloc failed\n");
        return 0;
    }
    /* aeaInputStreamLoadSegment AEA_CHEK validation */
    if (hmac_verify(chekKey, encodedData + authDataSize + 0x13c, 0x2800, encodedData + authDataSize + 0x293c, 0x2020, encodedData + authDataSize + 0x11c)) {
        free(chekKey);
        free(ckKey);
        NEO_AA_LogError("AEA_CHEK hmac failed\n");
        return 0;
    }
    free(chekKey);
    /* The final check... */
    void *aea_sk_ctx[10];
    memcpy(aea_sk_ctx, "AEA_SK", 6);
    memset(aea_sk_ctx + 6, 0, 4);
    void *skKey = do_hkdf(aea_sk_ctx, 10, ckKey);
    free(ckKey);
    if (!skKey) {
        NEO_AA_LogError("malloc failed\n");
        return 0;
    }
    /* Size of the compressed Apple Archive */
    size_t compressedSize = encodedDataSize - aaLzfseOffset;
    /* aeaInputStreamDecryptSegment AEA_SK validation */
    if (hmac_verify(skKey, encodedData + aaLzfseOffset, compressedSize, 0, 0, encodedData + authDataSize + 0x295c)) {
        free(skKey);
        NEO_AA_LogError("AEA_SK hmac failed\n");
        return 0;
    }
    free(skKey);
    /* We passed ALL HMAC verification and ECDSA-P256; verified! */
    return 1;
}

/*
 * neo_aea_archive_profile
 *
 * Returns the profile for the aea archive.
 * (libNeoAppleArchive only supports AEAProfile 0 at the moment)
 */
NeoAEAProfile neo_aea_archive_profile(NeoAEAArchive aea) {
    NEO_AA_NullParamAssert(aea);
    uint32_t *encodedData = (uint32_t *)aea->encodedData;
    NEO_AA_NullParamAssert(encodedData);
    return encodedData[1] & 0xffffff;
}

/*
 * neo_aea_archive_profile_is_valid
 *
 * Check if the NeoAEAProfile is valid.
 */
int neo_aea_archive_profile_is_valid(NeoAEAProfile profile) {
    return profile < 6;
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
NeoAAArchivePlain neo_aa_archive_plain_with_neo_aea_archive_verify(NeoAEAArchive aea) {
    if (neo_aea_archive_verify(aea)) {
        return neo_aa_archive_plain_with_neo_aea_archive(aea);
    }
    return 0;
}
