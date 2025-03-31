/*
 *  asn1parse.c
 *  libNeoAppleArchive
 *
 *  Created by Snoolie Keffaber on 2024/05/09.
 */

#ifndef EXCLUDE_AEA_SUPPORT

#include "asn1parse.h"

/*
 * raw_ecdsa_p256_signature_from_asn1
 *
 * Fills the sig buffer with r|s.
 * Returns 0 on success.
 * Returns a negative error code on failure.
 * Please have sig be 64 bytes.
 */
unsigned int ecdsa_p256_signature_asn1_len(uint8_t *prologueSignature, size_t maxSize) {
    if (!prologueSignature || !maxSize) {
        return 0;
    }
    if (prologueSignature[0] != 0x30) {
        /* ASN.1 signature should always begin with 0x30, if not, invalid */
        return 0;
    }
    size_t prologueSignatureSize = prologueSignature[1];
    if (prologueSignatureSize < 64 || prologueSignatureSize > (maxSize-2)) {
        /*
         * ECDSA signatures are concatenated r|s. For
         * ECDSA-P256, they are 256bit / 32 bytes each.
         * This means that the ASN.1 encoding should
         * *never* specify a smaller length than 64
         * (32+32) for ECDSA-P256. AEA also only has a
         * max size of 128 bytes for the ASN.1 encoded
         * signature, so if len(z)+2 is larger, then
         * the encoding is invalid.
         */
        return 0;
    }
    prologueSignatureSize += 2; /* account for the 30 len(z) bytes */
    if (prologueSignature[2] != 0x02) {
        /*
         * Signature should be r|s. r is an integer.
         * 02 is what specifies that the data is an integer.
         * If r is not an integer, this encoding isn't for ECDSA-P256.
         */
        return 0;
    }
    uint8_t prologueSignatureRSize = prologueSignature[3];
    if (prologueSignatureRSize+4 > prologueSignatureSize) {
        /*
         * Our R goes past the signature size!
         * Some funny business must be going on...
         */
        return 0;
    }
    prologueSignature += 4;
    uint8_t zeroBytes = prologueSignatureRSize - 32;
    if (zeroBytes && prologueSignatureRSize >= 32) {
        /* r is 0x21, double check that bits are 0 */
        for (int i = 0; i < zeroBytes; i++) {
            if (prologueSignature[i]) {
                return 0;
            }
        }
    }
    /* Move to s of prologue signature */
    prologueSignature += prologueSignatureRSize;
    if (prologueSignature[0] != 0x02) {
        /*
         * Signature should be r|s. s is an integer.
         * 02 is what specifies that the data is an integer.
         * If s is not an integer, this encoding isn't for ECDSA-P256.
         */
        return 0;
    }
    uint8_t prologueSignatureSSize = prologueSignature[1];
    if (prologueSignatureSSize+prologueSignatureRSize+6 > prologueSignatureSize) {
        /*
         * R|S goes past the signature size!
         * Some funny business must be going on...
         */
        return 0;
    }
    zeroBytes = prologueSignatureSSize - 32;
    if (zeroBytes && prologueSignatureSSize >= 32) {
        /* s is 0x21, double check that bits are 0 */
        for (int i = 0; i < zeroBytes; i++) {
            if (prologueSignature[i+2]) {
                return 0;
            }
        }
    }
    return 2+prologueSignatureSSize+prologueSignatureRSize+4;
}

#endif /* EXCLUDE_AEA_SUPPORT */
