//
//  asn1parse.c
//  libNeoAppleArchive
//
//  Created by Snoolie Keffaber on 2024/05/09.
//

#include "asn1parse.h"

/*
 * raw_ecdsa_p256_signature_from_asn1
 *
 * Fills the sig buffer with r|s.
 * Returns 0 on success.
 * Returns a negative error code on failure.
 * Please have sig be 64 bytes.
 */
int raw_ecdsa_p256_signature_from_asn1(uint8_t *prologueSignature, size_t maxSize, uint8_t *sig) {
    if (!sig || !prologueSignature || !maxSize) {
        return -1;
    }
    if (prologueSignature[0] != 0x30) {
        /* ASN.1 signature should always begin with 0x30, if not, invalid */
        return -1;
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
        return -1;
    }
    prologueSignatureSize += 2; /* account for the 30 len(z) bytes */
    if (prologueSignature[2] != 0x02) {
        /*
         * Signature should be r|s. r is an integer.
         * 02 is what specifies that the data is an integer.
         * If r is not an integer, this encoding isn't for ECDSA-P256.
         */
        return -1;
    }
    uint8_t prologueSignatureRSize = prologueSignature[3];
    if (prologueSignatureRSize < 32) {
        /*
         * R *must* be 256 bits.
         */
        return -1;
    }
    if (prologueSignatureRSize+4 > prologueSignatureSize) {
        /*
         * Our R goes past the signature size!
         * Some funny business must be going on...
         */
        return -1;
    }
    prologueSignature += 4;
    uint8_t zeroBytes = prologueSignatureRSize - 32;
    if (zeroBytes) {
        /* r is 0x21, double check that bits are 0 */
        for (int i = 0; i < zeroBytes; i++) {
            if (prologueSignature[i]) {
                return -1;
            }
        }
    }
    for (int i = 0; i < 32; i++) {
        /* Fill with r value */
        sig[i] = prologueSignature[i+zeroBytes];
    }
    /* Move to s of prologue signature */
    prologueSignature += prologueSignatureRSize;
    if (prologueSignature[0] != 0x02) {
        /*
         * Signature should be r|s. s is an integer.
         * 02 is what specifies that the data is an integer.
         * If s is not an integer, this encoding isn't for ECDSA-P256.
         */
        return -1;
    }
    uint8_t prologueSignatureSSize = prologueSignature[1];
    if (prologueSignatureSSize < 32) {
        /*
         * S *must* be 256 bits.
         */
        return -1;
    }
    if (prologueSignatureSSize+prologueSignatureRSize+6 > prologueSignatureSize) {
        /*
         * R|S goes past the signature size!
         * Some funny business must be going on...
         */
        return -1;
    }
    zeroBytes = prologueSignatureSSize - 32;
    if (zeroBytes) {
        /* s is 0x21, double check that bits are 0 */
        for (int i = 0; i < zeroBytes; i++) {
            if (prologueSignature[i+2]) {
                return -1;
            }
        }
    }
    for (int i = 32; i < 64; i++) {
        /* Fill with s value */
        sig[i] = prologueSignature[i+2+zeroBytes];
    }
    /* sig should now be r|s */
    return 0;
}
