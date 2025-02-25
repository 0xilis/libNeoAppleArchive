/*
 *  asn1parse.h
 *  libNeoAppleArchive
 *
 *  Created by Snoolie Keffaber on 2024/05/09.
 */

/* ONLY for ECDSA-P256 signatures !!!! */

#ifndef asn1parse_h
#define asn1parse_h

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * raw_ecdsa_p256_signature_from_asn1
 *
 * Fills the sig buffer with r|s.
 * Returns 0 on success.
 * Returns a negative error code on failure.
 * Please have sig be 64 bytes.
 */
int raw_ecdsa_p256_signature_from_asn1(uint8_t *prologueSignature, size_t maxSize, uint8_t *sig);

#endif /* asn1parse_h */
