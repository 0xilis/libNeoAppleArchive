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
int ecdsa_p256_signature_asn1_len(uint8_t *prologueSignature, size_t maxSize);

#endif /* asn1parse_h */
