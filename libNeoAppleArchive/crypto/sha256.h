/*********************************************************************
* Filename:   sha256.h
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Defines the API for the corresponding SHA1 implementation.
*********************************************************************/

#ifndef LNAA_SHA256_H
#define LNAA_SHA256_H

/*************************** HEADER FILES ***************************/
#include <stddef.h>

/****************************** MACROS ******************************/
#ifndef SHA256_BLOCK_SIZE
#define SHA256_BLOCK_SIZE 32            // SHA256 outputs a 32 byte digest
#endif

/**************************** DATA TYPES ****************************/
typedef unsigned char BYTE;             // 8-bit byte
typedef unsigned int  WORD;             // 32-bit word, change to "long" for 16-bit machines

typedef struct {
	BYTE data[64];
	WORD datalen;
	unsigned long long bitlen;
	WORD state[8];
} LNAA_SHA256_CTX;

/*********************** FUNCTION DECLARATIONS **********************/
void lnaa_sha256_init(LNAA_SHA256_CTX *ctx);
void lnaa_sha256_update(LNAA_SHA256_CTX *ctx, const BYTE data[], size_t len);
void lnaa_sha256_final(LNAA_SHA256_CTX *ctx, BYTE hash[]);

#endif   // LNAA_SHA256_H
