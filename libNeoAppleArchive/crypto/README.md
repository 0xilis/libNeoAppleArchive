# Credits

The SHA256 implementation is written here by Brad Conte and is from [https://github.com/B-Con/crypto-algorithms](https://github.com/B-Con/crypto-algorithms). This code is public domain. For the most part it is the same source, albeit with the function names changed to prepend "lnaa_", standing for libNeoAppleArchive, to them, as to not create any potential duplicate symbol warnings for those including libNeoAppleArchive in their projects and wanting to include these symbol names for easier debugging but also already have these functions in their project already. The memory.h header definition has also been swapped out for string.h.

The ECDSA-P256 implementation is from [https://github.com/syncom/tinyp256](https://github.com/syncom/tinyp256) and is licensed under MIT, the same license libNeoAppleArchive uses.

The parsing for ASN.1 encoded ECDSA-P256 signatures is done by me, specifically for libNeoAppleArchive. Some help from https://crypto.stackexchange.com/questions/57731/ecdsa-signature-rs-to-asn1-der-encoding-question https://stackoverflow.com/questions/59904522/asn1-encoding-routines-errors-when-verifying-ecdsa-signature-type-with-openssl
