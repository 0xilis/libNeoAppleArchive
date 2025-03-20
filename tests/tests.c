//
//  tests.c
//  libNeoAppleArchive
//
//  Created by Snoolie Keffaber on 2024/05/07.
//

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <libNeoAppleArchive.h>

int main(int argc, const char * argv[]) {
    (void)argc;
    (void)argv;
    /* TODO: More tests and implement a signal handler. Currently this is mainly NeoAAHeader tests and doesn't test NeoAAArchiveItem or NeoAAArchivePlain yet. */
    printf("start test...\n");
    NeoAAHeader header = neo_aa_header_create();
    if (!header) {
        fprintf(stderr,"header was null\n");
        return -1;
    }
    if (strncmp(header->encodedData, "AA01", 4)) {
        fprintf(stderr,"header->encodedData is not AA01\n");
        neo_aa_header_destroy(header);
        return -1;
    }
    if (header->headerSize != 6) {
        fprintf(stderr,"header->headerSize not 6 on creation\n");
        neo_aa_header_destroy(header);
        return -1;
    }
    if (header->fieldCount) {
        fprintf(stderr,"header->fieldCount not 0 on creation\n");
        neo_aa_header_destroy(header);
        return -1;
    }
    NeoAAArchiveItem item = neo_aa_archive_item_create_with_header(header);
    if (!item) {
        fprintf(stderr,"archiveItem failed to create\n");
        neo_aa_header_destroy(header);
        return -1;
    }
    if (item->header != header) {
        fprintf(stderr,"item->header different pointer than argument\n");
        return -1;
    }
    if (item->encodedBlobDataSize) {
        fprintf(stderr,"item->encodedBlobDataSize is not 0\n");
        neo_aa_archive_item_destroy(item);
        return -1;
    }
    /* neo_aa_header_destroy should also 0 out the header pointer in the associated NeoAAArchiveItem */
    neo_aa_header_destroy(header);
    if (item->header) {
        fprintf(stderr,"item->header should be 0 after destroy\n");
        return -1;
    }
    neo_aa_archive_item_destroy(item);
    uint8_t encodedSize = 34;
    uint8_t encodedHeader[34] = {'A', 'A', '0', '1', encodedSize, 0, 'T', 'Y', 'P', '1', 'D', 'P', 'A', 'T', 'P', 4, 0, 'T', 'E', 'S', 'T', 'A', 'P', 'L', '4', 0xce, 0xfa, 0xed, 0xfe, 'S', 'K', '0', '1', 5};
    header = neo_aa_header_create_with_encoded_data(encodedSize, encodedHeader);
    if (!header) {
        fprintf(stderr,"header was null\n");
        return -1;
    }
    if (header->headerSize != encodedSize) {
        fprintf(stderr,"header->headerSize isn't encodedSize\n");
        neo_aa_header_destroy(header);
        return -1;
    }
    if (memcmp(header->encodedData, encodedHeader, encodedSize)) {
        fprintf(stderr,"header->encodedData mismatch\n");
        neo_aa_header_destroy(header);
        return -1;
    }
    int typIndex = neo_aa_header_get_field_key_index(header, NEO_AA_FIELD_C("TYP"));
    if (typIndex) {
        fprintf(stderr,"index of typIndex is not 0\n");
        neo_aa_header_destroy(header);
        return -1;
    }
    if (neo_aa_header_get_field_type(header, typIndex) != NEO_AA_FIELD_TYPE_UINT) {
        fprintf(stderr,"TYP field is not NEO_AA_FIELD_TYPE_UINT\n");
        neo_aa_header_destroy(header);
        return -1;
    }
    if (neo_aa_header_get_field_key_uint(header, typIndex) != 'D') {
        fprintf(stderr,"TYP field is not D\n");
        neo_aa_header_destroy(header);
        return -1;
    }
    if (neo_aa_header_get_field_size(header, typIndex) != 1) {
        fprintf(stderr,"TYP field is not 1\n");
        neo_aa_header_destroy(header);
        return -1;
    }
    if (header->fieldCount != 4) {
        fprintf(stderr,"field count is not 4\n");
        neo_aa_header_destroy(header);
        return -1;
    }
    int patIndex = neo_aa_header_get_field_key_index(header, NEO_AA_FIELD_C("PAT"));
    if (patIndex != 1) {
        fprintf(stderr,"index of patIndex is not 1\n");
        neo_aa_header_destroy(header);
        return -1;
    }
    if (neo_aa_header_get_field_type(header, patIndex) != NEO_AA_FIELD_TYPE_STRING) {
        fprintf(stderr,"PAT field is not NEO_AA_FIELD_TYPE_STRING\n");
        neo_aa_header_destroy(header);
        return -1;
    }
    if (neo_aa_header_get_field_size(header, patIndex) != 4) {
        fprintf(stderr,"PAT field size not 4, is instead %zu\n",neo_aa_header_get_field_size(header, patIndex));
        neo_aa_header_destroy(header);
        return -1;
    }
    char *pathString = neo_aa_header_get_field_key_string(header, patIndex);
    if (!pathString) {
        fprintf(stderr,"pathString failed to copy\n");
        neo_aa_header_destroy(header);
        return -1;
    }
    if (strlen(pathString) != 4) {
        fprintf(stderr,"pathString size not 4\n");
        free(pathString);
        neo_aa_header_destroy(header);
        return -1;
    }
    if (strcmp(pathString, "TEST")) {
        fprintf(stderr,"PAT not equal to TEST\n");
        free(pathString);
        neo_aa_header_destroy(header);
        return -1;
    }
    free(pathString);
    neo_aa_header_set_field_uint(header, NEO_AA_FIELD_C("TYP"), 1, 'E');
    if (neo_aa_header_get_field_type(header, typIndex) != NEO_AA_FIELD_TYPE_UINT) {
        fprintf(stderr,"TYP field is not NEO_AA_FIELD_TYPE_UINT\n");
        neo_aa_header_destroy(header);
        return -1;
    }
    if (neo_aa_header_get_field_key_uint(header, typIndex) != 'E') {
        fprintf(stderr,"TYP field is not E\n");
        neo_aa_header_destroy(header);
        return -1;
    }
    if (neo_aa_header_get_field_size(header, typIndex) != 1) {
        fprintf(stderr,"TYP field is not 1\n");
        neo_aa_header_destroy(header);
        return -1;
    }
    if (header->fieldCount != 4) {
        fprintf(stderr,"field count is not 4\n");
        neo_aa_header_destroy(header);
        return -1;
    }
    unsigned char *encodedDataOfModifiedKeyHeader = (unsigned char*)header->encodedData;
    if (encodedDataOfModifiedKeyHeader[9] != '1' || encodedDataOfModifiedKeyHeader[10] != 'E' || encodedDataOfModifiedKeyHeader[11] != 'P') {
        fprintf(stderr,"TYP setting made encoded data corrupt in header\n");
        neo_aa_header_destroy(header);
        return -1;
    }
    int aplIndex = neo_aa_header_get_field_key_index(header, NEO_AA_FIELD_C("APL"));
    if (aplIndex != 2) {
        fprintf(stderr,"index of aplIndex is not 2\n");
        neo_aa_header_destroy(header);
        return -1;
    }
    if (neo_aa_header_get_field_type(header, aplIndex) != NEO_AA_FIELD_TYPE_UINT) {
        fprintf(stderr,"APL field is not NEO_AA_FIELD_TYPE_UINT\n");
        neo_aa_header_destroy(header);
        return -1;
    }
    if (neo_aa_header_get_field_key_uint(header, aplIndex) != 0xfeedface) {
        fprintf(stderr,"APL field is not feedface\n");
        neo_aa_header_destroy(header);
        return -1;
    }
    if (neo_aa_header_get_field_size(header, aplIndex) != 4) {
        fprintf(stderr,"APL field size is not 4\n");
        neo_aa_header_destroy(header);
        return -1;
    }
    neo_aa_header_set_field_uint(header, NEO_AA_FIELD_C("APL"), 4, 0xcefaedfe);
    if (neo_aa_header_get_field_key_uint(header, aplIndex) != 0xcefaedfe) {
        fprintf(stderr,"APL field is not cefaedfe, it's instead %02llx\n",neo_aa_header_get_field_key_uint(header, aplIndex));
        neo_aa_header_destroy(header);
        return -1;
    }
    if (encodedDataOfModifiedKeyHeader[23] != 'L' || encodedDataOfModifiedKeyHeader[24] != '4' || encodedDataOfModifiedKeyHeader[29] != 'S' || encodedDataOfModifiedKeyHeader[30] != 'K') {
        fprintf(stderr,"APL setting made encoded data corrupt in header\n");
        neo_aa_header_destroy(header);
        return -1;
    }
    NeoAAHeader headerClone = neo_aa_header_clone_header(header);
    if (headerClone == header) {
        fprintf(stderr,"neo_aa_header_clone_header returned the same header pointer, it did not clone\n");
        neo_aa_header_destroy(header);
        return -1;
    }
    if (!headerClone) {
        fprintf(stderr,"failed to clone header (likely malloc fail?)\n");
        neo_aa_header_destroy(header);
        return -1;
    }
    if (headerClone->archiveItem) {
        fprintf(stderr,"cloned headers should not inherit archiveItem pointer from the original\n");
        return -1;
    }
    char *clonedHeaderData = headerClone->encodedData;
    if (!clonedHeaderData) {
        fprintf(stderr,"clone header does not have encoded data\n");
        neo_aa_header_destroy(header);
        neo_aa_header_destroy(headerClone);
        return -1;
    }
    if (headerClone->headerSize != header->headerSize) {
        fprintf(stderr,"clone header size is not the same as original size\n");
        neo_aa_header_destroy(header);
        neo_aa_header_destroy(headerClone);
        return -1;
    }
    if (headerClone->fieldCount != 4) {
        fprintf(stderr,"clone header field count is not the same as original\n");
        neo_aa_header_destroy(header);
        neo_aa_header_destroy(headerClone);
        return -1;
    }
    size_t *clonedKeySizes = headerClone->fieldKeySizes;
    if (!clonedKeySizes) {
        fprintf(stderr,"headerClone->fieldKeySizes is NULL\n");
        neo_aa_header_destroy(header);
        neo_aa_header_destroy(headerClone);
        return -1;
    }
    if (clonedKeySizes == header->fieldKeySizes) {
        fprintf(stderr,"headerClone->fieldKeySizes is has the same pointer as original\n");
        neo_aa_header_destroy(header);
        return -1;
    }
    char *clonedKeyTypes = headerClone->fieldTypes;
    if (!clonedKeyTypes) {
        fprintf(stderr,"headerClone->fieldTypes is NULL\n");
        neo_aa_header_destroy(header);
        neo_aa_header_destroy(headerClone);
        return -1;
    }
    if (clonedKeyTypes == header->fieldTypes) {
        fprintf(stderr,"headerClone->fieldTypes is has the same pointer as original\n");
        neo_aa_header_destroy(header);
        return -1;
    }
    uint32_t *clonedKeys = headerClone->fieldKeys;
    if (!clonedKeys) {
        fprintf(stderr,"headerClone->fieldKeys is NULL\n");
        neo_aa_header_destroy(header);
        neo_aa_header_destroy(headerClone);
        return -1;
    }
    if (clonedKeys == header->fieldKeys) {
        fprintf(stderr,"headerClone->fieldKeys is has the same pointer as original\n");
        neo_aa_header_destroy(header);
        return -1;
    }
    void **clonedKeyValues = headerClone->fieldValues;
    if (!clonedKeyValues) {
        fprintf(stderr,"headerClone->fieldValues is NULL\n");
        neo_aa_header_destroy(header);
        neo_aa_header_destroy(headerClone);
        return -1;
    }
    void **originalKeyValues = header->fieldValues;
    if (clonedKeyValues == originalKeyValues) {
        fprintf(stderr,"headerClone->fieldValues is has the same pointer as original\n");
        neo_aa_header_destroy(header);
        return -1;
    }
    for (int i = 0; i < 4; i++) {
        void *clonedValuePtr = clonedKeyValues[i];
        if (!clonedValuePtr) {
            fprintf(stderr,"headerClone->fieldValues[%d] pointer is NULL\n",i);
            neo_aa_header_destroy(header);
            return -1;
        }
        if (clonedValuePtr == originalKeyValues[i]) {
            fprintf(stderr,"headerClone->fieldValues[%d] has the same pointer as original\n",i);
            neo_aa_header_destroy(header);
            return -1;
        }
    }
    neo_aa_header_destroy(headerClone);
    item = neo_aa_archive_item_create_with_header(header);
    if (!item) {
        fprintf(stderr,"archiveItem failed to create\n");
        neo_aa_header_destroy(header);
        return -1;
    }
    if (item->header != header) {
        fprintf(stderr,"item->header different pointer than argument\n");
        return -1;
    }
    if (item->encodedBlobDataSize) {
        fprintf(stderr,"item->encodedBlobDataSize is not 0\n");
        neo_aa_archive_item_destroy(item);
        return -1;
    }
    neo_aa_archive_item_destroy(item);
    printf("end tests\n");
    return 0;
}
