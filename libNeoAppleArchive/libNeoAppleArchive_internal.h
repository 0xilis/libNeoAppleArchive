//
//  neo_aa_header.h
//  libAppleArchive
//
//  Created by Snoolie Keffaber on 2024/04/24.
//

#ifndef libNeoAppleArchive_h
#error Include libNeoAppleArchive.h instead of this file
#endif

#ifndef libNeoAppleArchive_internal_h
#define libNeoAppleArchive_internal_h

uint16_t internal_do_not_call_flip_edian_16(uint16_t num);
uint32_t internal_do_not_call_flip_edian_32(uint32_t num);

#define FLIP_16(x) internal_do_not_call_flip_edian_32(x)
#define FLIP_32(x) internal_do_not_call_flip_edian_32(x)

#define NEO_AA_NullParamAssert(x) if (!x) {fprintf(stderr,"%s: invalid parameters.\n",__FUNCTION__);exit(1);};

#define NEO_AA_LogError(msg) fprintf(stderr, "%s %s", __FUNCTION__, msg);
/* Logs to stderr. printf-like. */
#define NEO_AA_LogErrorF(fmt, ...) fprintf(stderr, "%s " fmt, __FUNCTION__, __VA_ARGS__);

#define NEO_AA_UnsupportedKey(key) NEO_AA_LogErrorF("Unsupported field key for libNeoAppleArchive: %s\n",key)
#define NEO_AA_AssertUnsupportedKey(key, unsupported) if (key == NEO_AA_FIELD_C(unsupported)) {NEO_AA_UnsupportedKey(unsupported);exit(1);};
#define NEO_AA_ErrorHeapAlloc() NEO_AA_LogError("libNeoAppleArchive failed to malloc/realloc\n")
#define NEO_AA_AssertHeapAlloc(x) if (!x) {NEO_AA_LogError("libNeoAppleArchive failed to malloc/realloc\n");exit(1);}
#define NEO_AA_ErrorHSP() NEO_AA_LogError("heap overflow detected\n")

extern size_t lastLoadedBinarySize_internal_do_not_use;
char *internal_do_not_call_load_binary(const char *signedShortcutPath);
char *internal_do_not_call_memrchr(char *s, int c, size_t n);
void internal_do_not_call_apply_xattr_blob_to_path(uint8_t *blob, size_t blobSize, const char *path);
void internal_do_not_call_is_field_key_available(uint32_t key);
int internal_do_not_call_is_field_type_supported_size(NeoAAFieldType fieldType, size_t fieldSize);
char internal_do_not_call_neo_aa_header_subtype_for_field_type_and_size(uint32_t fieldType, size_t fieldSize);
uint64_t internal_do_not_call_neo_aa_archive_header_key_pos_in_encoded_data(NeoAAHeader header, int index);
size_t internal_do_not_call_neo_aa_archive_item_encoded_data_size_for_encoded_data(size_t maxSize, uint8_t *data);

#endif /* neo_aa_header_h */
