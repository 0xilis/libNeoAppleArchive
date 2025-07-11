/*
 *  libNeoAppleArchive_internal.h
 *  libNeoAppleArchive
 *
 *  Created by Snoolie Keffaber on 2024/04/24.
 */

#ifndef libNeoAppleArchive_h
#error Include libNeoAppleArchive.h instead of this file
#endif

#ifndef libNeoAppleArchive_internal_h
#define libNeoAppleArchive_internal_h

#ifdef __cplusplus
extern "C" {
#endif

uint32_t internal_do_not_call_flip_edian_32(uint32_t num);
#define FLIP_32(x) internal_do_not_call_flip_edian_32(x)

#define NEO_AA_NullParamAssert(x) if (!x) {fprintf(stderr,"%s: invalid parameters.\n",__FUNCTION__);exit(1);};

#define NEO_AA_LogError(msg) fprintf(stderr, "%s: %s", __FUNCTION__, msg);
/* Logs to stderr. printf-like. */
#define NEO_AA_LogErrorF(fmt, ...) fprintf(stderr, "%s " fmt, __FUNCTION__, __VA_ARGS__);

#define NEO_AA_UnsupportedKey(key) NEO_AA_LogErrorF("Unsupported field key for libNeoAppleArchive: %s\n",key)
#define NEO_AA_AssertUnsupportedKey(key, unsupported) if (key == NEO_AA_FIELD_C(unsupported)) {NEO_AA_UnsupportedKey(unsupported);exit(1);};
#define NEO_AA_ErrorHeapAlloc() NEO_AA_LogError("libNeoAppleArchive failed to malloc/realloc\n")

char *internal_do_not_call_memrchr(char *s, int c, size_t n);
void internal_do_not_call_apply_xattr_blob_to_fd(uint8_t *blob, size_t blobSize, int fd);
void internal_do_not_call_is_field_key_available(uint32_t key);
int internal_do_not_call_is_field_type_supported_size(NeoAAFieldType fieldType, size_t fieldSize);
char internal_do_not_call_neo_aa_header_subtype_for_field_type_and_size(uint32_t fieldType, size_t fieldSize);
uint64_t internal_do_not_call_neo_aa_archive_header_key_pos_in_encoded_data(NeoAAHeader header, int index);
size_t internal_do_not_call_neo_aa_archive_item_encoded_data_size_for_encoded_data(size_t maxSize, uint8_t *data);
int internal_do_not_call_inflate(const void *src, int srcLen, void *dst, int dstLen);

#define AAR_MAGIC 0x31304141 /* The AAR/AA01 Magic, raw. */
#define YAA_MAGIC 0x31414159 /* From tales of old, the YAA format; replaced by AA01 / AAR. */
#define PBZ__MAGIC 0x007A6270 /* For compressed Apple Archives */
#define PBZE_MAGIC 0x657A6270 /* LZFSE */
#define PBZB_MAGIC 0x627A6270 /* LZBITMAP */
#define PBZZ_MAGIC 0x7A7A6270 /* ZLIB */

#define NEO_INTERNAL_API __attribute__((visibility ("hidden"))) 

#ifdef __cplusplus
}
#endif

#endif /* libNeoAppleArchive_internal_h */
