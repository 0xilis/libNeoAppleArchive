/*
 *  libNeoAppleArchive_internal.h
 *  libNeoAppleArchive
 *
 *  Created by Snoolie Keffaber on 2024/04/24.
 */

#ifndef libNeoAppleArchive_h
#error Include libNeoAppleArchive.h instead of this file
#endif

#ifndef neo_aa_stream_h
#define neo_aa_stream_h

#ifdef __cplusplus
extern "C" {
#endif

/*
 * NOTICE: KEEP OUT!
 *
 * These are currently private APIs and it is not advised to rely on them.
 */

int neo_aa_copy_stream(FILE *src, FILE *dst, uint64_t bytes);
int neo_aa_read_exact(FILE *fp, void *buffer, size_t size);
int neo_aa_skip_stream(FILE *fp, uint64_t amount);
int neo_aa_validate_archive_path(const char *path);
int neo_aa_make_parent_directories(const char *root,const char *relativePath);
int neo_aa_read_apply_xattrs(FILE *archive, uint64_t xattrSize, int fd);

#ifdef __cplusplus
}
#endif

#endif /* neo_aa_stream_h */
