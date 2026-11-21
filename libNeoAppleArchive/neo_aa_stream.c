/*
 *  neo_aa_stream.c
 *  libNeoAppleArchive
 *
 *  Created by Snoolie Keffaber on 2026/11/20.
 */

#include "libNeoAppleArchive.h"
#include "libNeoAppleArchive_internal.h"

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>

#define NEO_AA_IO_BUFFER_SIZE (1024 * 1024)

NEO_INTERNAL_API int neo_aa_copy_stream(FILE *src, FILE *dst, uint64_t bytes) {
    uint8_t *buffer = malloc(NEO_AA_IO_BUFFER_SIZE);

    if (!buffer) {
        NEO_AA_ErrorHeapAlloc();
        return -1;
    }

    while (bytes > 0) {
        size_t chunk = bytes > NEO_AA_IO_BUFFER_SIZE ? NEO_AA_IO_BUFFER_SIZE : (size_t)bytes;

        size_t received = fread(buffer, 1, chunk, src);

        if (received != chunk) {
            free(buffer);
            NEO_AA_LogError("received != chunk\n");
            return -1;
        }

        size_t written = 0;

        while (written < received) {
            size_t result = fwrite(buffer + written, 1, received - written, dst);

            if (result == 0) {
                free(buffer);
                return -1;
            }

            written += result;
        }

        bytes -= received;
    }

    free(buffer);
    return 0;
}

NEO_INTERNAL_API int neo_aa_read_exact(FILE *fp, void *buffer, size_t size) {
    uint8_t *ptr = (uint8_t *)buffer;

    while (size > 0) {
        size_t n = fread(ptr, 1, size, fp);

        if (n == 0) {
            if (ferror(fp) && errno == EINTR) {
                clearerr(fp);
                continue;
            }
            return -1;
        }

        ptr += n;
        size -= n;
    }

    return 0;
}

/*
 * Skip bytes without allocating memory.
 * The archive is a seekable regular file.
 */
NEO_INTERNAL_API int neo_aa_skip_stream(FILE *fp, uint64_t amount) {
    if (amount > (uint64_t)INT64_MAX) {
        return -1;
    }

    off_t current = ftello(fp);
    if (current < 0 || (uint64_t)current > (uint64_t)INT64_MAX - amount) {
        return -1;
    }

    return fseeko(fp, (off_t)((uint64_t)current + amount), SEEK_SET);
}

/* Reject absolute paths and traversal components. Does not check symlinks. */
NEO_INTERNAL_API int neo_aa_validate_archive_path(const char *path) {
    if (!path || !path[0] || path[0] == '/') {
        return -1;
    }

    const char *component = path;

    for (const char *p = path; ; p++) {
        if (*p == '\\') {
            return -1;
        }

        if (*p == '/' || *p == '\0') {
            size_t len = (size_t)(p - component);

            if (len == 0 || (len == 1 && component[0] == '.') || (len == 2 && component[0] == '.' && component[1] == '.')) {
                return -1;
            }

            if (*p == '\0') {
                break;
            }

            component = p + 1;
        }
    }

    return 0;
}

/*
 * Create missing parent directories.
 * This helper expects an already validated relative path.
 */
NEO_INTERNAL_API int neo_aa_make_parent_directories(const char *root,const char *relativePath) {
    char fullPath[PATH_MAX];

    int n = snprintf(fullPath, sizeof(fullPath), "%s/%s", root, relativePath);

    if (n < 0 || (size_t)n >= sizeof(fullPath)) {
        return -1;
    }

    for (char *p = fullPath + strlen(root) + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';

            if (mkdir(fullPath, 0755) < 0 && errno != EEXIST) {
                return -1;
            }

            *p = '/';
        }
    }

    return 0;
}

/*
 * Read and apply an XAT blob.
 *
 * XAT data is kept separate from the file's DAT data.
 * The allocation is bounded to prevent an archive from
 * requesting an arbitrarily large allocation.
 */
#define NEO_AA_MAX_XATTR_BLOB (16ULL * 1024 * 1024)

NEO_INTERNAL_API int neo_aa_read_apply_xattrs(FILE *archive, uint64_t xattrSize, int fd) {
    if (!xattrSize) {
        return 0;
    }

    if (xattrSize > NEO_AA_MAX_XATTR_BLOB ||
        xattrSize > SIZE_MAX) {
        return -1;
    }

    uint8_t *blob = malloc((size_t)xattrSize);
    if (!blob) {
        return -1;
    }

    if (neo_aa_read_exact(archive, blob, (size_t)xattrSize)) {
        free(blob);
        return -1;
    }

    internal_do_not_call_apply_xattr_blob_to_fd(blob, (size_t)xattrSize, fd);

    free(blob);
    return 0;
}
