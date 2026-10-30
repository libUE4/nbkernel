/* nbg_path_normalize.h - allocation-free absolute path normalization */
#ifndef _NBG_PATH_NORMALIZE_H_
#define _NBG_PATH_NORMALIZE_H_

#ifdef __KERNEL__
#include <linux/string.h>
#include <linux/types.h>
#else
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#endif

static inline bool nbg_path_normalize_absolute(char *path, size_t cap)
{
    size_t read_pos = 1;
    size_t write_pos = 1;
    size_t len;

    if (!path || cap < 2 || path[0] != '/')
        return false;

    for (len = 0; len < cap && path[len]; len++)
        ;
    if (len == cap)
        return false;

    while (read_pos < len) {
        size_t segment;
        size_t segment_len;

        while (read_pos < len && path[read_pos] == '/')
            read_pos++;
        if (read_pos == len)
            break;

        segment = read_pos;
        while (read_pos < len && path[read_pos] != '/')
            read_pos++;
        segment_len = read_pos - segment;

        if (segment_len == 1 && path[segment] == '.')
            continue;
        if (segment_len == 2 && path[segment] == '.' &&
            path[segment + 1] == '.') {
            while (write_pos > 1 && path[write_pos - 1] != '/')
                write_pos--;
            if (write_pos > 1)
                write_pos--;
            continue;
        }

        if (write_pos > 1) {
            if (write_pos + 1 >= cap)
                return false;
            path[write_pos++] = '/';
        }
        if (segment_len >= cap - write_pos)
            return false;
        memmove(path + write_pos, path + segment, segment_len);
        write_pos += segment_len;
    }

    path[write_pos] = '\0';
    return true;
}

#endif /* _NBG_PATH_NORMALIZE_H_ */
