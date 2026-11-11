/* util.c — string buffer, subject accumulator, small helpers.
 * _GNU_SOURCE comes from the Makefile (-D_GNU_SOURCE). */
#include "internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ================= string buffer ================= */

void cv_sb_init(cv_sb *sb) { memset(sb, 0, sizeof *sb); }

void cv_sb_free(cv_sb *sb)
{
    free(sb->buf);
    memset(sb, 0, sizeof *sb);
}

static bool sb_reserve(cv_sb *sb, size_t extra)
{
    if (sb->oom) return false;
    if (sb->len + extra + 1 <= sb->cap) return true;
    size_t ncap = sb->cap ? sb->cap : 1024;
    while (ncap < sb->len + extra + 1) {
        if (ncap > SIZE_MAX / 2) { sb->oom = true; return false; }
        ncap *= 2;
    }
    char *n = realloc(sb->buf, ncap);
    if (!n) { sb->oom = true; return false; }
    sb->buf = n;
    sb->cap = ncap;
    return true;
}

void cv_sb_putc(cv_sb *sb, char c)
{
    if (!sb_reserve(sb, 1)) return;
    sb->buf[sb->len++] = c;
    sb->buf[sb->len] = '\0';
}

void cv_sb_puts(cv_sb *sb, const char *s)
{
    size_t n = strlen(s);
    if (!sb_reserve(sb, n)) return;
    memcpy(sb->buf + sb->len, s, n);
    sb->len += n;
    sb->buf[sb->len] = '\0';
}

void cv_sb_printf(cv_sb *sb, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    va_list ap2;
    va_copy(ap2, ap);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0) { va_end(ap2); sb->oom = true; return; }
    if (!sb_reserve(sb, (size_t)n)) { va_end(ap2); return; }
    vsnprintf(sb->buf + sb->len, (size_t)n + 1, fmt, ap2);
    va_end(ap2);
    sb->len += (size_t)n;
}

/* JSON string with escaping. Bytes >= 0x80 are passed through (process
 * names are usually UTF-8); control characters become \u00XX. */
void cv_sb_json_str(cv_sb *sb, const char *s)
{
    cv_sb_putc(sb, '"');
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        switch (*p) {
        case '"':  cv_sb_puts(sb, "\\\""); break;
        case '\\': cv_sb_puts(sb, "\\\\"); break;
        case '\n': cv_sb_puts(sb, "\\n");  break;
        case '\r': cv_sb_puts(sb, "\\r");  break;
        case '\t': cv_sb_puts(sb, "\\t");  break;
        default:
            if (*p < 0x20) cv_sb_printf(sb, "\\u%04x", *p);
            else           cv_sb_putc(sb, (char)*p);
        }
    }
    cv_sb_putc(sb, '"');
}

/* ================= subject accumulator =================
 * Open addressing, linear probing, FNV-1a over (kind, id, name).
 */

static uint64_t fnv1a(uint64_t h, const void *data, size_t n)
{
    const unsigned char *p = data;
    for (size_t i = 0; i < n; i++) { h ^= p[i]; h *= 1099511628211ULL; }
    return h;
}

static uint64_t subj_hash(cv_subject_kind kind, int64_t id, const char *name)
{
    uint64_t h = 14695981039346656037ULL;
    int k = (int)kind;
    h = fnv1a(h, &k, sizeof k);
    h = fnv1a(h, &id, sizeof id);
    if (name) h = fnv1a(h, name, strlen(name));
    return h;
}

static bool subj_eq(const cv_subject *s, cv_subject_kind kind, int64_t id, const char *name)
{
    return s->kind == kind && s->id == id &&
           strcmp(s->name, name ? name : "") == 0;
}

cv_status cv_acc_init(cv_acc *a, size_t hint)
{
    memset(a, 0, sizeof *a);
    size_t cap = 64;
    while (cap < hint * 2) cap *= 2;
    a->slots = calloc(cap, sizeof *a->slots);
    if (!a->slots) return CV_E_NOMEM;
    a->cap = cap;
    return CV_OK;
}

void cv_acc_free(cv_acc *a)
{
    free(a->slots);
    memset(a, 0, sizeof *a);
}

static bool acc_grow(cv_acc *a)
{
    size_t ncap = a->cap * 2;
    cv_subject *n = calloc(ncap, sizeof *n);
    if (!n) return false;
    for (size_t i = 0; i < a->cap; i++) {
        cv_subject *s = &a->slots[i];
        if (!s->used) continue;
        size_t j = subj_hash(s->kind, s->id, s->name) & (ncap - 1);
        while (n[j].used) j = (j + 1) & (ncap - 1);
        n[j] = *s;
    }
    free(a->slots);
    a->slots = n;
    a->cap = ncap;
    return true;
}

cv_subject *cv_acc_find(const cv_acc *a, cv_subject_kind kind, int64_t id, const char *name)
{
    if (!a->slots) return NULL;
    size_t j = subj_hash(kind, id, name) & (a->cap - 1);
    while (a->slots[j].used) {
        if (subj_eq(&a->slots[j], kind, id, name)) return &a->slots[j];
        j = (j + 1) & (a->cap - 1);
    }
    return NULL;
}

cv_subject *cv_acc_mark(cv_acc *a, cv_subject_kind kind, int64_t id,
                        const char *name, cv_view view)
{
    if (a->oom) return NULL;
    cv_subject *s = cv_acc_find(a, kind, id, name);
    if (!s) {
        if ((a->count + 1) * 10 > a->cap * 7 && !acc_grow(a)) { a->oom = true; return NULL; }
        size_t j = subj_hash(kind, id, name) & (a->cap - 1);
        while (a->slots[j].used) j = (j + 1) & (a->cap - 1);
        s = &a->slots[j];
        s->used = true;
        s->kind = kind;
        s->id = id;
        snprintf(s->name, sizeof s->name, "%s", name ? name : "");
        s->seen_mask = 0;
        a->count++;
    }
    s->seen_mask |= CV_VIEW_BIT(view);
    return s;
}

/* ================= misc ================= */

uint64_t cv_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

cv_status cv_status_from_errno(int e)
{
    switch (e) {
    case 0:       return CV_OK;
    case ENOMEM:  return CV_E_NOMEM;
    case EACCES:
    case EPERM:   return CV_E_PERM;
    case ENOENT:
    case ENOSYS:
    case ENOTSUP: return CV_E_UNSUPPORTED;
    case EINVAL:  return CV_E_INVAL;
    default:      return CV_E_IO;
    }
}

int cv_parse_pid(const char *s, pid_t *out)
{
    if (!s || !*s) return 0;
    long v = 0;
    for (const char *p = s; *p; p++) {
        if (*p < '0' || *p > '9') return 0;
        v = v * 10 + (*p - '0');
        if (v > 0x7fffffff) return 0;
    }
    if (v <= 0) return 0;
    *out = (pid_t)v;
    return 1;
}
