/*
 * internal.h — private structures shared by the libcrossview translation
 * units. NOT installed, NOT part of the public ABI. Tests include it to
 * exercise the diff engine directly with synthetic view results.
 */
#ifndef CV_INTERNAL_H
#define CV_INTERNAL_H

#include "libcrossview.h"
#include <stdbool.h>
#include <stdarg.h>

/* ---------- growable string buffer (used for JSON) ---------- */
typedef struct {
    char  *buf;
    size_t len;
    size_t cap;
    bool   oom;        /* sticky: once an allocation fails, everything no-ops */
} cv_sb;

void cv_sb_init(cv_sb *sb);
void cv_sb_free(cv_sb *sb);
void cv_sb_putc(cv_sb *sb, char c);
void cv_sb_puts(cv_sb *sb, const char *s);
void cv_sb_printf(cv_sb *sb, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void cv_sb_json_str(cv_sb *sb, const char *s);   /* writes "..." with escaping */

/* ---------- subject accumulator ----------
 * One entry per distinct subject (a PID, a module name, a port, ...).
 * Every view that reports a subject ORs its bit into seen_mask.
 * After all views run, a subject seen by some-but-not-all of the views
 * that ran successfully is a cross-view mismatch.
 */
typedef struct {
    cv_subject_kind kind;
    int64_t         id;
    char            name[CV_NAME_MAX];
    uint32_t        seen_mask;
    bool            used;
} cv_subject;

typedef struct {
    cv_subject *slots;
    size_t      cap;       /* power of two */
    size_t      count;
    bool        oom;
} cv_acc;

cv_status   cv_acc_init(cv_acc *a, size_t hint);
void        cv_acc_free(cv_acc *a);
/* Mark `view` as having seen this subject. name may be NULL. */
cv_subject *cv_acc_mark(cv_acc *a, cv_subject_kind kind, int64_t id,
                        const char *name, cv_view view);
cv_subject *cv_acc_find(const cv_acc *a, cv_subject_kind kind, int64_t id,
                        const char *name);

/* ---------- report internals ---------- */
struct cv_report {
    cv_finding   *findings;
    size_t        nfindings;
    size_t        capfindings;

    cv_view_stats stats[CV_VIEW__COUNT];
    bool          stats_used[CV_VIEW__COUNT];

    uint32_t      checks;
    char          started_at[32];   /* RFC 3339, UTC */
    double        duration_ms;

    /* host */
    char          hostname[256];
    char          kernel_release[128];
    char          boot_id[64];
    int           euid;
    const char   *syscall_dispatch;  /* static: "table" | "switch" | "unknown" */

    /* config snapshot */
    pid_t         pid_max;
    uint32_t      recheck_rounds;
    uint32_t      recheck_delay_ms;
    uint32_t      port_protos;
    uint32_t      flags;
};

cv_status cv_report_add(cv_report *r, const cv_finding *f);

struct cv_ctx {
    cv_config cfg;
    char      proc_root[512];
    char      sys_root[512];
    char      etc_root[512];
    char      errbuf[512];
};

void cv_set_error(cv_ctx *ctx, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

/* ---------- views ----------
 * Each view fills the accumulator and its stats slot. A view's failure is
 * recorded in stats and returned; the caller decides whether to continue.
 */
typedef cv_status (*cv_view_fn)(cv_ctx *ctx, cv_acc *acc, cv_view_stats *st);

cv_status cv_view_proc_readdir (cv_ctx *, cv_acc *, cv_view_stats *);
cv_status cv_view_proc_getdents(cv_ctx *, cv_acc *, cv_view_stats *);
cv_status cv_view_pid_kill     (cv_ctx *, cv_acc *, cv_view_stats *);
cv_status cv_view_pid_stat     (cv_ctx *, cv_acc *, cv_view_stats *);

cv_status cv_view_proc_modules (cv_ctx *, cv_acc *, cv_view_stats *);
cv_status cv_view_sys_module   (cv_ctx *, cv_acc *, cv_view_stats *);
cv_status cv_view_kernel_taint (cv_ctx *, cv_acc *, cv_view_stats *);

cv_status cv_view_proc_net     (cv_ctx *, cv_acc *, cv_view_stats *);
cv_status cv_view_bind_probe   (cv_ctx *, cv_acc *, cv_view_stats *);

cv_status cv_view_preload_libc (cv_ctx *, cv_acc *, cv_view_stats *);
cv_status cv_view_preload_raw  (cv_ctx *, cv_acc *, cv_view_stats *);
cv_status cv_view_proc_environ (cv_ctx *, cv_acc *, cv_view_stats *);
cv_status cv_view_self_symbols (cv_ctx *, cv_acc *, cv_view_stats *);

/* Single-subject probes, used by the recheck loop so re-verifying a
 * candidate costs one syscall instead of another full sweep. */
int cv_probe_kill(const cv_ctx *ctx, pid_t pid);            /* 1 alive, 0 not */
int cv_probe_stat(const cv_ctx *ctx, pid_t pid);            /* 1 present, 0 not */
int cv_probe_bind(const cv_ctx *ctx, int port, const char *proto); /* 1 busy */
void cv_read_comm(const cv_ctx *ctx, pid_t pid, char *out, size_t n);

/* Which check a view belongs to. */
cv_check cv_view_check(cv_view v);

/* Resolve a TID to its thread-group id via <proc_root>/<tid>/status.
 * Returns the tgid, or -1 if unreadable. */
pid_t cv_tid_to_tgid(const cv_ctx *ctx, pid_t tid);

/* ---------- diff engine ----------
 * Classify one subject given which views ran OK (ran_mask). Fills `out`
 * and returns true if this subject is a finding. Pure function: no I/O,
 * so unit tests drive it with hand-built masks.
 */
bool cv_classify(cv_check check, const cv_subject *s, uint32_t ran_mask,
                 cv_finding *out);

/* ---------- misc ---------- */
uint64_t  cv_now_ns(void);
cv_status cv_status_from_errno(int e);
int       cv_parse_pid(const char *s, pid_t *out);   /* 1 if all-digit name */

#endif /* CV_INTERNAL_H */
