/*
 * crossview.c — public API: config, context, scan orchestration,
 * recheck loop, host metadata, diagnostics.
 */
#include "internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#define CV_LIB_VERSION "0.1.0"
#define B(v) CV_VIEW_BIT(v)

/* ================= names ================= */

static const char *const VIEW_NAMES[CV_VIEW__COUNT] = {
    [CV_VIEW_PROC_READDIR] = "proc_readdir",  [CV_VIEW_PROC_GETDENTS] = "proc_getdents",
    [CV_VIEW_PID_KILL]     = "pid_kill",      [CV_VIEW_PID_STAT]      = "pid_stat",
    [CV_VIEW_PROC_MODULES] = "proc_modules",  [CV_VIEW_SYS_MODULE]    = "sys_module",
    [CV_VIEW_KERNEL_TAINT] = "kernel_taint",  [CV_VIEW_PROC_NET]      = "proc_net",
    [CV_VIEW_BIND_PROBE]   = "bind_probe",    [CV_VIEW_PRELOAD_LIBC]  = "preload_libc",
    [CV_VIEW_PRELOAD_RAW]  = "preload_raw",   [CV_VIEW_PROC_ENVIRON]  = "proc_environ",
    [CV_VIEW_PROC_MAPS]    = "proc_maps",     [CV_VIEW_SELF_SYMBOLS]  = "self_symbols",
};

const char *cv_view_name(cv_view v)
{
    return (unsigned)v < CV_VIEW__COUNT && VIEW_NAMES[v] ? VIEW_NAMES[v] : "unknown";
}

cv_check cv_view_check(cv_view v)
{
    switch (v) {
    case CV_VIEW_PROC_READDIR: case CV_VIEW_PROC_GETDENTS:
    case CV_VIEW_PID_KILL:     case CV_VIEW_PID_STAT:      return CV_CHECK_PROCESSES;
    case CV_VIEW_PROC_MODULES: case CV_VIEW_SYS_MODULE:
    case CV_VIEW_KERNEL_TAINT:                             return CV_CHECK_MODULES;
    case CV_VIEW_PROC_NET:     case CV_VIEW_BIND_PROBE:    return CV_CHECK_PORTS;
    default:                                               return CV_CHECK_PRELOAD;
    }
}

const char *cv_check_name(cv_check c)
{
    switch (c) {
    case CV_CHECK_PROCESSES: return "processes";
    case CV_CHECK_MODULES:   return "modules";
    case CV_CHECK_PORTS:     return "ports";
    case CV_CHECK_PRELOAD:   return "preload";
    default:                 return "unknown";
    }
}

const char *cv_strerror(cv_status s)
{
    switch (s) {
    case CV_OK:            return "ok";
    case CV_E_INVAL:       return "invalid argument";
    case CV_E_NOMEM:       return "out of memory";
    case CV_E_IO:          return "I/O error";
    case CV_E_PERM:        return "permission denied (run as root)";
    case CV_E_UNSUPPORTED: return "unsupported on this system";
    case CV_E_INTERNAL:    return "internal error";
    default:               return "unknown status";
    }
}

int         cv_abi_version(void) { return CV_ABI_VERSION; }
size_t      cv_config_size(void) { return sizeof(cv_config); }
const char *cv_version(void)     { return CV_LIB_VERSION; }
void        cv_free(void *p)     { free(p); }

/* ================= config / ctx ================= */

void cv_config_init(cv_config *cfg)
{
    if (!cfg) return;
    memset(cfg, 0, sizeof *cfg);
    cfg->struct_size      = sizeof *cfg;
    cfg->proc_root        = "/proc";
    cfg->sys_root         = "/sys";
    cfg->etc_root         = "/etc";
    cfg->pid_max          = 0;
    cfg->recheck_rounds   = 3;
    cfg->recheck_delay_ms = 50;
    cfg->port_protos      = CV_PROTO_TCP4 | CV_PROTO_TCP6;
    cfg->flags            = CV_F_SKIP_THREADS;
}

void cv_set_error(cv_ctx *ctx, const char *fmt, ...)
{
    if (!ctx) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(ctx->errbuf, sizeof ctx->errbuf, fmt, ap);
    va_end(ap);
}

const char *cv_last_error(const cv_ctx *ctx) { return ctx ? ctx->errbuf : ""; }

static int copy_root(char *dst, size_t n, const char *src, const char *def)
{
    const char *s = src && *src ? src : def;
    size_t len = strlen(s);
    while (len > 1 && s[len - 1] == '/') len--;      /* strip trailing slashes */
    if (len >= n) return -1;
    memcpy(dst, s, len);
    dst[len] = '\0';
    return 0;
}

cv_status cv_ctx_new(const cv_config *cfg, cv_ctx **out_ctx)
{
    if (!out_ctx) return CV_E_INVAL;
    *out_ctx = NULL;
    cv_ctx *ctx = calloc(1, sizeof *ctx);
    if (!ctx) return CV_E_NOMEM;

    cv_config_init(&ctx->cfg);
    if (cfg) {
        if (cfg->struct_size == 0 || cfg->struct_size > sizeof *cfg) { free(ctx); return CV_E_INVAL; }
        /* ABI growth: an older caller passes a smaller struct; fields it
         * doesn't know about keep their defaults. */
        memcpy(&ctx->cfg, cfg, cfg->struct_size);
        ctx->cfg.struct_size = sizeof ctx->cfg;
    }
    if (copy_root(ctx->proc_root, sizeof ctx->proc_root, ctx->cfg.proc_root, "/proc") ||
        copy_root(ctx->sys_root,  sizeof ctx->sys_root,  ctx->cfg.sys_root,  "/sys")  ||
        copy_root(ctx->etc_root,  sizeof ctx->etc_root,  ctx->cfg.etc_root,  "/etc")) {
        free(ctx);
        return CV_E_INVAL;
    }
    /* Don't keep caller-owned pointers past this call. */
    ctx->cfg.proc_root = ctx->proc_root;
    ctx->cfg.sys_root  = ctx->sys_root;
    ctx->cfg.etc_root  = ctx->etc_root;

    if (ctx->cfg.pid_max <= 0) {
        char path[640];
        snprintf(path, sizeof path, "%s/sys/kernel/pid_max", ctx->proc_root);
        FILE *f = fopen(path, "re");
        long v = 0;
        if (f) { if (fscanf(f, "%ld", &v) != 1) v = 0; fclose(f); }
        ctx->cfg.pid_max = v > 0 ? (pid_t)v : 32768;
    }
    if (ctx->cfg.recheck_rounds == 0) ctx->cfg.recheck_rounds = 1;
    *out_ctx = ctx;
    return CV_OK;
}

void cv_ctx_free(cv_ctx *ctx) { free(ctx); }

/* ================= host metadata ================= */

/* x86_64 kernels with the 2024 BHI change dispatch syscalls through
 * x64_sys_call() (a switch) instead of sys_call_table. Syscall-table hooks
 * are inert there, so we record which world a scan ran in. */
static const char *detect_dispatch(const cv_ctx *ctx)
{
#if defined(__x86_64__)
    char path[640];
    snprintf(path, sizeof path, "%s/kallsyms", ctx->proc_root);
    FILE *f = fopen(path, "re");
    if (!f) return "unknown";
    char line[512];
    int found = 0, any = 0;
    while (fgets(line, sizeof line, f)) {
        any = 1;
        char *sp = strrchr(line, ' ');
        if (!sp) continue;
        char *name = sp + 1;
        name[strcspn(name, "\t\n")] = '\0';
        if (strcmp(name, "x64_sys_call") == 0) { found = 1; break; }
    }
    fclose(f);
    if (!any) return "unknown";
    return found ? "switch" : "table";
#else
    (void)ctx;
    return "unknown";
#endif
}

static void fill_host(const cv_ctx *ctx, cv_report *r)
{
    struct utsname u;
    if (uname(&u) == 0) {
        snprintf(r->hostname, sizeof r->hostname, "%s", u.nodename);
        snprintf(r->kernel_release, sizeof r->kernel_release, "%s", u.release);
    }
    char path[640];
    snprintf(path, sizeof path, "%s/sys/kernel/random/boot_id", ctx->proc_root);
    FILE *f = fopen(path, "re");
    if (f) {
        if (fgets(r->boot_id, sizeof r->boot_id, f)) r->boot_id[strcspn(r->boot_id, "\n")] = '\0';
        fclose(f);
    }
    r->euid = (int)geteuid();
    r->syscall_dispatch = detect_dispatch(ctx);
}

/* ================= report helpers ================= */

cv_status cv_report_add(cv_report *r, const cv_finding *f)
{
    if (r->nfindings == r->capfindings) {
        size_t nc = r->capfindings ? r->capfindings * 2 : 16;
        cv_finding *n = realloc(r->findings, nc * sizeof *n);
        if (!n) return CV_E_NOMEM;
        r->findings = n;
        r->capfindings = nc;
    }
    r->findings[r->nfindings++] = *f;
    return CV_OK;
}

size_t cv_report_count(const cv_report *r) { return r ? r->nfindings : 0; }

const cv_finding *cv_report_get(const cv_report *r, size_t i)
{
    return r && i < r->nfindings ? &r->findings[i] : NULL;
}

cv_status cv_report_view_stats(const cv_report *r, cv_view v, cv_view_stats *out)
{
    if (!r || !out || (unsigned)v >= CV_VIEW__COUNT) return CV_E_INVAL;
    if (!r->stats_used[v]) return CV_E_UNSUPPORTED;    /* view wasn't run */
    *out = r->stats[v];
    return CV_OK;
}

void cv_report_free(cv_report *r)
{
    if (!r) return;
    free(r->findings);
    free(r);
}

/* ================= scan ================= */

typedef struct { cv_view view; cv_view_fn fn; } view_entry;

/* Listing views run before probe views: probe_hit() uses "already listed"
 * to skip the thread lookup for ordinary processes. */
static const view_entry PROCESS_VIEWS[] = {
    { CV_VIEW_PROC_READDIR,  cv_view_proc_readdir  },
    { CV_VIEW_PROC_GETDENTS, cv_view_proc_getdents },
    { CV_VIEW_PID_STAT,      cv_view_pid_stat      },
    { CV_VIEW_PID_KILL,      cv_view_pid_kill      },
};
static const view_entry MODULE_VIEWS[] = {
    { CV_VIEW_PROC_MODULES,  cv_view_proc_modules  },
    { CV_VIEW_SYS_MODULE,    cv_view_sys_module    },
    { CV_VIEW_KERNEL_TAINT,  cv_view_kernel_taint  },
};
static const view_entry PORT_VIEWS[] = {
    { CV_VIEW_PROC_NET,      cv_view_proc_net      },
    { CV_VIEW_BIND_PROBE,    cv_view_bind_probe    },
};
static const view_entry PRELOAD_VIEWS[] = {
    { CV_VIEW_PRELOAD_LIBC,  cv_view_preload_libc  },
    { CV_VIEW_PRELOAD_RAW,   cv_view_preload_raw   },
    { CV_VIEW_PROC_ENVIRON,  cv_view_proc_environ  },
    { CV_VIEW_SELF_SYMBOLS,  cv_view_self_symbols  },
};

#define N_OF(a) (sizeof (a) / sizeof (a)[0])

static void sleep_ms(uint32_t ms)
{
    struct timespec ts = { (time_t)(ms / 1000), (long)(ms % 1000) * 1000000L };
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {}
}

/*
 * Re-observe one candidate subject cheaply: re-run the cheap listing
 * views in full, and probe *only this subject* for the expensive views.
 * Returns the subject's fresh seen_mask.
 */
static uint32_t reobserve(cv_ctx *ctx, cv_check check, const cv_finding *f,
                          uint32_t ran, cv_acc *fresh)
{
    uint32_t mask = 0;
    const cv_subject *s = cv_acc_find(fresh, f->subject_kind, f->id,
                                      f->subject_kind == CV_SUBJ_PID ? NULL : f->name);
    if (s) mask = s->seen_mask;
    if (check == CV_CHECK_PROCESSES) {
        if ((ran & B(CV_VIEW_PID_STAT)) && cv_probe_stat(ctx, (pid_t)f->id)) mask |= B(CV_VIEW_PID_STAT);
        if ((ran & B(CV_VIEW_PID_KILL)) && cv_probe_kill(ctx, (pid_t)f->id)) mask |= B(CV_VIEW_PID_KILL);
    } else if (check == CV_CHECK_PORTS) {
        if ((ran & B(CV_VIEW_BIND_PROBE)) && cv_probe_bind(ctx, (int)f->id, f->name))
            mask |= B(CV_VIEW_BIND_PROBE);
    }
    return mask;
}

/* Views that are cheap to re-run in full during rechecks. */
static int is_cheap(cv_view v)
{
    return v != CV_VIEW_PID_KILL && v != CV_VIEW_PID_STAT && v != CV_VIEW_BIND_PROBE;
}

static cv_status run_check(cv_ctx *ctx, cv_report *r, cv_check check,
                           const view_entry *views, size_t nviews,
                           int racy, int *any_ok)
{
    cv_acc acc;
    cv_status st = cv_acc_init(&acc, 1024);
    if (st) return st;

    /* ---- round 1: every view, full sweep ---- */
    uint32_t ran = 0;
    for (size_t i = 0; i < nviews; i++) {
        cv_view v = views[i].view;
        if (v == CV_VIEW_BIND_PROBE && !(ctx->cfg.flags & CV_F_BIND_PROBE)) continue;
        cv_view_stats *vs = &r->stats[v];
        memset(vs, 0, sizeof *vs);
        r->stats_used[v] = true;
        if (views[i].fn(ctx, &acc, vs) == CV_OK) { ran |= B(v); *any_ok = 1; }
    }
    if (acc.oom) { cv_acc_free(&acc); return CV_E_NOMEM; }

    /* ---- classify ---- */
    cv_finding *cand = NULL;
    size_t ncand = 0, capcand = 0;
    for (size_t i = 0; i < acc.cap; i++) {
        const cv_subject *s = &acc.slots[i];
        if (!s->used) continue;
        cv_finding f;
        if (!cv_classify(check, s, ran, &f)) continue;
        f.confirmations = 1;
        if (ncand == capcand) {
            capcand = capcand ? capcand * 2 : 16;
            cv_finding *n = realloc(cand, capcand * sizeof *n);
            if (!n) { free(cand); cv_acc_free(&acc); return CV_E_NOMEM; }
            cand = n;
        }
        cand[ncand++] = f;
    }
    cv_acc_free(&acc);

    /* ---- rechecks: a mismatch must hold in every round ---- */
    uint32_t rounds = racy ? ctx->cfg.recheck_rounds : 1;
    for (uint32_t round = 1; round < rounds && ncand > 0; round++) {
        sleep_ms(ctx->cfg.recheck_delay_ms);
        cv_acc fresh;
        if (cv_acc_init(&fresh, 1024)) break;
        for (size_t i = 0; i < nviews; i++) {
            cv_view v = views[i].view;
            if (!(ran & B(v)) || !is_cheap(v)) continue;
            cv_view_stats scratch = { 0 };
            views[i].fn(ctx, &fresh, &scratch);
        }
        size_t keep = 0;
        for (size_t c = 0; c < ncand; c++) {
            cv_subject s = { 0 };
            s.kind = cand[c].subject_kind;
            s.id = cand[c].id;
            snprintf(s.name, sizeof s.name, "%s", cand[c].subject_kind == CV_SUBJ_PID ? "" : cand[c].name);
            s.used = true;
            s.seen_mask = reobserve(ctx, check, &cand[c], ran, &fresh);
            cv_finding again;
            if (cv_classify(check, &s, ran, &again) && again.layer == cand[c].layer) {
                cand[c].confirmations++;
                cand[keep++] = cand[c];
            }
        }
        ncand = keep;
        cv_acc_free(&fresh);
    }

    /* ---- commit ---- */
    for (size_t c = 0; c < ncand && st == CV_OK; c++) {
        if (cand[c].subject_kind == CV_SUBJ_PID)
            cv_read_comm(ctx, (pid_t)cand[c].id, cand[c].name, sizeof cand[c].name);
        st = cv_report_add(r, &cand[c]);
    }
    free(cand);
    return st;
}

cv_status cv_scan(cv_ctx *ctx, uint32_t checks, cv_report **out_report)
{
    if (!ctx || !out_report) return CV_E_INVAL;
    *out_report = NULL;
    if (checks == 0 || (checks & ~(uint32_t)CV_CHECK_ALL)) {
        cv_set_error(ctx, "checks mask 0x%x is empty or has unknown bits", checks);
        return CV_E_INVAL;
    }
    cv_report *r = calloc(1, sizeof *r);
    if (!r) return CV_E_NOMEM;

    time_t now = time(NULL);
    struct tm tm;
    gmtime_r(&now, &tm);
    strftime(r->started_at, sizeof r->started_at, "%Y-%m-%dT%H:%M:%SZ", &tm);
    uint64_t t0 = cv_now_ns();

    r->checks = checks;
    r->pid_max = ctx->cfg.pid_max;
    r->recheck_rounds = ctx->cfg.recheck_rounds;
    r->recheck_delay_ms = ctx->cfg.recheck_delay_ms;
    r->port_protos = ctx->cfg.port_protos;
    r->flags = ctx->cfg.flags;
    fill_host(ctx, r);

    int any_ok = 0;
    cv_status st = CV_OK;
    if (st == CV_OK && (checks & CV_CHECK_PROCESSES))
        st = run_check(ctx, r, CV_CHECK_PROCESSES, PROCESS_VIEWS, N_OF(PROCESS_VIEWS), 1, &any_ok);
    if (st == CV_OK && (checks & CV_CHECK_MODULES))
        st = run_check(ctx, r, CV_CHECK_MODULES, MODULE_VIEWS, N_OF(MODULE_VIEWS), 0, &any_ok);
    if (st == CV_OK && (checks & CV_CHECK_PORTS))
        st = run_check(ctx, r, CV_CHECK_PORTS, PORT_VIEWS, N_OF(PORT_VIEWS), 1, &any_ok);
    if (st == CV_OK && (checks & CV_CHECK_PRELOAD))
        st = run_check(ctx, r, CV_CHECK_PRELOAD, PRELOAD_VIEWS, N_OF(PRELOAD_VIEWS), 0, &any_ok);

    r->duration_ms = (double)(cv_now_ns() - t0) / 1e6;

    if (st != CV_OK) { cv_report_free(r); return st; }
    if (!any_ok) {
        cv_set_error(ctx, "every requested view failed (last: %s)", ctx->errbuf);
        cv_report_free(r);
        return CV_E_IO;
    }
    *out_report = r;
    return CV_OK;
}
