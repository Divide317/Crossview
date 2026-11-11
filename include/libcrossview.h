/*
 * libcrossview.h — public C API for the cross-view rootkit detector.
 *
 * STATUS: v0 design draft (Branch 01, week 0). No implementation yet.
 *
 * Idea: ask the OS the same question through several independent "views"
 * and diff the answers. A subject (PID, module, port, preload object) that
 * shows up in some views but not others is evidence. *Which* views disagree
 * tells you *where* the lie is (libc / LD_PRELOAD layer vs kernel layer).
 *
 * Boundary contract (C <-> Python ctypes):
 *   - C callers use the typed accessors (cv_report_get, cv_report_view_stats).
 *   - Python only calls the small FFI surface marked [FFI] and receives the
 *     report as JSON (schema: schema/crossview-report.schema.json), so
 *     Python never has to mirror cv_finding in ctypes.
 *
 * Memory ownership — one rule: the library allocates, the library frees.
 *   cv_ctx      created by cv_ctx_new        -> freed by cv_ctx_free
 *   cv_report   created by cv_scan           -> freed by cv_report_free
 *   JSON buffer created by cv_report_to_json -> freed by cv_free
 *   const char* returned by cv_*_name / cv_strerror / cv_version: static,
 *               never free.
 *   const char* from cv_last_error: borrowed, valid until the next call on
 *               that ctx.
 *   const cv_finding* from cv_report_get: borrowed, valid until
 *               cv_report_free.
 *
 * Threading: a cv_ctx is not thread-safe. Use one ctx per thread.
 * Scans are synchronous and blocking.
 *
 * Errors: every fallible function returns cv_status (0 = OK, < 0 = error).
 * A view that fails (e.g. EPERM) does NOT fail the whole scan; its failure
 * is recorded in that view's cv_view_stats and the scan continues.
 */
#ifndef LIBCROSSVIEW_H
#define LIBCROSSVIEW_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Build with -fvisibility=hidden; only CV_API symbols are exported. */
#if defined(__GNUC__) || defined(__clang__)
#  define CV_API __attribute__((visibility("default")))
#else
#  define CV_API
#endif

#define CV_ABI_VERSION     0        /* bump on any breaking change to this header */
#define CV_SCHEMA_VERSION  "0.1.0"  /* JSON report schema version (semver) */
#define CV_NAME_MAX        256
#define CV_DETAIL_MAX      512   /* room for a CV_NAME_MAX name plus the explanation */

/* ------------------------------------------------------------------ */
/* Status codes                                                        */
/* ------------------------------------------------------------------ */
typedef enum {
    CV_OK             =  0,
    CV_E_INVAL        = -1,  /* bad argument / bad config */
    CV_E_NOMEM        = -2,
    CV_E_IO           = -3,  /* a read failed; see cv_last_error() */
    CV_E_PERM         = -4,  /* needs root or a capability */
    CV_E_UNSUPPORTED  = -5,  /* view not available on this kernel/arch */
    CV_E_INTERNAL     = -6
} cv_status;

/* ------------------------------------------------------------------ */
/* Checks (what question is asked) — bitmask                           */
/* ------------------------------------------------------------------ */
typedef enum {
    CV_CHECK_PROCESSES = 1u << 0,   /* which processes exist?           */
    CV_CHECK_MODULES   = 1u << 1,   /* which kernel modules are loaded? */
    CV_CHECK_PORTS     = 1u << 2,   /* which ports are in use?          */
    CV_CHECK_PRELOAD   = 1u << 3,   /* is a library being injected?     */
    CV_CHECK_ALL       = 0xFu
} cv_check;

/* ------------------------------------------------------------------ */
/* Views (how the question is asked). Order within a check goes from   */
/* "easiest to fake" to "hardest to fake".                             */
/* ------------------------------------------------------------------ */
typedef enum {
    /* processes */
    CV_VIEW_PROC_READDIR = 0, /* libc opendir()/readdir() on /proc — what ps(1) sees.
                                 Subject to LD_PRELOAD and libc hooks.               */
    CV_VIEW_PROC_GETDENTS,    /* raw syscall(SYS_getdents64) on an fd for /proc.
                                 Bypasses libc; still subject to kernel hooks.        */
    CV_VIEW_PID_KILL,         /* raw syscall(SYS_kill, pid, 0) for pid in 1..pid_max.
                                 0 or EPERM = exists; ESRCH = doesn't.
                                 Never touches /proc directory listing at all.        */
    CV_VIEW_PID_STAT,         /* raw fstatat on "/proc/<pid>" — a direct lookup,
                                 not a listing, so getdents hooks don't apply.        */

    /* modules */
    CV_VIEW_PROC_MODULES,     /* /proc/modules (walks the kernel's module list)      */
    CV_VIEW_SYS_MODULE,       /* /sys/module/<name>/initstate exists. Only loadable
                                 modules have initstate; built-ins are skipped.       */
    CV_VIEW_KERNEL_TAINT,     /* /proc/sys/kernel/tainted vs per-module
                                 /sys/module/<name>/taint. Weak: taint is sticky
                                 after rmmod.                                         */

    /* ports */
    CV_VIEW_PROC_NET,         /* /proc/net/{tcp,tcp6,udp,udp6}, ALL socket states    */
    CV_VIEW_BIND_PROBE,       /* bind() each port without SO_REUSEADDR;
                                 EADDRINUSE = something holds it.                     */

    /* preload / injection */
    CV_VIEW_PRELOAD_LIBC,     /* /etc/ld.so.preload read via libc fopen()            */
    CV_VIEW_PRELOAD_RAW,      /* /etc/ld.so.preload read via raw openat/read          */
    CV_VIEW_PROC_ENVIRON,     /* LD_PRELOAD in /proc/<pid>/environ (needs root)      */
    CV_VIEW_PROC_MAPS,        /* shared objects in /proc/<pid>/maps (needs root)     */
    CV_VIEW_SELF_SYMBOLS,     /* dlsym(RTLD_DEFAULT, "readdir") etc. + dladdr():
                                 which .so actually provides these symbols in *this*
                                 process? Anything other than libc.so.6 = interposed. */

    CV_VIEW__COUNT
} cv_view;

#define CV_VIEW_BIT(v) (1u << (unsigned)(v))   /* cv_view -> bit in a view mask */

/* ------------------------------------------------------------------ */
/* Findings                                                            */
/* ------------------------------------------------------------------ */
typedef enum {
    CV_SUBJ_PID = 0,   /* id = pid,  name = comm (if readable)                   */
    CV_SUBJ_MODULE,    /* id = 0,    name = module name                          */
    CV_SUBJ_PORT,      /* id = port, name = "tcp" | "tcp6" | "udp" | "udp6"      */
    CV_SUBJ_FILE,      /* id = 0,    name = path (e.g. /etc/ld.so.preload)       */
    CV_SUBJ_SYMBOL     /* id = 0,    name = "readdir@/usr/local/lib/evil.so"     */
} cv_subject_kind;

/* Where the lie is, inferred from which views disagree. */
typedef enum {
    CV_LAYER_NONE = 0,   /* views agree (not reported as a finding)               */
    CV_LAYER_USERSPACE,  /* libc view differs from raw-syscall view -> LD_PRELOAD
                            or libc hook                                           */
    CV_LAYER_KERNEL,     /* raw listing differs from direct probe -> kernel hook
                            or kernel object manipulation (DKOM)                   */
    CV_LAYER_UNKNOWN     /* inconsistent pattern; report, don't explain           */
} cv_layer;

typedef enum { CV_CONF_LOW = 0, CV_CONF_MEDIUM, CV_CONF_HIGH } cv_confidence;

/* MISMATCH: views disagree (the core cross-view signal).
 * INDICATOR: views agree, but what they agree on is suspicious by itself
 *            (e.g. a non-empty /etc/ld.so.preload, an interposed readdir). */
typedef enum { CV_FIND_MISMATCH = 0, CV_FIND_INDICATOR } cv_finding_type;

/*
 * Plain-old-data: no owned pointers, so it can be copied freely and freed
 * with the report. Fixed-size arrays keep the ctypes mirror trivial if you
 * ever need it.
 */
typedef struct {
    cv_finding_type type;
    cv_check        check;
    cv_subject_kind subject_kind;
    int64_t         id;                    /* see cv_subject_kind            */
    char            name[CV_NAME_MAX];     /* NUL-terminated, may be ""      */
    uint32_t        queried;               /* view mask: views consulted      */
    uint32_t        seen_in;               /* view mask: views that saw it    */
    cv_layer        layer;
    cv_confidence   confidence;
    uint32_t        confirmations;         /* re-checks the mismatch survived */
    const char     *attack_ids;            /* static, e.g. "T1014"; never free */
    char            detail[CV_DETAIL_MAX]; /* one-line human explanation      */
} cv_finding;

/* Per-view measurements: feeds the evaluation table (time-to-detect,
 * overhead) and explains gaps (a view that hit EPERM saw nothing). */
typedef struct {
    cv_view   view;
    cv_status status;       /* CV_OK, or why this view failed               */
    int       sys_errno;    /* errno at failure, 0 if none                  */
    uint64_t  entries;      /* subjects this view reported                  */
    uint64_t  elapsed_ns;   /* wall time spent in this view                 */
} cv_view_stats;

/* ------------------------------------------------------------------ */
/* Configuration                                                       */
/* ------------------------------------------------------------------ */
#define CV_F_SKIP_THREADS   (1u << 0)  /* resolve TIDs to their TGID before diffing
                                          (default ON; turning it off floods you with
                                          false positives — threads exist in /proc/<tid>
                                          but are not listed by readdir(/proc))       */
#define CV_F_BIND_PROBE     (1u << 1)  /* opt-in: run the slow bind() port probe.
                                          Without it the ports check has only one
                                          view and can't produce mismatches.         */

#define CV_PROTO_TCP4  (1u << 0)
#define CV_PROTO_TCP6  (1u << 1)
#define CV_PROTO_UDP4  (1u << 2)
#define CV_PROTO_UDP6  (1u << 3)

/* Test seam: lets C unit tests simulate "this PID exists but is hidden"
 * without a real rootkit. Leave NULL in production and from Python.
 * Return 1 = alive, 0 = not alive, <0 = -errno. */
typedef int (*cv_pid_probe_fn)(pid_t pid, void *user);

typedef struct {
    uint32_t        struct_size;      /* MUST be sizeof(cv_config); lets the struct
                                         grow later without breaking old callers   */
    const char     *proc_root;        /* default "/proc"; point at a fixture tree in tests */
    const char     *sys_root;         /* default "/sys"  */
    const char     *etc_root;         /* default "/etc"  */
    pid_t           pid_max;          /* 0 = read <proc_root>/sys/kernel/pid_max  */
    uint32_t        recheck_rounds;   /* re-verify each mismatch N times (default 3)
                                         to filter races with short-lived processes */
    uint32_t        recheck_delay_ms; /* delay between rounds (default 50)         */
    uint32_t        port_protos;      /* CV_PROTO_* mask (default TCP4|TCP6)       */
    uint32_t        flags;            /* CV_F_* (default CV_F_SKIP_THREADS)        */
    cv_pid_probe_fn pid_probe;        /* test seam, NULL = real syscall            */
    void           *pid_probe_user;
} cv_config;

typedef struct cv_ctx    cv_ctx;      /* opaque */
typedef struct cv_report cv_report;   /* opaque */

/* ------------------------------------------------------------------ */
/* Lifecycle                                                           */
/* ------------------------------------------------------------------ */
CV_API void       cv_config_init(cv_config *cfg);                          /* [FFI] fill defaults */
CV_API cv_status  cv_ctx_new(const cv_config *cfg, cv_ctx **out_ctx);      /* [FFI] cfg may be NULL = defaults */
CV_API void       cv_ctx_free(cv_ctx *ctx);                                /* [FFI] NULL-safe */

/* ------------------------------------------------------------------ */
/* Scanning                                                            */
/* ------------------------------------------------------------------ */
/* Runs every check in `checks` (cv_check mask). Returns CV_OK even if some
 * views failed — inspect cv_report_view_stats. Fails only on bad args,
 * OOM, or if *every* requested view failed. */
CV_API cv_status  cv_scan(cv_ctx *ctx, uint32_t checks, cv_report **out_report); /* [FFI] */

/* ------------------------------------------------------------------ */
/* Reading a report — typed (C)                                        */
/* ------------------------------------------------------------------ */
CV_API size_t            cv_report_count(const cv_report *r);
CV_API const cv_finding *cv_report_get(const cv_report *r, size_t i);     /* borrowed; NULL if out of range */
CV_API cv_status         cv_report_view_stats(const cv_report *r, cv_view v, cv_view_stats *out);

/* ------------------------------------------------------------------ */
/* Reading a report — JSON (Python)                                    */
/* ------------------------------------------------------------------ */
/* *out_json is malloc'd by the library, NUL-terminated, length in *out_len
 * (excluding NUL). Free it with cv_free(), never with Python or another
 * allocator. */
CV_API cv_status  cv_report_to_json(const cv_report *r, char **out_json, size_t *out_len); /* [FFI] */
CV_API void       cv_report_free(cv_report *r);                            /* [FFI] NULL-safe */
CV_API void       cv_free(void *p);                                        /* [FFI] NULL-safe */

/* ------------------------------------------------------------------ */
/* Diagnostics                                                         */
/* ------------------------------------------------------------------ */
CV_API const char *cv_last_error(const cv_ctx *ctx);   /* [FFI] borrowed */
CV_API const char *cv_strerror(cv_status s);           /* static */
CV_API const char *cv_view_name(cv_view v);            /* static, matches JSON enum, e.g. "proc_getdents" */
CV_API const char *cv_check_name(cv_check c);          /* static, e.g. "processes" */
CV_API int         cv_abi_version(void);               /* [FFI] Python asserts == CV_ABI_VERSION */
CV_API size_t      cv_config_size(void);               /* [FFI] Python asserts == ctypes.sizeof(its mirror) */
CV_API const char *cv_version(void);                   /* [FFI] library semver */

#ifdef __cplusplus
}
#endif
#endif /* LIBCROSSVIEW_H */
