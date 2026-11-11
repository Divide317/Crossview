/*
 * views.c — every "view" libcrossview uses to ask the OS a question.
 *
 * A view is one independent way of answering a question like "which PIDs
 * exist?". Each view records what it saw in the shared accumulator; the
 * diff engine (classify.c) then compares views. The value of the design is
 * that the views go through *different code paths*, so a rootkit that
 * tampers with one path leaves a visible gap against the others.
 *
 *   libc wrapper  ─┐  (LD_PRELOAD / libc hooks act here)
 *                  ▼
 *   raw syscall   ─┐  (kernel syscall hooks act here)
 *                  ▼
 *   kernel object      (direct lookups / probes ask the object itself)
 */
#include "internal.h"

#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

/* ================================================================== */
/* Raw-syscall helpers: bypass libc entirely so LD_PRELOAD can't touch */
/* ================================================================== */

/* Layout the kernel writes for getdents64 (see getdents64(2)). */
struct cv_linux_dirent64 {
    uint64_t d_ino;
    int64_t  d_off;
    unsigned short d_reclen;
    unsigned char  d_type;
    char     d_name[];
};

static int raw_open(const char *path, int flags)
{
    return (int)syscall(SYS_openat, AT_FDCWD, path, flags | O_CLOEXEC, 0);
}

static void raw_close(int fd)
{
    if (fd >= 0) syscall(SYS_close, fd);
}

/* Read up to n-1 bytes of a small file via raw syscalls; NUL-terminates.
 * Returns bytes read, or -errno. */
static ssize_t raw_read_file(const char *path, char *buf, size_t n)
{
    int fd = raw_open(path, O_RDONLY);
    if (fd < 0) return -errno;
    size_t off = 0;
    while (off + 1 < n) {
        long r = syscall(SYS_read, fd, buf + off, n - 1 - off);
        if (r < 0) { if (errno == EINTR) continue; int e = errno; raw_close(fd); return -e; }
        if (r == 0) break;
        off += (size_t)r;
    }
    buf[off] = '\0';
    raw_close(fd);
    return (ssize_t)off;
}

typedef void (*dent_cb)(const char *name, unsigned char d_type, void *user);

/* Iterate a directory with raw getdents64. Returns 0 or -errno. */
static int raw_getdents_each(const char *dir, dent_cb cb, void *user)
{
    int fd = raw_open(dir, O_RDONLY | O_DIRECTORY);
    if (fd < 0) return -errno;
    char buf[32768] __attribute__((aligned(8)));
    for (;;) {
        long n = syscall(SYS_getdents64, fd, buf, sizeof buf);
        if (n < 0) { if (errno == EINTR) continue; int e = errno; raw_close(fd); return -e; }
        if (n == 0) break;
        for (long off = 0; off < n;) {
            struct cv_linux_dirent64 *d = (struct cv_linux_dirent64 *)(void *)(buf + off);
            if (d->d_reclen == 0) break;   /* defensive: malformed buffer */
            cb(d->d_name, d->d_type, user);
            off += d->d_reclen;
        }
    }
    raw_close(fd);
    return 0;
}

static void path_join(char *out, size_t n, const char *a, const char *b)
{
    snprintf(out, n, "%s/%s", a, b);
}

/* Finish a view's stats from an errno-style result. */
static cv_status view_done(cv_ctx *ctx, cv_view_stats *st, cv_view v,
                           int err, uint64_t t0, const char *what)
{
    st->view = v;
    st->elapsed_ns = cv_now_ns() - t0;
    st->sys_errno = err;
    st->status = cv_status_from_errno(err);
    if (err) cv_set_error(ctx, "%s: %s", what, strerror(err));
    return st->status;
}

/* ================================================================== */
/* Processes                                                           */
/* ================================================================== */

pid_t cv_tid_to_tgid(const cv_ctx *ctx, pid_t tid)
{
    char path[640], buf[4096];
    snprintf(path, sizeof path, "%s/%d/status", ctx->proc_root, (int)tid);
    if (raw_read_file(path, buf, sizeof buf) <= 0) return -1;
    const char *p = strstr(buf, "\nTgid:");
    if (!p) return -1;
    p += 6;
    while (*p == ' ' || *p == '\t') p++;
    long v = strtol(p, NULL, 10);
    return v > 0 ? (pid_t)v : -1;
}

/*
 * VIEW proc_readdir — libc opendir()/readdir() on /proc.
 * This is exactly what ps(1), top(1) and most scanners do. An LD_PRELOAD
 * library that overrides readdir() (libprocesshider) changes this view and
 * only this view.
 */
cv_status cv_view_proc_readdir(cv_ctx *ctx, cv_acc *acc, cv_view_stats *st)
{
    uint64_t t0 = cv_now_ns();
    DIR *d = opendir(ctx->proc_root);
    if (!d) return view_done(ctx, st, CV_VIEW_PROC_READDIR, errno, t0, "opendir(proc)");
    struct dirent *e;
    errno = 0;
    while ((e = readdir(d)) != NULL) {
        pid_t pid;
        if (cv_parse_pid(e->d_name, &pid)) {
            cv_acc_mark(acc, CV_SUBJ_PID, pid, NULL, CV_VIEW_PROC_READDIR);
            st->entries++;
        }
    }
    int err = errno;
    closedir(d);
    return view_done(ctx, st, CV_VIEW_PROC_READDIR, err, t0, "readdir(proc)");
}

/*
 * VIEW proc_getdents — raw syscall(SYS_getdents64) on /proc.
 * Skips libc, so LD_PRELOAD can't filter it. A kernel rootkit that hooks
 * getdents64 (Diamorphine on table-dispatch kernels) still changes it.
 */
struct getdents_pid_ctx { cv_acc *acc; cv_view_stats *st; };

static void getdents_pid_cb(const char *name, unsigned char t, void *u)
{
    (void)t;
    struct getdents_pid_ctx *c = u;
    pid_t pid;
    if (cv_parse_pid(name, &pid)) {
        cv_acc_mark(c->acc, CV_SUBJ_PID, pid, NULL, CV_VIEW_PROC_GETDENTS);
        c->st->entries++;
    }
}

cv_status cv_view_proc_getdents(cv_ctx *ctx, cv_acc *acc, cv_view_stats *st)
{
    uint64_t t0 = cv_now_ns();
    struct getdents_pid_ctx c = { acc, st };
    int r = raw_getdents_each(ctx->proc_root, getdents_pid_cb, &c);
    return view_done(ctx, st, CV_VIEW_PROC_GETDENTS, r < 0 ? -r : 0, t0, "getdents64(proc)");
}

/*
 * A probe hit for `pid`. Probes (kill/stat) also hit *threads*: every TID
 * answers kill(tid, 0) and has a /proc/<tid> entry, but readdir(/proc)
 * only lists thread-group leaders. Without this filter every thread on
 * the box looks like a hidden process.
 */
static void probe_hit(cv_ctx *ctx, cv_acc *acc, cv_view_stats *st, pid_t pid, cv_view v)
{
    if (ctx->cfg.flags & CV_F_SKIP_THREADS) {
        /* Already listed by a listing view => it's a TGID, no lookup needed. */
        const cv_subject *s = cv_acc_find(acc, CV_SUBJ_PID, pid, NULL);
        uint32_t listing = CV_VIEW_BIT(CV_VIEW_PROC_READDIR) | CV_VIEW_BIT(CV_VIEW_PROC_GETDENTS);
        if (!s || !(s->seen_mask & listing)) {
            pid_t tgid = cv_tid_to_tgid(ctx, pid);
            /* tgid unreadable (-1): keep it. Being conservative here costs a
             * possible race false positive, which the recheck loop removes. */
            if (tgid > 0 && tgid != pid) return;   /* it's a thread */
        }
    }
    cv_acc_mark(acc, CV_SUBJ_PID, pid, NULL, v);
    st->entries++;
}

static pid_t effective_pid_max(const cv_ctx *ctx)
{
    return ctx->cfg.pid_max > 0 ? ctx->cfg.pid_max : 32768;
}

/*
 * VIEW pid_kill — brute force: raw syscall(SYS_kill, pid, 0) for every
 * possible PID. Signal 0 delivers nothing; it only asks "does this PID
 * exist and may I signal it?". 0 or EPERM => exists; ESRCH => doesn't.
 * Never lists /proc at all, so getdents hooks can't affect it. A rootkit
 * has to also hook kill() to beat this view (see LIMITATIONS.md).
 */
cv_status cv_view_pid_kill(cv_ctx *ctx, cv_acc *acc, cv_view_stats *st)
{
    uint64_t t0 = cv_now_ns();
    pid_t max = effective_pid_max(ctx);
    for (pid_t pid = 1; pid < max; pid++) {
        int alive;
        if (ctx->cfg.pid_probe) {
            int r = ctx->cfg.pid_probe(pid, ctx->cfg.pid_probe_user);
            alive = (r == 1);
        } else {
            long r = syscall(SYS_kill, pid, 0);
            alive = (r == 0 || errno == EPERM);
        }
        if (alive) probe_hit(ctx, acc, st, pid, CV_VIEW_PID_KILL);
    }
    return view_done(ctx, st, CV_VIEW_PID_KILL, 0, t0, "kill-probe");
}

/*
 * VIEW pid_stat — fstatat(proc_fd, "<pid>") for every possible PID.
 * A *lookup* of one name, not a *listing*: the kernel resolves /proc/<pid>
 * through a different path (proc_pid_lookup) than getdents
 * (proc_pid_readdir), so getdents-only hiding leaves this view intact.
 */
cv_status cv_view_pid_stat(cv_ctx *ctx, cv_acc *acc, cv_view_stats *st)
{
    uint64_t t0 = cv_now_ns();
    int dfd = raw_open(ctx->proc_root, O_RDONLY | O_DIRECTORY);
    if (dfd < 0) return view_done(ctx, st, CV_VIEW_PID_STAT, errno, t0, "open(proc)");
    pid_t max = effective_pid_max(ctx);
    char name[16];
    struct stat sb;
    for (pid_t pid = 1; pid < max; pid++) {
        snprintf(name, sizeof name, "%d", (int)pid);
        if (syscall(SYS_newfstatat, dfd, name, &sb, 0) == 0 && S_ISDIR(sb.st_mode))
            probe_hit(ctx, acc, st, pid, CV_VIEW_PID_STAT);
    }
    raw_close(dfd);
    return view_done(ctx, st, CV_VIEW_PID_STAT, 0, t0, "stat-probe");
}

/* ================================================================== */
/* Kernel modules                                                      */
/* ================================================================== */

/* Synthetic subjects for the taint cross-check. */
#define TAINT_SUBJ_OOT      "taint:O"   /* out-of-tree module loaded  */
#define TAINT_SUBJ_UNSIGNED "taint:E"   /* unsigned module loaded     */

static void mark_taint_letters(cv_acc *acc, const char *flags, cv_view v)
{
    if (strchr(flags, 'O')) cv_acc_mark(acc, CV_SUBJ_MODULE, 0, TAINT_SUBJ_OOT, v);
    if (strchr(flags, 'E')) cv_acc_mark(acc, CV_SUBJ_MODULE, 0, TAINT_SUBJ_UNSIGNED, v);
}

/*
 * VIEW proc_modules — /proc/modules, which walks the kernel's linked list
 * of modules. A rootkit that unlinks itself from that list (list_del on
 * THIS_MODULE->list) disappears from here and from lsmod.
 * Also records which taint letters the *visible* modules account for.
 */
cv_status cv_view_proc_modules(cv_ctx *ctx, cv_acc *acc, cv_view_stats *st)
{
    uint64_t t0 = cv_now_ns();
    char path[640];
    path_join(path, sizeof path, ctx->proc_root, "modules");
    size_t cap = 1 << 20;
    char *buf = malloc(cap);
    if (!buf) return view_done(ctx, st, CV_VIEW_PROC_MODULES, ENOMEM, t0, "malloc");
    ssize_t n = raw_read_file(path, buf, cap);
    if (n < 0) { free(buf); return view_done(ctx, st, CV_VIEW_PROC_MODULES, (int)-n, t0, "read /proc/modules"); }

    char *save = NULL;
    for (char *line = strtok_r(buf, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        char name[CV_NAME_MAX];
        if (sscanf(line, "%255s", name) != 1) continue;
        cv_acc_mark(acc, CV_SUBJ_MODULE, 0, name, CV_VIEW_PROC_MODULES);
        st->entries++;
        const char *lp = strrchr(line, '(');      /* taint flags, e.g. "(OE)" */
        if (lp && strchr(lp, ')')) mark_taint_letters(acc, lp, CV_VIEW_PROC_MODULES);
    }
    free(buf);
    return view_done(ctx, st, CV_VIEW_PROC_MODULES, 0, t0, "proc_modules");
}

/*
 * VIEW sys_module — /sys/module/<name>/ via raw getdents. sysfs entries are
 * kobjects, a separate structure from the module list. Unlinking from the
 * list doesn't remove the kobject unless the rootkit also calls
 * kobject_del. Only entries with an `initstate` file are loadable modules
 * (built-in "modules" also appear in /sys/module but have none).
 */
struct sysmod_ctx { cv_ctx *ctx; cv_acc *acc; cv_view_stats *st; const char *base; };

static void sysmod_cb(const char *name, unsigned char t, void *u)
{
    (void)t;
    struct sysmod_ctx *c = u;
    if (name[0] == '.') return;
    char path[1024], buf[64];
    snprintf(path, sizeof path, "%s/%s/initstate", c->base, name);
    if (raw_read_file(path, buf, sizeof buf) < 0) return;   /* built-in: skip */
    cv_acc_mark(c->acc, CV_SUBJ_MODULE, 0, name, CV_VIEW_SYS_MODULE);
    c->st->entries++;
    snprintf(path, sizeof path, "%s/%s/taint", c->base, name);
    if (raw_read_file(path, buf, sizeof buf) > 0) mark_taint_letters(c->acc, buf, CV_VIEW_SYS_MODULE);
}

cv_status cv_view_sys_module(cv_ctx *ctx, cv_acc *acc, cv_view_stats *st)
{
    uint64_t t0 = cv_now_ns();
    char base[640];
    path_join(base, sizeof base, ctx->sys_root, "module");
    struct sysmod_ctx c = { ctx, acc, st, base };
    int r = raw_getdents_each(base, sysmod_cb, &c);
    return view_done(ctx, st, CV_VIEW_SYS_MODULE, r < 0 ? -r : 0, t0, "getdents64(/sys/module)");
}

/*
 * VIEW kernel_taint — /proc/sys/kernel/tainted. Bit 12 (O) is set the
 * first time an out-of-tree module loads; bit 13 (E) when an unsigned one
 * loads. Taint is sticky (stays set after rmmod), so this is weak
 * evidence on its own: it matters when *no visible module* accounts for
 * the taint.
 */
cv_status cv_view_kernel_taint(cv_ctx *ctx, cv_acc *acc, cv_view_stats *st)
{
    uint64_t t0 = cv_now_ns();
    char path[640], buf[64];
    path_join(path, sizeof path, ctx->proc_root, "sys/kernel/tainted");
    ssize_t n = raw_read_file(path, buf, sizeof buf);
    if (n < 0) return view_done(ctx, st, CV_VIEW_KERNEL_TAINT, (int)-n, t0, "read tainted");
    unsigned long long t = strtoull(buf, NULL, 10);
    if (t & (1ULL << 12)) { cv_acc_mark(acc, CV_SUBJ_MODULE, 0, TAINT_SUBJ_OOT, CV_VIEW_KERNEL_TAINT); st->entries++; }
    if (t & (1ULL << 13)) { cv_acc_mark(acc, CV_SUBJ_MODULE, 0, TAINT_SUBJ_UNSIGNED, CV_VIEW_KERNEL_TAINT); st->entries++; }
    return view_done(ctx, st, CV_VIEW_KERNEL_TAINT, 0, t0, "kernel_taint");
}

/* ================================================================== */
/* Ports                                                               */
/* ================================================================== */
/* Subjects are family-agnostic ("tcp"/"udp" + port). A socket on [::]
 * without IPV6_V6ONLY also occupies the IPv4 port, so keying by family
 * would create false positives on every dual-stack server. */

static void parse_proc_net(cv_ctx *ctx, cv_acc *acc, cv_view_stats *st,
                           const char *file, const char *proto, int *err)
{
    char path[640];
    path_join(path, sizeof path, ctx->proc_root, file);
    size_t cap = 4 << 20;
    char *buf = malloc(cap);
    if (!buf) { *err = ENOMEM; return; }
    ssize_t n = raw_read_file(path, buf, cap);
    if (n < 0) { if (n != -ENOENT) *err = (int)-n; free(buf); return; }
    char *save = NULL;
    char *line = strtok_r(buf, "\n", &save);              /* header */
    for (line = strtok_r(NULL, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        /* "  sl  local_address rem_address st ..."; local is HEXADDR:HEXPORT */
        char local[128];
        if (sscanf(line, "%*s %127s", local) != 1) continue;
        char *colon = strrchr(local, ':');
        if (!colon) continue;
        long port = strtol(colon + 1, NULL, 16);
        if (port <= 0 || port > 65535) continue;
        cv_acc_mark(acc, CV_SUBJ_PORT, port, proto, CV_VIEW_PROC_NET);
        st->entries++;
    }
    free(buf);
}

/* VIEW proc_net — /proc/net/{tcp,tcp6,udp,udp6}, all socket states. */
cv_status cv_view_proc_net(cv_ctx *ctx, cv_acc *acc, cv_view_stats *st)
{
    uint64_t t0 = cv_now_ns();
    int err = 0;
    uint32_t p = ctx->cfg.port_protos;
    if (p & CV_PROTO_TCP4) parse_proc_net(ctx, acc, st, "net/tcp",  "tcp", &err);
    if (p & CV_PROTO_TCP6) parse_proc_net(ctx, acc, st, "net/tcp6", "tcp", &err);
    if (p & CV_PROTO_UDP4) parse_proc_net(ctx, acc, st, "net/udp",  "udp", &err);
    if (p & CV_PROTO_UDP6) parse_proc_net(ctx, acc, st, "net/udp6", "udp", &err);
    return view_done(ctx, st, CV_VIEW_PROC_NET, err, t0, "proc_net");
}

/* Try to bind (family, type, port); 1 if EADDRINUSE (someone holds it). */
static int port_in_use(int family, int type, int port)
{
    int s = (int)syscall(SYS_socket, family, type | SOCK_CLOEXEC, 0);
    if (s < 0) return 0;
    int busy = 0;
    if (family == AF_INET6) {
        int one = 1;   /* v6-only: the v4 probe covers v4 separately */
        setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one);
        struct sockaddr_in6 a = { .sin6_family = AF_INET6, .sin6_port = htons((uint16_t)port),
                                  .sin6_addr = IN6ADDR_ANY_INIT };
        if (syscall(SYS_bind, s, &a, sizeof a) < 0 && errno == EADDRINUSE) busy = 1;
    } else {
        struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons((uint16_t)port),
                                 .sin_addr = { htonl(INADDR_ANY) } };
        if (syscall(SYS_bind, s, &a, sizeof a) < 0 && errno == EADDRINUSE) busy = 1;
    }
    raw_close(s);
    return busy;
}

/*
 * VIEW bind_probe — try to bind() every port (no SO_REUSEADDR). The kernel
 * refuses with EADDRINUSE if a socket holds the port, whatever /proc/net
 * says. A rootkit that filters /proc/net/tcp output can't hide a port from
 * the bind table without breaking networking. Off by default: it's slow,
 * and it briefly occupies each port. Other errors (EACCES on <1024 as
 * non-root) leave the port undecided, not "free".
 */
cv_status cv_view_bind_probe(cv_ctx *ctx, cv_acc *acc, cv_view_stats *st)
{
    uint64_t t0 = cv_now_ns();
    uint32_t p = ctx->cfg.port_protos;
    for (int port = 1; port <= 65535; port++) {
        int tcp = ((p & CV_PROTO_TCP4) && port_in_use(AF_INET,  SOCK_STREAM, port)) ||
                  ((p & CV_PROTO_TCP6) && port_in_use(AF_INET6, SOCK_STREAM, port));
        int udp = ((p & CV_PROTO_UDP4) && port_in_use(AF_INET,  SOCK_DGRAM,  port)) ||
                  ((p & CV_PROTO_UDP6) && port_in_use(AF_INET6, SOCK_DGRAM,  port));
        if (tcp) { cv_acc_mark(acc, CV_SUBJ_PORT, port, "tcp", CV_VIEW_BIND_PROBE); st->entries++; }
        if (udp) { cv_acc_mark(acc, CV_SUBJ_PORT, port, "udp", CV_VIEW_BIND_PROBE); st->entries++; }
    }
    return view_done(ctx, st, CV_VIEW_BIND_PROBE, 0, t0, "bind_probe");
}

/* ================================================================== */
/* Preload / injection                                                 */
/* ================================================================== */

static void mark_preload_list(cv_acc *acc, cv_view_stats *st, char *text, cv_view v)
{
    /* ld.so.preload and LD_PRELOAD are separated by whitespace or ':' */
    char *save = NULL;
    for (char *tok = strtok_r(text, " \t\r\n:", &save); tok; tok = strtok_r(NULL, " \t\r\n:", &save)) {
        if (tok[0] == '#') break;
        cv_acc_mark(acc, CV_SUBJ_FILE, 0, tok, v);
        st->entries++;
    }
}

/* VIEW preload_libc — /etc/ld.so.preload read with libc fopen()/fread(). */
cv_status cv_view_preload_libc(cv_ctx *ctx, cv_acc *acc, cv_view_stats *st)
{
    uint64_t t0 = cv_now_ns();
    char path[640], buf[8192];
    path_join(path, sizeof path, ctx->etc_root, "ld.so.preload");
    FILE *f = fopen(path, "re");
    if (!f) {
        int e = errno;   /* missing file is the normal, clean case */
        return view_done(ctx, st, CV_VIEW_PRELOAD_LIBC, e == ENOENT ? 0 : e, t0, "fopen ld.so.preload");
    }
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    buf[n] = '\0';
    fclose(f);
    mark_preload_list(acc, st, buf, CV_VIEW_PRELOAD_LIBC);
    return view_done(ctx, st, CV_VIEW_PRELOAD_LIBC, 0, t0, "preload_libc");
}

/* VIEW preload_raw — the same file via raw openat/read syscalls. A
 * userland rootkit that hooks fopen/read to hide its own preload entry
 * makes these two views disagree. */
cv_status cv_view_preload_raw(cv_ctx *ctx, cv_acc *acc, cv_view_stats *st)
{
    uint64_t t0 = cv_now_ns();
    char path[640], buf[8192];
    path_join(path, sizeof path, ctx->etc_root, "ld.so.preload");
    ssize_t n = raw_read_file(path, buf, sizeof buf);
    if (n < 0) return view_done(ctx, st, CV_VIEW_PRELOAD_RAW, n == -ENOENT ? 0 : (int)-n, t0, "read ld.so.preload");
    mark_preload_list(acc, st, buf, CV_VIEW_PRELOAD_RAW);
    return view_done(ctx, st, CV_VIEW_PRELOAD_RAW, 0, t0, "preload_raw");
}

/* VIEW proc_environ — LD_PRELOAD=... in every /proc/<pid>/environ.
 * Needs root for other users' processes; unreadable ones are counted as
 * skipped, not as errors. */
#define ENVIRON_BUF 131072
struct environ_ctx { cv_ctx *ctx; cv_acc *acc; cv_view_stats *st; char *buf; };

static void environ_cb(const char *name, unsigned char t, void *u)
{
    (void)t;
    struct environ_ctx *c = u;
    pid_t pid;
    if (!cv_parse_pid(name, &pid)) return;
    char path[640];
    snprintf(path, sizeof path, "%s/%d/environ", c->ctx->proc_root, (int)pid);
    char *buf = c->buf;
    ssize_t n = raw_read_file(path, buf, ENVIRON_BUF);
    if (n <= 0) return;
    for (ssize_t i = 0; i < n;) {           /* NUL-separated KEY=VALUE */
        char *kv = buf + i;
        size_t len = strnlen(kv, (size_t)(n - i));
        if (strncmp(kv, "LD_PRELOAD=", 11) == 0) {
            char tmp[4096];
            snprintf(tmp, sizeof tmp, "%s", kv + 11);
            mark_preload_list(c->acc, c->st, tmp, CV_VIEW_PROC_ENVIRON);
        }
        i += (ssize_t)len + 1;
    }
}

cv_status cv_view_proc_environ(cv_ctx *ctx, cv_acc *acc, cv_view_stats *st)
{
    uint64_t t0 = cv_now_ns();
    struct environ_ctx c = { ctx, acc, st, malloc(ENVIRON_BUF) };
    if (!c.buf) return view_done(ctx, st, CV_VIEW_PROC_ENVIRON, ENOMEM, t0, "malloc");
    int r = raw_getdents_each(ctx->proc_root, environ_cb, &c);
    free(c.buf);
    return view_done(ctx, st, CV_VIEW_PROC_ENVIRON, r < 0 ? -r : 0, t0, "proc_environ");
}

/*
 * VIEW self_symbols — which shared object actually provides readdir()
 * (and other commonly hooked functions) *in this process*?
 * dlsym(RTLD_DEFAULT, sym) returns whatever the dynamic linker resolved,
 * which is the interposer if one is preloaded. dlsym(libc_handle, sym)
 * returns libc's own definition. Different addresses => interposed.
 * dladdr() then names the object doing it.
 */
static const char *const HOOKED_SYMBOLS[] = {
    "readdir", "readdir64", "opendir", "fopen", "fopen64", "open", "open64",
    "openat", "stat", "lstat", "access", "kill", "getdents64", "unlink",
};

/* Sanitizer/profiler runtimes legitimately interpose libc functions. */
static int is_allowlisted_interposer(const char *path)
{
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    static const char *const ok[] = { "libasan", "liblsan", "libtsan", "libubsan",
                                      "libclang_rt", "libhwasan", "vgpreload_" };
    for (size_t i = 0; i < sizeof ok / sizeof ok[0]; i++)
        if (strncmp(base, ok[i], strlen(ok[i])) == 0) return 1;
    return 0;
}

cv_status cv_view_self_symbols(cv_ctx *ctx, cv_acc *acc, cv_view_stats *st)
{
    uint64_t t0 = cv_now_ns();
    void *libc = dlopen("libc.so.6", RTLD_LAZY | RTLD_NOLOAD);
    if (!libc) return view_done(ctx, st, CV_VIEW_SELF_SYMBOLS, ENOENT, t0, "dlopen(libc.so.6, NOLOAD)");
    for (size_t i = 0; i < sizeof HOOKED_SYMBOLS / sizeof HOOKED_SYMBOLS[0]; i++) {
        const char *sym = HOOKED_SYMBOLS[i];
        void *real = dlsym(libc, sym);
        void *resolved = dlsym(RTLD_DEFAULT, sym);
        if (!real || !resolved || real == resolved) continue;
        Dl_info info;
        if (!dladdr(resolved, &info) || !info.dli_fname) continue;
        if (is_allowlisted_interposer(info.dli_fname)) continue;
        char name[CV_NAME_MAX];
        snprintf(name, sizeof name, "%s@%s", sym, info.dli_fname);
        cv_acc_mark(acc, CV_SUBJ_SYMBOL, 0, name, CV_VIEW_SELF_SYMBOLS);
        cv_acc_mark(acc, CV_SUBJ_FILE, 0, info.dli_fname, CV_VIEW_SELF_SYMBOLS);
        st->entries++;
    }
    dlclose(libc);
    return view_done(ctx, st, CV_VIEW_SELF_SYMBOLS, 0, t0, "self_symbols");
}

/* ================================================================== */
/* Single-subject probes (recheck loop)                                */
/* ================================================================== */

int cv_probe_kill(const cv_ctx *ctx, pid_t pid)
{
    if (ctx->cfg.pid_probe) return ctx->cfg.pid_probe(pid, ctx->cfg.pid_probe_user) == 1;
    long r = syscall(SYS_kill, pid, 0);
    return r == 0 || errno == EPERM;
}

int cv_probe_stat(const cv_ctx *ctx, pid_t pid)
{
    char path[640];
    struct stat sb;
    snprintf(path, sizeof path, "%s/%d", ctx->proc_root, (int)pid);
    return syscall(SYS_newfstatat, AT_FDCWD, path, &sb, 0) == 0 && S_ISDIR(sb.st_mode);
}

int cv_probe_bind(const cv_ctx *ctx, int port, const char *proto)
{
    uint32_t p = ctx->cfg.port_protos;
    if (strcmp(proto, "tcp") == 0)
        return ((p & CV_PROTO_TCP4) && port_in_use(AF_INET,  SOCK_STREAM, port)) ||
               ((p & CV_PROTO_TCP6) && port_in_use(AF_INET6, SOCK_STREAM, port));
    return ((p & CV_PROTO_UDP4) && port_in_use(AF_INET,  SOCK_DGRAM, port)) ||
           ((p & CV_PROTO_UDP6) && port_in_use(AF_INET6, SOCK_DGRAM, port));
}

void cv_read_comm(const cv_ctx *ctx, pid_t pid, char *out, size_t n)
{
    char path[640];
    snprintf(path, sizeof path, "%s/%d/comm", ctx->proc_root, (int)pid);
    out[0] = '\0';
    if (raw_read_file(path, out, n) > 0) {
        size_t len = strlen(out);
        if (len && out[len - 1] == '\n') out[len - 1] = '\0';
    }
}
