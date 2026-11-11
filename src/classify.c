/*
 * classify.c — the diff engine: turn "which views saw this subject" into a
 * finding with a *location* for the lie.
 *
 * Pure function, no I/O: tests/test_main.c drives it with hand-built
 * view masks to cover cases no live system will reproduce on demand.
 *
 * Process example (R=readdir, G=getdents, S=stat probe, K=kill probe):
 *
 *   R G S K   meaning                                   layer
 *   ✓ ✓ ✓ ✓   consistent                                -
 *   ✗ ✓ ✓ ✓   filtered between libc and kernel          userspace (LD_PRELOAD)
 *   ✗ ✗ ✓ ✓   kernel's directory listing lies           kernel (getdents hook)
 *   ✗ ✗ ✗ ✓   only the signal path admits it exists     kernel (deeper hiding)
 *   ✓ ✓ ✗ ✗   listed but not probe-able                 unknown (usually exited mid-scan)
 */
#include "internal.h"

#include <stdio.h>
#include <string.h>

#define B(v) CV_VIEW_BIT(v)

static void base(cv_finding *f, cv_check check, const cv_subject *s)
{
    memset(f, 0, sizeof *f);
    f->check = check;
    f->subject_kind = s->kind;
    f->id = s->id;
    snprintf(f->name, sizeof f->name, "%s", s->name);
    f->seen_in = s->seen_mask;
    f->type = CV_FIND_MISMATCH;
}

/* ---------------- processes ---------------- */
static bool classify_process(const cv_subject *s, uint32_t ran, cv_finding *f)
{
    const uint32_t R = B(CV_VIEW_PROC_READDIR), G = B(CV_VIEW_PROC_GETDENTS);
    const uint32_t S = B(CV_VIEW_PID_STAT),     K = B(CV_VIEW_PID_KILL);
    ran &= (R | G | S | K);
    uint32_t seen = s->seen_mask & ran;
    if (seen == ran) return false;                         /* every view agrees */

    base(f, CV_CHECK_PROCESSES, s);
    f->queried = ran;
    uint32_t seen_list = seen & (R | G), seen_probe = seen & (S | K);

    if (seen_probe && !seen_list && (ran & G)) {
        /* Not in either listing, yet the PID answers a direct probe. The raw
         * syscall listing is wrong, so the lie is inside the kernel. */
        f->layer = CV_LAYER_KERNEL;
        f->confidence = (seen & S) && (seen & K) ? CV_CONF_HIGH : CV_CONF_MEDIUM;
        f->attack_ids = "T1014";
        snprintf(f->detail, sizeof f->detail,
                 "PID %lld answers %s but is absent from both libc readdir and raw getdents64: "
                 "the kernel's /proc listing is filtering it",
                 (long long)s->id, (seen & S) && (seen & K) ? "stat and kill probes" :
                                   (seen & S) ? "a stat probe" : "a kill probe");
        return true;
    }
    if ((ran & R) && !(seen & R) && (seen & G)) {
        /* Raw syscall sees it, libc doesn't: something between the program and
         * the kernel is filtering. That's LD_PRELOAD or a libc hook. */
        f->layer = CV_LAYER_USERSPACE;
        f->confidence = seen_probe ? CV_CONF_HIGH : CV_CONF_MEDIUM;
        f->attack_ids = "T1574.006";
        snprintf(f->detail, sizeof f->detail,
                 "PID %lld is listed by raw getdents64 but not by libc readdir: "
                 "a userland hook is filtering /proc", (long long)s->id);
        return true;
    }
    if (seen_list && (ran & (S | K)) && !seen_probe) {
        f->layer = CV_LAYER_UNKNOWN;
        f->confidence = CV_CONF_LOW;
        f->attack_ids = "";
        snprintf(f->detail, sizeof f->detail,
                 "PID %lld is listed but fails direct probes (usually a process that exited mid-scan)",
                 (long long)s->id);
        return true;
    }
    f->layer = CV_LAYER_UNKNOWN;
    f->confidence = CV_CONF_LOW;
    f->attack_ids = "";
    snprintf(f->detail, sizeof f->detail, "PID %lld: inconsistent view pattern", (long long)s->id);
    return true;
}

/* ---------------- modules ---------------- */
static bool classify_module(const cv_subject *s, uint32_t ran, cv_finding *f)
{
    const uint32_t P = B(CV_VIEW_PROC_MODULES), Y = B(CV_VIEW_SYS_MODULE), T = B(CV_VIEW_KERNEL_TAINT);

    if (strncmp(s->name, "taint:", 6) == 0) {
        ran &= (P | Y | T);
        uint32_t seen = s->seen_mask & ran;
        if (!(seen & T) || (seen & P) || !(ran & P)) return false;
        base(f, CV_CHECK_MODULES, s);
        f->queried = ran;
        f->layer = CV_LAYER_KERNEL;
        f->attack_ids = "T1014";
        const char *what = s->name[6] == 'O' ? "out-of-tree" : "unsigned";
        if (seen & Y) {
            f->confidence = CV_CONF_MEDIUM;
            snprintf(f->detail, sizeof f->detail,
                     "kernel is tainted by an %s module; a /sys/module entry carries that taint "
                     "but no module in /proc/modules does", what);
        } else {
            f->confidence = CV_CONF_LOW;
            snprintf(f->detail, sizeof f->detail,
                     "kernel is tainted by an %s module but no visible module accounts for it "
                     "(taint is sticky: also true after a legitimate rmmod)", what);
        }
        return true;
    }

    ran &= (P | Y);
    uint32_t seen = s->seen_mask & ran;
    if (seen == ran) return false;
    base(f, CV_CHECK_MODULES, s);
    f->queried = ran;
    if ((seen & Y) && !(seen & P)) {
        f->layer = CV_LAYER_KERNEL;
        f->confidence = CV_CONF_HIGH;
        f->attack_ids = "T1014";
        snprintf(f->detail, sizeof f->detail,
                 "module '%s' has a /sys/module kobject but is missing from /proc/modules: "
                 "it unlinked itself from the kernel module list", s->name);
    } else {
        f->layer = CV_LAYER_UNKNOWN;
        f->confidence = CV_CONF_LOW;
        f->attack_ids = "";
        snprintf(f->detail, sizeof f->detail,
                 "module '%s' is in /proc/modules but has no /sys/module entry (loading or unloading?)",
                 s->name);
    }
    return true;
}

/* ---------------- ports ---------------- */
static bool classify_port(const cv_subject *s, uint32_t ran, cv_finding *f)
{
    const uint32_t N = B(CV_VIEW_PROC_NET), BP = B(CV_VIEW_BIND_PROBE);
    ran &= (N | BP);
    if (!(ran & BP) || !(ran & N)) return false;     /* need both views to compare */
    uint32_t seen = s->seen_mask & ran;
    /* Only "bind refuses but /proc/net doesn't list it" is evidence. The
     * reverse happens legitimately (sockets that don't block a wildcard bind). */
    if (!(seen & BP) || (seen & N)) return false;
    base(f, CV_CHECK_PORTS, s);
    f->queried = ran;
    f->layer = CV_LAYER_KERNEL;
    f->confidence = CV_CONF_MEDIUM;
    f->attack_ids = "T1014";
    snprintf(f->detail, sizeof f->detail,
             "%s port %lld is held (bind fails with EADDRINUSE) but absent from /proc/net",
             s->name, (long long)s->id);
    return true;
}

/* ---------------- preload ---------------- */
static bool classify_preload(const cv_subject *s, uint32_t ran, cv_finding *f)
{
    const uint32_t L = B(CV_VIEW_PRELOAD_LIBC), W = B(CV_VIEW_PRELOAD_RAW);
    const uint32_t E = B(CV_VIEW_PROC_ENVIRON), Y = B(CV_VIEW_SELF_SYMBOLS);
    ran &= (L | W | E | Y);
    uint32_t seen = s->seen_mask & ran;
    if (!seen) return false;

    base(f, CV_CHECK_PRELOAD, s);
    f->attack_ids = "T1574.006";
    f->layer = CV_LAYER_USERSPACE;

    if (s->kind == CV_SUBJ_SYMBOL) {
        f->type = CV_FIND_INDICATOR;
        f->queried = seen;
        f->confidence = CV_CONF_HIGH;
        snprintf(f->detail, sizeof f->detail,
                 "%s: this libc function resolves to a non-libc object in the scanning process", s->name);
        return true;
    }

    if ((ran & L) && (ran & W) && (seen & W) && !(seen & L)) {
        f->queried = ran & (L | W);
        f->queried |= seen;
        f->confidence = CV_CONF_HIGH;
        snprintf(f->detail, sizeof f->detail,
                 "%s is in /etc/ld.so.preload when read with raw syscalls but hidden from libc reads",
                 s->name);
        return true;
    }
    if (seen & (L | W)) {
        f->type = CV_FIND_INDICATOR;
        f->queried = seen | (ran & Y);
        f->confidence = (seen & Y) ? CV_CONF_HIGH : CV_CONF_MEDIUM;
        snprintf(f->detail, sizeof f->detail, "/etc/ld.so.preload loads %s into every dynamically linked "
                 "program%s", s->name, (seen & Y) ? ", and it is interposing libc functions right now" : "");
        return true;
    }
    if ((seen & Y) && !(seen & E)) {
        f->queried = ran;
        f->confidence = CV_CONF_HIGH;
        snprintf(f->detail, sizeof f->detail,
                 "%s interposes libc functions in this process but appears in neither "
                 "/etc/ld.so.preload nor any visible LD_PRELOAD", s->name);
        return true;
    }
    f->type = CV_FIND_INDICATOR;
    f->queried = seen;
    f->confidence = CV_CONF_MEDIUM;
    snprintf(f->detail, sizeof f->detail, "a running process has LD_PRELOAD=%s", s->name);
    return true;
}

bool cv_classify(cv_check check, const cv_subject *s, uint32_t ran_mask, cv_finding *out)
{
    switch (check) {
    case CV_CHECK_PROCESSES: return s->kind == CV_SUBJ_PID    && classify_process(s, ran_mask, out);
    case CV_CHECK_MODULES:   return s->kind == CV_SUBJ_MODULE && classify_module(s, ran_mask, out);
    case CV_CHECK_PORTS:     return s->kind == CV_SUBJ_PORT   && classify_port(s, ran_mask, out);
    case CV_CHECK_PRELOAD:   return (s->kind == CV_SUBJ_FILE || s->kind == CV_SUBJ_SYMBOL) &&
                                    classify_preload(s, ran_mask, out);
    default:                 return false;
    }
}
