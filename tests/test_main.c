/*
 * test_main.c — smoke tests for the public API. Run under ASan/UBSan via
 * `make test`, under valgrind via `make valgrind`.
 *
 * These exercise the real views against the live system the tests run on
 * (a clean CI box or a fresh VM), so the expectation is agreement between
 * views: zero mismatch findings and sane view statistics.
 */
#include "libcrossview.h"
#include "internal.h"   /* cv_classify: tests build the sources directly */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures, checks;
#define CHECK(cond) do { checks++; if (!(cond)) { failures++; \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

static void test_config_defaults(void)
{
    cv_config cfg;
    cv_config_init(&cfg);
    CHECK(cfg.struct_size == sizeof cfg);
    CHECK(cfg.struct_size == cv_config_size());
    CHECK(cfg.recheck_rounds == 3);
    CHECK(cfg.flags & CV_F_SKIP_THREADS);
    CHECK(strcmp(cfg.proc_root, "/proc") == 0);
}

static void test_bad_args(void)
{
    cv_ctx *ctx = NULL;
    CHECK(cv_ctx_new(NULL, NULL) == CV_E_INVAL);
    CHECK(cv_ctx_new(NULL, &ctx) == CV_OK && ctx != NULL);
    cv_report *rep = NULL;
    CHECK(cv_scan(ctx, 0, &rep) == CV_E_INVAL && rep == NULL);
    CHECK(cv_scan(ctx, 0x100, &rep) == CV_E_INVAL);
    CHECK(strlen(cv_last_error(ctx)) > 0);
    cv_ctx_free(ctx);
    cv_ctx_free(NULL);        /* NULL-safe */
    cv_report_free(NULL);
    cv_free(NULL);
}

static void test_names(void)
{
    CHECK(strcmp(cv_view_name(CV_VIEW_PROC_GETDENTS), "proc_getdents") == 0);
    CHECK(strcmp(cv_view_name((cv_view)999), "unknown") == 0);
    CHECK(strcmp(cv_check_name(CV_CHECK_PRELOAD), "preload") == 0);
    CHECK(strcmp(cv_strerror(CV_OK), "ok") == 0);
    CHECK(cv_abi_version() == CV_ABI_VERSION);
}

static void test_live_scan_agrees(void)
{
    cv_config cfg;
    cv_config_init(&cfg);
    cfg.pid_max = 65536;            /* keep CI fast */
    cfg.recheck_delay_ms = 10;
    cv_ctx *ctx = NULL;
    CHECK(cv_ctx_new(&cfg, &ctx) == CV_OK);

    cv_report *rep = NULL;
    cv_status st = cv_scan(ctx, CV_CHECK_ALL, &rep);
    CHECK(st == CV_OK && rep != NULL);
    if (rep) {
        cv_view_stats vs;
        CHECK(cv_report_view_stats(rep, CV_VIEW_PROC_READDIR, &vs) == CV_OK && vs.entries > 0);
        CHECK(cv_report_view_stats(rep, CV_VIEW_PROC_GETDENTS, &vs) == CV_OK && vs.entries > 0);
        CHECK(cv_report_view_stats(rep, CV_VIEW_BIND_PROBE, &vs) == CV_E_UNSUPPORTED); /* off by default */

        size_t mismatches = 0;
        for (size_t i = 0; i < cv_report_count(rep); i++) {
            const cv_finding *f = cv_report_get(rep, i);
            if (f->type == CV_FIND_MISMATCH && f->confidence >= CV_CONF_MEDIUM) {
                mismatches++;
                fprintf(stderr, "  unexpected: %s\n", f->detail);
            }
        }
        CHECK(mismatches == 0);
        CHECK(cv_report_get(rep, cv_report_count(rep)) == NULL);

        char *json = NULL;
        size_t n = 0;
        CHECK(cv_report_to_json(rep, &json, &n) == CV_OK && json && n == strlen(json));
        CHECK(json && strstr(json, "\"schema_version\":\"" CV_SCHEMA_VERSION "\""));
        CHECK(json && strstr(json, "\"findings\":["));
        cv_free(json);
    }
    cv_report_free(rep);
    cv_ctx_free(ctx);
}

static void test_fixture_roots(void)
{
    /* Pointing the roots at an empty directory must fail cleanly, not crash. */
    cv_config cfg;
    cv_config_init(&cfg);
    cfg.proc_root = "/nonexistent-crossview";
    cfg.sys_root  = "/nonexistent-crossview";
    cfg.etc_root  = "/nonexistent-crossview";
    cfg.pid_max = 100;
    cv_ctx *ctx = NULL;
    CHECK(cv_ctx_new(&cfg, &ctx) == CV_OK);
    cv_report *rep = NULL;
    cv_status st = cv_scan(ctx, CV_CHECK_MODULES, &rep);
    CHECK(st != CV_OK && rep == NULL);
    cv_ctx_free(ctx);
}

/*
 * A subject that no view sees any more is gone, not hidden. The recheck
 * loop rebuilds a subject from scratch each round, so a process that exited
 * mid-scan comes back with an empty seen_mask; that must not count as a
 * confirmed mismatch.
 */
static void test_vanished_subject_is_not_a_finding(void)
{
    uint32_t procs = CV_VIEW_BIT(CV_VIEW_PROC_READDIR) | CV_VIEW_BIT(CV_VIEW_PROC_GETDENTS) |
                     CV_VIEW_BIT(CV_VIEW_PID_STAT)     | CV_VIEW_BIT(CV_VIEW_PID_KILL);
    cv_subject pid = { .kind = CV_SUBJ_PID, .id = 4242, .seen_mask = 0, .used = true };
    cv_finding f;
    CHECK(!cv_classify(CV_CHECK_PROCESSES, &pid, procs, &f));

    uint32_t mods = CV_VIEW_BIT(CV_VIEW_PROC_MODULES) | CV_VIEW_BIT(CV_VIEW_SYS_MODULE);
    cv_subject mod = { .kind = CV_SUBJ_MODULE, .name = "gone", .seen_mask = 0, .used = true };
    CHECK(!cv_classify(CV_CHECK_MODULES, &mod, mods, &f));

    /* Control: the userspace-hiding pattern is still reported. */
    pid.seen_mask = procs & ~CV_VIEW_BIT(CV_VIEW_PROC_READDIR);
    CHECK(cv_classify(CV_CHECK_PROCESSES, &pid, procs, &f) && f.layer == CV_LAYER_USERSPACE);
}

/*
 * End-to-end race: PID 2 exits after the listings and the stat probe have
 * seen it but before the kill probe reaches it. That is what a short-lived
 * process looks like on a host with a large pid_max, where the stat sweep
 * alone takes seconds. The scan must report nothing.
 */
struct race { char root[64]; };

static int exiting_pid_probe(pid_t pid, void *user)
{
    struct race *r = user;
    char path[128];
    snprintf(path, sizeof path, "%s/%d", r->root, (int)pid);
    if (pid == 2) rmdir(path);                 /* "exits" just before the kill probe */
    struct stat sb;
    return stat(path, &sb) == 0 && S_ISDIR(sb.st_mode);
}

static void test_process_exits_mid_scan(void)
{
    struct race r;
    snprintf(r.root, sizeof r.root, "/tmp/crossview-test-XXXXXX");
    CHECK(mkdtemp(r.root) != NULL);
    char path[128];
    for (int pid = 1; pid <= 3; pid++) {
        snprintf(path, sizeof path, "%s/%d", r.root, pid);
        CHECK(mkdir(path, 0700) == 0);
    }

    cv_config cfg;
    cv_config_init(&cfg);
    cfg.proc_root = r.root;
    cfg.pid_max = 10;
    cfg.recheck_delay_ms = 1;
    cfg.pid_probe = exiting_pid_probe;
    cfg.pid_probe_user = &r;
    cv_ctx *ctx = NULL;
    CHECK(cv_ctx_new(&cfg, &ctx) == CV_OK);
    cv_report *rep = NULL;
    CHECK(cv_scan(ctx, CV_CHECK_PROCESSES, &rep) == CV_OK && rep != NULL);
    CHECK(cv_report_count(rep) == 0);
    for (size_t i = 0; i < cv_report_count(rep); i++)
        fprintf(stderr, "  unexpected: %s\n", cv_report_get(rep, i)->detail);
    cv_report_free(rep);
    cv_ctx_free(ctx);

    for (int pid = 1; pid <= 3; pid++) {
        snprintf(path, sizeof path, "%s/%d", r.root, pid);
        rmdir(path);
    }
    rmdir(r.root);
}

int main(void)
{
    test_config_defaults();
    test_bad_args();
    test_names();
    test_live_scan_agrees();
    test_fixture_roots();
    test_vanished_subject_is_not_a_finding();
    test_process_exits_mid_scan();
    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
