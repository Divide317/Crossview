/*
 * test_main.c — smoke tests for the public API. Run under ASan/UBSan via
 * `make test`, under valgrind via `make valgrind`.
 *
 * These exercise the real views against the live system the tests run on
 * (a clean CI box or a fresh VM), so the expectation is agreement between
 * views: zero mismatch findings and sane view statistics.
 */
#include "libcrossview.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

int main(void)
{
    test_config_defaults();
    test_bad_args();
    test_names();
    test_live_scan_agrees();
    test_fixture_roots();
    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
