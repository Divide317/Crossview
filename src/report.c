/* report.c — cv_report -> JSON (schema/crossview-report.schema.json). */
#include "internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *status_str(cv_status s)
{
    switch (s) {
    case CV_OK:            return "ok";
    case CV_E_INVAL:       return "inval";
    case CV_E_NOMEM:       return "nomem";
    case CV_E_IO:          return "io";
    case CV_E_PERM:        return "perm";
    case CV_E_UNSUPPORTED: return "unsupported";
    default:               return "internal";
    }
}

static const char *kind_str(cv_subject_kind k)
{
    switch (k) {
    case CV_SUBJ_PID:    return "pid";
    case CV_SUBJ_MODULE: return "module";
    case CV_SUBJ_PORT:   return "port";
    case CV_SUBJ_FILE:   return "file";
    default:             return "symbol";
    }
}

static const char *layer_str(cv_layer l)
{
    switch (l) {
    case CV_LAYER_USERSPACE: return "userspace";
    case CV_LAYER_KERNEL:    return "kernel";
    default:                 return "unknown";
    }
}

static const char *conf_str(cv_confidence c)
{
    return c == CV_CONF_HIGH ? "high" : c == CV_CONF_MEDIUM ? "medium" : "low";
}

static void view_list(cv_sb *sb, uint32_t mask)
{
    cv_sb_putc(sb, '[');
    int first = 1;
    for (unsigned v = 0; v < CV_VIEW__COUNT; v++) {
        if (!(mask & CV_VIEW_BIT(v))) continue;
        if (!first) cv_sb_putc(sb, ',');
        cv_sb_json_str(sb, cv_view_name((cv_view)v));
        first = 0;
    }
    cv_sb_putc(sb, ']');
}

static void attack_list(cv_sb *sb, const char *ids)
{
    cv_sb_putc(sb, '[');
    if (ids && *ids) {
        char tmp[128];
        snprintf(tmp, sizeof tmp, "%s", ids);
        char *save = NULL;
        int first = 1;
        for (char *t = strtok_r(tmp, ",", &save); t; t = strtok_r(NULL, ",", &save)) {
            if (!first) cv_sb_putc(sb, ',');
            cv_sb_json_str(sb, t);
            first = 0;
        }
    }
    cv_sb_putc(sb, ']');
}

static void finding_id(cv_sb *sb, const cv_finding *f)
{
    char id[CV_NAME_MAX + 64];
    switch (f->subject_kind) {
    case CV_SUBJ_PID:  snprintf(id, sizeof id, "%s/pid/%lld", cv_check_name(f->check), (long long)f->id); break;
    case CV_SUBJ_PORT: snprintf(id, sizeof id, "%s/%s/%lld", cv_check_name(f->check), f->name, (long long)f->id); break;
    default:           snprintf(id, sizeof id, "%s/%s/%s", cv_check_name(f->check), kind_str(f->subject_kind), f->name);
    }
    cv_sb_json_str(sb, id);
}

cv_status cv_report_to_json(const cv_report *r, char **out_json, size_t *out_len)
{
    if (!r || !out_json) return CV_E_INVAL;
    *out_json = NULL;
    if (out_len) *out_len = 0;

    cv_sb sb;
    cv_sb_init(&sb);

    cv_sb_printf(&sb, "{\"schema_version\":\"%s\",", CV_SCHEMA_VERSION);
    cv_sb_printf(&sb, "\"tool\":{\"name\":\"libcrossview\",\"version\":\"%s\",\"abi\":%d},",
                 cv_version(), CV_ABI_VERSION);

    cv_sb_puts(&sb, "\"host\":{\"hostname\":");       cv_sb_json_str(&sb, r->hostname);
    cv_sb_puts(&sb, ",\"kernel_release\":");          cv_sb_json_str(&sb, r->kernel_release);
    cv_sb_puts(&sb, ",\"boot_id\":");                 cv_sb_json_str(&sb, r->boot_id);
    cv_sb_printf(&sb, ",\"euid\":%d,\"syscall_dispatch\":", r->euid);
    cv_sb_json_str(&sb, r->syscall_dispatch ? r->syscall_dispatch : "unknown");
    cv_sb_puts(&sb, "},");

    cv_sb_puts(&sb, "\"scan\":{\"started_at\":");     cv_sb_json_str(&sb, r->started_at);
    cv_sb_printf(&sb, ",\"duration_ms\":%.3f,\"checks\":[", r->duration_ms);
    int first = 1;
    for (uint32_t c = 1; c <= CV_CHECK_PRELOAD; c <<= 1) {
        if (!(r->checks & c)) continue;
        if (!first) cv_sb_putc(&sb, ',');
        cv_sb_json_str(&sb, cv_check_name((cv_check)c));
        first = 0;
    }
    cv_sb_printf(&sb, "],\"config\":{\"pid_max\":%d,\"recheck_rounds\":%u,\"recheck_delay_ms\":%u,"
                      "\"skip_threads\":%s,\"bind_probe\":%s,\"port_protos\":[",
                 (int)r->pid_max, r->recheck_rounds, r->recheck_delay_ms,
                 (r->flags & CV_F_SKIP_THREADS) ? "true" : "false",
                 (r->flags & CV_F_BIND_PROBE) ? "true" : "false");
    static const struct { uint32_t bit; const char *name; } protos[] = {
        { CV_PROTO_TCP4, "tcp" }, { CV_PROTO_TCP6, "tcp6" }, { CV_PROTO_UDP4, "udp" }, { CV_PROTO_UDP6, "udp6" } };
    first = 1;
    for (size_t i = 0; i < 4; i++) {
        if (!(r->port_protos & protos[i].bit)) continue;
        if (!first) cv_sb_putc(&sb, ',');
        cv_sb_json_str(&sb, protos[i].name);
        first = 0;
    }
    cv_sb_puts(&sb, "]}},");

    cv_sb_puts(&sb, "\"views\":[");
    first = 1;
    for (unsigned v = 0; v < CV_VIEW__COUNT; v++) {
        if (!r->stats_used[v]) continue;
        const cv_view_stats *s = &r->stats[v];
        if (!first) cv_sb_putc(&sb, ',');
        first = 0;
        cv_sb_puts(&sb, "{\"view\":");  cv_sb_json_str(&sb, cv_view_name((cv_view)v));
        cv_sb_puts(&sb, ",\"check\":"); cv_sb_json_str(&sb, cv_check_name(cv_view_check((cv_view)v)));
        cv_sb_puts(&sb, ",\"status\":"); cv_sb_json_str(&sb, status_str(s->status));
        if (s->sys_errno) cv_sb_printf(&sb, ",\"errno\":%d", s->sys_errno);
        else              cv_sb_puts(&sb, ",\"errno\":null");
        cv_sb_printf(&sb, ",\"entries\":%llu,\"elapsed_ms\":%.3f}",
                     (unsigned long long)s->entries, (double)s->elapsed_ns / 1e6);
    }
    cv_sb_puts(&sb, "],");

    cv_sb_puts(&sb, "\"findings\":[");
    for (size_t i = 0; i < r->nfindings; i++) {
        const cv_finding *f = &r->findings[i];
        if (i) cv_sb_putc(&sb, ',');
        cv_sb_puts(&sb, "{\"id\":");      finding_id(&sb, f);
        cv_sb_puts(&sb, ",\"type\":");    cv_sb_json_str(&sb, f->type == CV_FIND_INDICATOR ? "indicator" : "mismatch");
        cv_sb_puts(&sb, ",\"check\":");   cv_sb_json_str(&sb, cv_check_name(f->check));
        cv_sb_puts(&sb, ",\"subject\":{\"kind\":"); cv_sb_json_str(&sb, kind_str(f->subject_kind));
        cv_sb_printf(&sb, ",\"id\":%lld,\"name\":", (long long)(f->subject_kind == CV_SUBJ_PID ||
                                                    f->subject_kind == CV_SUBJ_PORT ? f->id : 0));
        cv_sb_json_str(&sb, f->name);
        cv_sb_puts(&sb, "},\"seen_in\":");      view_list(&sb, f->seen_in & f->queried);
        cv_sb_puts(&sb, ",\"missing_from\":");  view_list(&sb, f->queried & ~f->seen_in);
        cv_sb_puts(&sb, ",\"layer\":");         cv_sb_json_str(&sb, layer_str(f->layer));
        cv_sb_puts(&sb, ",\"confidence\":");    cv_sb_json_str(&sb, conf_str(f->confidence));
        cv_sb_printf(&sb, ",\"confirmations\":%u,\"attack\":", f->confirmations);
        attack_list(&sb, f->attack_ids);
        cv_sb_puts(&sb, ",\"detail\":");        cv_sb_json_str(&sb, f->detail);
        cv_sb_putc(&sb, '}');
    }
    cv_sb_puts(&sb, "]}");

    if (sb.oom) { cv_sb_free(&sb); return CV_E_NOMEM; }
    *out_json = sb.buf;                 /* ownership passes to caller; free with cv_free() */
    if (out_len) *out_len = sb.len;
    return CV_OK;
}
