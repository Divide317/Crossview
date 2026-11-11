"""`python -m crossview scan` — command-line front end.

Exit codes (so the evaluation harness and CI can script it):
  0  no mismatch findings above the --fail-on confidence
  1  at least one mismatch finding at or above --fail-on
  2  error
"""
from __future__ import annotations

import argparse
import json
import sys

from . import CHECKS, CrossviewError, Library

_CONF = {"low": 0, "medium": 1, "high": 2}
_COLOR = {"high": "\033[31m", "medium": "\033[33m", "low": "\033[2m"}
_RESET = "\033[0m"


def _fmt_human(report: dict, color: bool) -> str:
    h, s = report["host"], report["scan"]
    out = [
        f"libcrossview {report['tool']['version']}  host={h['hostname']}  kernel={h['kernel_release']}",
        (f"syscall dispatch: {h['syscall_dispatch']}   euid={h['euid']}   "
         f"scan: {s['duration_ms']:.0f} ms, checks={','.join(s['checks'])}"),
        "",
        f"{'VIEW':<15} {'CHECK':<10} {'STATUS':<12} {'ENTRIES':>8} {'MS':>9}",
    ]
    for v in report["views"]:
        out.append(f"{v['view']:<15} {v['check']:<10} {v['status']:<12} {v['entries']:>8} {v['elapsed_ms']:>9.1f}")
    out.append("")
    findings = report["findings"]
    if not findings:
        out.append("No findings: every view agrees.")
        return "\n".join(out)
    out.append(f"{len(findings)} finding(s):")
    for f in findings:
        c = f["confidence"]
        tag = f"[{f['type']}/{f['layer']}/{c}]"
        if color:
            tag = f"{_COLOR[c]}{tag}{_RESET}"
        subj = f["subject"]
        name = f" ({subj['name']})" if subj["name"] and subj["kind"] == "pid" else ""
        out.append(f"  {tag} {f['id']}{name}")
        out.append(f"      {f['detail']}")
        seen = ",".join(f["seen_in"]) or "-"
        miss = ",".join(f["missing_from"]) or "-"
        attack = ",".join(f["attack"]) or "-"
        out.append(f"      seen_in={seen}  missing_from={miss}  confirmations={f['confirmations']}  ATT&CK={attack}")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="crossview", description="Cross-view rootkit detector")
    sub = p.add_subparsers(dest="cmd", required=True)
    sc = sub.add_parser("scan", help="run a cross-view scan")
    sc.add_argument("--checks", default=",".join(CHECKS),
                    help="comma-separated subset of: " + ",".join(CHECKS))
    sc.add_argument("--json", action="store_true", help="print the raw JSON report")
    sc.add_argument("--pid-max", type=int, default=0, help="probe PIDs below this (default: kernel pid_max)")
    sc.add_argument("--rounds", type=int, default=None, help="recheck rounds a mismatch must survive (default 3)")
    sc.add_argument("--bind-probe", action="store_true", help="enable the slow bind() port probe")
    sc.add_argument("--protos", default=None, help="ports check protocols, e.g. tcp,tcp6,udp,udp6")
    sc.add_argument("--proc-root", default=None, help=argparse.SUPPRESS)  # testing
    sc.add_argument("--sys-root", default=None, help=argparse.SUPPRESS)
    sc.add_argument("--etc-root", default=None, help=argparse.SUPPRESS)
    sc.add_argument("--fail-on", choices=list(_CONF), default="medium",
                    help="exit 1 if a mismatch at or above this confidence is found")
    sc.add_argument("--lib", default=None, help="path to libcrossview.so")
    args = p.parse_args(argv)

    try:
        lib = Library(args.lib)
        report = lib.scan(
            [c.strip() for c in args.checks.split(",") if c.strip()],
            proc_root=args.proc_root, sys_root=args.sys_root, etc_root=args.etc_root,
            pid_max=args.pid_max, recheck_rounds=args.rounds, bind_probe=args.bind_probe,
            protos=args.protos.split(",") if args.protos else None,
        )
    except (CrossviewError, OSError, ValueError, ImportError) as e:
        print(f"crossview: {e}", file=sys.stderr)
        return 2

    if args.json:
        json.dump(report, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print(_fmt_human(report, sys.stdout.isatty()))

    threshold = _CONF[args.fail_on]
    bad = [f for f in report["findings"] if f["type"] == "mismatch" and _CONF[f["confidence"]] >= threshold]
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
