# crossview

A Linux rootkit detector built on **cross-view analysis**: ask the operating
system the same question through several independent interfaces and compare
the answers. A rootkit has to lie consistently through *every* interface, and
that is hard — so each disagreement between views is evidence, and *which*
views disagree tells you where the lie lives.

```
        ┌─ libc wrapper      readdir("/proc")            ← LD_PRELOAD / libc hooks act here
 same   ├─ raw syscall       getdents64("/proc")         ← kernel syscall hooks act here
 Q ?    └─ kernel object     kill(pid,0), stat /proc/pid ← direct probes ask the object itself
```

If a PID shows up in the raw syscall but not in libc, the hiding is in user
space (an `LD_PRELOAD` library). If it shows up only when you probe it
directly, both directory listings are lying, so the hiding is in the kernel.
The tool reports that distinction for every finding and maps it to a
[MITRE ATT&CK](https://attack.mitre.org/) technique.

> **Scope.** crossview only *observes*: it reads `/proc` and `/sys`, makes
> read-only syscalls, and probes for liveness. It never modifies the system
> and contains no hiding or evasion code. It is a defensive / blue-team tool.

## Architecture

A C data plane does the fast, low-level observation; a Python control plane
drives it and (soon) runs the behavioural ML. They are joined by a `ctypes`
FFI boundary, with the scan report crossing as JSON.

```
libcrossview.so  ──cv_report_to_json──▶  JSON  ──▶  crossview (Python CLI, ML)
   C data plane      (ctypes FFI)                       control plane
```

| Check | Views (easiest-to-fake → hardest) |
|---|---|
| **processes** | `proc_readdir` (libc) → `proc_getdents` (raw syscall) → `pid_stat` / `pid_kill` (direct probes over the PID space) |
| **modules** | `proc_modules` → `sys_module` (sysfs kobjects) → `kernel_taint` (did an invisible module taint the kernel?) |
| **ports** | `proc_net` → `bind_probe` (opt-in: try to `bind()` each port) |
| **preload** | `preload_libc` vs `preload_raw` (same file two ways) → `proc_environ` → `self_symbols` (`dlsym`/`dladdr`: who really provides `readdir` in this process?) |

## Build & run

Needs a C compiler, `make`, `libdl`, and Python ≥ 3.9. On Debian/Ubuntu:
`sudo apt install build-essential python3`.

```sh
make                              # build/libcrossview.so
cd python
sudo python3 -m crossview scan            # all checks, human-readable
sudo python3 -m crossview scan --json     # machine-readable report
sudo python3 -m crossview scan --checks processes --bind-probe
```

Root is needed to read other users' `/proc/<pid>/environ` and to probe the
full PID space; without it, those views are marked `perm` in the report and
the scan still runs. Exit codes: `0` clean, `1` a mismatch at or above
`--fail-on` (default `medium`), `2` error.

### Example

```
$ sudo python3 -m crossview scan --checks processes
libcrossview 0.1.0  host=rk-lab  kernel=6.1.0-18-amd64
syscall dispatch: table   euid=0   scan: 1840 ms, checks=processes

VIEW            CHECK      STATUS       ENTRIES       MS
proc_readdir    processes  ok               141      1.9
proc_getdents   processes  ok               142      0.7
pid_kill        processes  ok               142   1712.4
pid_stat        processes  ok               142      3.1

1 finding(s):
  [mismatch/userspace/high] processes/pid/4242 (evil_script.py)
      PID 4242 is listed by raw getdents64 but not by libc readdir: a userland hook is filtering /proc
      seen_in=proc_getdents,pid_stat,pid_kill  missing_from=proc_readdir  confirmations=3  ATT&CK=T1574.006
```

## Development

```sh
make test        # C unit tests under AddressSanitizer + UBSan
make valgrind    # C tests under valgrind (no leaks)
make tidy        # clang-tidy
make pytest      # Python tests (needs: pip install pytest jsonschema)
```

See [`docs/RUN_ON_VM.md`](docs/RUN_ON_VM.md) for the isolated lab setup and how
to test against real research rootkits safely, [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)
for what is and isn't defended, and [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md)
for how a smarter attacker would evade each view.

## Status

Cross-view engine (processes, modules, ports, preload), the C↔Python FFI
bridge, the JSON report and its schema, and the test/CI scaffolding are done.
The eBPF behavioural sensor, the Isolation Forest anomaly model, and the
automated evaluation harness are in progress — see [`docs/ROADMAP.md`](docs/ROADMAP.md).

## License

MIT — see [`LICENSE`](LICENSE).
