# Limitations & evasion

Cross-view detection is a bar an attacker must clear, not a wall. This is the
honest account of where it stops — the part of the project interviewers care
about most, because it shows the design was reasoned about rather than copied.

## The core assumption
Cross-view works only if **at least one view is still honest**. Every view
runs in the same process on the same kernel as a potential rootkit, so a
sufficiently privileged kernel implant can lie to all of them at once. We
raise the attacker's cost by consulting paths that are *independent* and
*increasingly expensive to subvert consistently*; we do not claim
completeness.

## Per-view evasion
| View | How a rootkit beats it | What would catch that |
|---|---|---|
| `proc_readdir` vs `proc_getdents` | Hide in the kernel instead of `LD_PRELOAD`, so both agree | the direct probes (`pid_kill`, `pid_stat`) |
| `pid_kill` | Also hook `kill()` to return `ESRCH` for the hidden PID | `pid_stat`, and the eBPF task-iterator view (planned) |
| `pid_stat` | Also hook the `/proc/<pid>` lookup path (`proc_pid_lookup`) | eBPF iterating the real task list in-kernel |
| `sys_module` | Also call `kobject_del` to remove the sysfs entry | `kernel_taint`, memory forensics (planned Volatility cross-check) |
| `kernel_taint` | Clear the taint flags, or never trip them (in-tree-signed build) | out of scope for this view; defence-in-depth only |
| `proc_net` vs `bind_probe` | Hook `bind()` as well, or use raw packet sockets | eBPF socket events (planned) |
| `preload_libc` vs `preload_raw` | Inject without `ld.so.preload` (ptrace injection, `process_vm_writev`) | `self_symbols`, `/proc/<pid>/maps` scan (planned) |
| `self_symbols` | Hook without changing the resolved symbol (inline/trampoline patching of libc in memory) | `/proc/<pid>/maps` text-segment hash vs on-disk libc (planned) |

## Structural blind spots
- **A rootkit that hides nothing** through these interfaces is invisible to
  cross-view by construction. It is an inconsistency detector, not a malware
  scanner.
- **The scanner's own syscalls can be targeted.** A kernel rootkit that
  recognises our access pattern can feed us consistent lies. The planned eBPF
  sensor partly mitigates this by observing from a different vantage (kernel
  hook points rather than `/proc` reads), but an attacker who also controls
  eBPF (or disables it) defeats that too — which is why the threat model
  assumes the kernel path is honest *at scan time*.
- **Races.** Short-lived processes and loading/unloading modules naturally
  produce transient disagreements. The recheck loop (default 3 rounds) and
  the `low`-confidence band reduce but do not eliminate these.

## The 2024 syscall-dispatch change (why it's in the report)
On x86_64, kernels since ~6.9 (and stable backports of CVE-2024-2201)
dispatch syscalls through a `switch` statement (`x64_sys_call`) rather than
the writable `sys_call_table`. Classic table-overwriting rootkits
(Diamorphine as shipped) are **inert** on those kernels — their process
hiding silently does nothing. Modern rootkits moved to ftrace/kprobe-based
hooking instead. crossview records `syscall_dispatch: table|switch` in every
report so an evaluation makes clear which world it ran in, and the detection
logic keys off *the result of hiding* (view disagreement), not the hooking
mechanism — so it is agnostic to that change.
