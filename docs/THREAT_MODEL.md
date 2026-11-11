# Threat model

## What crossview is for
Detecting the *artefacts of hiding* left by host-based rootkits on Linux:
processes, kernel modules, listening ports, and injected shared libraries
that are visible through one OS interface but concealed from another.

## Assumptions
- **The scanner runs after a compromise may have happened.** We do not assume
  a clean host; that is the whole point. We *do* assume the detector binary
  and the kernel's syscall path it relies on are not themselves subverted at
  the moment of scanning (see `LIMITATIONS.md` — this is the main caveat).
- **Root or `CAP_SYS_PTRACE`/`CAP_DAC_READ_SEARCH` for full coverage.** Some
  views degrade gracefully without privilege and are marked `perm`.
- **x86_64 Linux.** The syscall-dispatch detection and some view assumptions
  are architecture-specific; other arches report `syscall_dispatch: unknown`.

## In scope (what we aim to detect)
| Technique | ATT&CK | How |
|---|---|---|
| Userland process hiding (`LD_PRELOAD` `readdir` hook) | T1574.006 | libc view vs raw getdents view disagree |
| Kernel process hiding (`getdents` hook / DKOM) | T1014 | both listings vs direct `kill`/`stat` probe disagree |
| Module hiding (unlink from module list) | T1014 | `/proc/modules` vs `/sys/module` kobject disagree |
| Unaccounted kernel taint | T1014 | tainted kernel, no visible module explains it |
| Port hiding (filtered `/proc/net`) | T1014 | `/proc/net` vs `bind()` probe disagree |
| Library injection via `ld.so.preload` | T1574.006 | file present to raw read but hidden from libc; or an interposed libc symbol in-process |

## Out of scope
- **Memory-resident / fileless implants that hide nothing** through the
  interfaces above. crossview looks for inconsistency, not for malware as
  such; something that never lies to `/proc` won't trip it.
- **Network-level, firmware, hypervisor and SMM rootkits.** Different layer.
- **Anti-forensics that also subverts the detector's own code path** (e.g. a
  kernel rootkit that specifically neutralises our syscalls). Cross-view can
  only work if at least one of its views is still honest.
- **Attribution and remediation.** crossview flags and localises; it does not
  clean.

## Trust and failure modes
- A *false positive* is a view disagreement with a benign cause (a process
  exiting mid-scan, a module mid-load). The recheck loop and the
  mismatch/indicator split exist to suppress these; residual ones are
  reported at `low` confidence.
- A *false negative* is a rootkit consistent across every view we consult.
  Adding independent views (the eBPF sensor, memory forensics) raises the bar
  an attacker must clear. No single view is trusted alone.
