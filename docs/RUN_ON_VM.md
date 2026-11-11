# Running crossview in an isolated lab VM

crossview reads live kernel state, and testing it means running **real
research rootkits**. Both call for a throwaway virtual machine that never
touches your host or network. Never run the test rootkits on a machine you
care about.

## 1. Why a VM, and which kernel
Classic LKM rootkits that hook the syscall table only work on kernels from
*before* the 2024 syscall-dispatch change (see `docs/LIMITATIONS.md`). To see
Diamorphine actually hide a process, pin an older kernel:

- **VirtualBox** on your host (Windows/macOS/Linux).
- **Debian 12.5**, kernel **6.1.0-18-amd64**. Get the DVD ISO from the Debian
  cdimage archive and verify its SHA256.
- Confirm after install: `sudo grep -cw x64_sys_call /proc/kallsyms` → `0`
  means table dispatch (Diamorphine's hooks will work). `≥1` means switch
  dispatch (they won't; crossview still detects the module via `sys_module`).

### VM settings that matter
- **Legacy BIOS (EFI off)** → no Secure Boot → unsigned test modules load.
- **Network: host-only** for SSH from your editor. Attach a NAT adapter
  *only* while installing packages, then remove it before any rootkit runs.
- No shared folders, no clipboard sharing, no drag-and-drop.
- Snapshot ladder: `00-base` (fresh install) → `01-toolchain` (packages in)
  → `02-targets-built` (rootkits built, not loaded, NAT removed). **Revert to
  `02-targets-built` after every detonation.**

## 2. Install the toolchain (NAT attached, once)
```sh
sudo apt update
sudo apt install -y build-essential git python3 python3-pip python3-venv \
    valgrind clang clang-tidy linux-headers-$(uname -r)
# for the eBPF sensor (work in progress):
sudo apt install -y clang llvm libbpf-dev bpftool libelf-dev zlib1g-dev
pip3 install --user pytest jsonschema ruff
```
Then detach the NAT adapter and snapshot as `01-toolchain`.

## 3. Build and self-test crossview
```sh
git clone <your-repo-url> crossview && cd crossview
make                       # build/libcrossview.so
make test                  # C tests under ASan + UBSan
make pytest                # Python tests
sudo python3 -m crossview scan     # baseline: expect "every view agrees"
```
A clean baseline scan with **no findings** is the control for every test
below.

## 4. Simulating a rootkit (test targets)
These are public, well-known research tools. Clone and build them *inside the
VM* on the snapshotted disk, and keep them unloaded until you detonate.

> crossview itself contains no hiding code by design; these external targets
> are what you detect. Only ever load them in the isolated VM.

### 4a. Userland hiding — libprocesshider (safe, easy, no kernel module)
This uses `LD_PRELOAD` to override `readdir`, hiding a process from `ps` and
anything else that lists `/proc` through libc.
```sh
git clone https://github.com/gianlucaborello/libprocesshider
cd libprocesshider && make
sudo mv libprocesshider.so /usr/local/lib/
# hide any process whose name matches (default in the source: a chosen name)
echo /usr/local/lib/libprocesshider.so | sudo tee /etc/ld.so.preload
```
Start a long-running process with the hidden name, then:
```sh
sudo python3 -m crossview scan --checks processes preload
```
**Expect:** a `mismatch/userspace/high` finding (seen by `proc_getdents` and
the probes, missing from `proc_readdir`), plus a preload indicator. Remove
`/etc/ld.so.preload` and revert when done.

### 4b. Kernel hiding — Diamorphine (LKM; only on the 6.1 kernel)
A loadable kernel module that hooks `getdents`/`getdents64` and `kill` to hide
processes and itself.
```sh
git clone https://github.com/m0nad/Diamorphine
cd Diamorphine && make
sudo insmod diamorphine.ko
# its documented signal hides a given PID (read its README for the exact signal);
# hiding is triggered per-process. The module also hides itself from lsmod.
```
Then:
```sh
sudo python3 -m crossview scan --checks processes modules
```
**Expect (on the 6.1 kernel):** a `mismatch/kernel/*` process finding (missing
from both listings, seen by `pid_kill`/`pid_stat`) and a `mismatch/kernel/high`
module finding (in `/sys/module` but not `/proc/modules`). **On a newer
kernel**, the process hiding won't take effect (report shows
`syscall_dispatch: switch`); the module finding still fires. That contrast is
itself a great evaluation row and blog point.

**Detonation drill, every time:** NAT detached → snapshot at
`02-targets-built` → `insmod` / set preload → scan → record result → **revert
to snapshot**. Don't `rmmod` a hiding rootkit and trust the result; revert.

## 5. Running it elsewhere
Any x86_64 Linux (bare metal or VM) runs the detector; only the *rootkit
testing* needs the pinned-kernel lab. On another architecture the scan works
but `syscall_dispatch` reads `unknown` and some kernel-view assumptions don't
apply.
