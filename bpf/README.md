# eBPF sensor (work in progress)

A libbpf + CO-RE program that provides kernel-vantage views and the
behavioural event stream for the anomaly model. See `../docs/ROADMAP.md` §1.

Planned hook points: `sys_enter` (per-PID syscall histograms),
`sched_process_exec`, `init_module`/`finit_module`, and `connect`. Events
stream to user space over a ring buffer as JSONL, joined to a scan by
`boot_id`.

Build (on the VM, needs `clang`, `libbpf-dev`, `bpftool`, kernel BTF at
`/sys/kernel/btf/vmlinux`):

```sh
make -C bpf        # not yet implemented
```

This directory is intentionally a stub in the current release.
