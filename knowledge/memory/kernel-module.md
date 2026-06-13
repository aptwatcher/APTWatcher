---
id: kb-mem-rootkit-lkm-001
title: "Linux kernel-module rootkits — LKM persistence and memory-resident hiding"
source_type: author-original
attribution: "APTWatcher team (clean-room)"
mitre_techniques:
  - T1014
  - T1547.006
  - T1562.001
artifact_types:
  - memory
  - kernel_modules
  - syscall_table
tools:
  - volatility3
  - lsmod
  - kallsyms
  - rkhunter
last_updated: "2026-04-19"
---

## What LKM rootkits do

A Loadable Kernel Module (LKM) rootkit is a `.ko` object inserted into
the running kernel with `insmod`, `modprobe`, or the `init_module` /
`finit_module` syscalls. Once loaded, the module runs in ring 0 with
the full rights of the kernel: it can rewrite kernel data structures,
patch function pointers, and intercept any path that flows through a
hookable table. Because it executes in the same address space as the
kernel, a successful load invalidates most userland telemetry on the
same host — the classical T1014 vehicle on Linux.

The typical hook surfaces are the syscall table (`sys_call_table`),
where the rootkit swaps the pointer for `__x64_sys_getdents64`,
`__x64_sys_kill`, or `__x64_sys_openat` to filter directory listings,
signals, and file reads; VFS `iterate_shared` / `readdir` operations on
specific inodes, to hide PIDs under `/proc` or files matching a magic
prefix; netfilter hooks via `nf_register_net_hook`, to drop C2-flagged
packets or mask listening sockets from `/proc/net/tcp`; `ftrace_ops`
structures attached to kernel functions, using the tracer trampoline as
a documented function-hooking primitive; and `kprobes` on
`commit_creds` or syscall entry to silently elevate privileges when a
magic process calls in.

Hiding the module itself is part of the job: the rootkit unlinks its
`struct module` from the global `modules` list (so `lsmod` no longer
prints it), clears its `/sys/module/` entry, and sometimes overwrites
the kobject name. Code pages stay resident; only the bookkeeping is
removed. Persistence across reboot relies on userland, because a `.ko`
in RAM does not survive a power cycle:

| Mechanism                | Location                                          | Notes                                              |
|--------------------------|---------------------------------------------------|----------------------------------------------------|
| Auto-load at boot        | `/etc/modules-load.d/*.conf`, `/etc/modules`      | systemd-modules-load reads these before userspace  |
| modprobe alias / options | `/etc/modprobe.d/*.conf`                          | Aliases a benign name to the rootkit `.ko`         |
| initramfs injection      | `/boot/initrd.img-*`, `/boot/initramfs-*.img`     | Survives a package reinstall of the target         |
| systemd unit + `insmod`  | `/etc/systemd/system/*.service`                   | Often paired with a dropper in `/usr/local/sbin/`  |
| Module directory         | `/lib/modules/$(uname -r)/extra/` or `/updates/`  | Loaded when referenced by alias                    |

## How to detect them

The first move on a suspected host is to cross-check the three views
the kernel exposes of its own module list. On a clean system they
agree; divergence is the single most reliable LKM indicator.

```bash
lsmod                       # reads /proc/modules under the hood
cat /proc/modules           # raw kernel list
ls /sys/module/             # kobject directory, one entry per module
```

A module in `/sys/module/` but absent from `/proc/modules`, or whose
code pages are resident per `kallsyms` while its `struct module` is
unlinked, is hidden by construction. Volatility3 covers this post-mortem:

| Plugin                  | What it does                                                         |
|-------------------------|----------------------------------------------------------------------|
| `linux.lsmod`           | Walks the `struct module` list the way the kernel does for `lsmod`   |
| `linux.hidden_modules`  | Scans memory for `struct module` candidates not on the linked list   |
| `linux.check_modules`   | Compares module list vs `/sys/module/`, flags divergence             |
| `linux.check_syscall`   | Verifies each `sys_call_table` entry points inside kernel `.text`    |
| `linux.check_afinfo`    | Inspects `/proc/net/{tcp,udp}` `seq_operations` for tampering        |
| `linux.malfind`         | Finds executable anonymous mappings — catches userland loaders       |

Kernel symbol integrity is the follow-up: each pointer in the syscall
table should resolve via `/proc/kallsyms` to a symbol owned by
`vmlinux` or a legitimate module; a slot pointing at an address
`kallsyms` attributes to `[unknown]`, or to a module not in `lsmod`,
is an active hook. The same logic applies to `ftrace_ops` and to
`kprobe` breakpoints on sensitive functions such as `commit_creds`,
`prepare_creds`, or `__x64_sys_kill`. `rkhunter --check` is a useful
signature pass but corroborating only: it runs in userland, where a
hooked `getdents64` can lie to it.

## What APTWatcher records

For each suspicious module, the finding captures:

1. Module name as reported by each view (`lsmod`, `/proc/modules`,
   `/sys/module/`, `linux.hidden_modules`) plus the disagreement matrix.
2. Memory address range of the module's `.text` — load address, size,
   and `core_layout.base` through `core_layout.base + core_layout.size`.
3. On-disk path of the `.ko` when one is found (`/lib/modules/...`,
   `/tmp/`, a user home, or an initramfs extract path) with SHA-256 of
   the `.ko` bytes and its mtime.
4. Each syscall hook: number, symbolic name, expected target from
   `kallsyms` on a clean kernel of the same build, and current target
   with its owning module or `[unknown]` attribution.
5. Additional hooks: `ftrace_ops` on kernel functions, kprobes on
   credential routines, and netfilter hooks not owned by a distro module.
6. Persistence locator — which mechanism from the table above was found
   on disk, its full path, SHA-256 of the config or unit file, and the
   alias or module name it references.
7. Module signing state: `modinfo` `signer`, `sig_key`, `sig_hashalgo`,
   plus `CONFIG_MODULE_SIG_FORCE` and the current `lockdown` LSM mode.

## Confidence calibration and pitfalls

Out-of-tree modules are normal on production Linux: NVIDIA's
proprietary driver, VMware Tools (`vmw_balloon`, `vmw_vmci`),
VirtualBox Guest Additions (`vboxguest`, `vboxsf`), ZFS-on-Linux,
DKMS-built Wi-Fi drivers, and enterprise endpoint agents all ship
unsigned or signed with a vendor key not in the kernel's built-in
keyring. Presence alone is not suspicious and "unsigned" is not a
tier-up — a DKMS-built NVIDIA module looks unsigned on a host without
an enrolled MOK. Secure Boot and the `lockdown` LSM change that
calculus: under `lockdown=integrity` or `lockdown=confidentiality`, an
unsigned module should not have loaded at all, so a resident unsigned
module is itself an indicator independent of behavior.

Tier up to "likely rootkit" only when at least two of the following
hold: the module is unsigned or signed by an unknown authority; at
least one syscall, VFS, or netfilter hook points at its address range;
a persistence mechanism references it by alias or path; the module is
hidden from at least one of the three view mechanisms. A single
hidden-module hit with no hooks and no persistence is recorded as
`consistent with LKM rootkit` and capped near `0.5`, pending a
filesystem sweep or a second fleet host carrying the same SHA-256.
Never trust `lsmod` alone on a host under suspicion — the whole point
of an LKM rootkit is that the userland view is the first to lie.
