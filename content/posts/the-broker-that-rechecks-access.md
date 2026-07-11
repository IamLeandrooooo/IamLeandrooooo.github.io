---
title: The Sandbox Broker That Couldn't Be Confused - Forging an AppContainer Token to Reach bfs.sys and Failing to Path-Confuse a File Broker That Re-Runs the Access Check in the Caller's Own Context on Windows 11 24H2
description: A reverse-engineering write-up of a refuted sandbox-escape candidate in bfs.sys the Brokering File System on Windows 11 24H2 build 26100 - the device opens for a normal token and its per-IOCTL capability gate is passable by forging an AppContainer lowbox token carrying bfs's capability SID via NtCreateLowBoxToken, but the path and rename brokering opens every target with OBJ_FORCE_ACCESS_CHECK in the caller's own non-impersonated context against an FLT-normalized canonical name, so the broker can only ever touch files the sandbox could already open itself, leaving no path confusion, no TOCTOU, no privilege amplification, and nothing to report.
date: 2026-07-08
tldr: This write-up reverse-engineers bfs.sys on Windows 11 24H2 (build 26100), the Brokering File System that mediates filesystem access for AppContainer and sandboxed callers, and walks a sandbox-escape candidate from a promising reachability result to an intrinsic refutation. \Device\Bfs has no \GLOBAL?? symlink but its default security descriptor lets a normal token open it through \\?\GLOBALROOT\Device\Bfs, and each of its six IOCTLs is gated by FUN_140001280, which calls SeQueryInformationToken for AppContainer status and RtlCheckTokenCapability for a bfs-specific capability SID (DAT_14001b1d0, dumpable with kd dd bfs+0x1b1d0) against the caller-supplied token - a gate a normal user can pass by forging an AppContainer lowbox token that carries that capability via NtCreateLowBoxToken. The obvious target is the path and rename brokering IOCTL 0x228004 (FUN_14000ab30), the classic confused-deputy shape where a broker opens a privileged file on behalf of a sandbox that could not open it directly. It is refuted intrinsically - the broker opens the target with attributes 0x600 (OBJ_FORCE_ACCESS_CHECK plus OBJ_KERNEL_HANDLE) in the caller's own non-impersonated context, so the NT access check is re-run as the sandbox itself and the broker can only ever touch files the sandbox could already reach, and the brokering is not a privileged filesystem mutation but an in-memory grant table keyed on the FLT-normalized canonical name, closing any path-normalization or TOCTOU window, with probed and length-bounded input and no double-fetch. A broker that re-checks access in the caller's security context cannot be confused into amplifying privilege and there was nothing to report.
draft: false
tags:
  - windows
  - kernel
  - reversing
  - ghidra
  - bfs
  - brokering-file-system
  - appcontainer
  - sandbox
  - lowbox-token
  - ntcreatelowboxtoken
  - capability-sid
  - access-check
  - confused-deputy
  - path-confusion
  - toctou
  - refuted
  - false-positive
  - vulnerability-research
  - msrc
  - 24h2
toc: false
---

## 1. What a file broker is, and why it is a sandbox-escape target

An AppContainer (or otherwise sandboxed) process cannot touch the filesystem directly - its token carries a restricted capability set, and the object manager denies it any `FILE` object outside that set. To do legitimate file work it has to ask a **broker**: a more-privileged component that performs the operation on the sandbox's behalf and hands back the result. `bfs.sys` - the **Brokering File System** - is a kernel-mode broker for exactly this.

That asymmetry is the whole attraction. The broker runs with more authority than the sandbox that calls it, so the escape is the classic **confused deputy**: convince the broker to open, rename, or otherwise touch a file the sandbox itself could never reach - via path confusion (a name that resolves one way for the broker's check and another for its open), a TOCTOU swap between check and use, a symlink, or a grant-table mixup - and have it hand you the result. If the broker opens `\Device\HarddiskVolume3\Windows\System32\...` "for you" and returns a usable handle, you've walked out of the sandbox.

So I went to see whether `bfs` could be talked into it.

## 2. Reaching the surface - the device and the capability gate

`bfs` exposes `\Device\Bfs`. There is no `\GLOBAL??` (Win32) symlink for it, so you reach it through the native namespace:

```c
HANDLE h = CreateFileA("\\\\?\\GLOBALROOT\\Device\\Bfs",
                       GENERIC_READ | GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE,
                       NULL, OPEN_EXISTING, 0, NULL);
```

The device's default security descriptor permits a normal token to **open** it. But opening the device is not the same as reaching its IOCTL handlers - each of the six IOCTLs first runs a gate, `FUN_140001280`:

```c
// FUN_140001280 (per-IOCTL gate), reconstructed
if (!SeQueryInformationToken(token, TokenIsAppContainer, ...) || !isAppContainer)
    return STATUS_ACCESS_DENIED;
if (!RtlCheckTokenCapability(token, &BfsCapabilitySid /* DAT_14001b1d0 */, &has) || !has)
    return 0xC000A200;                 // STATUS_... capability not held
// ... proceed to the handler
```

Two conditions on the **caller-supplied token**: it must be an AppContainer token, and it must hold a specific **bfs capability SID** baked into the driver at `DAT_14001b1d0` (you can read it straight out of the image with `kd> dd bfs+0x1b1d0`). A normal, non-AppContainer token fails at the first check. My reachability probe confirms exactly that boundary - the device opens, the IOCTL is rejected:

```c
// bfs_probe.c -- reachability probe (build: gcc bfs_probe.c -o bfs_probe.exe), run NON-elevated
HANDLE h = CreateFileA("\\\\?\\GLOBALROOT\\Device\\Bfs", GENERIC_READ|GENERIC_WRITE,
                       FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
if (h == INVALID_HANDLE_VALUE) { printf("[!] open failed %lu\n", GetLastError()); return 1; }
printf("[+] opened \\Device\\Bfs (device SD permits this token)\n");

HANDLE tok = NULL;
OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY|TOKEN_DUPLICATE|TOKEN_IMPERSONATE, &tok);

unsigned char in[0x40] = {0}, out[0x200];
*(void**)(in+0) = tok;                       // input[0] = token handle
DWORD br = 0;
BOOL ok = DeviceIoControl(h, 0x224008, in, sizeof(in), out, sizeof(out), &br, NULL);
// -> FAIL, err = capability gate: a plain token is rejected; need a lowbox token
//    carrying the bfs capability SID.
```

So the surface is gated behind an AppContainer capability. That sounds like a wall. It is not.

## 3. Passing the gate - forge the lowbox token

The gate checks *the caller's own token* for a capability - and on Windows a normal user can **mint an AppContainer token with whatever capabilities they like**, no privilege required, via `NtCreateLowBoxToken`. You dump the capability SID from the driver, build a `SID_AND_ATTRIBUTES` array containing it, and create a lowbox token off your current one:

```c
// pass the gate: craft a lowbox (AppContainer) token carrying the bfs capability SID
SID_AND_ATTRIBUTES caps[1];
caps[0].Sid        = BfsCapabilitySid;        // = the SID at bfs+0x1b1d0
caps[0].Attributes = SE_GROUP_ENABLED;

HANDLE lowbox = NULL;
NTSTATUS st = NtCreateLowBoxToken(
        &lowbox, hCurrentToken, TOKEN_ALL_ACCESS, &objAttr,
        AnyPackageSid,       // any AppContainer package SID
        1, caps,             // <-- the forged capability set
        0, NULL);            // no saved handles
// impersonate `lowbox`, then re-issue the IOCTL -> FUN_140001280 now passes.
```

Impersonate that token, re-issue the IOCTL, and `FUN_140001280` waves you through. The full six-IOCTL surface is now reachable from an ordinary, non-elevated user.

Worth stating plainly, because it is a recurring mistake: **a capability check on the caller's own token is a reachability filter, not a security boundary.** Anyone who can call `NtCreateLowBoxToken` - i.e. anyone - can carry any capability. The capability tells `bfs` "this caller is a sandbox that wants brokering," not "this caller is authorized." If there is a real boundary in `bfs`, it has to be somewhere else. Spoiler: it is, and it is in exactly the right place.

## 4. The hunt - the path / rename brokering (IOCTL 0x228004)

The interesting handler is `FUN_14000ab30`, IOCTL `0x228004` - the path/rename broker. You hand it a path (two, for a rename) plus flags, and it performs the file operation. This is where a confused-deputy escape would live. The concrete attacks I was looking for:

- **Privilege amplification:** the broker opens the target in a *more-privileged* context (SYSTEM, or an impersonation that ignores my sandbox DACL restrictions) and returns me a handle to something my token was denied.
- **Path-normalization confusion:** I pass a name that normalizes to `X` when the broker validates it, but to `Y` when it opens it - `\??\C:\...` vs a symlink vs an 8.3 short name vs a differently-cased/Unicode-folded form.
- **TOCTOU:** the broker checks name `X`, I swap the underlying object, and it opens `Y`.

All three are the standard ways brokers fall over.

## 5. The refutation - `OBJ_FORCE_ACCESS_CHECK` in the caller's own context

`FUN_14000ab30` opens the brokered target with an `OBJECT_ATTRIBUTES` whose `Attributes` field is `0x600`:

```
0x600 = OBJ_FORCE_ACCESS_CHECK (0x400) | OBJ_KERNEL_HANDLE (0x200)
```

The load-bearing bit is `OBJ_FORCE_ACCESS_CHECK`. Normally, a `ZwCreateFile`/`ZwOpenFile` issued from kernel mode runs with `PreviousMode == KernelMode` and the object manager **skips** the access check entirely - kernel code is trusted. `OBJ_FORCE_ACCESS_CHECK` overrides that: it forces a full `SeAccessCheck` even though the open originates in the kernel. And crucially, `bfs` performs this open in the **caller's own, non-impersonated security context** - the access check is evaluated against *the sandbox's token*, not the broker's.

Follow the consequence through. The broker's open of `\...\Windows\System32\config\SAM` (or any other juicy target) is access-checked as *you*, the AppContainer caller. Your restricted token gets `STATUS_ACCESS_DENIED` for exactly the things it would be denied if it tried to open them directly. **The broker can only ever open what the sandbox could already open itself.** It is not a confused deputy, because for the purpose of the access decision it wields no more authority than its caller. Mediating the access does not *grant* the access.

That collapses the whole bug class, and it also disarms the path-confusion and TOCTOU angles - but `bfs` closes those a second way too. The brokering here is not a privileged filesystem mutation performed behind a separate check; the operation is recorded in an **in-memory grant table keyed on the FLT-normalized canonical name**. FltMgr normalizes the path to its canonical form *before* it becomes the table key **and** before the access check, so the "name I checked" and the "name I used" are the same normalized string. There is no `\??\`-vs-symlink-vs-8.3 gap to slip through, and no window between a check on one name and an open of another. The input path buffers are probed and copied with a length-bounded `memmove`; there is no double-fetch of the length or the path. So there is no normalization confusion and no TOCTOU on the name either.

Verdict on `FUN_14000ab30`: no privilege amplification, no path confusion, no TOCTOU, no escape. (For completeness, the sibling METHOD_NEITHER output-pack IOCTL `0x22400f` / `FUN_14000a200` is also bounded - its size-measuring pass and its write pass iterate a push-lock-snapshotted `'IsfB'` list with a byte-identical per-record size formula, so there is no grow-between-passes race and no output overflow; and a token/Job lifetime path was noted but low-priority.) The one place a broker is supposed to be exploitable, `bfs` simply is not.

## 6. The lesson

A broker is a confused-deputy risk **only when it acts with more authority than its caller.** `bfs` removes that at the root: `OBJ_FORCE_ACCESS_CHECK` in the caller's own non-impersonated context means every brokered open re-runs the caller's access check, so the entire "trick the broker into opening a privileged file" class is not *bounded* - it is *structurally impossible*. That is a genuinely nice design to see in the wild, and it is the pattern to recognize instantly the next time you open a broker: find the open, check the `Attributes`, and check whose token the access check runs against. If it is `OBJ_FORCE_ACCESS_CHECK` in the caller's context, the confused-deputy escape is dead before you write a line of PoC.

And the reachability half is its own reminder: the capability gate looked like a wall and was a turnstile. A capability on the *caller's own token* is a filter, not a boundary, because the caller can forge the token. The real boundary was never the gate - it was the access check, and `bfs` put it exactly where it belongs.

## 7. Closing

The interesting brokers are the ones that *don't* re-check access - the ones that open as SYSTEM and hand you the handle. `bfs` is not one of them, and the honest write-up is: I did the work to reach the surface - through the native namespace, past a forged-lowbox-token capability gate - and the surface was built correctly. That is still worth publishing. A documented reachability path and a clean design pattern are exactly what the next person wants when they open `\Device\Bfs` expecting an easy sandbox escape and need to know, quickly, that the door is actually locked from the right side.
