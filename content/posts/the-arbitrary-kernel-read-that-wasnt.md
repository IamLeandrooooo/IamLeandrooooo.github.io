---
title: Refuting a condrv Kernel Read - Chasing a COMPLETE_IO memmove Through the Console IPC and a Self-Verifying PoC, Only to Lose to One Decompiler-Hidden ProbeForRead on Windows 11 24H2
description: A deep reverse-engineering write-up of the most promising false positive of a Windows 11 24H2 kernel-driver research - a seemingly unprivileged arbitrary-kernel-address read in condrv.sys where a console server names a raw SourcePtr that the driver memmoves into a client's MDL-mapped output buffer via IOCTL_CONDRV_COMPLETE_IO - that survived a triage pass, a five-item adversarial kill-list, and full protocol extraction, produced a self-verifying dual-role PoC whose control case passed cleanly, and then collapsed the instant a kernel VA was named, killed by an inlined ProbeForRead the Hex-Rays decompiler folded to nothing.
date: 2026-07-10
tldr: This write-up reverse-engineers condrv.sys on Windows 11 24H2 (build 26100) and walks a fully unprivileged arbitrary-kernel-read candidate from discovery to refutation. condrv brokers the console client/server IPC, and because conhost runs at the caller's own integrity a single process can drive both roles - a client parks an output buffer via IOCTL_CONDRV_ISSUE_USER_IO (0x500016), a server drains it with READ_IO (0x500006) and completes it with COMPLETE_IO (0x50000b), at which point the copy engine FUN_1c000cae0 memmoves Size bytes from a server-named SourcePtr straight into the client's MDL-mapped output buffer, with no ProbeForRead visible between the raw load at 0x1c000caff and the copy at 0x1c000cb78 and condrv importing no ProbeForRead at all. On paper that is an attacker-chosen kernel-VA read into an attacker buffer - KASLR defeat and pool disclosure - reachable with no admin and no privilege, and it survived three independent static passes. The refutation came from the executable - a self-verifying dual-role PoC leaking KUSER_SHARED_DATA (kernel VA 0xFFFFF78000000000 versus its user mirror 0x7FFE0000) passed its control run with a user pointer and returned STATUS_ACCESS_VIOLATION (Win32 998) the moment a kernel VA was named. The autopsy found an inlined ProbeForRead(SourcePtr) at 0x1c000c874 inside a handler Ghidra never promoted to a function (reached only through dispatch pointer 0x1c00065a0) - a CMP against MmUserProbeAddress (0x7FFFFFFF0000) plus a boundary touch that the decompiler elides because it has no modeled data-flow effect - so condrv is hardened, the bug was never real, and the takeaway is that a missing probe in the decompiler is worth nothing until an executable proves the deref actually reaches a kernel address.
draft: false
tags:
  - windows
  - kernel
  - reversing
  - ghidra
  - windbg
  - condrv
  - console
  - ipc
  - ioctl
  - info-leak
  - memory-disclosure
  - kaslr
  - probeforread
  - inlined-probe
  - false-positive
  - decompiler-artifact
  - poc
  - vulnerability-research
  - msrc
  - 24h2
toc: false
---

## 1. Why the console driver is an attack surface at all

`condrv.sys` is the Console Driver. Since the Windows 7-era console rewrite (and especially post-Windows 10, when the console host moved out of `csrss` into `conhost.exe`), `condrv` is the kernel broker sitting between a **console client** (your `cmd.exe`, your `powershell.exe` - anything with a console) and a **console server** (`conhost.exe`). Every `ReadConsole`, `WriteConsole`, and the whole console-handle machinery is marshalled through it.

The important architectural fact for an attacker is this: **the client/server split is not a privilege boundary.** `conhost.exe` runs as the *same user* as the process it hosts. When you launch a console app with an ordinary `CreateProcess`, the OS spins up a `conhost` for it at your integrity level, no elevation involved. So if I can talk the driver's server-side protocol myself, I'm not crossing a security boundary to do it - I'm just doing what `conhost` already does, as me.

That matters, because the entire value of a kernel bug is gated on *reachability*. A beautiful memory-corruption primitive behind an `Administrators`-only DACL or a `SeTcbPrivilege` check is worth nothing for local privilege escalation. `condrv`'s server surface has **no `SePrivilegeCheck`, no `SeAccessCheck`, no UIAccess gate** anywhere on the dispatch path I care about - I confirmed the IAT slots for those routines have zero code cross-references reaching the handlers. That's what made this lead exciting before I'd even understood the bug: whatever lived in there was reachable by a plain, non-elevated process.

The device objects involved:

- `\Device\ConDrv\Server` - the core server object.
- `\Reference` - opened relative to the server.
- `\Connect` - the client side, opened relative to the reference.

A single process can open all three and drive **both roles** from two threads. That's the whole trick: I don't need to attack a *real* `conhost`; I *am* the `conhost`, and I'm also the client I'm serving.

---

## 2. The IPC protocol: ISSUE / READ / COMPLETE

The console IPC is a request/response queue built on three `METHOD_NEITHER` IOCTLs (the codes are what the client/server pair actually issue):

| IOCTL | Value | Role |
|---|---|---|
| `IOCTL_CONDRV_ISSUE_USER_IO` | `0x500016` | **Client**: park a pending I/O request, hand the driver an output buffer to be filled later |
| `IOCTL_CONDRV_READ_IO` | `0x500006` | **Server**: drain the next pending message, learn its `RequestId` |
| `IOCTL_CONDRV_COMPLETE_IO` | `0x50000b` | **Server**: complete a parked request - *this is the copy* |

The flow, from the attacker's dual-role vantage point:

1. **Client thread** opens `\Connect` and issues `ISSUE_USER_IO` with an output descriptor pointing at a buffer I own (`pOut`). This call **blocks** inside the kernel - the request is now parked, waiting for a server to complete it.
2. **Server thread** issues `READ_IO` and drains the message, learning the `RequestId`/`SubId` that identify the parked client request.
3. **Server thread** issues `COMPLETE_IO` with a completion descriptor. The driver takes a **source pointer** out of that descriptor and `memmove`s `Size` bytes from it into the parked client's locked output buffer. The client's blocked `ISSUE_USER_IO` returns, and the client reads the bytes back out of `pOut`.

The completion descriptor for `COMPLETE_IO` (`0x50000b`) is a 0x28-byte structure. Reconstructed field layout:

```c
typedef struct {           // IOCTL_CONDRV_COMPLETE_IO input, 0x28 bytes
    ULONG              RequestId;   // +0x00
    ULONG              SubId;       // +0x04
    ULONG              Status;      // +0x08
    ULONG              _pad;        // +0x0c
    unsigned long long Info;        // +0x10
    void*              SourcePtr;   // +0x18   <-- the pointer that gets copied FROM
    ULONG              Size;        // +0x20
    ULONG              Offset;      // +0x24
} COMPLETE_0B;
```

There is a sibling path, `0x500013`, that reaches the same copy engine with a leaner 0x18-byte descriptor (`SourcePtr` at `+0x08`). Keep that one in mind - it becomes important in the autopsy.

---

## 3. The bug, as I read it in Ghidra

Ghidra base for my `condrv.sys` load is `0x1c0000000`. The IOCTL dispatcher `FUN_1c000e860` routes server/console object requests through the object method `FUN_1c000c610` (type descriptor `0x1c0004290`), which switches on the control code. For `0x50000b` it lands in a completion handler that eventually calls the **copy engine**, `FUN_1c000cae0`.

Here's the copy engine, trimmed to the load-bearing lines (RVAs relative to base):

```
; FUN_1c000cae0  - the console COMPLETE_IO copy engine
1c000caff   MOV   R14, [descriptor+0x00]     ; R14 = SourcePtr, loaded RAW
   ...
;   dst = client MDL kernel mapping:
;   request+0xb8 -> +0x20 (MmMapLockedPagesSpecifyCache) + Offset
   ...
1c000cb78   CALL  FUN_1c0001540              ; memmove(dst, SourcePtr, Size)  - plain SSE, no SEH
```

`FUN_1c0001540` is a bog-standard SSE `memmove`. No `__try`, no fault handling of its own. The destination is the client's output buffer, mapped into the kernel via an MDL that `condrv` locked when the client parked the request (`request+0xb8 → +0x20`, an `MmMapLockedPagesSpecifyCache` result), offset by the attacker-supplied `Offset`.

Now look at what's *missing* between `0x1c000caff` (load `SourcePtr`) and `0x1c000cb78` (copy from it): **nothing**. No `ProbeForRead`. No comparison against `MmUserProbeAddress`. No sign check. In fact `condrv.sys` **imports no `ProbeForRead` at all** - I checked the import table. The one place `MmUserProbeAddress` shows up on the sibling handler `FUN_1c000cbf0` (the `0x500013` path) is at `0x1c000cc19`, and when you read what it's bounding, it's checking the **descriptor buffer range** `[R8, R8+0x18)` - i.e., "is the 0x18-byte descriptor itself in user space" - *not* the `SourcePtr` value living inside that descriptor.

So the model I built was:

> The server hands the driver a raw `SourcePtr`. The driver validates that the *descriptor* is a user buffer, then blindly `memmove`s `Size` bytes **from `SourcePtr`** into the client buffer. `SourcePtr` is never itself constrained to user space. A server that names a **kernel** virtual address makes `condrv` read kernel memory into the client buffer - and the client reads it straight back.

That is an **arbitrary kernel-address read**. Attacker picks the VA, attacker picks the length, kernel bytes land in an attacker buffer. It defeats KASLR outright, dumps pool and `ntoskrnl` and whatever else you can point at, and it composes as the read half of an exploit chain. And it's reachable, as established, by a normal non-admin process. For a local-privilege-escalation researcher this is close to a dream find - an info-leak primitive with no privilege prerequisite.

---

## 4. The verification I did *before* writing code

I have a hard rule from getting burned before: three independent looks before anything gets a "confirmed" label. This finding got all three:

**Pass 1 - triage.** Found the copy engine, mapped `SourcePtr → memmove`, noted the absent probe, confirmed reachability (no privilege gate on the dispatch path).

**Pass 2 - adversarial kill-list.** I wrote down every way the bug *could* be false and tried to prove each one true:

1. *Is `SourcePtr` secretly validated?* - No probe visible in the copy engine, no `ProbeForRead` import. ✗ (couldn't kill it)
2. *Is the descriptor range check actually covering `SourcePtr`?* - No; it bounds `[R8, R8+0x18)`, the descriptor, not the pointer inside. ✗
3. *Is the destination the thing that's constrained, making `SourcePtr` irrelevant?* - Destination is the client MDL; source is independent. ✗
4. *Is there an SEH frame that would swallow a kernel-read fault into a benign error?* - The `memmove` has no SEH; I didn't find a wrapping `__try` on the copy engine. ✗
5. *Is the server role privileged after all?* - No `SeAccessCheck`/`SePrivilegeCheck` xrefs on the path. ✗

Five kill attempts, five misses. By my own methodology, the bug *survived* an adversarial pass.

**Pass 3 - protocol extraction.** I reverse-engineered the exact wire protocol (the ISSUE/READ/COMPLETE sequence, the descriptor layouts, the connect handshake) so I could reproduce it from user mode.

Three passes, all green. Everything I could see in the decompiler said this was real.

---

## 5. The PoC - and the discipline of making it self-verifying

Here is the rule that ultimately saved me from filing garbage to MSRC: **a finding is a hypothesis until an executable triggers it.** Static confidence is not truth. So I built `condrv_leak.c` - a single-process, dual-role harness that speaks the protocol and is **self-verifying**: it leaks a kernel address whose value I already know, so I don't have to trust a debugger to grade it.

The perfect oracle for that is `KUSER_SHARED_DATA`. It lives at a fixed kernel VA `0xFFFFF78000000000` **and** is mirrored read-only into every process at user VA `0x7FFE0000`. If my "arbitrary kernel read" is real, then reading the kernel VA through the bug should return bytes **identical** to what I can read directly at `0x7FFE0000`. Match + nonzero = proof, no `kd` required.

The harness (abridged):

```c
#define IOCTL_REQUEST  0x500016   /* client: park a pending read w/ an output buffer */
#define IOCTL_READ     0x500006   /* server: drain a message */
#define IOCTL_COMPLETE 0x50000b   /* server: complete a request -> the copy */

/* client thread: park an output buffer and block until the server completes it */
static DWORD WINAPI client_thread(void* p){
    HANDLE hClient = openCondrv(L"\\Connect", g_hRef);
    REQ_MSG msg = {0};
    msg.OutCount = 1;
    msg.Desc[0].Size   = 0x100;
    msg.Desc[0].Buffer = g_pOut;              /* driver fills THIS from SourcePtr */
    DeviceIoControl(hClient, IOCTL_REQUEST, &msg, sizeof(msg), NULL, 0, &br, NULL);
    /* returns once the leak-completion lands: kernel bytes are now in g_pOut */
    return 0;
}

int main(int argc, char** argv){
    void* g_ctrl = VirtualAlloc(...); memset(g_ctrl, 0xAB, 0x1000);
    unsigned long long target = (unsigned long long)g_ctrl;   /* default: USER control buffer */
    if (argc > 1) target = strtoull(argv[1], NULL, 0);        /* arg: a kernel VA to leak    */

    /* open \Device\ConDrv\Server, \Reference, spawn the client thread ... */

    /* server side: drain + complete the CONNECT, then drain the client's REQUEST ... */

    COMPLETE_0B c = {0};
    c.RequestId = h->RequestId; c.SubId = h->SubId;
    c.Info = N; c.Size = N; c.Offset = 0;
    c.SourcePtr = (void*)target;              /* <-- the pointer under test */
    DeviceIoControl(hServer, IOCTL_COMPLETE, &c, sizeof(c), NULL, 0, &br, NULL);

    /* then: dump g_pOut; if target==kernel VA, compare against 0x7FFE0000 */
}
```

Two modes:

- **Control mode** (no argument): `SourcePtr` points at a user buffer I've filled with `0xAB`. This exercises the *entire* machinery - the connect handshake, the parked request, the completion, the `memmove`, the client read-back - with a source I know is legal. If the control passes, the protocol and the copy path are proven correct, and the *only* remaining variable is whether a kernel `SourcePtr` is accepted.
- **Leak mode** (`condrv_leak.exe 0xFFFFF78000000000`): the real test.

That control/leak split is deliberate. It isolates the one question that actually decides the finding: **does the driver care what `SourcePtr` points at?**

---

## 6. The run

Control mode first:

```
[i] SourcePtr = 0x000001d4c2a30000 (USER control buffer, expect 0xAB back)
[B] \Server core open
[B] \Reference open
[A] client connected
[B] drained connect msg ...
[B] connect completed -> client is live
[B] drained request msg ...
[B] COMPLETE_IO LEAK: SourcePtr=0x000001d4c2a30000 Size=0x100 -> client buffer
[A] REQUEST_IO completed ok=1 (kernel bytes now in pOut)

[*] bytes read from 0x000001d4c2a30000 (first 0x40):
ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab
ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab
...
[*] CONTROL (user source, pattern 0xAB): PASSED -> copy path + protocol WORK
    -> now test a kernel VA:   condrv_leak.exe 0xFFFFF78000000000
```

Perfect. The `0xAB` pattern round-tripped through the console IPC. The handshake, the parked I/O, the completion, the `memmove`, the client read-back - all correct. Every moving part except the source-pointer question was now proven.

Then leak mode:

```
[i] SourcePtr = 0xfffff78000000000 (user-supplied)
[B] \Server core open
[B] \Reference open
[A] client connected
[B] connect completed -> client is live
[B] drained request msg ...
[B] COMPLETE_IO LEAK: SourcePtr=0xfffff78000000000 Size=0x100 -> client buffer
[!] COMPLETE leak err=998
```

`err=998`. `ERROR_NOACCESS`. The kernel-mode `STATUS_ACCESS_VIOLATION` bubbling back through the I/O manager.

The control run and the leak run were **byte-for-byte identical** except for one field: `SourcePtr`. User pointer → the copy happens. Kernel pointer → `STATUS_ACCESS_VIOLATION` *before any bytes move*. There is only one explanation for that: **`SourcePtr` is validated as a user-mode address**, and my "arbitrary kernel read" was never a thing.

The bug was dead. My three green passes were three false positives.

---

## 7. The autopsy: the instruction the decompiler never showed me

A refutation isn't finished until you can point at the exact check you missed. So I went back - this time into the **disassembly**, not the decompiler - and looked at the `0x50000b` completion handler proper, `FUN_1c000c800`.

There it was, an inlined `ProbeForRead` on `SourcePtr`, right before the completion path reaches the copy engine:

```
; FUN_1c000c800 - IOCTL_CONDRV_COMPLETE_IO (0x50000b) handler
; R? = SourcePtr (from descriptor+0x18), length in another reg
1c000c874   LEA   R8, [SourcePtr + length]        ; end = base + len
1c000c87b   CMP   R8, [MmUserProbeAddress]        ; MmUserProbeAddress = 0x7FFFFFFF0000
1c000c882   JA    fault                           ; end > user-max  -> reject
1c000c884   CMP   R8, SourcePtr                    ; end < base ?
1c000c887   JNC   ok                               ; no wrap -> continue
1c000c88a   MOVZX EAX, byte ptr [MmUserProbeAddress]  ; boundary TOUCH -> #PF on bad ptr
```

This is the textbook inlined form of `ProbeForRead(SourcePtr, length, 1)`:

> `end = SourcePtr + length; if (end > 0x7FFFFFFF0000 || end < SourcePtr) *(volatile char*)0x7FFFFFFF0000;`

A kernel VA like `0xFFFFF78000000000` makes `end > 0x7FFFFFFF0000`, the `JA` is taken, and the boundary read at `[0x7FFFFFFF0000]` - a deliberately unmapped guard address - raises `STATUS_ACCESS_VIOLATION`. That fault is caught by the `__try` wrapping the dispatch, converted to a status, and returned to my `DeviceIoControl` as error `998`. Exactly the behavior I saw. And the sibling `0x500013` path carries the **same** probe at `0x1c000cc4a`.

The copy engine `FUN_1c000cae0` genuinely has no probe - but it doesn't need one, because **`SourcePtr` is already validated by the handler before it's ever handed to the copy engine.** The engine only ever sees pointers that survived the probe.

### Why three passes missed a probe sitting in plain sight

Two failures compounded, and they're worth internalizing:

**(1) The handler wasn't a defined function in my Ghidra database.** `FUN_1c000c800` was reached only through a dispatch-table pointer at `0x1c00065a0`. Ghidra's auto-analysis never promoted that address to a function, so `decompile`/`get_callees`/xref queries against it came back **empty**. With nothing to read there, all three passes leaned on the *sibling* code I *could* decompile - the copy engine `cae0` (which really has no probe) and the neighbouring handler `cbf0` (whose only visible `MmUserProbeAddress` use bounds the descriptor range). I audited the code around the bug instead of the code *with* the check, because the code with the check didn't exist as far as my tooling was concerned.

**(2) The decompiler silently folds inlined probes.** This is the deeper trap, and it's bitten me more than once during research. The inlined `ProbeForRead` sequence - `LEA end`, `CMP MmUserProbeAddress`, `JA`, conditional boundary-`MOVZX` - has **no modeled data-flow effect** on the values Hex-Rays is tracking. The `MOVZX` loads into a scratch register that's immediately discarded; the compare only influences a fault path. So the decompiler, quite reasonably from its own point of view, **elides the whole thing**. The pseudocode reads as a couple of innocent plain loads. A probe that is *unmissable* in three instructions of disassembly is *invisible* in the decompiler's C. If you audit pseudocode, you audit a lie of omission.

I have started calling this the "inlined-probe trap," and by the end of the research the executable rule had caught it **seven** separate times: a field looks unprobed in the decompiler, the instinct-to-verify fires, and the disassembly (or, as here, the PoC) shows a `CMP MmUserProbeAddress / JA / touch` that Hex-Rays swallowed. Every single time.

---

## 8. What I actually learned

**A "missing probe" in the decompiler is worth nothing.** Not "worth investigating" - *nothing*, until you've confirmed it in disassembly or with a running executable. The Hex-Rays output is a model, and the model deliberately drops exactly the security checks I'm hunting for. Three independent analysts (well - three independent passes by me) reading that model all reached the same wrong conclusion, because they were all reading the same lie.

**Undefined functions are blind spots, not empty space.** When decompile/xref queries return empty for an address that's clearly reached (here, via a dispatch table), that is not "nothing to see." It's "your tooling refuses to look here." Force-define the function, or disassemble the bytes raw. The check I missed lived entirely inside a function my database pretended didn't exist.

**Design the PoC so one variable decides the verdict.** The control/leak split - same protocol, same everything, *only* the pointer changes - is what turned a vague "it returned an error, maybe I set up the IOCTL wrong" into "the driver rejects kernel pointers specifically." A self-verifying oracle (`KUSER_SHARED_DATA` at a known kernel VA vs. its user mirror) meant I didn't need to trust a debugger to grade the run. The experiment was built to falsify the claim cleanly, and it did.

**The executable is the only arbiter.** This is the whole thing. Static analysis is how you *find* candidates; it is not how you *confirm* them. On a modern, hardened target like 24H2, the difference between "the decompiler shows no probe" and "there is no probe" is the difference between a real MSRC report and an embarrassing one. The running PoC is the line between the two, and it does not care how confident three passes of reading pseudocode made me.

---

## 9. Closing

This was the most promising lead of that I had for a while, and it was wrong. That's not the exception in vulnerability research, it *is* the research. The satisfying version of this story, where the kernel bytes come back and KASLR falls over, is the one that gets written up. The actual day-to-day is this one: a great-looking primitive, a clean PoC, a control case that passes, and then a single instruction you never saw quietly deleting your finding. Most leads die. The ones that die on *your* PoC, in *your* lab, before they reach a vendor, are the ones you should be grateful for - because the alternative is that they die in the report, in public, with your name on them.

The discipline that kills your own findings is the same discipline that lets you trust the ones that live. `condrv` is hardened. The probe was always there. I just couldn't see it until the executable made me look.
