---
title: Five Ghosts in Ring Zero - Autopsies of Windows Kernel Exploits That Vanished Under Proof
description: A deep Windows 11 24H2 kernel-reversing write-up about five vulnerability candidates that looked reportable in static analysis - a near-4 GiB FileCrypt integer wrap, an ahcache kernel-address oracle, a BindFlt minifilter underflow, an IntelPEP pool overflow, and a KSecDD raw callback registration primitive - and the exact runtime, producer-contract, filesystem, and boot-lifetime invariants that killed every one before it reached MSRC.
date: 2026-07-29
tldr: This write-up is about the part of kernel vulnerability research that does not fit cleanly into a CVE announcement - the candidates that survive the decompiler, survive the first call-graph pass, survive a threat-model review, and then die when the executable, the upstream producer, or the object lifetime finally gets a vote. FileCrypt really does round a near-4 GiB write length through 32-bit arithmetic, but ordinary NTFS/EFS writes never enter the private transformation context that would make the wrapped value dangerous. ahcache really does expose an access-bit alias and a nested pointer-shaped request, but a debugger-grounded mapped kernel address is rejected exactly like an unmapped address, so there is no address oracle. BindFlt really does subtract eight from a tiny returned length before copying, but NTFS rejects lengths 1 through 7 before the minifilter callback runs. IntelPEP really does allocate N * 0x90 + 8 in 32 bits and then populate N records, but acpi.sys can reach the wrapping count only after materializing roughly 29.8 million serializable AML objects and about 1.19 GB of interpreter state. KSecDD really does accept a raw callback pointer through a FILE_ANY_ACCESS IOCTL, but the useful slots are write-once, claimed during boot, inherited into silos, and never reopened. Every arithmetic bug was real. Every security claim was wrong. The difference was not better pattern matching; it was reconstructing who creates the input, when the state exists, what the previous layer guarantees, and whether a normal attacker can ever make all of those conditions true at once.
draft: false
tags:
  - windows
  - kernel
  - drivers
  - reversing
  - ghidra
  - windbg
  - vulnerability-research
  - false-positive
  - refutation
  - integer-overflow
  - minifilter
  - acpi
  - efs
  - ksecdd
  - ahcache
  - filecrypt
  - bindflt
  - intelpep
  - msrc
  - code-archaeology
toc: false
---

There is a version of vulnerability research that reads like archaeology with a kill chain at the end.

You find the unchecked multiply. You recover the IOCTL. You draw the structure.
You name the primitive. You write the report. Microsoft assigns the case, the case becomes a CVE, and the write-up begins with the satisfying sentence:

> I found a bug.

This is not that write-up.

This is about five times I found code that was absolutely wrong and a vulnerability that absolutely was not there.

That distinction matters more in the Windows kernel than almost anywhere else.
A driver can contain a real integer wrap, a real undersized allocation, a real raw pointer, and a real out-of-bounds copy while still giving an ordinary attacker nothing. The I/O manager may reject the request before the dispatch routine. NTFS may refuse the buffer before the minifilter sees it. An upstream serializer may make the dangerous count physically unconstructable. A callback slot may be writable exactly once, six seconds before the attacker exists.

If you stop at the vulnerable instruction, you report fiction.

So this is the autopsy collection: FileCrypt, ahcache, BindFlt, IntelPEP, and KSecDD. Five candidates from one Windows 11 24H2 driver review. Five different ways a beautiful primitive can die.

The common lesson is simple:

> A vulnerable instruction is not a vulnerability. The vulnerability is the complete path from attacker authority to violated security boundary.

Everything after that sentence is evidence.

* * *

## 1. My acceptance rule: four proofs or it is only a candidate

Before the individual bugs, I need to define what I mean by "refuted."

For a kernel finding to survive, I want four separate proofs:

1. **Instruction proof** - the machine code violates a memory, arithmetic,
   lifetime, or authorization invariant.
2. **Input proof** - a lower-privilege actor controls every field and state
   required to reach that instruction.
3. **Path proof** - the I/O manager, filesystem, framework, producer, broker,
   and previous parser layers actually permit that input to arrive.
4. **Impact proof** - the resulting operation crosses a meaningful security
   boundary under the real mitigations and deployment model.

Static analysis is excellent at proof one.

Most false positives die in proofs two and three.

That is why the strongest question in driver research is not:

> Where is the unchecked copy?

It is:

> Who is allowed to manufacture the object that reaches the unchecked copy?

The answer may be an ordinary process. It may be SYSTEM. It may be the filesystem after enforcing an invariant. It may be firmware after allocating a gigabyte of interpreter state. It may be a boot component that wins a one-time race before logon.

Those are completely different vulnerabilities, even if the final instruction is the same `memmove`.

* * *

## 2. FileCrypt - the four-gigabyte write that wrapped to zero and did nothing

FileCrypt was the cleanest arithmetic candidate in the entire review.

The basic shape looked almost offensively good:

1. A write length approaches `2^32`.
2. FileCrypt rounds that length to its transformation block size.
3. The rounding occurs in 32-bit arithmetic.
4. The rounded value becomes zero or tiny.
5. Downstream code still knows about the original enormous write.

That is the classic allocation/copy mismatch:

```text
rounded = (length + blockSize - 1) & ~(blockSize - 1)
```

For a 512-byte block:

```text
length      = 0xfffffe01
blockSize   = 0x200

length + 0x1ff
            = 0x100000000

truncated32 = 0
rounded     = 0
```

If one side allocates `rounded` bytes and another side processes `length` bytes, the result should be catastrophic: tiny allocation, enormous copy, nonpaged-pool destruction, bugcheck at minimum, and maybe something stronger with the right downstream shape.

### 2.1 Why the static bug looked reportable

The arithmetic was not a decompiler artifact. It was visible in the actual width of the registers. The add and mask occurred in 32-bit state. No checked addition widened the expression. No explicit rejection handled the boundary.

The attacker model looked ordinary too. Windows exposes EFS through normal file operations. A user can create a file, mark it encrypted, reserve a huge virtual buffer, and call `WriteFile` with a near-`UINT32_MAX` length.

That is enough to make the candidate feel real:

- ordinary user;
- ordinary file;
- ordinary cached write;
- attacker-controlled length;
- confirmed 32-bit wrap;
- kernel transformation driver downstream.

I built the trigger around exactly that model.

The first run failed early:

```text
validated volume=C:\ filesystem=NTFS EFS=yes free=52394 MiB
reserved user buffer=000000007FFF0000 length=0xFFFFF002
EncryptFileW failed: error=50
```

That was not interesting yet. It only meant that particular environment did not support the requested EFS operation.

The second VM did.

```text
validated volume=C:\ filesystem=NTFS EFS=yes free=28896 MiB
reserved user buffer=0000024009E30000 length=0xFFFFF002
target=C:\FileCryptCrashTest\trigger.bin attributes=0x00004020
TRIGGERING: one synchronous cached WriteFile length=0xFFFFF002
WriteFile returned ok=1 error=0 bytesWritten=4294963202
host survived
```

Then I corrected the exact boundary:

```text
validated volume=C:\ filesystem=NTFS EFS=yes logicalSector=512
derived trigger length=0xFFFFFE01 modeledRounded=0x00000000
reserved user buffer=00000201D0C00000 length=0xFFFFFE01
target=C:\FileCryptCrashTest\trigger-corrected.bin attributes=0x00004020
TRIGGERING: one synchronous cached WriteFile length=0xFFFFFE01
WriteFile returned ok=1 error=0 bytesWritten=4294966785
host survived
```

The exact wrapping write completed successfully.

Not "the process survived but the kernel logged an error." Not "Verifier caught something later." The system accepted the write and reported the entire near-four-gigabyte length.

### 2.2 The invariant I had modeled incorrectly

The mistake was treating "EFS-encrypted file" and "FileCrypt transformation context" as the same state.

They are not.

The vulnerable rounding code is downstream of a private stream/operation context. Ordinary EFS writes do not automatically enter that exact path merely because the target file carries the encrypted attribute. NTFS and EFS can service the write through a different pipeline whose length accounting never uses the wrapped FileCrypt value as an allocation boundary.

So the arithmetic defect is real, but the dangerous state transition is missing:

```text
ordinary user write
    -> NTFS/EFS path
    -> no required private FileCrypt stream context
    -> vulnerable transform not selected
    -> write completes normally
```

The candidate died because I proved the most important attacker-controlled input - the write length - while assuming the most important driver-controlled input - the transformation context.

That is a classic kernel-research trap. A callback can be attached to an IRP path without every IRP of that broad type reaching it. The file attribute, major function, and byte count may all match while an ECP, stream context, internal flag, or originating component still gates the vulnerable branch.

### 2.3 Verdict

FileCrypt contains a genuine length-invariant defect.

I did not establish an ordinary-user path into the state where that defect becomes memory corruption.

No report.

The right future question is not "can I issue a larger write?" The VM already answered that. The right question is:

> Which trusted component creates the private FileCrypt context, and can an ordinary attacker cause that component to attach it to attacker-controlled file data and length?

Without that bridge, the four-gigabyte wrap is a latent bug, not a vulnerability.

* * *

## 3. ahcache - the kernel-address oracle where every address returned the same answer

The ahcache candidate was the opposite kind of seduction.

FileCrypt had spectacular arithmetic and missing state. ahcache had suspicious reachability and a structure that looked like a kernel pointer oracle.

The device could be opened through an access-bit alias with a restricted token.
A forged operation-6 request accepted a nested address and length. The obvious model was:

```text
attacker supplies candidate kernel VA
    -> driver attempts to consume bytes at VA
    -> mapped address behaves differently from unmapped address
    -> attacker learns kernel address validity
```

Even a one-bit mapped/unmapped oracle matters in the kernel. It can recover module bases, defeat KASLR, guide a separate write primitive, or distinguish pool layouts.

### 3.1 The first probe was ambiguous

The initial request:

```text
Original-token open: valid=True, error=0
Restricted-token DesiredAccess=0 open: OK
Forged op6: ok=True error=0 bytesReturned=0 result=0
```

That proved two things:

- the alias/restricted-token handle path existed;
- the forged operation shape was accepted in at least one benign form.

It did not prove the address oracle.

The address oracle required a controlled pair: one address known to be mapped, one address known not to be mapped, identical request otherwise.

Guessing a kernel address is not a control. If both guesses fail, I learn nothing about the driver.

So I connected kernel WinDbg and asked the kernel itself:

```text
0: kd> x nt!NtBuildNumber
fffff801`9f9aa74c nt!NtBuildNumber

0: kd> dw nt!NtBuildNumber L1
fffff801`9f9aa74c  6658
```

Now I had a debugger-proven mapped kernel address containing known data.

The test:

```text
AhcacheProbe.exe --address 0xFFFFF8019F9AA74C --length 2

Original-token open: valid=True, error=0
Restricted-token DesiredAccess=0 open: OK
Oracle input: address=0xFFFFF8019F9AA74C length=2
Forged op6: ok=False error=998 bytesReturned=0 result=0
```

Then an address selected as unmapped:

```text
AhcacheProbe.exe --address 0xFFFFF00000000000 --length 2

Original-token open: valid=True, error=0
Restricted-token DesiredAccess=0 open: OK
Oracle input: address=0xFFFFF00000000000 length=2
Forged op6: ok=False error=998 bytesReturned=0 result=0
```

Mapped and unmapped produced the same result:

```text
ERROR_NOACCESS (998)
```

### 3.2 Why that result kills the oracle

An oracle is not "the driver touches my field."

An oracle is a stable, attacker-observable distinction correlated with the secret property being queried.

Formally, if:

```text
f(mapped_address) == f(unmapped_address)
```

then `f` communicates no mapped/unmapped bit.

The nested pointer shape and access alias were real. The security interpretation was wrong. Somewhere before the useful dereference, the path constrains the address, probes it as user memory, rejects the request's mode, or otherwise normalizes both kernel-space cases into the same access violation.

The exact internal mechanism matters for code quality, but not for the vulnerability verdict. The executable already answered the security question.

### 3.3 The methodological point

Kernel-address candidates need debugger-grounded controls.

Not:

```text
try 0xfffff80000000000
try 0xfffff90000000000
both failed
```

But:

```text
resolve a symbol in the running kernel
read it successfully in kd
send that exact VA through the candidate
compare with a deliberately unmapped VA
```

Anything weaker is astrology with hexadecimal.

### 3.4 Verdict

The access-bit alias exists.

The forged operation exists.

The kernel-address oracle does not.

No report.

* * *

## 4. BindFlt - the minifilter underflow that NTFS refuses to deliver

BindFlt was the purest example of why a minifilter callback cannot be audited as if it owns the whole request contract.

The suspicious code consumed a returned filename structure and performed an eight-byte subtraction before copying. For returned lengths from one through seven:

```text
payloadLength = returnedLength - 8
```

Unsigned arithmetic turns that into an enormous value.

Inside the callback, this looks fatal. Tiny structure, huge derived copy, kernel memory corruption.

### 4.1 The tempting model

The minifilter is loaded and attached. An ordinary process can query file information. Some BindFlt mappings may expose paths the user can open. The callback receives the query result and transforms it.

So the hypothesis was:

```text
ordinary process requests tiny output length
    -> filesystem returns short success/partial result
    -> BindFlt pre/post path sees returnedLength 1..7
    -> returnedLength - 8 underflows
    -> oversized pool copy
```

The arithmetic proof was easy.

The upstream-contract proof was the entire case.

### 4.2 Native tests against the actual filesystem boundary

I tested the relevant native information classes with lengths 1 through 7.

Every one returned:

```text
STATUS_INFO_LENGTH_MISMATCH
IoStatus.Information = 0
```

And it happened before the minifilter received a usable short result.

Length 8 was the first request that crossed the native minimum and entered the normal dispatch shape.

That changes the reachable range:

```text
static function domain:
    returnedLength = 0..UINT32_MAX

filesystem-produced domain:
    returnedLength = 0 on rejection
    or returnedLength >= 8 on dispatch
```

The vulnerable interval `1..7` exists in the C arithmetic and does not exist in the producer's output language.

### 4.3 Why "but the driver should still check" is not a security argument

It absolutely should check.

Defense in depth says the callback should reject any length below the structure minimum. Contracts change. Alternate filesystems exist. Kernel callers can be wrong. Robust code validates at every trust boundary.

But MSRC severity is not assigned to hypothetical future contract violations.
The question was whether an ordinary process on the reviewed Microsoft stack could cause the affected callback to receive one of those values.

The answer was no.

The filesystem is not merely "another function before the bug." It is the producer of the value. If the producer's successful-output invariant excludes the dangerous range, the attacker cannot select that range by choosing a smaller user buffer. The request is rejected before the vulnerable consumer exists.

### 4.4 A second BindFlt lesson: device reachability is not path reachability

BindFlt also has a communication port protected by FltMgr's default security descriptor. Standard and restricted tokens were denied at `FilterConnectCommunicationPort`. Mapping creation belongs to privileged components.

That does not by itself refute every filesystem callback bug - a user might operate through a mapping created by SYSTEM. But it destroys the lazy argument:

> The driver is loaded, therefore the user reaches the vulnerable state.

Loaded is not reachable.

Attached is not reachable.

An open handle is not the required stream context.

And a minifilter callback is not proof that the filesystem will manufacture every integer the decompiler lets you imagine.

### 4.5 Verdict

The subtraction should be hardened.

The vulnerable length interval is not produced by the native filesystem path.

No report.

* * *

## 5. IntelPEP - a real pool overflow behind thirty million AML objects

IntelPEP was the candidate that survived the longest because every time one invariant killed it, a deeper architectural fact revived it.

The parser consumes ACPI `_DSM` output describing firmware dependency packages. It reads a count `N` and allocates:

```text
allocationSize = N * 0x90 + 8
```

The arithmetic is 32-bit.

The parser then walks `N` package elements and writes fixed-size output records.

This is textbook:

```text
small wrapped allocation
    + original large iteration count
    = nonpaged pool overflow
```

### 5.1 The first static model

The machine code effectively performs:

```text
edx = N * 9
edx <<= 4
edx += 8
```

All in 32 bits.

No checked multiply. No `N <= maximum`. No comparison between `N` and the serialized ACPI output length.

Once the allocation wraps, the first record writes fields near offsets
`+0x8c` and `+0x90`, already beyond a tiny allocation.

The `_DSM` call was automatic during Intel PEP initialization, giving a clear firmware-to-kernel boundary.

This looked reportable as malicious-ACPI boot-time pool corruption.

### 5.2 The first attempted refutation - Count might be one

`N` was not a raw AML integer. It was `ACPI_EVAL_OUTPUT_BUFFER.Count`, produced by `acpi.sys`.

That matters because ACPI packages can be represented in two ways:

1. one top-level package argument whose nested payload contains elements;
2. a flattened top-level output whose `Count` equals the package element count.

If IntelPEP always received representation one, `Count` would be one and the overflow would be dead.

So I reversed the ACPI serializer.

The result revived the bug.

For a top-level Package/VarPackage, the size helper reads the internal element count, writes that count to `ACPI_EVAL_OUTPUT_BUFFER.Count`, recursively sizes every child, and omits an outer wrapper. The serializer mirrors the same behavior and serializes the children directly.

So IntelPEP really can receive a large flattened `Count`.

The producer-contract refutation failed.

### 5.3 The actual killing constraint - every element must exist

The first wrapping count is roughly:

```text
N ~= 29,826,162
```

Could firmware encode that compactly with:

```text
VarPackage(29826162) {
    one_valid_element
    // omitted remainder
}
```

If omitted slots became serializable zero integers, the AML could stay small while `Count` became enormous. That would make the IntelPEP overflow real.

So I traced uninitialized `VarPackage` elements through `acpi.sys`.

The size helper tolerates internal type-zero/null elements as zero-byte children.

The serializer does not.

It accepts only the serializable internal object types - Integer, String, Buffer, and Package. On the first uninitialized slot it returns:

```text
STATUS_ACPI_INVALID_DATA
```

That means every one of the roughly 29.8 million elements must be initialized to a serializable object before IntelPEP receives a successful result.

And ACPI's internal package representation costs roughly `0x28` bytes per element:

```text
29,826,162 * 0x28
    = 1,193,046,480 bytes
```

About 1.19 GB just for the internal element array, before interpreter overhead, child objects, serialization buffers, traversal, and the IntelPEP allocation.

Firmware also needs tens of millions of AML initialization operations unless a bulk-initialization primitive exists. I found none.

The chain becomes:

```text
malicious AML
    -> allocate ~1.19 GB ACPI package state
    -> execute ~29.8 million serializable element initializations
    -> recursively size every child
    -> allocate canonical output
    -> serialize every child
    -> only then hand Count to IntelPEP
    -> IntelPEP allocation wraps
```

The arithmetic bug at the end is real.

The machine is overwhelmingly more likely to fail from ACPI resource exhaustion long before reaching it.

### 5.4 Why this refutation is different

This is not a clean mathematical impossibility like BindFlt's excluded length range.

It is a feasibility refutation.

No explicit serializer cap forbids the count. The representation supports it.
Given absurd enough resources and time, the state may be constructable.

But vulnerability research is not about inputs that exist in Platonic integer space. It is about realistic attacker mechanisms on real machines.

A candidate whose prerequisite is "successfully construct more than a gigabyte of ACPI interpreter objects and run thirty million AML initializations during firmware evaluation" is not the boot-time tiny-allocation pool overflow the first pseudocode suggested.

The correct classification is:

- unsafe arithmetic;
- valuable hardening target;
- possible resource-exhaustion behavior upstream;
- no realistic demonstrated path to the wrapped IntelPEP allocation.

### 5.5 Verdict

The multiplication is wrong.

The parser should use checked `size_t` arithmetic and validate `N` against serialized length.

The malicious-firmware corruption path is not practically established.

No report as a reachable pool overflow.

* * *

## 6. KSecDD - the FILE_ANY_ACCESS raw callback pointer that arrives too late

KSecDD was the candidate that looked the most like immediate code execution.

The device security descriptor allowed broad access. A buffered `FILE_ANY_ACCESS` IOCTL accepted a 16-byte record:

```text
slot
rawPointer
```

The dispatcher forwarded it without an observed token check, `PreviousMode` gate, pointer probe, or provenance validation.

Some slots installed the raw pointer into a global callback table. Later dispatch loaded the global, dereferenced its first qword, and invoked through `__guard_dispatch_icall`.

Another slot treated the raw address as an array of provider records and rewrote them in place.

On paper:

```text
ordinary user
    -> FILE_ANY_ACCESS IOCTL
    -> attacker raw kernel pointer stored globally
    -> later indirect kernel call/dereference
```

That is the shape of a catastrophic vulnerability.

### 6.1 Why KCFG does not magically make raw pointers safe

Kernel Control Flow Guard constrains indirect-call targets. It does not make an attacker-selected pointer safe to dereference.

Even if KCFG blocks direct execution of user memory:

- a pointer to invalid kernel memory can bugcheck;
- a pointer to a valid CFG target with attacker-controlled object layout may
  create call-oriented behavior;
- an unchecked record-array rewrite can corrupt kernel data without calling
  anything.

So "there is `__guard_dispatch_icall`" was not a refutation.

The raw-pointer trust was real.

### 6.2 The live test that changed the threat model

The registration slots were write-once.

Safe zero-pointer probes against the useful global slots returned:

```text
STATUS_OBJECT_NAME_COLLISION
```

for slots 0, 1, 3, and 4.

They were already claimed.

Then I reconstructed lifetime:

- KSecDD is a boot-start/Base-group driver.
- SYSTEM/LSASS security initialization claims the provider slots.
- There is no unregister path.
- There is no reset IOCTL.
- There is no practical unload/reload cycle available to an ordinary user.
- Fresh server/container silos inherit the already-populated host provider
  table rather than receiving empty slots.

The useful state exists once:

```text
slot == NULL
```

And it exists during early boot before the ordinary attacker can open the device and race registration.

By the time user mode is alive:

```text
slot != NULL
registration -> STATUS_OBJECT_NAME_COLLISION
```

### 6.3 The slot-2 complication

Slot 2 was not a normal callback install. It performed a one-time in-place rotation/prepend over a provider-record array.

That is still unsafe with an untrusted pointer. But host initialization claims the operation, and silo creation copies the populated host provider table into the silo. A new silo does not reopen an empty registration window.

Without:

- a reset mechanism;
- an unregister path;
- a user-controlled preclaim before legitimate initialization;
- or a fresh namespace whose table starts empty;

the raw-pointer primitive is unreachable at the time the attacker has the handle.

### 6.4 This is the lifetime equivalent of an ACL

Security reviews usually treat authorization spatially:

```text
Who can open the device?
Who can issue the IOCTL?
Which token passes the check?
```

KSecDD required temporal authorization:

```text
Who can issue the IOCTL while the slot is still writable?
```

The DACL said "broadly reachable."

The lifetime said "too late."

That is why a one-time initialization primitive can look world-writable in the binary and still be unavailable to every post-logon attacker.

The vulnerable state is protected by chronology.

### 6.5 Verdict

The registration API trusts raw pointers too aggressively.

The useful slots are already populated before an ordinary attacker exists and cannot be reopened.

No practical local privilege-escalation path.

No report as a post-logon vulnerability.

* * *

## 7. The smaller bodies in the morgue

The five candidates above deserved full autopsies. Several smaller findings died for the same underlying reasons.

### 7.1 RDBSS - a real 16-bit allocation wrap with no Microsoft caller

`RxPrepareToReparseSymbolicLink` performs a 16-bit `Length + 0x16` allocation calculation and copies the original length. Values around `0xffea` produce a tiny allocation followed by an approximately 64 KiB overwrite.

That root cause is real.

But:

- no installed Microsoft inbox driver imported the export by name or ordinal;
- RDBSS had no internal caller;
- normal reparse payload limits sit far below the wrapping range.

An exported kernel function is not an attack surface by itself. Someone lower privileged needs a path to call it with the dangerous value.

No caller, no vulnerability.

### 7.2 NDProxy - a buffered output overflow behind a SYSTEM-only device

One NDProxy IOCTL accepts output sizes below its true completion structure requirement because of unsigned subtraction, then an asynchronous completion writes roughly 48 bytes plus a header.

The copy bug is real.

Direct device access is SYSTEM-only. The RAS broker constructs trusted output sizes from its own allocations, and I found no unprivileged forwarding path for an attacker-selected small length.

The difference between "the IOCTL is vulnerable" and "an attacker can issue the vulnerable IOCTL" is the device security descriptor plus broker protocol.

### 7.3 ACPI generic method marshalling - firmware bugs behind a UMDF trust flag

Generic ACPI method marshallers contained real malformed-buffer behavior, but the direct user path required `IRP_UM_DRIVER_INITIATED` semantics or a permissive Microsoft UMDF bridge. I found neither for the candidate method.

The parser may be wrong. The trust-boundary bridge was missing.

### 7.4 The proposed StorUFS bitmap overflow - one runtime field decides reality

The HPB parser passes a 16-bit region index to `RtlSetBit` without an explicit comparison against `SizeOfBitMap`.

That sounds like a one-bit OOB write up to 8 KiB past the bitmap.

Except a 65,536-bit bitmap is exactly 8 KiB, and then every possible 16-bit index is valid.

`storufs.sys` only reads the bitmap pointer/size fields; an external StorPort setup path populates them. Static analysis could not prove whether the size is negotiated and smaller or fixed at `0x10000`.

One debugger command decides the finding:

```text
dd adapter+ef0 L1
```

If it prints `00010000`, the global OOB theory is dead.

That candidate is not "confirmed with a caveat." It is conditional and must stay conditional until the invariant is measured.

* * *

## 8. Five different ways a kernel finding dies

These cases look unrelated at the driver level. At the invariant level they form a useful taxonomy.

| Candidate | Vulnerable instruction | What killed the security claim |
|---|---|---|
| FileCrypt | 32-bit near-4 GiB rounding wrap | Required private transformation context absent from ordinary EFS writes |
| ahcache | Nested address-shaped operation | Mapped and unmapped kernel addresses produce identical rejection |
| BindFlt | `returnedLength - 8` underflow | NTFS rejects lengths 1–7 before minifilter consumption |
| IntelPEP | `N * 0x90 + 8` allocation wrap | Producer must materialize ~29.8 million serializable objects and ~1.19 GB state |
| KSecDD | Raw pointer registration | Write-once slots claimed during boot; no reset/unregister/post-logon window |

Those are five refutation families:

1. **Missing state** - the attacker controls the bytes but cannot create the
   internal context.
2. **Missing distinction** - suspicious behavior exists but communicates no
   security-relevant bit.
3. **Producer invariant** - the previous layer excludes the dangerous value.
4. **Feasibility ceiling** - the dangerous value exists mathematically but not
   through a realistic producer.
5. **Lifetime exclusion** - the operation is exposed only after its useful
   state has disappeared.

This is the checklist I now apply before I let myself call anything a vulnerability.

* * *

## 9. Why the decompiler keeps winning arguments it should lose

Decompiler output is local.

Security is architectural.

Ghidra can show:

```c
size = count * 0x90 + 8;
buffer = Allocate(size);
for (i = 0; i < count; i++)
    populate(buffer + 8 + i * 0x90);
```

And that pseudocode can be perfectly accurate while the vulnerability claim is wrong.

The decompiler does not tell you:

- `count` came from a serializer that rejects omitted elements;
- the callback only runs with a private ECP;
- the filesystem refuses the dangerous length;
- the slot was consumed during boot;
- the device DACL blocks the caller;
- the broker reconstructs a safe buffer;
- the completion reports one value but leaves another buffer modified;
- the relevant pointer is provider-owned, not the lookaside object you found
  five functions later.

Those facts live in different binaries, different phases, different object lifetimes, or the running machine.

This is why "I audited the function" is not enough.

The unit of kernel security research is the system.

* * *

## 10. How I try to kill a finding now

Every serious candidate gets a written kill-list before I build the PoC.

### Input provenance

- Is the field raw user input, firmware input, network input, or produced by a trusted parser?
- Is the apparent count serialized, flattened, normalized, clamped, or reconstructed?
- Does another layer replace the caller's buffer with its own?

### Reachability

- What exact handle, IOCTL, FSCTL, escape, callback, or protocol message reaches the instruction?
- What access bits are encoded in the control code?
- What does the device or communication-port ACL allow?
- Does a broker expose the dangerous parameter or manufacture a safe one?

### State

- Which context, flag, ECP, stream object, feature bit, mapping, or queue must exist?
- Who creates it?
- Can the attacker create it, inherit it, or race it?
- Is it available after logon?

### Producer contract

- What values can the immediate producer successfully return?
- What lengths does the filesystem reject before the callback?
- What object types does the serializer accept?
- Does failure zero `Information`, preserve partial bytes, or suppress the consumer entirely?

### Lifetime

- Is the slot write-once?
- Is the object referenced across unlock?
- Does teardown wait for callbacks?
- Can a fresh silo/device/session recreate vulnerable initial state?

### Impact

- Is this arbitrary addressable memory access, relative access, one-bit access, resource exhaustion, or only malformed state?
- Who already controls the victim?
- Is "host to ordinary guest" actually a boundary in that deployment?
- Do I have a disclosure channel, or merely an internal OOB read?

### Executable falsification

- Can I build a control case that proves the whole protocol except one disputed variable?
- Can WinDbg give me a known mapped address rather than a guessed one?
- Can I stop before the corrupting instruction and prove the inequality?
- What result would make me delete the report?

That last question matters.

If no possible experiment can make you abandon the finding, you are not validating it. You are defending it.

* * *

## 11. What I would have reported if I had stopped early

If I had stopped at the best-looking pseudocode, the report titles would have been spectacular:

- **FileCrypt near-4 GiB integer overflow leads to nonpaged-pool corruption**
- **ahcache restricted-token IOCTL exposes kernel address-validity oracle**
- **BindFlt short filename query causes unsigned-underflow pool overwrite**
- **IntelPEP malicious ACPI package count causes boot-time pool overflow**
- **KSecDD FILE_ANY_ACCESS callback registration enables kernel code execution**

Every vulnerability report begins with an inference. The first clause is usually true; the second is merely assumed. The arithmetic is correct, therefore the execution path is assumed. The path is reachable, therefore the program state is assumed. The state exists at boot, therefore it is assumed to exist after logon. The driver accepts a pointer, therefore the destination is assumed to be unused. The driver reads an address, therefore the result is assumed to distinguish mapped from unmapped. Vulnerability research is largely the systematic removal of those "therefore" statements, replacing assumptions with evidence until only the facts remain.

* * *

## 12. Closing - be the person who kills your own bugs - ALWAYS

There is ego in reversing.

You spend hours naming anonymous functions, reconstructing structures from offsets, following an IRP through three drivers, and finally land on the one instruction that explains everything. The primitive is elegant. The exploit story writes itself. You can already see the title.

That is exactly when you should become hostile to your own conclusions. The best reverser in the room is not the person who can make every `FUN_140...` sound exploitable, but the one who knows which invisible contract still needs to be reconstructed. **FileCrypt** taught me that a file attribute is not an internal transformation context. **ahcache** taught me that a suspicious pointer is not an oracle until mapped and unmapped behavior actually diverges. **BindFlt** taught me that the producer's successful-output domain is part of the consumer's security proof. **IntelPEP** taught me to count the objects required to manufacture the count. **KSecDD** taught me that time itself can become part of a security boundary. None of those investigations became CVEs—and that is exactly as it should be. They failed in my VM, under my debugger, and in my notebook, rather than in an MSRC response explaining the invariant I should have discovered myself. That is not failed research; it is the work.
