# Kestrel translation runtime architecture

## Goal

Run an x86_64 macOS application on Apple Silicon without asking LaunchServices to start the Intel executable under Rosetta. Kestrel itself is an ARM64 macOS program. It translates guest instructions into ARM64 instructions and implements the guest process contract around them.

The guest is **not** literally converted into an ordinary ARM64 Mach-O file. Its x86_64 architectural state and ABI still exist inside Kestrel. What becomes native is the code that the M-series CPU executes and the host-side calls into macOS.

## Process model

The intended production layout is:

```text
Kestrel.app (ARM64 SwiftUI launcher)
        |
        | target path + argv + environment + launch profile
        v
KestrelRuntime (separate ARM64 helper process)
        |
        +-- Mach-O loader / guest image registry
        +-- x86_64 guest CPU state
        +-- x86_64 decoder -> semantic IR -> AArch64 backend
        +-- translated-block cache (guest-RIP keyed AArch64 word arrays)
        +-- one shared host MAP_JIT execution arena (code is still copied per block call, but only the previous block's stale tail is cleared; the guest page table passed to native code is cached until the mapping changes)
        +-- guest virtual-memory manager (guest addresses are not host pointers)
        +-- Darwin API / libSystem compatibility layer
        +-- x86_64-to-native-ARM64 ABI thunks
        +-- guest threads, TLS, exceptions, and signals
```

A separate helper gives each translated application its own host process, crash boundary, JIT arena, and guest address-space metadata. The ARM64 helper is the actual executable macOS starts. Kestrel will not attempt to load x86_64 instructions into an ARM64 process as if the two instruction sets were interchangeable.

## Address-space invariant

Keep these three concepts separate:

1. **Guest virtual address** — the address the x86_64 program believes it owns.
2. **Host backing address** — where Kestrel stores the guest's bytes in the ARM64 process.
3. **Host JIT address** — where Kestrel stores generated ARM64 instructions.

Guest pointers are resolved through guest-region metadata. They are not cast to host pointers, and guest requests for fixed addresses do not force Kestrel to request those same addresses from macOS. Guest executable permissions are guest metadata; only generated ARM64 blocks are written to the host JIT arena.

This is the central design safeguard for the address overlap, `MAP_FIXED`, `mprotect`, and `MAP_JIT` issues encountered in the Kyty experiments. Native translated blocks now access a sparse multi-region guest VM through a checked page-table ABI; the bounded byte-array model remains only as a compatibility fixture for older tests. This is still an experimental VM, not a production process memory manager.

## Translation pipeline

```text
                         +-> reference interpreter -> guest CPU state + guest memory
x86_64 bytes -> decoder -> semantic IR
                         +-> AArch64 backend -> block validation
                                                -> host MAP_JIT arena -> native ARM64 execution
```

The reference interpreter and native backend consume the same semantic IR. The interpreter is the correctness oracle: the AArch64 path must match its register, memory, and flag results for every supported test program. The backend receives a separate host pointer to a bounded guest-memory byte region and the guest virtual base/size. It validates each memory access before converting the guest address into a host pointer. It also emits guest stack operations and control-flow exits. Control-flow instructions end a translated block and return an exit status plus the updated guest RIP. The Swift dispatcher uses that RIP to select, compile, cache, and execute the next basic block.

### Current native block ABI

Generated AArch64 blocks receive two arguments using the native ARM64 C calling convention:

1. Pointer to an 18-word guest CPU context.
2. Pointer to a short-lived `KestrelGuestMemoryView` descriptor.

The guest-memory view points to sorted parallel arrays containing guest page bases, stable host backing pointers, per-page R/W/X permissions, and per-page write generations. It also carries a page count, a sticky fault code, a native write counter, the faulting guest address, and the requested permission. Swift pins all page allocations for the synchronous C/JIT call; the generated block and its C helpers never dereference a guest virtual address as a host pointer.

The 18-word context layout is:

| Word index | Meaning |
|---:|---|
| 0–15 | x86_64 GPRs in ModRM order (RAX through R15) |
| 16 | Guest RIP |
| 17 | Guest RFLAGS |

The generated function preserves host callee-saved registers and returns to the ARM64 dispatcher. Guest `RET` is an emulated x86 operation: it reads the return address from checked guest memory, updates guest RSP/RIP, and returns a control-flow-exit status to the host. It never uses the host stack as the guest stack.

Generated block result values are:

| Result | Meaning |
|---:|---|
| 0 | Normal fallthrough. |
| 1 | Guest control-flow exit; the dispatcher continues from the guest RIP written by the block. |
| 2 | Guest memory permission/invalid-access fault. |
| 3 | Native page-table helper reported a missing page; Swift may demand-zero commit one permitted page and retry the unchanged faulting instruction. |
| 4 | Guest `SYSCALL` exit; the dispatcher handles the syscall outside native code. |

For each native guest memory access, C helpers binary-search the sorted guest page table, validate address arithmetic, every page in the access span, committed backing, and R/W permission, and only then read or write host backing. Cross-page scalar stores are prevalidated in full before the first byte changes. Native writes update page generations and a global write count, which Swift synchronizes back to the guest VM after the block call. Instruction fetch is checked separately by Swift against guest X permission.

The current native instruction subset includes:

- MOV, ADD, SUB, CMP, XOR, register/register XCHG, NOP, and PAUSE;
- supported MOV/ADD/SUB/CMP/XOR memory operands;
- LEA with base, index, scale, displacement, RIP-relative addressing, and 32-bit address-size override;
- PUSH and POP, including 16-bit stack-width forms;
- direct and indirect CALL/JMP, RET, all 16 x86 conditional-branch predicates, and dispatcher-handled `SYSCALL` (`0F 05`).

The arithmetic/logic operations themselves execute as native AArch64 instructions. A small C helper receives the original operands and result to calculate x86 CF/PF/AF/ZF/SF/OF exactly and store them into the guest context. The helper address is embedded through an AArch64 literal load/indirect call. Unrelated RFLAGS bits are preserved, and XOR retains the prior AF bit because AF is undefined for that instruction.

Conditional-branch predicates first load guest RFLAGS into a dedicated immutable scratch register (x14). Each predicate bit is extracted from this snapshot. This is important for compound x86 predicates such as `BE` (`CF || ZF`), `L` (`SF != OF`), and `LE` (`ZF || SF != OF`): extracting one flag must not overwrite the source before the next flag is read. A regression test covers `JBE +2` with RFLAGS `0x842` (ZF=1, CF=0, OF=1), which must branch to `instruction.nextAddress + 2`.

Widths 8/16/32/64 are handled, including AH/CH/DH/BH slices and the x86 rule that a 32-bit GPR write clears its upper 32 bits. For byte and word writes, the backend merges the new value into the preserved guest register value. For dword writes it zero-extends before storing the full context word.

The differential suite runs the same instruction streams through the interpreter and AArch64 backend. It compares all 16 GPRs, RIP, RFLAGS, and the complete bounded guest-memory backing array. Coverage includes memory load/store, indexed and RIP-relative addressing, LEA, stack operations, return/call behavior, conditional branches, all 16 Jcc conditions across several flag patterns, and an out-of-range memory fault. These native execution tests must be run on Apple Silicon; the development environment used to package the project cannot execute Apple's MAP_JIT path.

### Translated-block dispatcher and cache

`X64ARM64BlockDispatcher` repeatedly executes one basic block at a time until a caller-supplied guest halt address is reached, a guest memory fault is returned, or a configured instruction/block budget is exhausted. `X64ARM64TranslationCache` is a bounded LRU cache keyed by guest start RIP. On a cache lookup it compares the current guest code bytes with the cached source bytes; changed bytes invalidate that translation before it can execute. Explicit address-range invalidation and full-cache clearing are also exposed for the future virtual-memory manager.

The block builder decodes sequentially and ends a block at the first conditional/unconditional branch, CALL, or RET. It also bounds instructions and bytes per block, and honors a caller-supplied halt RIP when a sequential block would otherwise fall through it. The halt RIP is a stop sentinel, not an upper bound on guest addresses: a CALL/JMP target above it may execute and later return to it. Guest branches never jump directly to another host block: they write the new guest RIP and exit to the dispatcher, which performs a fresh lookup. The dispatcher test suite exercises taken and not-taken branches, CALL/RET redispatch, reuse across repeated runs, self-modifying-code detection at a dispatch boundary, bounded loop execution, memory-fault propagation, and LRU eviction.

This cache detects modified code when the guest RIP is dispatched again. It is not yet a complete x86 self-modifying-code coherence model: page write-protection, cross-thread invalidation, instruction-fetch synchronization, and invalidation during a currently executing translated block belong to the future guest memory manager.

Memory XCHG is deliberately rejected until atomic semantics are implemented. FS/GS segment-base addressing, LOCK-prefixed operations, SIMD/FPU, system instructions other than dispatcher-handled `SYSCALL`, and instructions outside the decoder/IR subset are also unsupported and fail closed. A native `SYSCALL` ends its block with result 4; Swift writes the guest return RIP to RCX, the pre-entry RFLAGS to R11, then dispatches a narrow BSD class subset (`exit`, `read`, `write`, `getpid`). Unsupported syscalls return an `ENOSYS`-style code with the guest carry flag set. Native translated memory operations use the sparse page-table ABI; the legacy byte-array memory type remains only as a compatibility adapter for older test fixtures.

## Sparse guest virtual-memory manager (initial implementation)

`X64GuestVirtualMemory` introduces a page-based guest address space independent of the host JIT arena and independent of the old single-byte-array test fixture. It models x86-64 guest pages as 4 KiB, regardless of the host Mac's physical/virtual page size. Reservations are sparse metadata; committed pages allocate individual stable 4 KiB host backing blocks. A 4 GiB region can therefore be reserved without allocating 4 GiB of host memory.

The manager currently provides:

- non-overlapping page-aligned region reservations and deterministic first-fit allocation;
- independent region kinds for anonymous, image, heap, stack, and shared mappings;
- lazy commit, decommit, release, and zero-fill on recommit;
- metadata-only demand-zero ranges that materialize one zero-filled 4 KiB page on first permitted read, write, or executable fetch, splitting the lazy range without preallocating per-page metadata;
- per-page read, write, and execute permissions;
- execute-only instruction-fetch validation distinct from ordinary reads;
- access spanning page boundaries and adjacent reservations;
- complete prevalidation of cross-page writes, preventing partial mutation when a later page faults;
- guarded stack reservations with uncommitted low/high guard pages;
- deterministic faults for unreserved, uncommitted, or permission-denied accesses;
- mapping, per-page, and write generations for future translation-cache coherence.

The guest VM manager has its own 24-group Swift test suite. The original `X64GuestMemory` byte-array type remains available for older differential fixtures, but its runtime adapter constructs a temporary sparse VM and invokes the same page-table JIT ABI. The v0.10.3 native integration suite has seven MAP_JIT tests, including demand-zero data-fault retry. v0.11 adds two further MAP_JIT tests for the dispatcher-handled `SYSCALL` exit and imported `_write` host thunk; those new tests still require M4 execution. Permission failures and pages outside registered lazy ranges remain deterministic faults.

## ABI and operating-system boundary

The translator must not branch directly from guest code into arbitrary ARM64 framework functions. A real boundary thunk must:

- read x86_64 argument registers and guest stack arguments;
- convert the x86_64 calling convention to the native ARM64 calling convention;
- marshal structures, callbacks, variadic arguments, and return values;
- translate guest pointers through the guest-memory manager;
- preserve guest error, thread, and exception semantics where required.

v0.11 contains only an initial, explicit bootstrap subset. The dispatcher handles BSD `SYSCALL` calls for `exit`, `read`, `write`, and `getpid`; unsupported calls report `ENOSYS`-style failure. A separate guest thunk page provides `_read`, `_write`, `_getpid`, and `_exit` stubs. The current host adapter supports standard input/output/error only, caps I/O at 1 MiB, and does not maintain thread-local `errno`. These functions are sufficient for tests, not a general libSystem implementation or a complete x86_64-to-ARM64 ABI bridge.

The process-startup builder reserves a stack with guard pages and writes the kernel-to-dyld `KernelArgs` shape: main executable mach-header pointer, argc, argv and terminator, envp and terminator, apple vector and terminator, plus pointed-to strings. The apple vector is minimal. This structure is **not** a complete runnable process: Kestrel still needs a compatible dyld image and its `__dyld_start` entrypoint. The initial guest RIP must be `__dyld_start`; `LC_MAIN` is the executable's eventual main entry after dyld has loaded dependencies, applied fixups, and initialized runtime state. v0.11 intentionally prepares the stack without installing an initial RIP or transferring control.

A staged compatibility strategy remains preferable: extend the narrow C/libSystem subset, then add dependent images and dyld/shared-cache startup, then Objective-C runtime and selected frameworks, then the specific dependencies used by the target application. A universal bridge for all macOS frameworks is a major subsystem, not a small launcher feature.

## Current code

The prototype currently has:

- an ARM64-only SwiftUI launcher;
- thin/fat Mach-O architecture inspection;
- native ARM64 `.app` and executable launch with arguments and environment variables;
- a guest x86_64 CPU-state model with 16 GPRs, RIP, and RFLAGS;
- width-correct register reads/writes, including AH/CH/DH/BH and REX byte-register decoding;
- a decoder and guest-semantic IR for an explicit instruction subset, including dispatcher-boundary `SYSCALL`;
- a legacy bounded byte-array guest-memory fixture for native differential tests;
- a sparse multi-region guest virtual-memory manager with 4 KiB pages, lazy commitment, per-page RWX permissions, guard-page stacks, demand-zero tail metadata, and deterministic faults;
- a reference interpreter for the supported non-syscall IR subset;
- an AArch64 backend for supported register, immediate, and memory integer operations, LEA, stack operations, direct/indirect control flow, Jcc predicates, and native syscall exits;
- a fixed 18-word guest CPU context plus a separate sparse page-table descriptor;
- checked native guest-memory access across independent committed pages, with deterministic faults that leave the faulting instruction's RIP unchanged;
- a native C helper for exact CF/PF/AF/ZF/SF/OF updates after generated integer operations;
- a differential suite that compares GPRs, RIP, RFLAGS, and guest memory against the interpreter;
- one process-wide `MAP_JIT` arena, with write protection changed using `pthread_jit_write_protect_np` and the instruction cache invalidated before execution;
- a bounded basic-block builder, guest-RIP dispatcher, and LRU cache with source-byte validation and explicit code invalidation APIs;
- a load-only thin/universal x86_64 Mach-O `MH_EXECUTE` parser/mapper with sparse reservations, demand-zero BSS/tails, classic 64-bit pointer rebases for explicit PIE slides, classic regular/weak/lazy bind-action decoding, export-trie parsing, dependency/rpath metadata, guest-address import resolution, segment permissions, and rollback;
- exact-install-name, bounded breadth-first planning of the full cache-backed dylib dependency closure (ordinary, weak, reexport, upward, and lazy-load edges), with required misses distinguished from optional weak misses;
- discovery and validated guest mapping of the x86_64 MH_DYLINKER image from the Rosetta shared cache, including its x86_THREAD_STATE64 LC_UNIXTHREAD RIP and the dyld_path KernelArgs apple parameter;
- four experimental guest C import thunks (`_read`, `_write`, `_getpid`, `_exit`) and a narrow BSD syscall dispatcher;
- a guarded kernel-shaped `KernelArgs` stack builder, with no dyld entrypoint or initial guest RIP installed.

The Swift translation cache retains compiled AArch64 words, but the current C executor still copies each requested block into the single shared `MAP_JIT` arena before each execution; persistent per-block executable mappings and concurrent JIT execution are not implemented.

Kestrel can now execute a restricted freestanding x86_64 MH_EXECUTE by calling its LC_MAIN as C main(argc, argv, envp). This is a direct-main development mode, not a normal macOS process launch: it requires no dylib dependencies, bind actions or chained fixups, and it deliberately skips dyld and image initializers. The shared-cache path now plans the full declared recursive dependency closure, so ordinary transitive dylibs are included in the mapping plan rather than only direct dependencies and reexport providers. Kestrel now maps the x86_64 MH_DYLINKER from the Rosetta cache, extracts its validated LC_UNIXTHREAD RIP, supplies dyld_path in KernelArgs, and has a bounded runner that executes __dyld_start until the main executable's LC_MAIN handoff. A separate continuation can then begin executing the real program entrypoint. This path has not yet been validated against KytyPS5 on the M4; uncached/@rpath loading, dyld runtime compatibility, unsupported instructions/syscalls, thread-local errno, guest threads/TLS, signals, exceptions, and framework ABI bridges remain likely blockers to resolve from the first target run.


## Recommended milestones

1. **Complete — guest CPU state.** Implemented 16 GPRs, RIP, RFLAGS, partial-register semantics, legacy high-byte/REX byte-register selection, and integer flag calculations.
2. **Complete as an initial subset — decoder and guest-semantic IR.** Prefix, REX, opcode-map, ModRM/SIB, displacement and immediate parsing, sequential decoding, and fail-closed behavior are implemented for selected instructions.
3. **Complete as an initial subset — reference instruction execution.** A bounded test-memory model and interpreter execute the supported IR subset against guest CPU state.
4. **Complete as a tested initial slice — native AArch64 backend.** Register/immediate, memory, LEA, stack, and control-flow subsets passed 27 native differential test groups on the M4. Broaden the ISA only with additional reference comparisons.
5. **Complete as an initial slice — block dispatcher and translation cache.** Basic-block splitting, guest-RIP redispatch, byte-validated LRU caching, stale-code detection, explicit invalidation, and bounded execution passed 8 native dispatcher test groups on the M4.
6. **Implemented and demonstrated on the M4 — sparse guest VM and demand-zero JIT integration.** The seven v0.10.3 MAP_JIT tests passed on the user's M4, including one-page demand-zero fault/retry. v0.11 adds two more native integration tests for `SYSCALL` dispatch and the imported `_write` thunk; these two require M4 confirmation.
7. **Implemented as load-only slices — Mach-O mapping, classic rebases, and initial bind processing.** The loader maps the main `MH_EXECUTE`, registers BSS/tails for demand-zero, and handles the supported classic pointer rebase subset. v0.11 decodes regular/weak/lazy bind actions, indexes basic exports, discovers dependency candidates, and applies bindings only from explicit guest-address resolver entries. It does not recursively load dependencies, map dyld shared cache, handle chained fixups, or implement complete two-level/reexport/lazy-binding semantics.
8. **Implemented as scaffolding — Darwin bootstrap boundary.** A small syscall subset, four imported C thunks, and a kernel-shaped `KernelArgs` stack builder exist. The real blocking stage remains loading and initializing dyld (including shared-cache dependencies) before normal application startup.
9. **Implemented as a bounded slice — STUB_AND_RESOLVER execution.** Positive-ordinal lazy imports can use a resolver's return only after isolated guest execution and executable-address validation; the resulting pointer is applied in the staged image. This is eager prebinding, not first-call lazy rebinding.
10. **Implemented as a first executable slice — direct-main guest launcher.** Freestanding no-dependency x86_64 images can enter LC_MAIN through a C-compatible call frame and execute under the native dispatcher. This deliberately bypasses dyld and is not normal macOS application startup.
11. **Implemented as a bounded cache-loading stage — recursive dylib dependency closure.** The planner walks declared dependency edges in breadth-first load order, maps every discovered cache-backed image, enforces image/metadata limits, and distinguishes optional weak misses from required missing images. It deliberately does not guess @rpath paths or claim to initialize dyld.
12. **Implemented as an experimental launch path — x86_64 dyld entry and program handoff.** Kestrel discovers and maps the cached MH_DYLINKER, installs dyld_path in KernelArgs, starts at its x86_THREAD_STATE64 entrypoint, and can continue from the main executable's LC_MAIN entry after dyld returns control. This is an execution path, not yet a successful KytyPS5 compatibility result.
13. **Future — complete the process contract against KytyPS5.** Execute the target, record and implement the first real unsupported instruction/syscall/ABI blocker, add uncached and @rpath dependency loading and missing chained-fixup behavior as needed, then build out TLS/errno, guest threads, signals/exceptions, Objective-C runtime, and only the frameworks KytyPS5 actually uses.

Each milestone should have isolated tests before the next subsystem is introduced. In particular, keep guest memory allocation separate from executable-code allocation.


## v0.9 — sparse guest VM / native JIT integration

The native translated-block ABI now takes `(guest_context, KestrelGuestMemoryView *)`. The view is a short-lived C stack descriptor containing sorted guest page bases, stable host page pointers, per-page permissions, per-page write generations, a sticky fault field, and a write counter. Swift keeps each page's host allocation alive and pinned for the duration of the synchronous JIT call. It also carries a fault page and required permission back to Swift when a page is absent.

Generated AArch64 memory operations call two C helpers: `kestrel_guest_memory_read` and `kestrel_guest_memory_write`. The helpers binary-search the page table, validate address overflow, committed-page presence, and R/W permission for every page touched by a scalar access (1–8 bytes), then perform little-endian access. A cross-page write validates the complete span before changing bytes. A fault sets the view's sticky fault field; the generated block branches to its memory-fault epilogue before committing the faulting instruction's RIP.

Swift synchronizes the modified page-generation array back to the VM after each JIT call and advances the VM's write generation by the native write count. Instruction fetch uses the VM's execute permission before decode. Translation cache lookup still compares current guest instruction bytes, so guest code modified by a native store cannot silently reuse an old translation.

The prior contiguous `X64GuestMemory` object remains only for older self-test fixtures. Its runtime adapter constructs a temporary sparse VM and still invokes the new page-table JIT ABI; it is not a separate native memory path.

The on-device test button runs native tests for distant independent regions, cross-page atomic stores across adjacent reservations, instruction execute permission, cross-region little-endian reads, and CALL/RET through a guest stack page. A sixth test verifies that block construction stops cleanly at the end of an executable region. These tests require Apple Silicon MAP_JIT and must be executed on the target Mac.

## v0.10 — initial x86_64 Mach-O image loader

`X64MachOParser` accepts thin or universal Mach-O files, selects the x86_64 slice, validates the `mach_header_64` and bounded load-command region, parses `LC_SEGMENT_64` and `LC_MAIN`, and rejects malformed sizes, arithmetic overflow, overlapping segments, unsupported CPU types/file types, missing `__TEXT`, missing `LC_MAIN`, and non-executable entry points. Universal FAT32 and FAT64 tables, including swapped-endian FAT headers, are recognized.

`X64MachOLoader` reserves each non-empty segment's complete virtual range at its preferred guest address. `__PAGEZERO` and unbacked segment tails are metadata-only. It eagerly commits only the page-rounded portion needed to contain each segment's file-backed bytes, copies those bytes into guest memory, and applies `initprot` to the committed pages. `LC_MAIN` must resolve to a committed executable page. Failed loads roll back all reservations created by that load; successful images can be unloaded. The 512 MiB safety cap applies only to eager host backing, never to sparse guest virtual-address reservations.

The first implementation incorrectly counted each segment's full `vmsize` as committed RAM. Real Intel binaries can reserve hundreds of gigabytes of guest address space while containing only a comparatively small amount of file data. v0.10.1 corrected that accounting. In v0.10.3, unused segment tails and BSS remain reserved but are registered for demand-zero materialization; the first permitted access backs only the touched page. A zero tail within a committed file-backed page is naturally zero initialized by the guest VM allocator.

The v0.10.4 loader adds an explicit, page-aligned PIE slide and decodes classic `LC_DYLD_INFO` / `LC_DYLD_INFO_ONLY` rebase streams for 64-bit `REBASE_TYPE_POINTER` locations. Rebase locations are validated against the selected segment's file-backed and virtual ranges. Before final segment protections are applied, the loader adjusts non-null pointer values that refer into this image by the slide; it leaves external values unchanged only when they are not marked as rebases. `__PAGEZERO` is never slid. Unsupported rebase types, invalid ULEB128 values, out-of-range targets, overflow, non-PIE slides, and missing rebase metadata fail closed. This is an explicit slide API, not automatic ASLR placement.

Regular/weak/lazy bind streams are range-validated and their byte counts are exposed, but symbol binding is not implemented. `LC_DYLD_CHAINED_FIXUPS` is recognized and its data range validated, but its pointer formats are not decoded; images containing chained fixups are rejected when a nonzero slide is requested. Export tries, code-signature checks, and `LC_UNIXTHREAD` state are not interpreted. The entry address is still recorded rather than invoked: on normal macOS `LC_MAIN` is the executable's `main` entry point reached after dyld startup, so Kestrel still needs process arguments/stack setup, dyld/libSystem compatibility, and ABI thunks before it can execute an ordinary application.

## v0.10.1 — sparse Mach-O segment accounting

The loader safety limit now measures page-rounded file-backed host pages, not full Mach-O `vmsize`. Segment address ranges are still fully reserved in the guest VM, so large `__DATA`, `__BSS`, and `__PAGEZERO` address ranges do not trigger massive backing allocations. The UI reports virtual bytes reserved separately from host backing committed. A 623 GiB synthetic segment fixture verifies that a 1-page file-backed segment consumes only one guest page of backing while retaining its full virtual range. At v0.10.1 those BSS/segment-tail accesses still fault; v0.10.3 adds per-page demand-zero materialization and native fault retry.


## v0.10.2 — dispatcher cache-test fix

The LRU-capacity self-test calls `cache.block(at:memory:)` with `memory` rather than `&memory`. That cache API accepts a read-only `X64GuestMemory` value, whereas the block-dispatcher's execution method separately accepts memory as `inout`. The test exercises three distinct NOP/RET blocks against a capacity-two cache and expects two retained entries and one eviction.

## v0.10.3 — demand-zero Mach-O pages

Mach-O loading still eagerly backs only file-backed pages. The loader now registers the remaining aligned segment tails as metadata-only demand-zero ranges carrying each segment's final `initprot`. The first permitted access allocates a single zero-initialized 4 KiB page. Native C page-table helpers distinguish a missing page from an ordinary protection fault and return the fault page/access requirement to Swift; the dispatcher commits the page and retries at the unchanged faulting guest RIP. Cross-page native stores remain all-or-nothing because the C helper validates the full span before writing. Executable demand-zero pages are materialized on instruction fetch as well. The guest VM suite now has 24 groups, the Mach-O suite has 19, and the MAP_JIT integration suite has seven tests. This does not implement dyld or process startup.


## v0.10.4 — classic dyld pointer rebases

The Mach-O parser now recognizes `LC_DYLD_INFO`, `LC_DYLD_INFO_ONLY`, and `LC_DYLD_CHAINED_FIXUPS`, checks their link-edit data ranges against the selected slice, records binding-stream sizes, and decodes the classic rebase opcode stream. The supported subset is 64-bit `REBASE_TYPE_POINTER`; the stream decoder handles segment selection, ULEB128 offsets/counts, address increments, repeated rebases, and skip forms with overflow and target-range checks. Unsupported rebase types fail closed.

`X64MachOLoader.load` accepts an optional page-aligned `slide`. It requires `MH_PIE`, classic dyld rebase metadata, and no chained-fixups payload. `__PAGEZERO` remains fixed at zero. Other segments and `LC_MAIN` are shifted; non-null rebased pointer values within the image are adjusted by the same slide. File-backed pages remain temporarily writable while rebases are applied, then each segment's declared initial permissions are restored. Bind streams remain unresolved and are surfaced as metadata. This milestone does not execute `LC_MAIN`, provide imports, or implement dyld startup.


## v0.11.1 — bind-stream cursor and BSS fixups

The classic bind-opcode interpreter now preserves an overflow/out-of-range cursor as invalid parser state and validates it only when a subsequent bind action is emitted. This avoids rejecting streams solely because the cursor is advanced after their final valid action, while still rejecting any attempted bind at the invalid location with a stream-specific offset diagnostic. Bind locations are validated against segment virtual size rather than file size, so fixups in registered zero-fill tails can materialize the necessary demand-zero page. Four regressions cover these cases.

## v0.11.0 — initial dyld binding and Darwin startup scaffold

The parser now records dylib dependency load commands (`LC_LOAD_DYLIB` and weak/reexport/upward/lazy variants), `LC_RPATH`, classic regular/weak/lazy bind streams, and the export trie. The bind-stream decoder supports the classic pointer-bind opcode subset and produces validated actions with symbol, library ordinal, addend, flags, stream kind, and guest location. Threaded/chained bind formats and unsupported pointer types fail closed.

The loader can apply a bind only when the resolver returns a mapped **guest address**. It builds a simple resolver from ordinary main-image exports and accepts caller-provided import addresses, including addresses for the four guest C thunks. Unresolved weak imports become null; unresolved strong imports are preserved and reported, or can cause rollback when strict binding is requested. Decoded lazy-bind actions are currently applied eagerly when a resolver is available; dyld's lazy binder and on-first-call rebinding are not implemented. Reexports, absolute/TLS exports, resolver stubs, complete two-level namespace handling, recursive dependent-image loading, and dyld shared-cache resolution remain incomplete. Dependency path resolution locates possible files only.

The AArch64 backend recognizes `SYSCALL` (`0F 05`) as a block terminator and returns status 4 to Swift. The dispatcher saves the guest return RIP in RCX and pre-entry RFLAGS in R11, then handles the initial BSD syscall subset: `exit`, `read`, `write`, and `getpid`. A separate guest RX thunk page exposes `_read`, `_write`, `_getpid`, and `_exit`; the dispatcher intercepts those exact guest thunk addresses and translates buffer access through the sparse VM. The default host adapter is limited to standard I/O; thread-local errno and broad syscall semantics do not exist.

`X64GuestProcessStackBuilder` reserves an 8 MiB default usable stack plus low/high guard pages, writes the main executable mach-header pointer, argc, argv, envp, and a minimal apple vector, and returns the vector addresses. This models the kernel-to-dyld `KernelArgs` handoff, not the final C `main(argc, argv, envp)` call. The startup assembly enters `__dyld_start` with the original KernelArgs stack; dyld later performs dependency loading and initialization before handing control to the executable's `LC_MAIN`. v0.11 does not load dyld or its shared cache and deliberately does not install a first guest RIP.

Portable validation: 100 Swift checks across CPU state, decoder/IR, interpreter, sparse guest VM, Mach-O parser/loader, and Darwin runtime/startup suites. The full Xcode build and the two new MAP_JIT integration tests must still be confirmed on Apple Silicon.


## 0.11.2 bind-stream diagnostics

The classic bind interpreter records cursor provenance. If an emitted bind points outside the selected segment, the failure includes the segment index, segment-selection opcode and initial ULEB offset, last cursor mutation, overflow state, and a byte window from the bind stream. Invalid writes still fail closed; only the diagnostic is expanded.


## v0.12.1 — Rosetta Cryptex cache discovery

On Apple Silicon, baseline x86_64 shared-cache products may be shipped inside the Rosetta Cryptex rather than in the native OS cache tree. Discovery now checks the full Rosetta product at `/System/Volumes/Preboot/Cryptexes/Rosetta/System/Library/dyld/`, the reduced `x86Support` product at `/System/Volumes/Preboot/Cryptexes/Rosetta/System/x86Support/System/Library/dyld/`, staged Rosetta paths, `/private/preboot` equivalents, and then legacy/native OS locations. Each candidate is still opened and validated by its `dyld_v1 ... x86_64` magic; an ARM64 or `x86_64h` cache is never substituted. Failed candidates are retained in the final diagnostic while discovery continues.

## v0.12 — x86_64 dyld shared-cache inventory

Kestrel can locate the system x86_64 dyld shared cache in the Rosetta Cryptex products, standard macOS dyld directory, or the known Preboot/Cryptex locations. The reader validates the cache architecture magic, mapping table, file ranges, image-info array, optional version-2 subcache suffixes and UUIDs, and non-overlapping VM mappings. It enumerates cached image install names, translates each image's VM header address to its backing cache file, and verifies x86_64 Mach-O headers. Main-image dependency install names are matched exactly against that inventory; no basename substitution is attempted.

This is an inventory milestone only. It does not copy/map cache image segments into guest memory, apply `dyld_cache_mapping_and_slide_info`, load recursive dependencies, resolve the 1,053 imports, or initialize `__dyld_start`. Cache page mapping must preserve the x86_64 cache's guest VM addresses and handle its slide/fixup metadata before any cached export address can safely be used by the guest.


## v0.12.2 — shared-cache image mapping preflight

The cache reader retains the primary cache and all validated subcache backing files and can read a guest/cache VM range across adjacent mappings and split-cache files. The preflight parser walks exact install-name matches, reads each cached `mach_header_64` plus bounded load-command region, parses `LC_SEGMENT_64`, and verifies each non-`__PAGEZERO` segment's outward-rounded 4 KiB guest-page span is fully cache-backed. Segment starts and exact `vmsize` values may both be non-page-aligned. It rejects invalid CPU/file types, malformed commands, exact byte-overlapping segments within an image, missing dependencies, and page-rounded reservation plans over 16 GiB. v0.12.4 also coalesces pages shared by separate segments and separate cached images in reservation accounting.

The **Analyze cached dependency segments** action remains read-only. The separate **Materialize cached dependency pages** action handles the current 4 KiB v2 format and copies the selected pages into private guest backing. It does not register cached exports or execute code. Formats other than 4 KiB slide-info v2 still fail closed.


## v0.21.0 — first executable x86_64 direct-main launcher

The SwiftUI pipeline now exposes a guest Launch action. For a freestanding x86_64 MH_EXECUTE with no LC_LOAD_DYLIB dependencies, classic bind actions, unresolved imports or chained fixups, Kestrel builds the Darwin argument/environment stack, installs a CALL-compatible x86_64 C main(argc, argv, envp) frame at LC_MAIN, and runs it through the native AArch64 block dispatcher. Main's RAX return value becomes the process status; Darwin SYSCALL exits and the current small host-I/O bridge are also dispatched. Instruction and block budgets bound execution, and unsupported instructions or guest faults are surfaced in the launcher log.

This mode intentionally bypasses dyld. It does not call dependent-image initializers, process libc startup, or claim compatibility with ordinary macOS applications. It provides the first end-to-end guest execution/debug loop while the real __dyld_start path is developed. The runtime self-tests include a freestanding Mach-O that returns a status, a guest that writes to host stdout, the C entry stack ABI, and fail-closed rejection of dependency-linked images.

## v0.20.0 — bounded execution of STUB_AND_RESOLVER exports

The shared-cache import resolver now executes each unique candidate resolver in a reusable, isolated guest snapshot with a private stack and bounded instruction/block budgets. Existing guest pages are write-protected in the snapshot; syscalls and host thunks are blocked. A result is accepted only when RAX names an address that is mapped and executable in the original guest address space. The implementation address is stored in a lazy-only symbol map under the import's exact declared two-level dependency, keeping ordinary binds pointed at the export stub; the staged main-image loader applies it only to matching lazy-bind pointer slots. Resolver failures and non-executable return values remain unresolved.

This is an eager prebinding slice, not dyld's runtime first-call lazy-binding machinery. Only positive-ordinal two-level lazy imports are promoted by this path. Resolver side effects are discarded with the snapshot; resolvers that require writable shared globals, TLS, syscalls, host thunks, or broader dyld process initialization remain unsupported. Flat/weak special-ordinal resolver exports and complete dyld startup are still future work.

## v0.19.0 — bounded dependency-route diagnostics

The v0.18.0 unresolved-provider diagnostic used a breadth-first queue whose entries each carried a copy of the current path's visited-image set. In a dependency graph with repeated diamonds, that enumerates many distinct simple paths to the same images; the count can grow exponentially even though the parsed graph is small. This diagnostic code was not needed for symbol resolution itself, but it ran after resolution and could exhaust host memory while building candidate routes.

v0.19.0 replaces that path enumeration with a conventional graph BFS: each image is marked visited once, and one parent image plus edge kind is stored for route reconstruction. It is bounded by the parsed closure (at most 1,024 images), returns a deterministic shortest route, and preserves the actual `LC_LOAD_DYLIB`/`LC_REEXPORT_DYLIB` labels. The route finder therefore uses O(V + E) time and O(V) additional memory per route search. Import resolution and strict two-level binding rules are unchanged.

The new regression constructs a 66-image layered diamond graph with exponentially many possible paths and verifies that route search visits each image at most once. The v0.18.0 report of a process reaching 69+ GB was not reproduced in this environment; code inspection identifies this exponential diagnostic queue as a credible cause. The selected direct shared-cache materialization plan itself remains 337,683 pages (1,383,149,568 bytes, about 1.29 GiB), and the resolver's 555-image metadata walk previously parsed about 15.6 MB of export-trie bytes. A fresh M4 memory-profile run is required to confirm the fix under the actual Rosetta cache.

## v0.18.0 — unresolved bind provenance

The cache resolver now retains diagnostics for unresolved bind actions: original positive or special library ordinal, exact declared install name (when applicable), regular/weak/lazy stream, weak-import flag, and candidate provider routes through the parsed dependency graph. Route labels preserve the actual load-command kind (`LC_LOAD_DYLIB`, `LC_REEXPORT_DYLIB`, and related forms). These candidates do not change binding policy: a positive two-level import can still be satisfied only by its declared dylib or valid reexports. The loader separately reports unresolved bind slots and unique unresolved symbol names because multiple slots may use the same name.

## v0.17.0 — load-command reexports and dependency closure

When a requested symbol is absent from an image's own export trie, the resolver follows its actual `LC_REEXPORT_DYLIB` dependencies, in load-command order, matching dyld's runtime lookup behavior. Explicit export-trie reexport terminals continue to follow their encoded dependency ordinal. `MH_NO_REEXPORTED_DYLIBS` is a static-linker optimization hint; it is not used as a runtime veto when explicit reexport load commands are present.

Positive two-level imports remain constrained to the declared dependency and the dependency's supported reexport chain. The resolver does not bind a same-named symbol from an unrelated transitive dependency. Cycles and excessive reexport depth fail closed. The breadth-first metadata closure limit is now 1,024 images (up from 256); byte and symbol-count ceilings remain active, and truncation is still reported.

The UI distinguishes applied bind fixup slots, unresolved bind slots, and unique unresolved symbol names because multiple opcode actions can refer to one symbol. The v0.17.0 M4 run completed a 555-image metadata closure (below the 1,024-image cap), parsed 533,793 exports from 15,578,992 bytes of export tries, and resolved 895 main-image imports from cached exports. It applied 1,007 bind fixups while reporting 457 unique unresolved names. Candidate providers included private/transitive images but were not exposed through the declared provider's supported reexport graph. v0.18.0 prints the original ordinal, declared provider, stream, weak-import flag, and candidate dependency route without broadening the binding rules.

Portable suite: 141/141 checks. This is still metadata resolution, not a complete dyld process launch: transitive dependency pages beyond the selected materialized set are not automatically mapped, initializers are not run, TLS/errno and framework ABIs are absent, and `LC_MAIN` is not entered.

## v0.16.0 — dependency closure and special dyld lookup namespaces

The cached-image resolver now walks `LC_LOAD_DYLIB`-family commands breadth-first from the executable's direct dependencies. The metadata walk is capped at 256 images; if the cap is reached, it reports truncation rather than claiming the closure is complete. Missing paths are reported separately. This walk reads dependency metadata and export tries only: it does not automatically materialize the transitive images' pages.

Positive library ordinals retain exact two-level namespace behavior: the symbol must be exported by the named dependency or reachable through that image's explicit `EXPORT_SYMBOL_FLAGS_REEXPORT` chain. A same-named export in a different, unrelated dylib is not used. Candidate exports found elsewhere in the loaded dependency closure are reported for diagnosis only.

`BIND_SPECIAL_DYLIB_FLAT_LOOKUP` searches an existing global resolver entry, then the main executable's ordinary exports, then eligible providers across the bounded dependency closure. Because this metadata walk does not reproduce dyld's live image-list order, Kestrel binds only when all eligible dependency providers converge on the same guest address; distinct candidate addresses are reported as ambiguous and left unresolved. Exact per-install-name guest thunks are considered for their corresponding cached image. `BIND_SPECIAL_DYLIB_WEAK_LOOKUP` uses a separate weak-definition table and searches only exports carrying `EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION`; an ordinary strong export or guest host thunk cannot accidentally satisfy that lookup. Distinct weak providers with different addresses remain unresolved. The main-image loader registers weak exports in both the ordinary export table and the dedicated weak table, while the weak-lookup opcode reads only the latter.

Portable suite: 139/139 checks. The live v0.15.0 M4 baseline was 1,011 bound main-image slots and 453 unresolved bind slots. v0.16.0's special-ordinal and dependency-closure code still needs a real-M4 run. This remains import resolution, not full dyld: transitive dependency pages are not mapped by the metadata walk, initializers are not run, TLS/errno and framework ABIs are absent, and `LC_MAIN` is not entered.

## v0.15.0 — cached export metadata and dependency-qualified import resolution

After the direct cache dependency pages have been materialized, the resolver reads cached dylib Mach-O headers and bounded load-command regions from shared-cache VM addresses. It records each image's `LC_SEGMENT_64` file/VM ranges, dependency load commands in ordinal order, and export-trie range from `LC_DYLD_INFO(_ONLY)` or `LC_DYLD_EXPORTS_TRIE`. The export-trie file offset is translated through that image's `__LINKEDIT` segment and then read through the cache's primary/subcache VM mapping table.

The export trie is decoded by the same bounded trie parser used for the main executable. Main-image bind actions are resolved under their exact dependency ordinal/install name. Ordinary image-relative exports are accepted only when their computed guest address is inside that cached image's segment and an already materialized guest-memory region. Reexports follow the target ordinal from the exporting dylib's own load-command dependency list; the resolver does not guess from a basename. Recursive reexport traversal is depth- and cycle-limited.

Absolute, thread-local, stub/resolver exports, unresolved/unsupported reexports, and non-pointer bind formats are intentionally not applied. The loader refuses to treat a non-pointer bind action as an eight-byte pointer store. The resolver starts from the existing guest thunk table, adds dependency-qualified cached addresses, then reloads the main executable into a staged copy of the current guest VM. It releases the prior main image and any prepared stack only in that staged copy; the published VM/image is replaced only after binding succeeds.

This stage is still not dyld. It parses metadata for a bounded transitive dependency closure but does not automatically materialize all transitive dependency pages, run dylib initializers, resolve every import form, construct TLS or errno, bridge macOS frameworks, process main-image chained fixups, locate/enter `__dyld_start`, or execute `LC_MAIN`. The v0.17.0 real-cache run validated the export-trie path and showed the remaining unresolved-provider problem; v0.18.0 adds provenance diagnostics to investigate it without weakening two-level binding.

## v0.14.0 — guest-owned shared-cache page materialization

The cache reader's validated image plans now feed a separate materializer. It forms the global union of 4 KiB page-rounded ranges for all selected direct dependency segments, deduplicates pages shared by adjacent segments or different images, and requires each materialized guest page to lie entirely inside one validated cache mapping. Page-level permissions come from that mapping's `maxProt`/`initProt` fields, not the Mach-O segment label; inconsistent or unknown protection bits are rejected.

Materialization is transactional. Kestrel creates a value-copy of the existing guest VM, reserves contiguous runs as `.shared`, commits writable backing, then reads each source page from its corresponding primary/subcache file. If a mapping has slide-info v2, the page's direct or page-extras chains are walked in the private `Data` buffer. For each word, the delta bits are removed; nonzero pointer payloads are reconstructed as `payload + valueAdd + cacheSlideAmount`, and the delta chain advances using the original encoded word. This build selects `cacheSlideAmount = 0`, retaining the cache's recorded guest VM addresses. The modified page is copied into Kestrel-owned backing, and all affected runs are finally protected using the cache mapping's initial protection. The original cache `Data` is never modified.

The caller's guest VM is replaced only after all pages have been copied, fixed up, and protected. A reservation collision or malformed page leaves the previously loaded main image and its guest memory unchanged. The current x86_64 Rosetta cache reports 4 KiB v2 pages; 16 KiB slide-info pages and non-v2 formats are rejected by the materializer even though the read-only inventory/parser can inspect some of those layouts.

This stage materializes the 26 exact direct dependency images in the current `kyty_emulator` target. It does not perform recursive dependency closure, export resolution or rebinding for the main executable, dyld startup/initializers, TLS, or process launch. The selected direct-dependency page plan reserves approximately 1.29 GiB (337,683 4 KiB pages) of guest backing and is capped by a separate 2 GiB materialization limit and should be treated as an explicit memory-heavy diagnostic action.

## v0.13.0 — shared-cache slide-info v2 validation

The reader now parses each cache file's modern `dyld_cache_mapping_and_slide_info` table. Each extended record must match one legacy mapping exactly by VM address, size, file offset, and protections, and its slide-info blob must be fully contained in that same backing file. The parser then reads slide-info v2 metadata: page size/count, page-start table, optional page-extras table, delta mask, and value-add. It accepts the documented 4 KiB and 16 KiB page sizes and verifies that the page-start count matches the mapping's page geometry.

For every page, the parser decodes direct chain starts and multi-chain page-extras entries, including the END marker. Each chain is traversed using the version-2 delta mask; pointer reads must remain inside the backing mapping and page, deltas must be aligned and forward-only, duplicate locations and unterminated extras are rejected, and value-add arithmetic is overflow-checked. Nonzero encoded pointers are counted as potential interior-pointer rebases. The parser does not rewrite the mapped cache file or produce guest writes.

Only slide-info version 2 is currently supported. Version 1 and versions 3–5 are rejected explicitly until their distinct formats are implemented. The **Analyze cached dependency segments** action reports validated mapping/page/chain/pointer counts alongside Mach-O segment plans. v0.14.0 adds a separate materialization action, described above, which copies selected 4 KiB pages, applies v2 pointer reconstruction with a zero guest slide, and installs cache mapping protections.

## v0.12.4 — sub-page shared-cache segment layout

Mach-O segment byte ranges inside a dyld shared cache are not necessarily aligned to the 4 KiB guest-page boundary. The cached image's `__DATA_CONST` segment reported by the Rosetta cache begins at an intra-page offset (`...A640`) and has a short exact size (`0x3C8`). The preflight now keeps `virtualAddress`/`virtualSize` exact and records a separate page span with `pageRoundedAddress = floor(vmaddr, 4 KiB)` and `pageRoundedEnd = ceil(vmaddr + vmsize, 4 KiB)`.

The full page span must be covered by validated shared-cache mappings before a mapping plan is accepted. Segment overlap is checked using exact byte ranges; separate, non-overlapping segments may share a guest page, and page reservation accounting coalesces that page rather than counting it twice. This remains a read-only preflight: it does not copy cache pages, apply slide fixups, or alter guest page permissions. The future mapper must derive effective guest-page permissions from the cache mapping metadata and resolve any page shared by multiple exact Mach-O segments before committing memory.

## v0.12.3 — page-rounded shared-cache segment preflight

Mach-O `LC_SEGMENT_64.vmsize` is an exact byte count and need not be a multiple of the x86_64 guest page size. Kestrel now requires the segment's VM start to be 4 KiB aligned, calculates its exact end with overflow checks, and rounds that end up to a separate 4 KiB reservation span. The preflight verifies that the entire rounded span is covered by shared-cache VM mappings, including adjacent and split-cache mappings. Exact segment size and page-rounded reservation size are both retained in the plan. Segment overlap checks and the aggregate 16 GiB safety limit use the rounded guest-page spans. This remains a read-only preflight: no cache pages are copied into guest memory and no cache slide fixups are applied.
