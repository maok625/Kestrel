## v0.24.0 — bounded isolated dyld resolver probes

- Execute each unique mapped-executable lazy resolver address once using the guest x86-64 dispatcher, with 2,048-instruction and 512-block limits.
- Create one reusable guest-memory snapshot, remove write permission from all pre-existing committed and demand-zero pages, and allocate a separate private stack for probe calls. Shared source-page backing is therefore not writable by speculative guest code.
- Reject guest syscalls and omit host-thunk dispatch during probes. Report normal returns, mapped-executable RAX results, guest memory faults, blocked syscalls, and execution failures.
- Resolver return values remain diagnostic only. Kestrel does not bind imports from these probes because dyld initialization, TLS and resolver side-effect semantics are not implemented.
- Add dispatcher regressions for a successful return, blocked writes that leave source memory unchanged, and syscall rejection.
- Full Xcode build and live M4 validation remain outstanding.

## v0.23.0 — expose lazy resolver targets in unresolved-bind diagnostics

- Unresolved imports now report the exact export provider reached through the declared reexport chain, its flags, stub/resolver guest addresses, and whether the resolver target is executable.
- Common unresolved causes are classified instead of reporting only a candidate dependency path.
- Lazy STUB_AND_RESOLVER imports remain unresolved until the guest resolver can be executed safely.
- A synthetic regression validates the resolver address and confirms Kestrel does not bind the lazy slot to the stub.

## v0.22.0 — correct Mach-O STUB_AND_RESOLVER bind handling

- Non-lazy pointer binds can now resolve a STUB_AND_RESOLVER export to its stub address.
- Lazy binds to these exports remain unresolved until Kestrel can execute the guest resolver and use the returned implementation address.
- The change preserves exact two-level dependency and reexport rules, with portable regressions for regular and lazy bind streams.
- Portable validation: 145/145 checks pass with warnings treated as errors under Swift 6.2.1; a full Xcode/M4 run is still required.

# Kestrel — ARM64 launcher and x86_64 translation prototype


## v0.20.0 — responsive launcher, faster JIT bridge, headless tests

- **UI no longer freezes during long operations.** All ten self-test suites, the x86 → ARM64 smoke test, Mach-O load, shared-cache inspect/analyze, materialize and import resolution now run off the main actor.
- **One data-driven test runner.** `SelfTestSuite` replaces ten near-identical view-model methods; the new **Run all tests** button and the per-suite buttons share one code path and one reporting format.
- **Headless test mode.** `Kestrel.app/Contents/MacOS/Kestrel --run-self-tests` runs every suite without opening a window and exits 0 only if all pass (usable from Terminal or CI on Apple Silicon).
- **Guest VM native page table is cached.** `withNativePageTable` used to sort and re-hash every committed page on *every* block execution (about 337k pages after cache materialization). The table is now rebuilt only when `mappingGeneration` changes, and only pages whose generation a native write changed are synchronised back.
- **JIT arena no longer cleared per call.** `KestrelJIT.c` zeroed the full 256 KiB arena before every block; it now clears only the stale tail of a previous, longer block (trailing zero words still trap if a block ever ran off its end).
- **Translation cache hits are O(1).** The LRU list (`removeAll` per touch) is replaced by monotonic last-use stamps; the oldest entry is searched only on overflow.
- **Guest startup failure no longer corrupts UI state.** A failed *Prepare KernelArgs stack* previously disabled every dependent action and dropped the recorded startup state although the old stack was still reserved. It now retains the previous state.
- **Launcher polish.** Fixed the unstyled explanatory paragraph (duplicated modifiers), grouped the controls into scrollable sections with a numbered pipeline, added log **Copy**/**Clear**, an auto-scrolling log capped at 5,000 lines, and a **Stop** button for natively launched processes.
- **Version metadata single-sourced.** `Info.plist` now uses `$(MARKETING_VERSION)` / `$(CURRENT_PROJECT_VERSION)` (it previously said build 25 while the project said 26); the header badge reads the bundle version.
- **Not compiled in the authoring environment.** These changes were syntax-checked (Swift parse, C `-fsyntax-only` with stubbed Apple headers) but not built or run; no Swift/macOS toolchain was available. Run **Run all tests** on the M4 before relying on them.

## v0.19.0 — bounded dependency-route diagnostics (critical memory fix)

- Replace per-path visited sets in unresolved-provider route tracing with a breadth-first search that marks each cached image visited globally and stores one parent edge per image.
- Bound route exploration to the already parsed dependency closure (maximum 1,024 images); memory and work are now O(images + dependency edges), rather than proportional to the number of possible simple paths.
- Preserve deterministic shortest-path output and exact Mach-O load-command labels without changing import-binding policy.
- Add a 66-image layered-diamond regression with exponentially many possible simple paths; verify that each image is visited at most once.
- This addresses a critical v0.18.0 diagnostic-path bug that could expand a route queue exponentially and plausibly account for the reported multi-tens-of-gigabytes memory spike. The intended direct-cache materialization remains approximately 1.29 GiB; the full real-M4 memory profile still needs confirmation.

## v0.18.0 — unresolved binding provenance diagnostics

- Report unresolved main-image bind slots separately from the deduplicated unresolved symbol-name count.
- Preserve each unresolved action's original library ordinal, declared install name, regular/weak/lazy stream, and weak-import flag.
- Print unresolved unique-symbol counts by exact declared dependency.
- For candidate symbols found elsewhere in the loaded dependency graph, print the dependency-command route (for example, `LC_LOAD_DYLIB` versus `LC_REEXPORT_DYLIB`). Candidate routes are diagnostic only and never broaden two-level binding rules.
- Correct the resolver report label to distinguish main-image imports resolved from cache metadata from imports belonging to the cached dylibs.
- Add portable tests proving a candidate reachable only through `LC_LOAD_DYLIB` is reported with its exact route but is not rebound to a positive two-level ordinal.

## v0.17.0 — load-command reexports and expanded dependency closure

- When a symbol is absent from an image's export trie, follow its actual `LC_REEXPORT_DYLIB` dependencies in load-command order, with cycle/depth guards. `MH_NO_REEXPORTED_DYLIBS` is not treated as a runtime veto.
- Keep positive dependency ordinals strict: a symbol found elsewhere in the cache is not sufficient unless the declared dependency exposes it through an explicit export-trie or load-command reexport path.
- Increase the bounded metadata dependency-closure limit from 256 to 1,024 images. Export-byte and symbol-count ceilings remain in force.
- Report candidate exports that are not exposed through the declared dependency or its reexports.
- Clarify diagnostics: the loader reports applied bind fixups and unique unresolved symbol names separately, since repeated bind actions can target the same symbol.
- Add real-shaped synthetic regressions for `AVFoundation -> LC_REEXPORT_DYLIB -> AVFCapture` resolution, including a header with `MH_NO_REEXPORTED_DYLIBS` set to ensure the runtime follows the actual load-command graph.

The v0.16.0 M4 run materialized all 337,683 selected cache pages, parsed 259,413 exports across 256 closure images, and resolved 895 imports from cached dylibs. The closure hit its 256-image cap; the main-image rebind applied 1,007 fixups and reported 457 unique unresolved symbols. This release's reexport fallback is portable-test validated only and still requires a live M4 run.

## v0.16.0 — dependency-closure and special dyld lookup semantics

- Walk cached dylib load-command dependencies in a bounded breadth-first load order (maximum 256 metadata images) after reading the executable's direct dependencies.
- Implement `BIND_SPECIAL_DYLIB_FLAT_LOOKUP` by searching the global resolver and main executable first, then collecting eligible providers across the bounded dependency closure. Bind only when candidates converge on one guest address; ambiguous providers remain unresolved.
- Implement `BIND_SPECIAL_DYLIB_WEAK_LOOKUP` using a dedicated weak-definition address table; ordinary strong exports and host thunks cannot satisfy weak lookup. If distinct weak providers produce different addresses, leave the import unresolved as ambiguous.
- Register weak exports from the main image and cached dylibs separately from ordinary symbol entries.
- Keep positive dependency ordinals two-level: resolve only from the exact linked image or through its explicit export-trie reexports.
- Report missing dependency paths, closure truncation, flat/weak lookup resolutions, and candidate providers in other dependency images. Candidate providers are diagnostic only and are never used to violate two-level binding.
- Add regressions for flat lookup, weak-definition lookup, and rejection of strong-only providers for weak lookup.

The v0.16.0 M4 run reached the 256-image closure limit. v0.17.0 adds runtime traversal of actual `LC_REEXPORT_DYLIB` dependencies and raises the metadata closure cap to 1,024. The baseline output reported 1,007 bind fixups applied and 457 unique unresolved symbol names; these are not complementary counts because repeated actions can bind the same symbol and unresolved names are deduplicated.

## v0.15.0 — cached dylib export parsing and import resolution

- Parse cached x86_64 dylib Mach-O load commands, dependency ordinals, `__LINKEDIT` ranges, and export-trie metadata from the selected Rosetta shared cache.
- Translate export-trie file offsets through each cached image's `__LINKEDIT` segment into validated shared-cache VM reads, including split-cache backing mappings.
- Resolve two-level imports by exact install name and ordinal; follow reexports only through the referenced cached dylib's own dependency ordinal.
- Register only ordinary guest addresses that belong to already materialized guest regions. Thread-local, absolute, stub/resolver exports, missing images, and unsupported bind types remain unresolved.
- Rebuild the main executable against a staged guest-VM copy and publish it only after rebinding completes; preserve the prior image/VM if resolution fails.
- Add a **Resolve imports from cached dylibs** action after successful materialization.

This resolves only supported imports from the selected direct cache images and any already materialized reexport targets. It does not initialize dyld, resolve all special/flat namespace forms, provide TLS/errno or framework ABI bridges, or execute `LC_MAIN`.

## v0.14.0 — guest-owned shared-cache page materialization

- Materialize the union of the selected direct dependency images' page-rounded `LC_SEGMENT_64` ranges into Kestrel-owned sparse guest memory.
- Copy one 4 KiB page at a time from the validated primary/subcache backing files; do not write into the source dyld cache.
- Apply x86_64 slide-info v2 pointer reconstruction to each private page using `valueAdd` and a zero guest slide, so reconstructed pointers refer to the cache's recorded guest VM addresses.
- Derive final guest read/write/execute permissions from the cache mapping table, after the temporary writable copy step.
- Coalesce shared pages across images and common `__LINKEDIT` mappings; publish the updated guest VM only after the entire mapping transaction succeeds.
- Reject unsupported slide-info page geometry/versions, invalid cache protections, collisions with existing guest regions, and malformed pointer chains.

This maps the selected **direct** dependencies only. It does not yet recursively load their transitive dependencies, resolve `kyty_emulator`'s unresolved imports, initialize dyld, or start the process.

## v0.13.0 — x86_64 shared-cache slide-info v2 preflight

- Parse modern mapping-with-slide records for the primary cache and every subcache.
- Validate slide-info v2 page tables and walk direct/extra pointer chains, counting rebasing locations without changing any cache bytes.
- Report slide-info page, chain, and pointer-fixup totals during cached dependency analysis.
- Unknown slide-info versions fail closed. This provided the read-only validation used by the v0.14.0 materializer.

## v0.12.4 — sub-page shared-cache segment layout

- Accept cached `LC_SEGMENT_64` commands whose `vmaddr` and `vmsize` are not 4 KiB aligned. Shared-cache images may pack exact segment ranges within a guest page.
- Preserve the exact segment start/size while separately rounding the guest reservation start down and end up.
- Validate complete cache backing coverage for the outward-rounded page span, including ranges crossing adjacent/split-cache mappings.
- Reject exact byte-range segment overlap, but allow disjoint exact segments to share a guest page; count shared guest pages once in reservation accounting.
- Show both exact segment byte ranges and page-rounded guest reservation ranges in preflight output.
- Add a regression matching the observed `libSystem` `__DATA_CONST` layout (`vmaddr` ending in `0xA640`, `vmsize=0x3C8`).



Kestrel is an experimental native macOS application for Apple Silicon. It combines a SwiftUI launcher with an incremental x86_64-to-AArch64 translation runtime. It deliberately does not send Intel-only executables to Rosetta.

## v0.12.2 — cached dependency Mach-O mapping preflight

- Read cached Mach-O headers/load commands through the shared cache VM mapping table, including split-cache backing files.
- Parse exact-matched cached dylibs' `LC_SEGMENT_64` commands and validate segment VM ranges/protections against the cache mappings.
- Add **Analyze cached dependency segments** to generate a per-image mapping plan for the executable's direct dependencies.
- Validate exact segment ranges, outward-rounded cache-page coverage, bounds, byte-range overlap, command sizes, architecture/file type, and aggregate rounded reservation size.

This is intentionally a preflight only. It does not modify guest memory or expose cached code as executable. Cache mapping-with-slide metadata, slide-info versions, and pointer fixups must be applied before cached pages can safely be mapped for execution.

## v0.12.1 — Rosetta Cryptex cache discovery

- Search the full Rosetta x86_64 shared cache and reduced `x86Support` cache before checking legacy OS cache locations.
- Probe staged Rosetta Cryptex paths and the equivalent `/private/preboot` mount paths.
- Continue discovery when a candidate exists but is unreadable, malformed, ARM64, or `x86_64h`; report every rejected candidate if no baseline x86_64 cache is usable.
- Add three regression tests for candidate ordering, skipping an incompatible cache, and complete rejection diagnostics.

## v0.12.0 — x86_64 dyld shared-cache inventory

- Locate the x86_64 dyld shared cache in the full/reduced Rosetta Cryptex products first, then standard macOS and legacy locations.
- Validate cache magic/architecture, mapping ranges, image-info metadata, split-cache filenames and UUIDs, and non-overlapping VM mappings.
- Enumerate cached image paths and inspect each image's Mach-O header through the cache's VM-to-file mapping.
- Match the executable's dependency install names against cached images by exact path; do not guess based on basename.
- Add a launcher action to inspect the real cache and report which dependencies are present.

This is an inventory step, not dependency loading. No cached image segments are copied into guest memory, and cache slide/fixup metadata is not applied. dyld startup and process execution remain unavailable.

## v0.11.3 — dyld bind cursor modulo arithmetic

- Match dyld's unsigned 64-bit arithmetic for `ADD_ADDR_ULEB`, implicit pointer advances, and skip advances. A ULEB value may encode a backwards cursor adjustment using its modulo-2^64 representation.
- Validate the resulting cursor only when a bind action is emitted. A wrapped cursor that lands inside the selected segment is valid; a wrapped cursor that remains outside the segment is still rejected.
- Keep detailed diagnostics for invalid emitted locations, including stream type, opcode offset, selected segment, initial offset, last cursor mutation, wrap state, and raw opcode bytes.
- Add regressions reproducing the real executable's `0x2838 + 0xFFFFFFFFFFFFDAE0 = 0x318` sequence, applying the resulting bind through a guest-address resolver, and rejecting a wrapped result that remains outside the segment.
- Retain the v0.11.1 fix allowing valid binds into segment BSS/zero-fill tails.


This milestone extends the load-only Mach-O image mapper with classic dyld binding metadata and a deliberately narrow import/startup bridge:

- Parses dylib load commands (`LC_LOAD_DYLIB`, weak, reexport, upward, and lazy variants), `LC_RPATH`, and export-trie metadata.
- Decodes classic regular, weak, and lazy dyld bind opcode streams into individual pointer-bind actions. It validates ordinals, segment offsets, encoded strings, addends, and write locations. Unsupported bind types/opcodes fail closed.
- Parses the simple export-trie terminal forms (ordinary exports, reexports, absolute exports, and stub/resolver metadata).
- Applies a bind only when a supplied resolver returns a **guest virtual address**. Ordinary exports from the main image are indexed for self-bind resolution; weak unresolved imports are written as zero, while unresolved strong imports remain untouched and are reported. A strict loader option can roll back when strong imports remain unresolved. Decoded lazy-bind actions are currently applied eagerly when a resolver is available; the actual dyld lazy binder and on-first-call rebinding are not implemented.
- Discovers possible dependency files using direct paths, `@executable_path`, `@loader_path`, and `@rpath`. This is path discovery only: it does not parse/load dependent dylibs, map the dyld shared cache, or perform a complete two-level namespace lookup.
- Installs a small set of guest C import stubs: `_read`, `_write`, `_getpid`, and `_exit`. The host thunk dispatcher marshals the x86_64 register arguments, copies data only through checked guest memory, and returns through the guest stack.
- Implements a narrow BSD `SYSCALL` subset for `exit`, `read`, `write`, and `getpid`, including the x86_64 `RCX`/`R11` syscall return convention and Darwin carry-flag error indication.
- Builds a guarded, zero-filled initial stack in the Darwin kernel-to-dyld `KernelArgs` shape: main Mach-O header pointer, `argc`, `argv`, `envp`, and a minimal `apple` vector.

**This does not yet start a process.** The initial instruction pointer must be dyld's `__dyld_start`, not the executable's `LC_MAIN`. v0.11 can prepare the stack, but it does not map/initialize dyld or its shared-cache entrypoint, so it intentionally does not install an initial RIP or transfer control. The `apple` vector is minimal and is not a complete kernel parameter set.

## Current implementation

- Native ARM64 `.app` and executable launcher with arguments and environment variables.
- Thin/fat Mach-O architecture inspection and an x86_64 `MH_EXECUTE` image parser/mapper.
- Sparse image mapping: file-backed pages are committed; BSS and unbacked segment tails are reserved as demand-zero ranges and materialized one page at a time on first permitted access.
- Classic 64-bit pointer rebases for explicitly supplied page-aligned PIE slides.
- Classic regular/weak/lazy dyld bind action decoding, basic export-trie parsing, dependency metadata, and `LC_RPATH` candidate discovery.
- x86_64 dyld shared-cache inventory, exact direct-dependency matching, cached Mach-O segment planning, slide-info v2 validation, and guest-owned page materialization with pointer fixups and cache-derived permissions.
- Cached Mach-O export-trie parsing and a bounded (1,024-image) transitive dependency-metadata walk, including explicit `LC_REEXPORT_DYLIB` resolution and provenance diagnostics for unresolved imports.
- Guest-address-only binding application, main-image self-export lookup, and four experimental guest C thunk stubs (`_read`, `_write`, `_getpid`, `_exit`).
- A guarded initial kernel-shaped `KernelArgs` stack builder; no dyld entrypoint is installed or executed.
- x86_64 architectural state: 16 GPRs, RIP, RFLAGS, and width-correct partial-register semantics.
- A tested decoder and guest-semantic IR for an explicit, intentionally limited opcode subset.
- Sparse multi-region guest virtual memory with 4 KiB guest pages, lazy commit/decommit, per-page RWX permissions, guard-page stacks, and mapping/write generations.
- A native AArch64 basic-block compiler using a persistent host `MAP_JIT` arena, a guest-RIP dispatcher, and a bounded source-byte-validated LRU translation cache.
- Native guest-memory access through a checked sparse page-table ABI. Guest virtual addresses, host backing pointers, and host JIT addresses remain separate.
- A reference interpreter used as the correctness oracle for supported IR operations.

## Native AArch64 backend coverage

The backend currently supports selected forms of MOV, ADD, SUB, CMP, XOR, register/register XCHG, NOP, PAUSE, LEA, PUSH, POP, CALL, RET, direct/indirect JMP, and all 16 x86 conditional-branch predicates. Supported memory operands include selected MOV/ADD/SUB/CMP/XOR forms and base/index/scale/displacement/RIP-relative addressing. Memory XCHG, LOCK operations, FS/GS, SIMD/FPU, system instructions other than the dispatcher-handled `SYSCALL`, and instructions outside the explicit decoder/IR subset are rejected.

The translated `SYSCALL` instruction exits the native block to the Swift dispatcher. The current syscall subset is `exit`, `read`, `write`, and `getpid`; unsupported calls return an `ENOSYS`-style error. This is not a general Darwin syscall layer. The host thunk registry is also only a bootstrap subset, not a general x86_64-to-ARM64 ABI bridge.

Every translated memory access uses native C page-table helpers that validate region presence, page commitment, access permissions, and cross-page ranges before touching host backing. Cross-page stores are prevalidated to prevent partial writes. Demand-zero faults are returned to Swift, which commits the single faulting page and retries the instruction without advancing guest RIP. Native writes update page generations used by translation-cache invalidation.

## Important scope boundary

**Kestrel is not a Rosetta replacement and cannot yet launch arbitrary Intel-only macOS applications.** The x86_64 engine executes a tested subset of instructions, maps an x86_64 `MH_EXECUTE` image, handles demand-zero guest pages, and has initial classic rebase/bind processing. It can inventory the x86_64 shared cache, parse a bounded transitive dependency-metadata closure, preflight the executable's direct cached dependencies, and materialize those selected 4 KiB pages into private guest memory with slide-info v2 rebases and cache-derived protections. It does not yet recursively materialize transitive dependency pages, resolve all remaining strong imports, initialize dyld, or install the actual `__dyld_start` entrypoint. Main-image chained fixups remain unsupported. Only four host C imports and four BSD syscalls are bridged. Thread-local `errno`, broad libSystem, Objective-C/runtime and framework calls, guest threads/TLS, signals, exceptions, atomics, and complete process lifecycle semantics remain absent.

The process stack builder models the kernel-to-dyld `KernelArgs` arrangement, but it cannot launch without a mapped and initialized dyld image and a valid `__dyld_start` entrypoint. `LC_MAIN` is the executable's later main entry, not the kernel's initial instruction pointer. Kestrel does not currently execute the selected `kyty_emulator` image.

## Guest/host memory separation

Kestrel keeps three address concepts separate:

1. Guest virtual address used by the x86_64 program.
2. Host backing address where Kestrel stores guest bytes.
3. Host JIT address where generated AArch64 instructions reside.

Guest pointers are metadata and are translated through guest-region/page-table validation. They are never cast directly to host pointers. Guest executable permissions are metadata; only generated AArch64 blocks are written into the host JIT arena.

## Build and test on your M4

1. Extract the project and open `KestrelLauncher.xcodeproj` in Xcode.
2. Select the `Kestrel` scheme and your Mac as the run destination; use your own signing identity or Xcode automatic signing.
3. Build and run the app.
4. Click **Run all tests** (or any individual suite button): CPU state, decoder/IR, interpreter, native ARM64 differential, block dispatcher, guest VM, native guest VM/JIT, Mach-O loader, dyld shared-cache and Darwin runtime. For a windowless run use `Kestrel.app/Contents/MacOS/Kestrel --run-self-tests`.
5. Select `kyty_emulator` and use the numbered **x86_64 guest pipeline** buttons in order.
6. **1. Load selected x86_64 Mach-O image** maps the image, applies classic rebases/binds, and installs the guest C thunks.
7. **2. Inspect x86_64 dyld shared cache** verifies exact dependency matches.
8. **3. Analyze cached dependency segments** inspects each cached dylib's `LC_SEGMENT_64` ranges/protections and the cache's slide-info v2 page/chain/fixup totals.
9. **4. Materialize cached dependency pages** copies the selected pages into guest-owned memory, reconstructs v2 pointers with a zero guest slide, and applies cache mapping protections (about 1.29 GiB for the current target).
10. **5. Resolve imports from cached dylibs** parses cached export tries and reloads the main image against supported, dependency-qualified guest addresses. It may leave many imports unresolved.
11. **6. Prepare Darwin KernelArgs stack** only builds/inspects the stack; it does not launch the image.
12. The **Native guest VM/JIT tests** suite on Apple Silicon. The nine tests include the seven previously established sparse-VM/MAP_JIT tests plus two v0.11 tests for native `SYSCALL` dispatch and the imported `_write` thunk.

## Verification status (v0.21.0)

The user's v0.19.0 M4 run confirmed that the unresolved-provider diagnostic no longer causes the earlier memory explosion: reported peak memory stayed below approximately 1.58 GB. The 26 direct dependencies materialized successfully as 337,683 guest pages (1,383,149,568 bytes), with 83 guest regions reserved and 974,418 pointer words rebased at a zero cache slide. The original Rosetta cache remained unchanged.

The v0.19.0 resolver parsed metadata for 555 cached images but only the 26 direct dependencies had their guest pages materialized. It resolved 895 main-image imports from cached exports; 457 unique symbol names remained unresolved. The attached runtime log showed that several unresolved libSystem symbols were available through explicit LC_REEXPORT_DYLIB providers such as libsystem_c, libsystem_m, libdispatch, libdyld, libsystem_kernel, libsystem_blocks, and libxpc, but their pages were not part of the original 26-image materialization plan.

v0.21.0 extends preflight to select the direct dependencies plus the bounded closure of actual reexport providers. It follows LC_REEXPORT_DYLIB commands and explicit export-trie reexport ordinals only; ordinary LC_LOAD_DYLIB, weak-load, upward-load, and lazy-load edges are not expanded for page materialization. Export metadata is processed one image at a time and discarded after its provider edges are collected. The selection is bounded to 1,024 selected images, 4,096 queued install names, 128 MiB of export tries, and 2,000,000 exports. The normal page planner globally coalesces overlapping page ranges, and materialization still refuses plans above the 2 GiB backing ceiling before guest memory is modified.

All seven portable Swift suites pass **144/144 checks**: CPU state (10), decoder/IR (13), interpreter (9), guest VM (24), Mach-O parser/loader (45), Darwin runtime/startup (7), and dyld shared-cache/materializer/export resolver (36). The portable harness was compiled with Swift 6.2.1 and warnings treated as errors. The modified engine sources pass Swift syntax parsing.

**Not yet verified:** a full Xcode/macOS build or a live v0.21.0 run against the user's Rosetta cache. The reexport-provider page count and resulting memory use must be confirmed on the M4. Kestrel still does not initialize dyld or execute LC_MAIN.

## Security and reliability note

This is experimental executable-code generation, not a security boundary. Do not use it to run untrusted binaries. The loader, sparse VM, parser, and host thunk/syscall bridges are experimental and deliberately reject unsupported instructions and metadata rather than guessing.


## Bind cursor validation note

Bind-cursor arithmetic follows dyld's unsigned 64-bit addition semantics. Modulo wrap is not treated as an error by itself because linkers can encode backwards movement in an unsigned ULEB delta. Every actual bind is still bounds-checked against its selected segment before it becomes a fixup action or writes guest memory. Diagnostic context is retained for invalid results.
