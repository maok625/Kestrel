## 0.24.0 — bounded isolated dyld resolver probes

- Add a reusable isolated guest-execution session for mapped lazy resolver functions, with hard instruction and block budgets.
- Protect all pre-existing committed pages and demand-zero ranges against writes in the copied VM; allocate a separate private guest stack for calls.
- Reject syscalls and disable host-thunk dispatch. Record resolver return values and whether RAX points to mapped executable guest memory.
- Keep all probe results diagnostic-only; no import is rebound from speculative resolver execution before dyld initialization and TLS are available.
- Add regressions for normal return, blocked writes/source-memory integrity, and syscall rejection.
- Full Xcode build and live M4 validation remain outstanding.

## 0.23.0 — expose lazy resolver targets in unresolved-bind diagnostics

- Preserve the exact provider export reached through the declared dependency's LC_REEXPORT_DYLIB chain for each unresolved binding.
- Report export flags, stub guest address, resolver guest address, and whether the resolver address is mapped executable.
- Classify common blockers explicitly, including lazy STUB_AND_RESOLVER resolver execution, thread-local exports, absolute exports, missing reexports, and unmapped addresses.
- Keep lazy STUB_AND_RESOLVER pointers unresolved; do not substitute the stub for the resolver's returned implementation address.
- Add a synthetic regression proving the reported resolver address is the provider's executable guest address while the lazy import stays unresolved.
- Full Xcode build and live M4 v0.23.0 validation remain outstanding.

## 0.22.0 — correct Mach-O STUB_AND_RESOLVER bind handling

- Resolve a cached or main-image STUB_AND_RESOLVER export to its stub address for non-lazy pointer binds.
- Keep lazy binds to STUB_AND_RESOLVER exports unresolved until Kestrel can execute the guest resolver and use its returned implementation address; do not bind them to the stub or resolver entry.
- Preserve exact dependency and reexport lookup rules, and keep guest-address validation in force.
- Add portable regressions for regular and lazy bind streams using a synthetic stub/resolver export.
- Portable Swift validation: 145/145 checks pass with warnings treated as errors under Swift 6.2.1. Full Xcode build and live M4 v0.22.0 validation remain outstanding.

## 0.21.0 — bounded reexport-provider cache materialization

- Extend the shared-cache page plan from the executable's direct dylibs to the exact cached images reachable through LC_REEXPORT_DYLIB commands and explicit export-trie reexport ordinals.
- Do not expand ordinary LC_LOAD_DYLIB, weak-load, upward-load, or lazy-load edges for page materialization; this avoids copying the complete 555-image metadata dependency closure.
- Parse one image's export metadata at a time and discard it after collecting provider edges. Bound selection to 1,024 selected images, 4,096 queued install names, 128 MiB of export tries, and 2,000,000 exports.
- Feed the selected exact install names into the existing shared-cache segment mapper, which globally deduplicates overlapping page ranges. Reuse the transactional page copier, slide-info v2 fixups, cache-derived protections, and 2 GiB backing ceiling.
- Add regressions proving an LC_REEXPORT_DYLIB provider is included in the page plan while an ordinary LC_LOAD_DYLIB target is not.
- Portable Swift validation: 144/144 checks pass with warnings treated as errors under Swift 6.2.1. Full Xcode build and live M4 v0.21.0 validation remain outstanding.

## 0.20.0 — responsive launcher, faster JIT bridge, headless tests

- Run all long operations (self-tests, Mach-O load, shared-cache inspect/analyze) off the main actor, matching the existing detached materialize/resolve steps.
- Replace ten per-suite view-model methods with a data-driven `SelfTestSuite` list; add **Run all tests** and a `--run-self-tests` headless mode with a process exit status.
- Cache the sorted native page table in `X64GuestVirtualMemory` keyed by `mappingGeneration`; sync back only changed page generations.
- Stop zeroing the whole 256 KiB MAP_JIT arena on every block execution; clear only the previous block's stale tail.
- Make translation-cache LRU hits O(1) with monotonic last-use stamps.
- Keep prior guest startup state and dependent actions enabled when *Prepare KernelArgs stack* fails.
- Fix duplicated/ineffective text modifiers in the launcher, add scrolling sections, log Copy/Clear/auto-scroll (5,000-line cap) and a Stop button for native launches.
- Drive `Info.plist` versions from `MARKETING_VERSION` / `CURRENT_PROJECT_VERSION` (was build 25 vs project 26).
- Changes were syntax-checked only; no Swift/macOS toolchain was available to build or run them.

## 0.19.0 — bounded dependency-route diagnostics

- Replace per-path visited sets in unresolved-provider route tracing with a global breadth-first search (each image visited once), fixing a critical memory blow-up. See README for details.

## 0.18.0 — unresolved binding provenance diagnostics

- Report unresolved bind slots separately from unique unresolved symbol names.
- Preserve each unresolved action's library ordinal, exact declared dependency, bind-stream kind, and weak-import flag.
- Group unresolved unique symbols by declared dependency.
- Trace candidate providers through exact dependency-command edges and label each edge by its Mach-O command type.
- Keep candidate reporting diagnostic-only; do not broaden positive two-level binds to unrelated transitive exports.
- Add a regression where a provider is reachable only through `LC_LOAD_DYLIB`: report the candidate path but leave the import unresolved.
- Portable validation: 142 checks across seven suites. Full Xcode/M4 v0.18.0 build and execution remain unverified.

# Changelog

## 0.19.0 — bounded dependency-route diagnostics / critical memory fix

- Fix exponential simple-path enumeration in unresolved-provider diagnostics. A dependency graph with many diamond-shaped paths could grow the route queue dramatically despite a small unique image count.
- Use one global visited set and one parent edge per image to find deterministic shortest routes in O(images + dependency edges) time and O(images) auxiliary memory.
- Restrict route traversal to parsed metadata images and the existing 1,024-image closure bound.
- Add a 66-image layered-diamond stress regression proving each image is visited at most once despite exponentially many possible simple paths.
- Portable Swift tests: 143/143 expected. Full Xcode build and live M4 memory-profile verification remain outstanding.

## 0.17.0 — load-command reexports and larger dependency closure

- Follow actual `LC_REEXPORT_DYLIB` commands at runtime when a symbol is absent from the current image export trie, preserving load-command order and explicit export-trie reexports; reject cycles and excessive depth. `MH_NO_REEXPORTED_DYLIBS` is not treated as a runtime veto.
- Increase the bounded dependency metadata closure from 256 to 1,024 images; retain export-byte and symbol-count safety limits.
- Keep positive two-level binds restricted to the declared dependency's direct exports and supported reexport chain.
- Clarify output to distinguish bind fixups applied from unique unresolved symbol names; revise candidate provider wording.
- Add two regression tests for an umbrella-framework/private-framework `LC_REEXPORT_DYLIB` chain, including when the `MH_NO_REEXPORTED_DYLIBS` header bit is set.
- Portable Swift tests: 141/141 pass with warnings treated as errors under Swift 6.2.1. Full Xcode build and live M4 verification remain outstanding.


## 0.16.0 — dependency closure and special dyld lookup

- Build a bounded breadth-first metadata closure from the executable's direct cached dependencies (maximum 256 images), reporting missing paths and truncation.
- Resolve `BIND_SPECIAL_DYLIB_FLAT_LOOKUP` through the global resolver and main executable first, then collect dependency-closure providers; bind only if all eligible providers converge on one guest address.
- Add a separate weak-definition symbol table for `BIND_SPECIAL_DYLIB_WEAK_LOOKUP`; only `EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION` providers can satisfy it, and conflicting weak providers are left unresolved.
- Preserve exact positive dependency ordinals and explicit reexport traversal; same-named exports in unrelated images are diagnostic candidates only, never implicit two-level providers.
- Report flat/weak lookup counts and candidate provider images for still-unresolved imports.
- Add shared-cache and Mach-O regressions for flat lookup, weak definition lookup, rejecting strong-only weak-lookup providers, and preventing global symbols from satisfying positive two-level ordinals.
- Portable Swift suites pass 139/139 checks with warnings treated as errors under Swift 6.2.1. Full Xcode build and v0.16.0 live M4 verification remain outstanding.

## 0.15.0 — cached dylib export parsing and import resolution

- Parse cached x86_64 dylib load commands, dependency ordinals, `__LINKEDIT` ranges, and export tries from the selected shared cache.
- Translate the cached export-trie file range through each image's `__LINKEDIT` segment and validated cache VM mappings.
- Resolve imports under the executable's exact dylib ordinal/install name and follow reexports through the target dylib's own dependency ordinals with cycle/depth limits.
- Register only ordinary guest addresses inside already materialized guest regions; leave TLS, absolute, stub/resolver, unresolved reexport, and unsupported bind forms unpatched.
- Restrict the loader to `BIND_TYPE_POINTER` stores so an unsupported bind kind cannot overwrite an eight-byte guest slot.
- Rebuild the main executable against a staged guest-VM snapshot and publish only after the bind completes; retain the original image/VM on error.
- Add two shared-cache regressions for cached export-trie parsing and two-level import resolution through the actual main-image binder.
- Portable Swift suites pass 135/135. Full Xcode build and v0.15.0 testing against the live Rosetta cache remain to be performed on the M4.

## 0.14.0 — guest-owned shared-cache page materialization

- Add a separate **Materialize cached dependency pages** action after successful dependency preflight.
- Coalesce all selected dependency segment page ranges so shared pages and common `__LINKEDIT` spans are copied only once.
- Copy each 4 KiB cache page into private guest-owned memory; the original cache files remain read-only and unchanged.
- Apply x86_64 slide-info v2 pointer reconstruction to private page buffers using `valueAdd` plus an explicit zero guest slide, preserving the cache's recorded guest VM addresses.
- Apply final guest page permissions from the authoritative cache mapping metadata, not individual Mach-O segment labels.
- Enforce a separate 2 GiB materialization allocation ceiling.
- Make the operation transactional: collisions, malformed slide data, or failed page writes leave the caller's original guest VM unchanged.
- Add regressions for page bytes, pointer fixups, cache immutability, RX protection, and rollback on reservation collision.
- Portable Swift suites pass 133/133 checks. Full Xcode build and live M4 materialization still require verification on Apple Silicon.


- Parse each cache file's `mappingWithSlide` table and require every extended row to exactly match its legacy VM mapping and backing-file range.
- Parse slide-info v2 headers, page-start arrays, optional page-extras arrays, page geometry, value-add and delta-mask metadata with strict bounds/overflow checks.
- Walk direct and page-extras pointer chains in the mapped cache file, validate every pointer read and chain boundary, and count pages/chains/nonzero pointer fixups without modifying source bytes.
- Reject unknown slide-info versions rather than guessing their pointer encoding; v1/v3/v4/v5 remain unsupported.
- Extend the cached-dependency analysis log with validated slide-info mapping/page/chain/fixup totals.
- Add five portable regressions for v2 header parsing, direct chains, page-extras chains, unsupported versions and out-of-file slide-info ranges.
- Portable suites pass 130/130 checks. A full Xcode build and execution against the user's live Rosetta cache remain to be verified on the M4.

## 0.12.4 — sub-page shared-cache segment layout

- Accept cached Mach-O segment starts and sizes that fall inside 4 KiB guest-page boundaries.
- Preserve the exact segment byte range and separately compute an outward-rounded guest-page range.
- Validate that the complete guest-page span is covered by shared-cache mappings, including adjacent mapping boundaries.
- Check segment overlap by exact byte ranges, allowing disjoint segments to share a guest page.
- Count shared guest pages once in per-image reservation accounting.
- Improve preflight output to print exact ranges and rounded guest-page ranges independently.
- Add regressions for the real `libSystem` `__DATA_CONST` shape (offset `0xA640`, size `0x3C8`), adjacent segments sharing a page, and page deduplication across images.
- Shared-cache parser/preflight suite expanded to 18 checks; all seven portable suites pass 125/125. Full Xcode/M4 verification remains outstanding.

## 0.12.3 — page-rounded shared-cache segment preflight

- Do not require `LC_SEGMENT_64.vmsize` to be a multiple of the x86_64 guest page size. Segment starts must remain guest-page aligned, but the exact segment end may fall inside its final page.
- Preserve exact segment byte size and compute a separate page-rounded reservation size using overflow-checked arithmetic.
- Validate that every byte of the complete page-rounded guest span is backed by shared-cache mappings, including ranges that cross adjacent or split-cache mappings.
- Detect segment overlap at guest-page granularity and apply the aggregate virtual reservation limit to page-rounded sizes.
- Update diagnostics to distinguish exact segment size from required page-rounded reservation and add regressions for the reported `libSystem` `__TEXT` segment (`vmsize=0x1BAE`) and a missing final page.
- Keep this milestone preflight-only: it does not copy cache pages into guest memory or apply cache slide fixups.
- Shared-cache parser/preflight suite: 15/15 passed; portable suite total: 122/122 based on the existing six suites plus two new cache regressions.

## v0.12.2 — cached dependency Mach-O mapping preflight

- Read cached Mach-O headers and bounded load-command regions through the shared cache VM mapping table, including split-cache backing files.
- Parse each exact-matched dependency's `LC_SEGMENT_64` commands, including segment names, VM addresses/sizes, and maximum/initial protections.
- Validate 4 KiB guest-page alignment, complete coverage by cache VM mappings, segment non-overlap, image type/architecture, command bounds, and a 16 GiB aggregate virtual-size ceiling.
- Add **Analyze cached dependency segments** to print a per-image/per-segment mapping plan for the matched libraries.
- Keep the operation preflight-only: it does not reserve or modify guest memory and does not grant execute permission. Shared-cache slide-info decoding and pointer fixups must be implemented before any cached data pages are mapped for execution.
- Add four portable regressions for VM-backed Mach-O reads, two-image segment planning, out-of-mapping segment rejection, and aggregate-size limit enforcement.

## 0.12.1 — Rosetta Cryptex shared-cache discovery

- Search the full Rosetta x86_64 shared-cache product and reduced `x86Support` product before legacy/native OS cache paths.
- Add staged Rosetta Cryptex and `/private/preboot` candidate paths for alternate mount/update layouts.
- Continue after an existing candidate is unreadable, malformed, or the wrong architecture; preserve detailed rejection reasons and report them if no usable baseline x86_64 cache is found.
- Add three discovery regressions covering candidate priority, wrong-architecture fallback, and multi-candidate diagnostics.
- Portable validation passes: 116 checks across seven suites.

## 0.12.0 — x86_64 dyld shared-cache inventory

- Added a read-only x86_64 dyld shared-cache reader for standard macOS and Preboot/Cryptex cache locations.
- Validates cache magic, mapping and image tables, file bounds, mapping overlap, subcache suffix/UUID metadata, and cached Mach-O architecture headers.
- Matches executable dependency install names to cache image records by exact path.
- Added six shared-cache parser tests and launcher actions to inspect the real cache on the user's M4.
- Portable validation passes: 113 checks across seven suites.
- No cached library pages are mapped into guest memory in this release; shared-cache slide handling, recursive dependency mapping, binding from cached exports, and dyld initialization remain outstanding.

# Changelog

## 0.11.3 — dyld bind cursor modulo arithmetic

- Match dyld's unsigned 64-bit bind-address arithmetic: `ADD_ADDR_ULEB` and the implicit pointer/skip advances wrap modulo 2^64 rather than treating wrap as an automatic malformed-stream condition.
- Validate every emitted pointer location against the selected segment after the modulo operation; wrapped results inside the segment are accepted, while wrapped results outside the segment remain rejected.
- Extend the synthetic Mach-O fixture to model a larger sparse `__DATA` segment.
- Add regressions for the exact backwards cursor pattern from `kyty_emulator` (`0x2838 + 0xFFFFFFFFFFFFDAE0 = 0x318`), successful resolver application at that slot, and rejection when modulo arithmetic still yields an out-of-segment slot.
- Keep stream/opcode/segment provenance in diagnostics for genuinely invalid bind locations.

## 0.11.2 — bind stream cursor diagnostics

- Keep strict rejection for a bind that actually targets a location outside its selected segment; do not silently skip or patch an invalid slot.
- Extend invalid-location diagnostics with the segment index, source `SET_SEGMENT_AND_OFFSET_ULEB` opcode, initial selected offset, most recent cursor-advance operation, overflow state, and raw opcode bytes surrounding the failing instruction.
- Reset all diagnostic cursor provenance between lazy-bind records.
- Add a regression proving malformed `UINT64_MAX` bind locations remain rejected and carry enough stream context to diagnose a real executable.


## 0.11.1 — bind-stream cursor and BSS fixups

- Do not reject a bind stream solely because a post-bind cursor advance moves beyond the current segment or overflows after the final valid action. Retain an invalid cursor state and reject it only if a later bind actually tries to use it.
- Include bind stream type, opcode offset, segment name, and segment offset in invalid-location diagnostics.
- Validate pointer-bind locations against segment virtual size rather than file size, allowing valid fixups in zero-fill/BSS tails. Demand-zero pages are materialized through the guest VM when a bind writes there.
- Add four Mach-O loader regressions covering trailing cursor overflow, cursor reset, invalid emitted locations, and BSS binding.
- Explain why the KernelArgs preparation action remains disabled until a Mach-O image has loaded successfully.

## 0.11.0 — initial dyld binding and Darwin startup scaffold

- Parse dylib dependency load commands and `LC_RPATH` metadata.
- Decode classic regular, weak, and lazy pointer-bind opcode streams into validated bind actions.
- Parse basic export-trie entries, including ordinary exports, reexports, absolute exports, and stub/resolver metadata.
- Apply bindings supplied as guest virtual addresses; support main-image self-export resolution and explicit external resolver entries.
- Preserve unresolved strong imports for diagnostics; zero unresolved weak imports; add optional strict unresolved-import failure/rollback.
- Discover candidate dependency paths for direct, `@executable_path`, `@loader_path`, and `@rpath` install names without claiming to load those images.
- Add guest import stubs for `_read`, `_write`, `_getpid`, and `_exit`.
- Add a narrow BSD `SYSCALL` dispatcher for `exit`, `read`, `write`, and `getpid`, including `RCX`/`R11` state and carry-flag error indication.
- Add a guarded initial kernel-style `KernelArgs` stack builder with `argc`, `argv`, `envp`, and a minimal `apple` vector.
- Add seven portable Darwin startup/syscall checks, including demand-zero source-page materialization for `write`, and two Apple Silicon native integration checks.
- Correct decoder validation for `SYSCALL` (`0F 05`).
- Keep process launch explicitly disabled until dyld/shared-cache loading and initialization provide a valid `__dyld_start` entrypoint.

## 0.10.4 — classic dyld pointer rebases

- Parse classic `LC_DYLD_INFO` / `LC_DYLD_INFO_ONLY` rebase streams.
- Apply supported 64-bit pointer rebases for explicit page-aligned PIE slides.
- Report bind and chained-fixup data without claiming to resolve them.

## 0.10.3 — demand-zero Mach-O pages

- Register unbacked Mach-O segment tails and BSS as sparse demand-zero ranges.
- Materialize a single zero-filled guest page on first permitted access and retry the faulting instruction.

## 0.10.2 — dispatcher cache-test fix

- Correct LRU-capacity self-test calls to pass `X64GuestMemory` by value rather than using `inout` syntax.

## 0.10.1 — sparse Mach-O segment accounting

- Separate reserved guest virtual bytes from eagerly committed host backing bytes.


## v0.12.0 — x86_64 dyld shared-cache inventory

- Added a read-only x86_64 dyld shared-cache reader for standard macOS and Preboot/Cryptex cache locations.
- Validates cache magic, mapping and image tables, file bounds, mapping overlap, subcache suffix/UUID metadata, and cached Mach-O architecture headers.
- Matches executable dependency install names to cache image records by exact path.
- Added six shared-cache parser tests and launcher actions to inspect the real cache on the user's M4.
- Portable validation passes: 113 checks across seven suites.
- No cached library pages are mapped into guest memory in this release; shared-cache slide handling, recursive dependency mapping, binding from cached exports, and dyld initialization remain outstanding.
