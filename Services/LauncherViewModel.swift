import AppKit
import Foundation
import SwiftUI

// MARK: - Self-test suites

/// One on-device test suite. Suites are plain data so the launcher buttons, the
/// "Run all tests" action and the headless `--run-self-tests` mode all share
/// one code path instead of ten near-identical methods.
struct SelfTestSuite: Identifiable, Sendable {
    let id: String
    let buttonTitle: String
    let systemImage: String
    let passSummary: String
    let failureLabel: String
    let notes: [String]
    let run: @Sendable () throws -> [String]
}

extension SelfTestSuite {
    static let all: [SelfTestSuite] = [
        SelfTestSuite(
            id: "cpu-state",
            buttonTitle: "CPU-state tests",
            systemImage: "memorychip",
            passSummary: "x86_64 architectural CPU-state tests",
            failureLabel: "CPU-STATE TESTS",
            notes: ["CPU-state milestone complete: 16 GPRs, RIP, RFLAGS, partial-register semantics, and ADD/SUB status flags."],
            run: { try X64CPUStateSelfTests.run() }
        ),
        SelfTestSuite(
            id: "decoder",
            buttonTitle: "Decoder + IR tests",
            systemImage: "waveform.path",
            passSummary: "x86_64 decoder and semantic-IR tests",
            failureLabel: "DECODER TESTS",
            notes: [
                "Decoder milestone slice complete: prefixes, opcode maps, ModRM/SIB, displacements, immediates, sequential decode, and guest-semantic IR.",
                "Coverage is an explicit opcode subset, not a complete x86_64 decoder; unsupported opcodes are rejected rather than guessed."
            ],
            run: { try X64InstructionDecoderSelfTests.run() }
        ),
        SelfTestSuite(
            id: "interpreter",
            buttonTitle: "Interpreter tests",
            systemImage: "play.rectangle",
            passSummary: "x86_64 interpreter execution tests",
            failureLabel: "INTERPRETER TESTS",
            notes: [
                "Interpreter milestone slice complete: real fetch/decode/IR execution, bounded guest memory, integer operations, branches, and stack control flow.",
                "This is a reference interpreter for an explicit opcode subset; it does not yet load or launch Mach-O applications."
            ],
            run: { try X64InterpreterSelfTests.run() }
        ),
        SelfTestSuite(
            id: "arm64-translation",
            buttonTitle: "Native ARM64 memory + control-flow tests",
            systemImage: "arrow.triangle.branch",
            passSummary: "x86_64 IR → native AArch64 differential tests",
            failureLabel: "ARM64 TRANSLATION TESTS",
            notes: [
                "Native backend slice complete: integer operations, bounded guest memory, LEA, stack operations, CALL/RET, and guest branch exits are compared against the reference interpreter.",
                "Control-flow instructions terminate a translated block and return to the guest dispatcher; this does not yet load or launch x86_64 Mach-O applications."
            ],
            run: { try X64ARM64TranslationSelfTests.run() }
        ),
        SelfTestSuite(
            id: "dispatcher",
            buttonTitle: "Block dispatcher tests",
            systemImage: "point.3.connected.trianglepath.dotted",
            passSummary: "x86_64 translated-block dispatcher tests",
            failureLabel: "BLOCK DISPATCHER TESTS",
            notes: [
                "Dispatcher milestone slice complete: basic-block splitting, RIP redispatch, translated-block caching, guest-code change detection, and bounded execution.",
                "This remains a bounded guest-memory prototype; it does not yet load or launch x86_64 Mach-O applications."
            ],
            run: { try X64ARM64DispatcherSelfTests.run() }
        ),
        SelfTestSuite(
            id: "guest-vm",
            buttonTitle: "Guest VM tests",
            systemImage: "memorychip.fill",
            passSummary: "x86_64 guest virtual-memory manager tests",
            failureLabel: "GUEST VIRTUAL-MEMORY TESTS",
            notes: [
                "Virtual-memory manager slice complete: sparse reservations, 4 KiB guest pages, commit/decommit, per-page RWX permissions, execute fetch, guard pages, deterministic faults, and write generations.",
                "The sparse page-based VM is now the memory backing used by the native JIT bridge; run the native guest-VM integration suite to verify it on this Mac."
            ],
            run: { try X64GuestVirtualMemorySelfTests.run() }
        ),
        SelfTestSuite(
            id: "native-vm-jit",
            buttonTitle: "Native guest VM/JIT tests",
            systemImage: "cpu",
            passSummary: "native AArch64 ↔ sparse guest-VM integration tests",
            failureLabel: "NATIVE GUEST-VM INTEGRATION TESTS",
            notes: [
                "Native runtime integration slice complete: MAP_JIT blocks use the sparse page-table ABI, demand-zero faults retry, Darwin SYSCALL exits dispatch through Swift, and imported host thunks return through the guest stack.",
                "This is a narrow bootstrap bridge only: supported imports are _read, _write, _getpid and _exit. Dyld startup, chained fixups, TLS, errno, broad syscalls, and framework ABI coverage remain outstanding."
            ],
            run: { try X64GuestVMNativeIntegrationSelfTests.run() }
        ),
        SelfTestSuite(
            id: "macho-loader",
            buttonTitle: "Mach-O loader tests",
            systemImage: "doc.text.magnifyingglass",
            passSummary: "x86_64 Mach-O parser/loader tests",
            failureLabel: "MACH-O LOADER TESTS",
            notes: [
                "Mach-O loader slice complete: thin/fat parsing, sparse image mapping, demand-zero BSS, classic rebases, regular/weak/lazy bind-action decoding, dependency metadata, export tries, and LC_RPATH discovery.",
                "The loader can apply bindings from explicit guest-address resolvers and the main image's ordinary exports. It does not recursively load dependent dylibs or the dyld shared cache; chained fixups and dyld startup remain unsupported."
            ],
            run: { try X64MachOLoaderSelfTests.run() }
        ),
        SelfTestSuite(
            id: "dyld-shared-cache",
            buttonTitle: "dyld shared-cache tests",
            systemImage: "externaldrive.badge.checkmark",
            passSummary: "x86_64 dyld shared-cache parser tests",
            failureLabel: "DYLD SHARED-CACHE TESTS",
            notes: [
                "Shared-cache inventory slice complete: x86_64 cache magic, VM mappings, image paths, Mach-O headers, exact dependency matching, and bounds validation.",
                "These tests inspect cache metadata only; they do not map cached dylib pages into guest memory or execute dyld."
            ],
            run: { try X64DyldSharedCacheSelfTests.run() }
        ),
        SelfTestSuite(
            id: "darwin-runtime",
            buttonTitle: "Darwin runtime tests",
            systemImage: "terminal",
            passSummary: "Darwin runtime and process-startup tests",
            failureLabel: "DARWIN RUNTIME TESTS",
            notes: ["Darwin runtime slice complete: initial argc/argv/envp/apple stack, entry-register setup, and a narrow syscall/host-I/O contract. This does not yet provide dyld startup, TLS, errno, or general libSystem compatibility."],
            run: { try X64DarwinRuntimeSelfTests.run() }
        )
    ]
}

enum SelfTestRunner {
    /// Runs one suite off the main actor so long native/JIT suites never block the UI.
    static func execute(_ suite: SelfTestSuite) async -> Result<[String], Error> {
        await Task.detached(priority: .userInitiated) { () -> Result<[String], Error> in
            do {
                return .success(try suite.run())
            } catch {
                return .failure(error)
            }
        }.value
    }

    /// Synchronous runner for `Kestrel --run-self-tests` (CI or terminal use).
    /// Returns the process exit status: 0 when every suite passes, otherwise 1.
    static func runAllHeadless() -> Int32 {
        var failedSuites = 0
        for suite in SelfTestSuite.all {
            do {
                let passed = try suite.run()
                print("PASS \(suite.id): \(passed.count) checks")
            } catch {
                failedSuites += 1
                print("FAIL \(suite.id): \(error.localizedDescription)")
            }
        }
        print(failedSuites == 0 ? "ALL SUITES PASSED" : "\(failedSuites) SUITE(S) FAILED")
        return failedSuites == 0 ? 0 : 1
    }
}

@MainActor
final class LauncherViewModel: ObservableObject {
    @Published var targetPath = ""
    @Published var architectureLabel = "No target selected"
    @Published var argumentsText = ""
    @Published var environmentText = ""
    @Published private(set) var output = LauncherViewModel.readyMessage
    @Published var isBusy = false
    @Published private(set) var hasRunningProcess = false
    @Published var canLoadX86MachOImage = false
    @Published var canPrepareGuestProcessStartup = false
    @Published private(set) var canLaunchX64Guest = false
    @Published private(set) var canLaunchX64GuestViaDyld = false
    @Published private(set) var canContinueX64GuestAfterDyld = false
    @Published var canMaterializeCachedDependencies = false
    @Published var canResolveCachedImports = false

    private static let readyMessage = "Kestrel is ready. Select a Mach-O executable or .app bundle."
    private static let maximumLogLines = 5_000

    private var logLines: [String] = [LauncherViewModel.readyMessage]
    
    /// Read-only line view for SwiftUI's LazyVStack. The underlying buffer is
    /// already bounded by maximumLogLines and remains the source for Copy.
    var displayedLogLines: [String] { logLines }
    private var target: TargetDescriptor?
    private var runningProcess: Process?
    private var loadedGuestMemory: X64GuestVirtualMemory?
    private var loadedMachOImage: X64MachOLoadedImage?
    private var parsedX64MachOImage: X64MachOImage?
    private var guestHostThunkTable: X64DarwinHostThunkTable?
    private var guestThunkResolver: X64MachOSymbolResolver?
    private var preparedStartupState: X64GuestProcessStartupState?
    private var inspectedDyldSharedCache: X64DyldSharedCacheSummary?
    private var plannedDyldSharedCacheMappings: X64DyldSharedCacheMappingPlan?
    private var cachedDyldEntry: X64DyldSharedCacheDylinkerEntry?
    private var cachedDependencyClosureIsComplete = false
    private var cachedDependenciesMaterialized = false
    private var postDyldCPUState: X64CPUState?

    func chooseTarget() {
        guard !isBusy else { return }
        let panel = NSOpenPanel()
        panel.title = "Choose a macOS application or executable"
        panel.prompt = "Select"
        panel.canChooseFiles = true
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        panel.resolvesAliases = true

        guard panel.runModal() == .OK, let url = panel.url else { return }
        inspectTarget(url)
    }

    func inspectTarget(_ url: URL) {
        guard !isBusy else { return }
        resetGuestState()
        targetPath = url.path
        do {
            let descriptor = try TargetInspector.inspect(url)
            target = descriptor
            canLoadX86MachOImage = descriptor.architectures.contains(.x86_64)
            architectureLabel = descriptor.architectureSummary
            append("Selected: \(url.lastPathComponent)")
            append("Executable: \(descriptor.executableURL.path)")
            append("Architectures: \(descriptor.architectureSummary)")
        } catch {
            target = nil
            architectureLabel = "Inspection failed"
            append("ERROR: \(error.localizedDescription)")
        }
    }

    /// Drops every piece of guest state derived from the current target and
    /// disables the actions that depend on it.
    private func resetGuestState() {
        canLoadX86MachOImage = false
        loadedGuestMemory = nil
        loadedMachOImage = nil
        parsedX64MachOImage = nil
        guestHostThunkTable = nil
        guestThunkResolver = nil
        preparedStartupState = nil
        inspectedDyldSharedCache = nil
        plannedDyldSharedCacheMappings = nil
        cachedDyldEntry = nil
        cachedDependencyClosureIsComplete = false
        cachedDependenciesMaterialized = false
        postDyldCPUState = nil
        canLaunchX64GuestViaDyld = false
        canContinueX64GuestAfterDyld = false
        canMaterializeCachedDependencies = false
        canResolveCachedImports = false
        canPrepareGuestProcessStartup = false
        canLaunchX64Guest = false
    }

    // MARK: Self-tests

    func runSelfTestSuite(_ suite: SelfTestSuite) {
        guard !isBusy else { return }
        isBusy = true
        Task {
            let outcome = await SelfTestRunner.execute(suite)
            report(outcome, for: suite)
            isBusy = false
        }
    }

    func runAllSelfTests() {
        guard !isBusy else { return }
        isBusy = true
        Task {
            append("Running \(SelfTestSuite.all.count) self-test suites…")
            var failedSuites: [String] = []
            var totalChecks = 0
            for suite in SelfTestSuite.all {
                let outcome = await SelfTestRunner.execute(suite)
                switch outcome {
                case .success(let passed): totalChecks += passed.count
                case .failure: failedSuites.append(suite.buttonTitle)
                }
                report(outcome, for: suite)
            }
            if failedSuites.isEmpty {
                append("ALL \(SelfTestSuite.all.count) SUITES PASSED (\(totalChecks) checks).")
            } else {
                append("\(failedSuites.count) SUITE(S) FAILED: \(failedSuites.joined(separator: ", ")). Checks passed in the other suites: \(totalChecks).")
            }
            isBusy = false
        }
    }

    private func report(_ outcome: Result<[String], Error>, for suite: SelfTestSuite) {
        switch outcome {
        case .success(let passed):
            append("PASS: \(suite.passSummary) (\(passed.count)).")
            for test in passed { append("  ✓ \(test)") }
            for note in suite.notes { append(note) }
        case .failure(let error):
            append("\(suite.failureLabel) FAILED: \(error.localizedDescription)")
        }
    }

    func runTranslationSelfTest() {
        guard !isBusy else { return }
        isBusy = true
        Task {
            do {
                let test = try await Task.detached(priority: .userInitiated) {
                    try KestrelRuntime.runSelfTest()
                }.value
                let hex = test.arm64Words.map { String(format: "%08X", $0) }.joined(separator: " ")
                append("PASS: x86_64 block translated to AArch64 and executed natively.")
                append("Test result: 42 + 8 = \(test.result)")
                append("Generated ARM64 words: \(hex)")
                append("This validates the tiny block translator only; it does not launch the selected x86_64 application.")
            } catch {
                append("SELF-TEST FAILED: \(error.localizedDescription)")
            }
            isBusy = false
        }
    }

    func prepareGuestProcessStartup() {
        guard !isBusy else { return }
        guard let target, let loadedMachOImage, var memory = loadedGuestMemory else {
            append("Load an x86_64 Mach-O image before preparing guest startup.")
            return
        }
        isBusy = true
        Task {
            do {
                // Repeated preparation replaces the previous guest stack rather
                // than leaking another multi-megabyte reservation each click.
                // `memory` is a working copy: the previous stack and state stay
                // intact unless the new stack is built successfully.
                if let previous = preparedStartupState {
                    try memory.release(at: previous.stackReservation.baseAddress)
                }
                let (mainHeaderAddress, headerOverflow) = loadedMachOImage.preferredLoadAddress.addingReportingOverflow(loadedMachOImage.slide)
                guard !headerOverflow else {
                    throw X64MachOFormatError(message: "The slid main Mach-O header address overflows.")
                }
                let startup = try X64GuestProcessStackBuilder.build(
                    entryPoint: loadedMachOImage.entryAddress,
                    mainMachHeaderAddress: mainHeaderAddress,
                    executablePath: target.executableURL.path,
                    arguments: parseArguments(argumentsText),
                    environment: parseEnvironment(environmentText),
                    into: &memory,
                    dyldPath: cachedDyldEntry?.installName
                )
                loadedGuestMemory = memory
                preparedStartupState = startup
                canPrepareGuestProcessStartup = true
                postDyldCPUState = nil
                canContinueX64GuestAfterDyld = false
                let dyldEntryIsExecutable = cachedDyldEntry.map {
                    memory.permissions(at: $0.entryPoint)?.contains(.execute) == true
                } ?? false
                let mainEntryIsExecutable = memory.permissions(at: loadedMachOImage.entryAddress)?.contains(.execute) == true
                canLaunchX64GuestViaDyld = cachedDependenciesMaterialized
                    && cachedDependencyClosureIsComplete
                    && dyldEntryIsExecutable
                    && mainEntryIsExecutable
                append("PASS: Darwin kernel-style KernelArgs stack prepared (not executed).")
                append(String(format: "Main mach_header: 0x%016llX; LC_MAIN after dyld: 0x%016llX; initial RSP: 0x%016llX; RSP mod 16: %llu", startup.mainMachHeaderAddress, startup.entryPoint, startup.stackPointer, startup.stackPointer % 16))
                append("argc: \(startup.argumentCount); argv: 0x\(String(startup.argvPointer, radix: 16)); envp: 0x\(String(startup.envpPointer, radix: 16)); apple: 0x\(String(startup.applePointer, radix: 16))")
                append("Stack reservation: \(startup.usableStackSize) usable bytes plus two guard pages.")
                if let dyld = cachedDyldEntry {
                    append(String(format: "dyld_path=%@; __dyld_start=0x%016llX; dyld mapped executable=%@", dyld.installName, dyld.entryPoint, dyldEntryIsExecutable ? "yes" : "no"))
                } else {
                    append("BLOCKED: no x86_64 MH_DYLINKER entry was found in the selected Rosetta cache; KernelArgs has no dyld_path.")
                }
                if canLaunchX64GuestViaDyld {
                    append("DYLD LAUNCH READY: recursive cache dependencies are materialized, the dyld entry is executable, and LC_MAIN is mapped. Kestrel will now let dyld handle the main executable's bind and chained-fixup metadata.")
                } else {
                    append("DYLD LAUNCH NOT READY: materialize a complete cache dependency closure and map the x86_64 dyld image before attempting __dyld_start.")
                }
            } catch {
                // The loaded image is still valid, so keep the other actions
                // enabled and let the user retry.
                append("GUEST STARTUP PREPARATION FAILED (previous guest state retained): \(error.localizedDescription)")
            }
            isBusy = false
        }
    }

    func loadSelectedX64MachOImage() {
        guard !isBusy else { return }
        guard let target else {
            append("Choose an x86_64 executable or .app bundle first.")
            return
        }
        guard target.architectures.contains(.x86_64) else {
            append("BLOCKED: selected target has no x86_64 slice.")
            return
        }

        isBusy = true
        let executableURL = target.executableURL
        Task {
            do {
                // Parsing, mapping and binding a large executable can take a
                // while; keep it off the SwiftUI main actor.
                let result = try await Task.detached(priority: .userInitiated) {
                    let fileData = try Data(contentsOf: executableURL, options: [.mappedIfSafe])
                    let image = try X64MachOParser.parse(
                        data: fileData,
                        sourceName: executableURL.lastPathComponent
                    )
                    var memory = try X64GuestVirtualMemory()
                    let (thunkTable, thunkResolver) = try X64DarwinHostThunkTable.install(into: &memory)
                    let loaded = try X64MachOLoader.load(
                        image,
                        into: &memory,
                        symbolResolver: thunkResolver
                    )
                    let dependencyPaths = X64MachODependencyPathResolver.resolveAll(in: image, executableURL: executableURL)
                    return (memory, loaded, image, thunkTable, thunkResolver, dependencyPaths)
                }.value
                let memory = result.0
                let loaded = result.1
                let image = result.2
                let thunkTable = result.3
                let thunkResolver = result.4

                resetGuestState()
                loadedGuestMemory = memory
                loadedMachOImage = loaded
                parsedX64MachOImage = image
                guestHostThunkTable = thunkTable
                guestThunkResolver = thunkResolver
                canLoadX86MachOImage = true
                canPrepareGuestProcessStartup = true
                canLaunchX64Guest = true

                append("PASS: x86_64 Mach-O image mapped; bind streams decoded and the supported guest C thunks installed.")
                append("Image: \(loaded.sourceName)")
                append(String(format: "Preferred image base: 0x%016llX", loaded.preferredLoadAddress))
                append(String(format: "LC_MAIN address: 0x%016llX", loaded.entryAddress))
                append(String(format: "Load slide: 0x%016llX; classic rebase locations parsed/applied: %d/%d", loaded.slide, loaded.rebaseFixupCount, loaded.rebasesApplied))
                append("Bind actions: regular=\(loaded.bindFixupCount), weak=\(loaded.weakBindFixupCount), lazy=\(loaded.lazyBindFixupCount); applied/zero-resolved=\(loaded.boundFixupCount); unresolved strong imports=\(loaded.unresolvedBindSymbols.count)")
                append("Raw bind opcode bytes: \(loaded.unresolvedBindOpcodeBytes); chained-fixup bytes: \(loaded.unresolvedChainedFixupsBytes); exported symbols: \(loaded.exports.count)")
                append("Installed guest C thunk stubs: \(thunkTable.supportedSymbols.joined(separator: ", "))")
                append("Dependencies discovered: \(loaded.dependencies.count)")
                for resolution in result.5 {
                    if let url = resolution.resolvedURL {
                        append("  \(resolution.dependency.installName) -> \(url.path)")
                    } else {
                        append("  \(resolution.dependency.installName) -> NOT FOUND ON DISK (shared cache not checked)")
                    }
                }
                if !loaded.unresolvedBindSymbols.isEmpty {
                    append("Unresolved import preview: \(loaded.unresolvedBindSymbols.prefix(18).joined(separator: ", "))")
                }
                append("Segments mapped: \(loaded.reservedSegmentCount); virtual bytes reserved: \(loaded.reservedVirtualBytes); file-backed host memory committed: \(loaded.committedBytes); demand-zero bytes reserved: \(loaded.demandZeroBytes) (\(loaded.demandZeroPageCount) pages)")
                for segment in loaded.mappedSegments {
                    append(String(format: "  %@: 0x%016llX + 0x%llX virtual; 0x%llX committed; 0x%llX demand-zero %@", segment.name, segment.guestAddress, segment.byteCount, segment.committedByteCount, segment.demandZeroByteCount, segment.permissions.description))
                }
                append("Image mapping and supported import binding are complete; this still does NOT execute LC_MAIN. Dependency paths are discovery only: their images and the dyld shared cache are not recursively loaded. Chained fixups, dyld initialization, TLS, errno, broad syscall and macOS framework ABI compatibility remain unsupported.")
            } catch {
                resetGuestState()
                canLoadX86MachOImage = true
                append("MACH-O LOAD FAILED: \(error.localizedDescription)")
            }
            isBusy = false
        }
    }

    func inspectX64DyldSharedCache() {
        guard !isBusy else { return }
        guard let loadedMachOImage else {
            append("Load the selected x86_64 Mach-O image before inspecting its dyld dependencies.")
            return
        }
        isBusy = true
        let dependencies = loadedMachOImage.dependencies
        Task {
            do {
                let inspection = try await Task.detached(priority: .userInitiated) {
                    let cache = try X64DyldSharedCacheReader.discoverDefault()
                    return (cache, cache.matchDependencies(dependencies))
                }.value
                let cache = inspection.0
                let matches = inspection.1
                let exactMatches = matches.compactMap(\.image)
                let x86Matches = exactMatches.filter(\.hasReadableX86_64Header)
                append("PASS: x86_64 dyld shared cache discovered and indexed.")
                append("Cache: \(cache.url.path)")
                append("Architecture: \(cache.magic); UUID: \(cache.uuid); platform: \(cache.platform)")
                append("Mappings: \(cache.mappings.count); cached image records: \(cache.images.count); validated x86_64 Mach-O headers: \(cache.x86_64ImageCount); subcaches: \(cache.subcachePaths.count)")
                append("Kyty dependencies present by exact install name: \(x86Matches.count)/\(matches.count)")
                for match in matches {
                    if let cached = match.image, cached.hasReadableX86_64Header {
                        append(String(format: "  CACHE  0x%016llX  %@", cached.machHeaderAddress, match.installName))
                    } else if match.image != nil {
                        append("  HEADER INVALID  \(match.installName)")
                    } else {
                        append("  NOT IN CACHE  \(match.installName)")
                    }
                }
                append("This is cache inventory only. Cached images are not mapped into guest memory yet; their cache slide/fixup metadata and image pages still need a dedicated mapping path.")
            } catch {
                append("DYLD SHARED-CACHE INSPECTION FAILED: \(error.localizedDescription)")
            }
            isBusy = false
        }
    }

    func planX64DyldSharedCacheMappings() {
        guard !isBusy else { return }
        guard let loadedMachOImage else {
            append("Load the selected x86_64 Mach-O image before planning cached dependency mappings.")
            return
        }
        isBusy = true
        plannedDyldSharedCacheMappings = nil
        cachedDyldEntry = nil
        cachedDependencyClosureIsComplete = false
        cachedDependenciesMaterialized = false
        canMaterializeCachedDependencies = false
        canLaunchX64GuestViaDyld = false
        canContinueX64GuestAfterDyld = false
        postDyldCPUState = nil
        let dependencies = loadedMachOImage.dependencies
        Task {
            do {
                let planned = try await Task.detached(priority: .userInitiated) {
                    let cache = try X64DyldSharedCacheReader.discoverDefault()
                    let dependencyClosure = try X64DyldSharedCacheDependencyClosurePlanner.select(
                        cache: cache,
                        roots: dependencies
                    )
                    let dyldEntry = try X64DyldSharedCacheDylinkerReader.find(in: cache)
                    var selectedInstallNames = dependencyClosure.installNames
                    if let dyldEntry, !selectedInstallNames.contains(dyldEntry.installName) {
                        selectedInstallNames.append(dyldEntry.installName)
                    }
                    let mappingDependencies = selectedInstallNames.enumerated().map { index, installName in
                        X64MachODylibDependency(
                            ordinal: index + 1,
                            installName: installName,
                            timestamp: 0,
                            currentVersion: 0,
                            compatibilityVersion: 0,
                            kind: .load
                        )
                    }
                    let plan = try X64DyldSharedCacheImageMapper.makePlan(
                        cache: cache,
                        dependencies: mappingDependencies,
                        additionalImages: dyldEntry.map { [$0.imageRecord] } ?? []
                    )
                    return (cache, plan, dependencyClosure, dyldEntry)
                }.value
                let cache = planned.0
                let plan = planned.1
                let dependencyClosure = planned.2
                let dyldEntry = planned.3
                inspectedDyldSharedCache = cache
                cachedDyldEntry = dyldEntry
                cachedDependencyClosureIsComplete = dependencyClosure.isComplete
                plannedDyldSharedCacheMappings = plan
                // Cache pages are registered as sparse lazy-backed ranges.
                // The planner's aggregate virtual-size limit remains in force;
                // no host backing is allocated until guest code touches a page.
                canMaterializeCachedDependencies = dependencyClosure.isComplete
                canLaunchX64GuestViaDyld = false
                append("PASS: recursive shared-cache dependency closure and mapping preflight completed.")
                append("Cache UUID: \(plan.cacheUUID); images selected: \(plan.images.count); direct dependencies: \(dependencyClosure.rootImageCount); transitive dependencies: \(dependencyClosure.transitiveImageCount); dyld image: \(dyldEntry == nil ? "missing" : "included")")
                if let dyldEntry {
                    append(String(format: "DYLD IMAGE: %@; mach_header=0x%016llX; __dyld_start=0x%016llX", dyldEntry.installName, dyldEntry.machHeaderAddress, dyldEntry.entryPoint))
                } else {
                    append("BLOCKED: no x86_64 MH_DYLINKER was found in this Rosetta shared cache; dependencies can still be inspected, but normal guest startup cannot begin.")
                }
                append("Dependency metadata parsed: \(dependencyClosure.parsedExportCount) exports from \(dependencyClosure.exportTrieBytes) bytes of export tries.")
                if dependencyClosure.truncated {
                    append("BLOCKED: recursive dependency closure reached its safety limit (1,024 mapped images or 8,192 queued names); the mapped set is incomplete.")
                }
                if !dependencyClosure.missingRequiredInstallNames.isEmpty {
                    append("BLOCKED: required dependencies absent from the x86_64 cache: \(dependencyClosure.missingRequiredInstallNames.prefix(16).joined(separator: ", "))")
                }
                if !dependencyClosure.missingWeakInstallNames.isEmpty {
                    append("Optional weak dependencies absent from this cache: \(dependencyClosure.missingWeakInstallNames.prefix(16).joined(separator: ", "))")
                }
                append("Cache VM mappings available: \(plan.reservedMappingCount); segment commands validated: \(plan.totalSegmentCount)")
                append("Executable segments inventoried: \(plan.executableSegmentCount); __LINKEDIT segments: \(plan.linkeditSegmentCount)")
                append("Exact guest segment bytes: \(plan.totalVirtualBytes); page-rounded reservation bytes: \(plan.totalPageRoundedReservationBytes) (virtual reservation only; no host pages allocated)")
                let plannedPages = plan.totalPageRoundedReservationBytes / X64GuestVirtualMemoryConstants.pageSize
                let plannedGiB = Double(plan.totalPageRoundedReservationBytes) / 1_073_741_824.0
                append(String(format: "LAZY MATERIALIZATION PLAN: %llu guest pages; %.2f GiB of guest virtual coverage; host pages are allocated only on first permitted access.", plannedPages, plannedGiB))
                let slidePages = plan.slideInfoSummaries.reduce(UInt64(0)) { $0 + $1.pageCount }
                let rebasedPages = plan.slideInfoSummaries.reduce(UInt64(0)) { $0 + $1.pagesWithRebases }
                let slideChains = plan.slideInfoSummaries.reduce(UInt64(0)) { $0 + $1.chainCount }
                let slidePointers = plan.slideInfoSummaries.reduce(UInt64(0)) { $0 + $1.rebasingPointerCount }
                let slideVersions = Dictionary(grouping: plan.slideInfoSummaries, by: \.version)
                    .map { "v\($0.key)=\($0.value.count)" }.sorted().joined(separator: ", ")
                append("Slide-info mappings validated: \(plan.slideInfoSummaries.count) (\(slideVersions.isEmpty ? "none" : slideVersions)); pages scanned: \(slidePages); pages with rebases: \(rebasedPages); chains: \(slideChains); pointer fixups inventoried: \(slidePointers)")
                for slideInfo in plan.slideInfoSummaries.prefix(8) {
                    append(String(format: "  SLIDE v%u mapping 0x%016llX + 0x%llX; page size %u; pages %llu; rebased pages %llu; chains %llu; pointers %llu", slideInfo.version, slideInfo.mappingAddress, slideInfo.mappingSize, slideInfo.pageSize, slideInfo.pageCount, slideInfo.pagesWithRebases, slideInfo.chainCount, slideInfo.rebasingPointerCount))
                }
                for image in plan.images {
                    append(String(format: "  IMAGE 0x%016llX %@ (%d segments)", image.machHeaderAddress, image.installName, image.segmentPlans.count))
                    for segment in image.segmentPlans {
                        append(String(format: "    %@ exact 0x%016llX + 0x%llX; guest pages 0x%016llX + 0x%llX; segment prot max=0x%X init=0x%X", segment.name, segment.virtualAddress, segment.virtualSize, segment.pageRoundedAddress, segment.pageRoundedSize, segment.maximumProtection, segment.initialProtection))
                    }
                }
                if dependencyClosure.isComplete {
                    append("PREFLIGHT COMPLETE: all discovered required cache-backed dependencies have validated segment mappings, including ordinary transitive LC_LOAD_DYLIB edges. The next action registers sparse cache-backed guest ranges; each 4 KiB page is copied and slide-info v2 fixed up on first permitted guest access.")
                    if dyldEntry != nil { append("The __dyld_start image is included in the same guest mapping transaction.") }
                } else {
                    append("PREFLIGHT INCOMPLETE: do not materialize this partial closure as a launchable process. Resolve the missing or truncated dependency set first.")
                }
            } catch {
                append("DYLD CACHE MAPPING PREFLIGHT FAILED: \(error.localizedDescription)")
            }
            isBusy = false
        }
    }

    func materializeX64DyldSharedCacheDependencies() {
        guard !isBusy else { return }
        guard let cache = inspectedDyldSharedCache,
              let plan = plannedDyldSharedCacheMappings,
              let originalMemory = loadedGuestMemory else {
            append("Analyze the recursive dependency closure and dyld mapping plan successfully before materializing them.")
            return
        }

        isBusy = true
        Task {
            do {
                // Registration is metadata-only, but run the cache validation
                // and provider setup away from the SwiftUI main actor.
                let result = try await Task.detached(priority: .userInitiated) {
                    var workingMemory = originalMemory
                    let summary = try X64DyldSharedCacheMaterializer.materialize(
                        cache: cache,
                        plan: plan,
                        into: &workingMemory,
                        cacheSlideAmount: 0
                    )
                    return (workingMemory, summary)
                }.value

                loadedGuestMemory = result.0
                // Keep the cache file mapping and executable metadata available
                // for the next stage: reading cached export tries and binding imports.
                plannedDyldSharedCacheMappings = nil
                canMaterializeCachedDependencies = false
                canResolveCachedImports = true
                append("PASS: recursive cache page ranges registered for lazy guest page-in.")
                append("Cache UUID: \(result.1.cacheUUID); images: \(result.1.imageCount); guest pages available: \(result.1.pageCount); guest virtual bytes: \(result.1.byteCount)")
                append("Guest regions reserved: \(result.1.reservedRegionCount); lazy ranges: \(result.1.lazyRangeCount); slide-info mappings: \(result.1.slideInfoMappingCount); cache slide: 0x\(String(result.1.cacheSlideAmount, radix: 16))")
                cachedDependenciesMaterialized = true
                canLaunchX64GuestViaDyld = false
                append("No cache pages were eagerly allocated. On first guest access, Kestrel loads one 4 KiB page, applies its slide-info v2 fixups to a private copy, and commits it with the cache mapping's initial protections (including RX text and read-only linkedit). The source cache remains unchanged. The lazy mapped set includes the complete discovered recursive dependency closure and the x86_64 dyld image when present. Prepare KernelArgs with dyld_path next; then Kestrel can attempt __dyld_start.")
            } catch {
                append("DYLD CACHE MATERIALIZATION FAILED (guest-memory transaction rolled back): \(error.localizedDescription)")
            }
            isBusy = false
        }
    }

    func resolveX64MachOImportsFromCache() {
        guard !isBusy else { return }
        guard let cache = inspectedDyldSharedCache,
              let executable = parsedX64MachOImage,
              let previousImage = loadedMachOImage,
              let originalMemory = loadedGuestMemory,
              let thunkResolver = guestThunkResolver else {
            append("Load the x86_64 image, inspect and materialize its cached dependencies before resolving imports.")
            return
        }

        let previousStackBase = preparedStartupState?.stackReservation.baseAddress
        isBusy = true
        Task {
            do {
                // Resolve from a snapshot of the materialized guest address
                // space, then rebuild the main image in a staged copy. A
                // failed export parse or bind cannot leave a half-rebound VM.
                let result = try await Task.detached(priority: .userInitiated) {
                    let resolution = try X64DyldSharedCacheImportResolver.build(
                        cache: cache,
                        executable: executable,
                        guestMemory: originalMemory,
                        baseResolver: thunkResolver
                    )
                    var stagedMemory = originalMemory
                    if let previousStackBase {
                        try stagedMemory.release(at: previousStackBase)
                    }
                    try X64MachOLoader.unload(previousImage, from: &stagedMemory)
                    let reboundImage = try X64MachOLoader.load(
                        executable,
                        into: &stagedMemory,
                        symbolResolver: resolution.resolver
                    )
                    return (stagedMemory, reboundImage, resolution)
                }.value

                loadedGuestMemory = result.0
                loadedMachOImage = result.1
                preparedStartupState = nil
                canPrepareGuestProcessStartup = true
                canLaunchX64GuestViaDyld = false
                canContinueX64GuestAfterDyld = false
                postDyldCPUState = nil
                canResolveCachedImports = false
                append("PASS: cached dylib export metadata parsed; supported dependency-qualified bind fixups applied.")
                append("Cached images examined: \(result.2.examinedImageCount); dependency closure images: \(result.2.dependencyClosureImageCount); export symbols parsed: \(result.2.parsedExportCount); export trie bytes: \(result.2.exportTrieBytes)")
                if result.2.dependencyClosureTruncated {
                    append("WARNING: dependency closure stopped at Kestrel's 1,024-image safety limit; flat/weak lookup results may be incomplete.")
                }
                if !result.2.missingDependencyPaths.isEmpty {
                    append("Dependencies absent from this cache: \(result.2.missingDependencyPaths.prefix(12).joined(separator: ", "))")
                }
                append("Main-image imports resolved from cache: \(result.2.resolvedImportCount); lazy resolver pointer slots prebound: \(result.2.lazyResolverResolvedImportCount); flat lookup: \(result.2.flatLookupResolvedCount); weak lookup: \(result.2.weakLookupResolvedCount); unique unresolved cache imports: \(result.2.unresolvedImportCount)")
                for dependency in result.2.unresolvedByDependency.keys.sorted(by: {
                    let left = result.2.unresolvedByDependency[$0] ?? 0
                    let right = result.2.unresolvedByDependency[$1] ?? 0
                    return left == right ? $0 < $1 : left > right
                }).prefix(12) {
                    append("  Unresolved under \(dependency): \(result.2.unresolvedByDependency[dependency] ?? 0) unique symbols")
                }
                if !result.2.ambiguousFlatLookupSymbols.isEmpty {
                    append("Ambiguous flat-lookup providers (left unresolved): \(result.2.ambiguousFlatLookupSymbols.prefix(12).joined(separator: ", "))")
                }
                if !result.2.ambiguousWeakLookupSymbols.isEmpty {
                    append("Ambiguous weak-lookup providers (left unresolved): \(result.2.ambiguousWeakLookupSymbols.prefix(12).joined(separator: ", "))")
                }
                for dependency in result.2.resolvedByDependency.keys.sorted() {
                    append("  \(dependency): \(result.2.resolvedByDependency[dependency] ?? 0) import bindings")
                }
                let totalBindSlots = result.1.bindFixupCount + result.1.weakBindFixupCount + result.1.lazyBindFixupCount
                append("Main-image bind actions: regular=\(result.1.bindFixupCount), weak=\(result.1.weakBindFixupCount), lazy=\(result.1.lazyBindFixupCount); total slots=\(totalBindSlots); fixups applied=\(result.1.boundFixupCount); unresolved slots=\(result.1.unresolvedBindFixupCount); unique unresolved symbols=\(result.1.unresolvedBindSymbols.count)")
                if !result.1.unresolvedBindSymbols.isEmpty {
                    append("Unresolved import preview: \(result.1.unresolvedBindSymbols.prefix(24).joined(separator: ", "))")
                }
                if !result.2.lazyResolverProbeResults.isEmpty {
                    append("ISOLATED LAZY-RESOLVER PROBES: \(result.2.lazyResolverProbeResults.count) unique resolver(s); existing writable pages protected: \(result.2.lazyResolverProtectedPageCount); one reusable snapshot with shared pages write-protected and a private writable stack; syscalls and host thunks disabled.")
                    for probe in result.2.lazyResolverProbeResults {
                        let detail = probe.detail.map { "; \($0)" } ?? ""
                        append(String(
                            format: "  RESOLVER PROBE 0x%016llX: %@; instructions=%d; blocks=%d%@",
                            probe.resolverAddress,
                            probe.status.rawValue,
                            probe.instructionsExecuted,
                            probe.blocksExecuted,
                            detail
                        ))
                        if let returned = probe.returnedAddress {
                            let executable = probe.returnedAddressIsMappedExecutable == true ? "yes" : "no"
                            append(String(format: "    returned RAX: 0x%016llX; mapped executable: %@", returned, executable))
                        }
                    }
                    append("Only successful two-level lazy probes whose RAX points to mapped executable guest memory are used to prebind the staged image. This is eager setup, not first-call lazy rebinding; resolver side effects, TLS and broader dyld initialization remain unsupported.")
                }
                for diagnostic in result.2.unresolvedBindingDiagnostics.prefix(24) {
                    let dependency = diagnostic.dependencyInstallName ?? "special ordinal"
                    let weak = diagnostic.isWeakImport ? "; weak-import flag" : ""
                    append("  UNRESOLVED: \(diagnostic.symbolName); ordinal=\(diagnostic.libraryOrdinal); provider=\(dependency); stream=\(diagnostic.stream)\(weak)")
                    for route in diagnostic.candidateRoutes.prefix(2) {
                        append("    candidate path (diagnostic only): \(route)")
                    }
                    append("    binding blocker: \(diagnostic.resolutionBlocker.explanation)")
                    if let provider = diagnostic.candidateExportProviderInstallName {
                        let flags = diagnostic.candidateExportFlags.map { String(format: "0x%llX", $0) } ?? "unknown"
                        append("    exact export provider: \(provider); flags=\(flags)")
                    }
                    if let stub = diagnostic.candidateStubAddress {
                        append(String(format: "    export stub guest address: 0x%016llX", stub))
                    }
                    if let resolver = diagnostic.candidateResolverAddress {
                        let executable = diagnostic.candidateResolverIsExecutable == true ? "yes" : "no"
                        append(String(format: "    export resolver guest address: 0x%016llX; mapped executable: %@", resolver, executable))
                    }
                }
                append("The main image was reloaded transactionally against guest addresses from materialized cache pages. This diagnostic prebinding pass is optional for the dyld launch path: dyld is expected to process the main executable bind and chained-fixup commands itself. TLS/errno and the broader Darwin process ABI remain incomplete.")
            } catch {
                append("CACHED IMPORT RESOLUTION FAILED (original guest memory and image retained): \(error.localizedDescription)")
            }
            isBusy = false
        }
    }

    func launchSelectedX64Guest() {
        guard !isBusy else { return }
        guard let target,
              let image = parsedX64MachOImage,
              let loadedImage = loadedMachOImage,
              let originalMemory = loadedGuestMemory else {
            append("Load an x86_64 Mach-O image before launching the guest.")
            return
        }

        let previousStackBase = preparedStartupState?.stackReservation.baseAddress
        let executablePath = target.executableURL.path
        let arguments = parseArguments(argumentsText)
        let environment = ProcessInfo.processInfo.environment.merging(parseEnvironment(environmentText)) { _, new in new }
        let hostThunks = guestHostThunkTable
        isBusy = true

        Task {
            do {
                let result = try await Task.detached(priority: .userInitiated) {
                    var memory = originalMemory
                    if let previousStackBase {
                        try memory.release(at: previousStackBase)
                    }
                    let (mainHeaderAddress, overflow) = loadedImage.preferredLoadAddress.addingReportingOverflow(loadedImage.slide)
                    guard !overflow else {
                        throw X64MachOFormatError(message: "The slid main Mach-O header address overflows.")
                    }
                    let startup = try X64GuestProcessStackBuilder.build(
                        entryPoint: loadedImage.entryAddress,
                        mainMachHeaderAddress: mainHeaderAddress,
                        executablePath: executablePath,
                        arguments: arguments,
                        environment: environment,
                        into: &memory
                    )
                    let execution = try X64GuestDirectMainLauncher.launch(
                        image: image,
                        loadedImage: loadedImage,
                        startup: startup,
                        memory: &memory,
                        hostThunks: hostThunks
                    )
                    return (memory, startup, execution)
                }.value

                loadedGuestMemory = result.0
                preparedStartupState = result.1
                append("GUEST EXECUTION STARTED: direct-main mode bypasses dyld.")
                append(String(format: "LC_MAIN=0x%016llX; RSP=0x%016llX; argc=%d; instructions=%d; blocks=%d",
                              result.1.entryPoint,
                              result.1.stackPointer - 8,
                              result.1.argumentCount,
                              result.2.report.instructionsExecuted,
                              result.2.report.blocksExecuted))
                switch result.2.report.exit {
                case .halted:
                    append("GUEST MAIN RETURNED: exit status \(result.2.exitStatus ?? 0).")
                case .processExit:
                    append("GUEST PROCESS EXIT: status \(result.2.exitStatus ?? -1).")
                case .memoryFault(let rip):
                    append(String(format: "GUEST MEMORY/EXECUTE FAULT at instruction RIP 0x%016llX.", rip))
                }
                append("Translation cache: hits=\(result.2.report.cache.hits), misses=\(result.2.report.cache.misses), compiled=\(result.2.report.cache.compilations).")
                append("This is a freestanding direct-main prototype. It does not run dyld initializers, load dependent libraries, or provide libc/framework compatibility.")
            } catch {
                append("GUEST LAUNCH BLOCKED/FAILED: \(error.localizedDescription)")
            }
            isBusy = false
        }
    }


    func launchSelectedX64GuestViaDyld() {
        guard !isBusy else { return }
        guard let dyld = cachedDyldEntry,
              let loadedImage = loadedMachOImage,
              let startup = preparedStartupState,
              let originalMemory = loadedGuestMemory else {
            append("Prepare the recursive cache mapping and KernelArgs stack before starting x86_64 dyld.")
            return
        }
        guard canLaunchX64GuestViaDyld else {
            append("BLOCKED: the recursive dependency closure, materialized dyld image, or executable entry permissions are not ready.")
            return
        }

        let hostThunks = guestHostThunkTable
        isBusy = true
        Task {
            do {
                let result = try await Task.detached(priority: .userInitiated) {
                    var memory = originalMemory
                    let execution = try X64GuestDyldLauncher.launch(
                        dyld: dyld,
                        loadedImage: loadedImage,
                        startup: startup,
                        memory: &memory,
                        hostThunks: hostThunks
                    )
                    return (memory, execution)
                }.value

                loadedGuestMemory = result.0
                canLaunchX64GuestViaDyld = false
                if result.1.reachedMainEntry {
                    postDyldCPUState = result.1.finalState
                    canContinueX64GuestAfterDyld = true
                    append("DYLD HANDOFF COMPLETE: __dyld_start executed and reached the main executable's LC_MAIN entrypoint.")
                    append(String(format: "dyld entry=0x%016llX; LC_MAIN=0x%016llX; RSP=0x%016llX; instructions=%d; blocks=%d",
                                  dyld.entryPoint,
                                  result.1.mainEntryPoint,
                                  result.1.finalState.registerValue(.rsp),
                                  result.1.report.instructionsExecuted,
                                  result.1.report.blocksExecuted))
                    append("The next action continues execution inside the actual x86_64 program. This is the first non-direct-main launch path.")
                } else {
                    postDyldCPUState = nil
                    canContinueX64GuestAfterDyld = false
                    switch result.1.report.exit {
                    case .processExit(let status):
                        append("DYLD EXITED BEFORE LC_MAIN: status \(status).")
                    case .memoryFault(let address):
                        append(String(format: "DYLD MEMORY/EXECUTE FAULT before LC_MAIN at guest RIP 0x%016llX.", address))
                    case .halted:
                        append("DYLD stopped without a matching main-entry handoff.")
                    }
                    append(String(format: "dyld instructions=%d; blocks=%d; final RIP=0x%016llX",
                                  result.1.report.instructionsExecuted,
                                  result.1.report.blocksExecuted,
                                  result.1.report.finalRIP))
                }
                append("Translation cache: hits=\(result.1.report.cache.hits), misses=\(result.1.report.cache.misses), compiled=\(result.1.report.cache.compilations).")
            } catch {
                canContinueX64GuestAfterDyld = false
                postDyldCPUState = nil
                append("DYLD STARTUP STOPPED: \(error.localizedDescription)")
            }
            isBusy = false
        }
    }

    func continueSelectedX64GuestAfterDyld() {
        guard !isBusy else { return }
        guard canContinueX64GuestAfterDyld,
              let state = postDyldCPUState,
              let loadedImage = loadedMachOImage,
              let startup = preparedStartupState,
              let originalMemory = loadedGuestMemory else {
            append("Run x86_64 dyld successfully to the LC_MAIN handoff before continuing into the program.")
            return
        }
        let hostThunks = guestHostThunkTable
        let initialState = state
        isBusy = true
        Task {
            do {
                let result = try await Task.detached(priority: .userInitiated) {
                    var memory = originalMemory
                    var guestState = initialState
                    let report = try X64GuestDyldLauncher.continueFromMain(
                        state: &guestState,
                        loadedImage: loadedImage,
                        startup: startup,
                        memory: &memory,
                        hostThunks: hostThunks
                    )
                    return (memory, guestState, report)
                }.value
                loadedGuestMemory = result.0
                postDyldCPUState = result.1
                canContinueX64GuestAfterDyld = false
                switch result.2.exit {
                case .processExit(let status):
                    append("GUEST PROCESS EXIT: status \(status).")
                case .memoryFault(let address):
                    append(String(format: "GUEST MEMORY/EXECUTE FAULT at instruction RIP 0x%016llX.", address))
                case .halted:
                    append("GUEST EXECUTION HALTED at the guarded return boundary.")
                }
                append("Program instructions=\(result.2.instructionsExecuted); blocks=\(result.2.blocksExecuted); final RIP=0x\(String(result.2.finalRIP, radix: 16)).")
                append("Translation cache: hits=\(result.2.cache.hits), misses=\(result.2.cache.misses), compiled=\(result.2.cache.compilations).")
            } catch {
                canContinueX64GuestAfterDyld = false
                append("GUEST EXECUTION STOPPED: \(error.localizedDescription)")
            }
            isBusy = false
        }
    }

    func launchSelectedTarget() {
        guard !isBusy else { return }
        guard let target else {
            append("Choose a target first.")
            return
        }

        guard target.canRunNativelyOnAppleSilicon else {
            append("BLOCKED: this target has no ARM64 slice.")
            append("Intel-only targets can be mapped into guest memory for inspection, but execution and macOS process startup are not implemented yet.")
            append("Kestrel will not silently fall back to Rosetta.")
            return
        }

        let args = parseArguments(argumentsText)
        let environment = parseEnvironment(environmentText)
        append("Launching native ARM64 target with \(args.count) argument(s).")

        if target.isApplicationBundle {
            let configuration = NSWorkspace.OpenConfiguration()
            configuration.arguments = args
            configuration.environment = environment
            configuration.createsNewApplicationInstance = true
            configuration.activates = true

            isBusy = true
            NSWorkspace.shared.openApplication(at: target.selectedURL, configuration: configuration) { [weak self] app, error in
                Task { @MainActor in
                    self?.isBusy = false
                    if let error {
                        self?.append("Launch failed: \(error.localizedDescription)")
                    } else {
                        self?.append("Launched: \(app?.localizedName ?? target.selectedURL.lastPathComponent)")
                    }
                }
            }
        } else {
            let process = Process()
            process.executableURL = target.executableURL
            process.arguments = args
            process.environment = ProcessInfo.processInfo.environment.merging(environment) { _, new in new }
            process.terminationHandler = { [weak self] process in
                Task { @MainActor in
                    self?.append("Process exited with status \(process.terminationStatus).")
                    self?.runningProcess = nil
                    self?.hasRunningProcess = false
                    self?.isBusy = false
                }
            }

            do {
                try process.run()
                runningProcess = process
                hasRunningProcess = true
                isBusy = true
                append("Started PID \(process.processIdentifier).")
            } catch {
                append("Launch failed: \(error.localizedDescription)")
            }
        }
    }

    private func parseArguments(_ text: String) -> [String] {
        // One argument per line. No shell expansion or quote interpretation.
        text.split(whereSeparator: \.isNewline).map(String.init)
    }

    private func parseEnvironment(_ text: String) -> [String: String] {
        var result: [String: String] = [:]
        for line in text.split(whereSeparator: \.isNewline) {
            guard let separator = line.firstIndex(of: "=") else { continue }
            let key = line[..<separator].trimmingCharacters(in: .whitespaces)
            let value = String(line[line.index(after: separator)...])
            guard !key.isEmpty else { continue }
            result[key] = value
        }
        return result
    }

    private func append(_ line: String) {
        logLines.append(line)
        if logLines.count > LauncherViewModel.maximumLogLines {
            // Keep the log (and the SwiftUI text view that renders it) bounded.
            logLines.removeFirst(logLines.count - LauncherViewModel.maximumLogLines)
        }
        output = logLines.joined(separator: "\n")
    }

    func clearLog() {
        logLines = []
        output = ""
    }

    func copyLogToPasteboard() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(output, forType: .string)
    }

    func stopRunningProcess() {
        guard let process = runningProcess, process.isRunning else { return }
        append("Terminating PID \(process.processIdentifier)…")
        process.terminate()
    }
}
