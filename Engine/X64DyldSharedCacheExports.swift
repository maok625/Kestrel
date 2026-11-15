import Foundation

// MARK: - Cached Mach-O export metadata

struct X64CachedImageSegmentMetadata: Sendable, Equatable {
    let name: String
    let virtualAddress: UInt64
    let virtualSize: UInt64
    let fileOffset: UInt64
    let fileSize: UInt64

    var virtualEnd: UInt64 { virtualAddress &+ virtualSize }
    var fileEnd: UInt64 { fileOffset &+ fileSize }
}

struct X64CachedImageMetadata: Sendable {
    let image: X64DyldSharedCacheImageRecord
    let segments: [X64CachedImageSegmentMetadata]
    let dependencies: [X64MachODylibDependency]
    let exports: [X64MachOExport]
    let exportsByName: [String: X64MachOExport]
    let exportTrieByteCount: Int

    init(
        image: X64DyldSharedCacheImageRecord,
        segments: [X64CachedImageSegmentMetadata],
        dependencies: [X64MachODylibDependency],
        exports: [X64MachOExport],
        exportTrieByteCount: Int
    ) {
        self.image = image
        self.segments = segments
        self.dependencies = dependencies
        self.exports = exports
        self.exportsByName = Dictionary(exports.map { ($0.symbolName, $0) }, uniquingKeysWith: { first, _ in first })
        self.exportTrieByteCount = exportTrieByteCount
    }
}

/// Reads an individual cached image's own Mach-O commands and its export trie.
/// The export trie dataoff is translated through that image's __LINKEDIT
/// segment, then read using the cache VM mapping table (including subcaches).
enum X64DyldSharedCacheImageMetadataReader {
    private static let machMagic64: UInt32 = 0xFEED_FACF
    private static let cpuTypeX86_64: UInt32 = X64DyldSharedCacheReader.cpuTypeX86_64
    private static let fileTypeDylib: UInt32 = 0x6
    private static let lcSegment64: UInt32 = 0x19
    private static let lcDyldInfo: UInt32 = 0x22
    private static let lcDyldInfoOnly: UInt32 = 0x8000_0022
    private static let lcDyldExportsTrie: UInt32 = 0x8000_0033
    private static let lcLoadDylib: UInt32 = 0x0C
    private static let lcLoadWeakDylib: UInt32 = 0x8000_0018
    private static let lcReexportDylib: UInt32 = 0x8000_001F
    private static let lcLoadUpwardDylib: UInt32 = 0x8000_0023
    private static let lcLazyLoadDylib: UInt32 = 0x20
    private static let headerSize = 32
    private static let segmentCommandSize = 72
    private static let maximumCommands: UInt32 = 65_536
    private static let maximumCommandBytes: UInt32 = 16 * 1024 * 1024
    private static let maximumExportTrieBytes = 64 * 1024 * 1024

    static func read(
        cache: X64DyldSharedCacheSummary,
        image: X64DyldSharedCacheImageRecord
    ) throws -> X64CachedImageMetadata {
        guard image.hasReadableX86_64Header else {
            throw X64DyldSharedCacheError.malformed("Cached image \(image.installName) is not a readable x86_64 Mach-O image.")
        }
        let header = try cache.readVMBytes(atVMAddress: image.machHeaderAddress, count: headerSize)
        guard readLE32(header, 0) == machMagic64,
              readLE32(header, 4) == cpuTypeX86_64,
              readLE32(header, 12) == fileTypeDylib else {
            throw X64DyldSharedCacheError.malformed("Cached image \(image.installName) has an invalid x86_64 MH_DYLIB header.")
        }
        let commandCount = readLE32(header, 16)
        let commandBytes = readLE32(header, 20)
        guard commandCount <= maximumCommands, commandBytes <= maximumCommandBytes else {
            throw X64DyldSharedCacheError.malformed("Cached image \(image.installName) has unreasonable Mach-O load-command dimensions.")
        }
        let (totalBytes, totalOverflow) = UInt64(headerSize).addingReportingOverflow(UInt64(commandBytes))
        guard !totalOverflow, totalBytes <= UInt64(Int.max) else {
            throw X64DyldSharedCacheError.malformed("Cached image \(image.installName) load-command size overflows.")
        }
        let commandData = try cache.readVMBytes(atVMAddress: image.machHeaderAddress, count: Int(totalBytes))
        let commandEnd = headerSize + Int(commandBytes)
        var cursor = headerSize
        var segments: [X64CachedImageSegmentMetadata] = []
        var dependencies: [X64MachODylibDependency] = []
        var legacyExportRange: (offset: UInt32, size: UInt32)?
        var dedicatedExportRange: (offset: UInt32, size: UInt32)?

        for commandIndex in 0..<Int(commandCount) {
            guard cursor <= commandEnd - 8 else {
                throw X64DyldSharedCacheError.malformed("Cached image \(image.installName) load command \(commandIndex) is truncated.")
            }
            let command = readLE32(commandData, cursor)
            let commandSize = readLE32(commandData, cursor + 4)
            guard commandSize >= 8, UInt64(commandSize) <= UInt64(commandEnd - cursor) else {
                throw X64DyldSharedCacheError.malformed("Cached image \(image.installName) load command \(commandIndex) has an invalid size.")
            }

            switch command {
            case lcSegment64:
                guard commandSize >= segmentCommandSize else {
                    throw X64DyldSharedCacheError.malformed("Cached image \(image.installName) contains a truncated LC_SEGMENT_64 command.")
                }
                let sectionCount = readLE32(commandData, cursor + 64)
                let (sectionBytes, sectionOverflow) = UInt64(sectionCount).multipliedReportingOverflow(by: 80)
                let (minimumSize, commandOverflow) = UInt64(segmentCommandSize).addingReportingOverflow(sectionBytes)
                guard !sectionOverflow, !commandOverflow, minimumSize <= UInt64(commandSize) else {
                    throw X64DyldSharedCacheError.malformed("Cached image \(image.installName) LC_SEGMENT_64 section table exceeds its command size.")
                }
                let nameData = commandData[(cursor + 8)..<(cursor + 24)]
                let name = String(decoding: nameData.prefix { $0 != 0 }, as: UTF8.self)
                let vmAddress = readLE64(commandData, cursor + 24)
                let vmSize = readLE64(commandData, cursor + 32)
                let fileOffset = readLE64(commandData, cursor + 40)
                let fileSize = readLE64(commandData, cursor + 48)
                let (_, vmOverflow) = vmAddress.addingReportingOverflow(vmSize)
                let (_, fileOverflow) = fileOffset.addingReportingOverflow(fileSize)
                guard !vmOverflow, !fileOverflow, fileSize <= vmSize else {
                    throw X64DyldSharedCacheError.malformed("Cached image \(image.installName) segment \(name) has an overflowing or inconsistent range.")
                }
                if vmSize > 0 {
                    segments.append(X64CachedImageSegmentMetadata(
                        name: name,
                        virtualAddress: vmAddress,
                        virtualSize: vmSize,
                        fileOffset: fileOffset,
                        fileSize: fileSize
                    ))
                }

            case lcDyldInfo, lcDyldInfoOnly:
                guard commandSize >= 48 else {
                    throw X64DyldSharedCacheError.malformed("Cached image \(image.installName) has a truncated LC_DYLD_INFO command.")
                }
                let offset = readLE32(commandData, cursor + 40)
                let size = readLE32(commandData, cursor + 44)
                if size > 0 { legacyExportRange = (offset, size) }

            case lcDyldExportsTrie:
                guard commandSize >= 16 else {
                    throw X64DyldSharedCacheError.malformed("Cached image \(image.installName) has a truncated LC_DYLD_EXPORTS_TRIE command.")
                }
                let offset = readLE32(commandData, cursor + 8)
                let size = readLE32(commandData, cursor + 12)
                if size > 0 { dedicatedExportRange = (offset, size) }

            case lcLoadDylib, lcLoadWeakDylib, lcReexportDylib, lcLoadUpwardDylib, lcLazyLoadDylib:
                guard commandSize >= 24 else {
                    throw X64DyldSharedCacheError.malformed("Cached image \(image.installName) has a truncated LC_LOAD_DYLIB-family command.")
                }
                let stringOffset = readLE32(commandData, cursor + 8)
                guard stringOffset >= 24, stringOffset < commandSize else {
                    throw X64DyldSharedCacheError.malformed("Cached image \(image.installName) has an invalid dependency install-name offset.")
                }
                let stringStart = cursor + Int(stringOffset)
                let stringEnd = cursor + Int(commandSize)
                guard let nul = commandData[stringStart..<stringEnd].firstIndex(of: 0), nul > stringStart,
                      let installName = String(bytes: commandData[stringStart..<nul], encoding: .utf8) else {
                    throw X64DyldSharedCacheError.malformed("Cached image \(image.installName) contains a malformed dependency install name.")
                }
                let kind: X64MachODylibKind
                switch command {
                case lcLoadWeakDylib: kind = .weakLoad
                case lcReexportDylib: kind = .reexport
                case lcLoadUpwardDylib: kind = .upward
                case lcLazyLoadDylib: kind = .lazyLoad
                default: kind = .load
                }
                dependencies.append(X64MachODylibDependency(
                    ordinal: dependencies.count + 1,
                    installName: installName,
                    timestamp: readLE32(commandData, cursor + 12),
                    currentVersion: readLE32(commandData, cursor + 16),
                    compatibilityVersion: readLE32(commandData, cursor + 20),
                    kind: kind
                ))

            default:
                break
            }
            cursor += Int(commandSize)
        }
        guard cursor == commandEnd else {
            throw X64DyldSharedCacheError.malformed("Cached image \(image.installName) load commands do not consume sizeofcmds exactly.")
        }
        guard let linkedit = segments.first(where: { $0.name == "__LINKEDIT" }) else {
            // Images with no export metadata can legitimately have no useful
            // __LINKEDIT range for this narrow resolver, but malformed commands
            // must not be interpreted as an empty successful export table.
            if legacyExportRange == nil && dedicatedExportRange == nil {
                return X64CachedImageMetadata(image: image, segments: segments, dependencies: dependencies, exports: [], exportTrieByteCount: 0)
            }
            throw X64DyldSharedCacheError.malformed("Cached image \(image.installName) advertises exports but has no __LINKEDIT segment.")
        }

        // The dedicated command is authoritative when present; otherwise use
        // the export range embedded in LC_DYLD_INFO(_ONLY).
        let exportRange = dedicatedExportRange ?? legacyExportRange
        guard let exportRange, exportRange.size > 0 else {
            return X64CachedImageMetadata(image: image, segments: segments, dependencies: dependencies, exports: [], exportTrieByteCount: 0)
        }
        guard exportRange.size <= UInt32(maximumExportTrieBytes) else {
            throw X64DyldSharedCacheError.malformed("Cached image \(image.installName) export trie exceeds 64 MiB.")
        }
        let exportStart = UInt64(exportRange.offset)
        let exportSize = UInt64(exportRange.size)
        let (exportEnd, exportOverflow) = exportStart.addingReportingOverflow(exportSize)
        let (linkeditEnd, linkeditOverflow) = linkedit.fileOffset.addingReportingOverflow(linkedit.fileSize)
        guard !exportOverflow, !linkeditOverflow,
              exportStart >= linkedit.fileOffset, exportEnd <= linkeditEnd else {
            throw X64DyldSharedCacheError.malformed("Cached image \(image.installName) export trie is outside its __LINKEDIT file range.")
        }
        let delta = exportStart - linkedit.fileOffset
        let (exportVMAddress, addressOverflow) = linkedit.virtualAddress.addingReportingOverflow(delta)
        guard !addressOverflow, cache.containsVMRange(address: exportVMAddress, size: exportSize) else {
            throw X64DyldSharedCacheError.malformed("Cached image \(image.installName) export trie does not map to readable shared-cache VM pages.")
        }
        let trie = try cache.readVMBytes(atVMAddress: exportVMAddress, count: Int(exportSize))
        let exports = try X64MachOParser.parseExportTriePayload(trie)
        return X64CachedImageMetadata(
            image: image,
            segments: segments,
            dependencies: dependencies,
            exports: exports,
            exportTrieByteCount: trie.count
        )
    }

    private static func readLE32(_ data: Data, _ offset: Int) -> UInt32 {
        UInt32(data[offset]) | (UInt32(data[offset + 1]) << 8)
            | (UInt32(data[offset + 2]) << 16) | (UInt32(data[offset + 3]) << 24)
    }

    private static func readLE64(_ data: Data, _ offset: Int) -> UInt64 {
        UInt64(readLE32(data, offset)) | (UInt64(readLE32(data, offset + 4)) << 32)
    }
}

// MARK: - Minimal shared-cache reexport-provider materialization

/// The selected cached images whose guest pages are needed to satisfy imports
/// exposed through direct dylib reexports. This is intentionally much smaller
/// than the complete transitive dependency metadata closure: ordinary
/// LC_LOAD_DYLIB edges are not followed for page materialization.
struct X64DyldSharedCacheReexportSelection: Sendable, Equatable {
    let installNames: [String]
    let rootImageCount: Int
    let missingInstallNames: [String]
    let parsedExportCount: Int
    let exportTrieBytes: Int
    let truncated: Bool
}

enum X64DyldSharedCacheReexportPlanner {
    private static let maximumImages = 1_024
    private static let maximumQueuedImages = 4_096
    private static let maximumExportBytes = 128 * 1024 * 1024
    private static let maximumExportCount = 2_000_000

    /// Starts with the executable's direct dependencies and follows only
    /// LC_REEXPORT_DYLIB edges plus explicit EXPORT_SYMBOL_FLAGS_REEXPORT
    /// targets. All other dependency commands are intentionally excluded.
    /// Install names are matched exactly; no basename or framework-name
    /// guessing is performed. Each image's export metadata is discarded after
    /// its outgoing reexport edges are collected, so the planner does not keep
    /// hundreds of decoded export tries alive while building the page plan.
    static func select(
        cache: X64DyldSharedCacheSummary,
        roots: [X64MachODylibDependency]
    ) throws -> X64DyldSharedCacheReexportSelection {
        let imageByPath = Dictionary(
            cache.images.map { ($0.installName, $0) },
            uniquingKeysWith: { first, _ in first }
        )
        var queue: [String] = []
        var discoveredPaths = Set<String>()
        var truncated = false

        func enqueue(_ installName: String) {
            guard discoveredPaths.insert(installName).inserted else { return }
            guard queue.count < maximumQueuedImages else {
                truncated = true
                return
            }
            queue.append(installName)
        }
        for dependency in roots { enqueue(dependency.installName) }

        var selected: [String] = []
        var missing: [String] = []
        var totalExportBytes = 0
        var totalExportCount = 0
        var rootImageCount = 0
        var queueIndex = 0
        let rootPaths = Set(roots.map(\.installName))

        while queueIndex < queue.count {
            let installName = queue[queueIndex]
            queueIndex += 1

            guard selected.count < maximumImages else {
                truncated = true
                break
            }
            guard let image = imageByPath[installName], image.hasReadableX86_64Header else {
                missing.append(installName)
                continue
            }

            // The path is enqueued once globally, so there is no need to cache
            // the entire parsed metadata object after this iteration.
            let metadata = try X64DyldSharedCacheImageMetadataReader.read(cache: cache, image: image)
            let (newBytes, byteOverflow) = totalExportBytes.addingReportingOverflow(metadata.exportTrieByteCount)
            let (newExports, exportOverflow) = totalExportCount.addingReportingOverflow(metadata.exports.count)
            guard !byteOverflow, !exportOverflow,
                  newBytes <= maximumExportBytes,
                  newExports <= maximumExportCount else {
                throw X64DyldSharedCacheError.malformed("Reexport-provider metadata exceeds Kestrel's bounded export parsing limits.")
            }
            totalExportBytes = newBytes
            totalExportCount = newExports

            selected.append(installName)
            if rootPaths.contains(installName) { rootImageCount += 1 }

            // LC_REEXPORT_DYLIB commands preserve the runtime search order
            // recorded by the parent Mach-O. Explicit export-trie reexports
            // can target other dependency commands by their original ordinal.
            for dependency in metadata.dependencies where dependency.kind == .reexport {
                enqueue(dependency.installName)
            }
            for export in metadata.exports where export.isReexport {
                guard let ordinal = export.reexportOrdinal,
                      let dependency = metadata.dependencies.first(where: { $0.ordinal == ordinal }) else {
                    throw X64DyldSharedCacheError.malformed("Cached image \(installName) contains an export-trie reexport with an invalid dependency ordinal.")
                }
                enqueue(dependency.installName)
            }
        }

        return X64DyldSharedCacheReexportSelection(
            installNames: selected,
            rootImageCount: rootImageCount,
            missingInstallNames: Array(Set(missing)).sorted(),
            parsedExportCount: totalExportCount,
            exportTrieBytes: totalExportBytes,
            truncated: truncated || queueIndex < queue.count
        )
    }
}

enum X64DyldUnresolvedBindingReason: String, Sendable {
    case unsupportedBindType
    case noExportInDeclaredReexportChain
    case absoluteExportRequiresDyldHandling
    case threadLocalExportRequiresTLS
    case weakLookupRequiresWeakDefinition
    case lazyResolverExecutionRequired
    case exportAddressOverflow
    case exportAddressOutsideImage
    case exportAddressNotMapped
    case unresolvedForOtherReason

    var explanation: String {
        switch self {
        case .unsupportedBindType:
            return "The bind type is not supported by Kestrel."
        case .noExportInDeclaredReexportChain:
            return "No definition was found in the declared dependency or its explicit LC_REEXPORT_DYLIB chain."
        case .absoluteExportRequiresDyldHandling:
            return "The candidate is an absolute export and needs dyld-specific handling."
        case .threadLocalExportRequiresTLS:
            return "The candidate is thread-local and requires per-thread TLS support."
        case .weakLookupRequiresWeakDefinition:
            return "Weak lookup found no eligible weak definition."
        case .lazyResolverExecutionRequired:
            return "The candidate is STUB_AND_RESOLVER; a lazy bind requires executing its resolver and using the returned address."
        case .exportAddressOverflow:
            return "The candidate export address overflows the guest address space."
        case .exportAddressOutsideImage:
            return "The candidate export address is outside its provider's declared segments."
        case .exportAddressNotMapped:
            return "The candidate export address is not mapped in guest memory."
        case .unresolvedForOtherReason:
            return "A candidate exists, but it did not satisfy the current binding rules."
        }
    }
}

struct X64DyldUnresolvedBindingDiagnostic: Sendable {
    let symbolName: String
    let libraryOrdinal: Int
    let dependencyInstallName: String?
    let stream: String
    let isWeakImport: Bool
    /// Candidate providers reachable through ordinary dependency edges. The
    /// route labels make it explicit which edges are not LC_REEXPORT_DYLIB.
    let candidateRoutes: [String]
    /// The actual provider found through the declared dependency's reexport
    /// chain, if one exists. This is deliberately distinct from diagnostic-only
    /// providers found elsewhere in the load graph.
    let candidateExportProviderInstallName: String?
    let candidateExportFlags: UInt64?
    let candidateStubAddress: UInt64?
    let candidateResolverAddress: UInt64?
    let candidateResolverIsExecutable: Bool?
    let resolutionBlocker: X64DyldUnresolvedBindingReason
}

struct X64DyldDependencyRouteResult: Sendable, Equatable {
    let description: String
    let visitedImageCount: Int
}

/// Finds one deterministic shortest dependency route without enumerating
/// every possible path through a graph. A global visited set and one parent
/// link per image keep both memory and work O(images + dependency edges),
/// even when the dependency graph contains many diamonds or cycles.
enum X64DyldDependencyRouteFinder {
    static func find(
        from root: String,
        to target: String,
        dependenciesByImage: [String: [X64MachODylibDependency]],
        maximumVisitedImages: Int = 1_024
    ) -> X64DyldDependencyRouteResult? {
        guard maximumVisitedImages > 0,
              dependenciesByImage[root] != nil,
              dependenciesByImage[target] != nil else { return nil }
        if root == target {
            return X64DyldDependencyRouteResult(description: root, visitedImageCount: 1)
        }

        var queue: [String] = [root]
        var queueIndex = 0
        var visited: Set<String> = [root]
        var parentByImage: [String: (parent: String, edgeKind: X64MachODylibKind)] = [:]

        while queueIndex < queue.count, visited.count <= maximumVisitedImages {
            let current = queue[queueIndex]
            queueIndex += 1

            for dependency in dependenciesByImage[current] ?? [] {
                let next = dependency.installName
                // Only traverse metadata that was actually parsed into this
                // bounded closure. Missing images cannot lead to a known
                // candidate provider and should not expand the route search.
                guard visited.count < maximumVisitedImages,
                      dependenciesByImage[next] != nil,
                      visited.insert(next).inserted else { continue }

                parentByImage[next] = (current, dependency.kind)
                if next == target {
                    var reversedEdges: [(image: String, kind: X64MachODylibKind)] = []
                    var cursor = target
                    while cursor != root {
                        guard let parent = parentByImage[cursor] else { return nil }
                        reversedEdges.append((cursor, parent.edgeKind))
                        cursor = parent.parent
                    }

                    var description = root
                    for edge in reversedEdges.reversed() {
                        description += " --\(commandLabel(edge.kind))--> \(edge.image)"
                    }
                    return X64DyldDependencyRouteResult(
                        description: description,
                        visitedImageCount: visited.count
                    )
                }
                queue.append(next)
                if visited.count >= maximumVisitedImages { break }
            }
        }
        return nil
    }

    private static func commandLabel(_ kind: X64MachODylibKind) -> String {
        switch kind {
        case .load: return "LC_LOAD_DYLIB"
        case .weakLoad: return "LC_LOAD_WEAK_DYLIB"
        case .reexport: return "LC_REEXPORT_DYLIB"
        case .upward: return "LC_LOAD_UPWARD_DYLIB"
        case .lazyLoad: return "LC_LAZY_LOAD_DYLIB"
        }
    }
}

struct X64DyldSharedCacheImportResolutionSummary: Sendable {
    let resolver: X64MachOSymbolResolver
    let examinedImageCount: Int
    let dependencyClosureImageCount: Int
    let dependencyClosureTruncated: Bool
    let missingDependencyPaths: [String]
    let parsedExportCount: Int
    let exportTrieBytes: Int
    let resolvedImportCount: Int
    let unresolvedImportCount: Int
    let flatLookupResolvedCount: Int
    let weakLookupResolvedCount: Int
    let ambiguousFlatLookupSymbols: [String]
    let ambiguousWeakLookupSymbols: [String]
    let candidateProvidersBySymbol: [String: [String]]
    let unresolvedBindingDiagnostics: [X64DyldUnresolvedBindingDiagnostic]
    let unresolvedByDependency: [String: Int]
    let resolvedByDependency: [String: Int]
}

/// Builds a dependency-qualified guest symbol resolver from already
/// materialized cache images. Exact positive ordinals retain two-level
/// namespace behavior. Flat and weak special ordinals are handled explicitly
/// over a bounded breadth-first dependency closure; ordinary imports are never
/// redirected to an unrelated image merely because it exports the same name.
enum X64DyldSharedCacheImportResolver {
    // The real Rosetta x86_64 cache's dependency closure exceeds 256 images.
    // Keep the walk bounded, but large enough to cover ordinary framework
    // reexport trees without silently stopping at a small arbitrary cutoff.
    private static let maximumImages = 1_024
    private static let maximumExportBytes = 128 * 1024 * 1024
    private static let maximumReexportDepth = 32
    private static let specialOrdinalMainExecutable = -1
    private static let specialOrdinalFlatLookup = -2
    private static let specialOrdinalWeakLookup = -3

    static func build(
        cache: X64DyldSharedCacheSummary,
        executable: X64MachOImage,
        guestMemory: X64GuestVirtualMemory,
        baseResolver: X64MachOSymbolResolver
    ) throws -> X64DyldSharedCacheImportResolutionSummary {
        let imageByPath = Dictionary(cache.images.map { ($0.installName, $0) }, uniquingKeysWith: { first, _ in first })
        var metadataByPath: [String: X64CachedImageMetadata] = [:]
        var loadingPaths = Set<String>()
        var totalExportBytes = 0
        var totalExportCount = 0
        var dependencyClosureTruncated = false
        var missingDependencyPaths = Set<String>()

        func metadata(for installName: String) throws -> X64CachedImageMetadata? {
            if let cached = metadataByPath[installName] { return cached }
            guard !loadingPaths.contains(installName),
                  let image = imageByPath[installName], image.hasReadableX86_64Header else {
                return nil
            }
            guard metadataByPath.count + loadingPaths.count < maximumImages else {
                dependencyClosureTruncated = true
                return nil
            }
            loadingPaths.insert(installName)
            defer { loadingPaths.remove(installName) }
            let parsed = try X64DyldSharedCacheImageMetadataReader.read(cache: cache, image: image)
            let (newByteCount, byteOverflow) = totalExportBytes.addingReportingOverflow(parsed.exportTrieByteCount)
            let (newExportCount, exportOverflow) = totalExportCount.addingReportingOverflow(parsed.exports.count)
            guard !byteOverflow, !exportOverflow, newByteCount <= maximumExportBytes, newExportCount <= 2_000_000 else {
                throw X64DyldSharedCacheError.malformed("Cached export metadata exceeds Kestrel's memory-safety limits.")
            }
            totalExportBytes = newByteCount
            totalExportCount = newExportCount
            metadataByPath[installName] = parsed
            return parsed
        }

        func resolveExport(
            symbol: String,
            from installName: String,
            depth: Int,
            visited: Set<String>,
            requireWeakDefinition: Bool = false,
            allowStubAndResolver: Bool = false
        ) throws -> UInt64? {
            guard depth <= maximumReexportDepth, !visited.contains(installName),
                  let imageMetadata = try metadata(for: installName) else { return nil }
            let nextVisited = visited.union([installName])
            guard let export = imageMetadata.exportsByName[symbol] else {
                // dyld searches LC_REEXPORT_DYLIB dependencies when a symbol
                // is not present in this image's own export trie. This is
                // distinct from arbitrary transitive lookup: only dependencies
                // explicitly marked as reexports may provide the symbol, and
                // load-command order determines the first successful result.
                for dependency in imageMetadata.dependencies where dependency.kind == .reexport {
                    if let address = try resolveExport(
                        symbol: symbol,
                        from: dependency.installName,
                        depth: depth + 1,
                        visited: nextVisited,
                        requireWeakDefinition: requireWeakDefinition,
                        allowStubAndResolver: allowStubAndResolver
                    ) {
                        return address
                    }
                }
                return nil
            }

            if export.isReexport {
                guard let ordinal = export.reexportOrdinal,
                      let dependency = imageMetadata.dependencies.first(where: { $0.ordinal == ordinal }) else {
                    return nil
                }
                let forwardedName = (export.importedName?.isEmpty == false) ? export.importedName! : symbol
                return try resolveExport(
                    symbol: forwardedName,
                    from: dependency.installName,
                    depth: depth + 1,
                    visited: nextVisited,
                    requireWeakDefinition: requireWeakDefinition,
                    allowStubAndResolver: allowStubAndResolver
                )
            }

            // For a STUB_AND_RESOLVER export, dyld uses the stub address for
            // non-lazy pointer binds. Lazy pointer binds must call the resolver
            // and use its returned implementation address; Kestrel does not
            // execute resolver functions yet, so those remain unresolved.
            guard !export.isAbsolute, !export.isThreadLocal,
                  (!export.hasStubAndResolver || allowStubAndResolver),
                  (!requireWeakDefinition || export.isWeakDefinition),
                  let addressOffset = export.addressOffset else { return nil }
            let (address, overflow) = imageMetadata.image.machHeaderAddress.addingReportingOverflow(addressOffset)
            guard !overflow,
                  imageMetadata.segments.contains(where: { address >= $0.virtualAddress && address < $0.virtualEnd }),
                  guestMemory.region(containing: address) != nil else { return nil }
            return address
        }

        /// Returns the concrete export provider reached only through the
        /// declared image and its explicit reexport edges. Ordinary transitive
        /// dependencies are intentionally not considered here.
        func findExportCandidate(
            symbol: String,
            from installName: String,
            depth: Int,
            visited: Set<String>
        ) throws -> (provider: String, metadata: X64CachedImageMetadata, export: X64MachOExport)? {
            guard depth <= maximumReexportDepth,
                  !visited.contains(installName),
                  let imageMetadata = try metadata(for: installName) else { return nil }
            let nextVisited = visited.union([installName])

            if let export = imageMetadata.exportsByName[symbol] {
                if export.isReexport {
                    guard let ordinal = export.reexportOrdinal,
                          let dependency = imageMetadata.dependencies.first(where: { $0.ordinal == ordinal }) else {
                        return nil
                    }
                    let forwardedName = (export.importedName?.isEmpty == false) ? export.importedName! : symbol
                    return try findExportCandidate(
                        symbol: forwardedName,
                        from: dependency.installName,
                        depth: depth + 1,
                        visited: nextVisited
                    )
                }
                return (installName, imageMetadata, export)
            }

            for dependency in imageMetadata.dependencies where dependency.kind == .reexport {
                if let candidate = try findExportCandidate(
                    symbol: symbol,
                    from: dependency.installName,
                    depth: depth + 1,
                    visited: nextVisited
                ) {
                    return candidate
                }
            }
            return nil
        }

        func guestAddress(for offset: UInt64?, in metadata: X64CachedImageMetadata) -> UInt64? {
            guard let offset else { return nil }
            let (address, overflow) = metadata.image.machHeaderAddress.addingReportingOverflow(offset)
            return overflow ? nil : address
        }

        func isExecutableGuestAddress(_ address: UInt64?, in metadata: X64CachedImageMetadata) -> Bool? {
            guard let address else { return nil }
            let belongsToExecutableSegment = metadata.segments.contains {
                address >= $0.virtualAddress && address < $0.virtualEnd
            }
            guard belongsToExecutableSegment,
                  guestMemory.region(containing: address) != nil,
                  let permissions = guestMemory.permissions(at: address) else {
                return false
            }
            return permissions.contains(.execute)
        }

        // Build the load-order dependency closure. dyld recursively loads
        // direct dependencies and their dependencies; breadth-first ordering is
        // stable and gives flat lookup a deterministic provider order.
        var dependencyLoadOrder: [String] = []
        var queuedPaths = Set<String>()
        var queue: [String] = []
        for dependency in executable.dependencies where queuedPaths.insert(dependency.installName).inserted {
            queue.append(dependency.installName)
        }
        var queueIndex = 0
        while queueIndex < queue.count {
            let path = queue[queueIndex]
            queueIndex += 1
            guard let imageMetadata = try metadata(for: path) else {
                if imageByPath[path] == nil { missingDependencyPaths.insert(path) }
                continue
            }
            dependencyLoadOrder.append(path)
            for dependency in imageMetadata.dependencies where queuedPaths.insert(dependency.installName).inserted {
                queue.append(dependency.installName)
            }
        }

        var resolver = baseResolver
        func mainExecutableExportAddress(
            _ symbol: String,
            weakOnly: Bool = false,
            allowStubAndResolver: Bool = false
        ) -> UInt64? {
            guard let export = executable.exports.first(where: { $0.symbolName == symbol }),
                  !export.isReexport, !export.isAbsolute, !export.isThreadLocal,
                  (!export.hasStubAndResolver || allowStubAndResolver),
                  (!weakOnly || export.isWeakDefinition),
                  let offset = export.addressOffset else { return nil }
            let (address, overflow) = executable.preferredLoadAddress.addingReportingOverflow(offset)
            guard !overflow,
                  executable.segments.contains(where: { address >= $0.virtualAddress && address < $0.virtualEnd }),
                  guestMemory.region(containing: address) != nil else { return nil }
            return address
        }

        var resolvedImportCount = 0
        var flatLookupResolvedCount = 0
        var weakLookupResolvedCount = 0
        var ambiguousFlatLookupSymbols = Set<String>()
        var ambiguousWeakLookupSymbols = Set<String>()
        var resolvedByDependency: [String: Int] = [:]
        var unresolvedKeys = Set<String>()
        var unresolvedActions: [(action: X64MachOBindAction, dependency: String?)] = []
        var candidateProvidersBySymbol: [String: [String]] = [:]
        let allActions = executable.bindActions + executable.weakBindActions + executable.lazyBindActions

        for action in allActions {
            guard action.type == 1 else {
                unresolvedKeys.insert("type:\(action.type):\(action.symbolName)")
                let dependency = action.libraryOrdinal > 0
                    ? executable.dependencies.first(where: { $0.ordinal == action.libraryOrdinal })?.installName
                    : nil
                unresolvedActions.append((action, dependency))
                continue
            }

            if action.libraryOrdinal > 0 {
                guard let dependency = executable.dependencies.first(where: { $0.ordinal == action.libraryOrdinal }) else {
                    unresolvedKeys.insert("ordinal:\(action.libraryOrdinal):\(action.symbolName)")
                    continue
                }
                if let address = try resolveExport(
                    symbol: action.symbolName,
                    from: dependency.installName,
                    depth: 0,
                    visited: [],
                    allowStubAndResolver: action.stream != .lazy
                ) {
                    resolver.register(symbol: action.symbolName, address: address, installName: dependency.installName)
                    resolvedImportCount += 1
                    resolvedByDependency[dependency.installName, default: 0] += 1
                } else {
                    unresolvedKeys.insert("\(dependency.installName)|\(action.symbolName)")
                    unresolvedActions.append((action, dependency.installName))
                }
                continue
            }

            switch action.libraryOrdinal {
            case 0, specialOrdinalMainExecutable:
                // The main-image loader registers its own ordinary exports in
                // the global resolver before it writes any bind slots.
                continue

            case specialOrdinalFlatLookup:
                if resolver.resolve(symbol: action.symbolName, dependency: nil) != nil {
                    resolvedImportCount += 1
                    flatLookupResolvedCount += 1
                    continue
                }
                if let mainAddress = mainExecutableExportAddress(
                    action.symbolName,
                    allowStubAndResolver: action.stream != .lazy
                ) {
                    resolver.register(symbol: action.symbolName, address: mainAddress)
                    resolvedImportCount += 1
                    flatLookupResolvedCount += 1
                    continue
                }
                var matches: [(path: String, address: UInt64)] = []
                for path in dependencyLoadOrder {
                    if let address = resolver.resolveExact(symbol: action.symbolName, installName: path) {
                        matches.append((path, address))
                    } else if let address = try resolveExport(symbol: action.symbolName, from: path, depth: 0, visited: [], allowStubAndResolver: action.stream != .lazy) {
                        matches.append((path, address))
                    }
                }
                let uniqueAddresses = Set(matches.map(\.address))
                if uniqueAddresses.count == 1, let found = matches.first {
                    resolver.register(symbol: action.symbolName, address: found.address)
                    resolvedImportCount += 1
                    flatLookupResolvedCount += 1
                    resolvedByDependency[found.path, default: 0] += 1
                } else if uniqueAddresses.count > 1 {
                    ambiguousFlatLookupSymbols.insert(action.symbolName)
                    candidateProvidersBySymbol[action.symbolName] = Array(matches.prefix(4).map(\.path))
                    unresolvedKeys.insert("flat-ambiguous|\(action.symbolName)")
                } else {
                    unresolvedKeys.insert("flat|\(action.symbolName)")
                    unresolvedActions.append((action, nil))
                }

            case specialOrdinalWeakLookup:
                // WEAK_LOOKUP is specifically a search for weak definitions;
                // do not accept an arbitrary strong export or a host thunk
                // merely because the base resolver has a wildcard entry.
                if let mainWeakAddress = mainExecutableExportAddress(
                    action.symbolName,
                    weakOnly: true,
                    allowStubAndResolver: action.stream != .lazy
                ) {
                    resolver.registerWeak(symbol: action.symbolName, address: mainWeakAddress)
                    resolvedImportCount += 1
                    weakLookupResolvedCount += 1
                    continue
                }
                var matches: [(path: String, address: UInt64)] = []
                for path in dependencyLoadOrder {
                    if let address = resolver.resolveWeakExact(symbol: action.symbolName, installName: path) {
                        matches.append((path, address))
                    } else if let address = try resolveExport(
                        symbol: action.symbolName,
                        from: path,
                        depth: 0,
                        visited: [],
                        requireWeakDefinition: true,
                        allowStubAndResolver: action.stream != .lazy
                    ) {
                        matches.append((path, address))
                    }
                }
                let uniqueAddresses = Set(matches.map(\.address))
                if uniqueAddresses.count == 1, let found = matches.first {
                    resolver.registerWeak(symbol: action.symbolName, address: found.address)
                    resolvedImportCount += 1
                    weakLookupResolvedCount += 1
                    resolvedByDependency[found.path, default: 0] += 1
                } else if uniqueAddresses.count > 1 {
                    ambiguousWeakLookupSymbols.insert(action.symbolName)
                    candidateProvidersBySymbol[action.symbolName] = Array(matches.prefix(4).map(\.path))
                    unresolvedKeys.insert("weak-ambiguous|\(action.symbolName)")
                } else {
                    unresolvedKeys.insert("weak|\(action.symbolName)")
                    unresolvedActions.append((action, nil))
                }

            default:
                unresolvedKeys.insert("special:\(action.libraryOrdinal):\(action.symbolName)")
                unresolvedActions.append((action, nil))
            }
        }

        // Report plausible providers elsewhere in the loaded dependency graph.
        // These are diagnostic only: a two-level import is not rebound to a
        // transitive image unless its declared dependency reexports the name.
        for missing in unresolvedActions {
            guard let root = missing.dependency else { continue }
            if candidateProvidersBySymbol[missing.action.symbolName] != nil { continue }
            var providers: [String] = []
            for path in dependencyLoadOrder where path != root {
                guard let candidate = metadataByPath[path],
                      candidate.exportsByName[missing.action.symbolName] != nil else { continue }
                providers.append(path)
                if providers.count == 4 { break }
            }
            if !providers.isEmpty {
                candidateProvidersBySymbol[missing.action.symbolName] = providers
            }
        }

        // Materialize the compact adjacency table once. The diagnostic route
        // finder uses one global visited set; never carry a full per-path Set
        // in every queue entry, which can explode exponentially in a graph
        // with repeated dependency diamonds.
        let dependenciesByPath = metadataByPath.mapValues(\.dependencies)

        var unresolvedByDependency: [String: Set<String>] = [:]
        var unresolvedBindingDiagnostics: [X64DyldUnresolvedBindingDiagnostic] = []
        var seenDiagnosticKeys = Set<String>()
        for missing in unresolvedActions {
            let action = missing.action
            if let dependency = missing.dependency {
                unresolvedByDependency[dependency, default: []].insert(action.symbolName)
            }
            let diagnosticKey = "\(action.libraryOrdinal)|\(action.stream.rawValue)|\(action.symbolName)|\(action.isWeakImport)"
            guard seenDiagnosticKeys.insert(diagnosticKey).inserted else { continue }
            let routes: [String]
            if let root = missing.dependency {
                routes = (candidateProvidersBySymbol[action.symbolName] ?? []).compactMap { target in
                    X64DyldDependencyRouteFinder.find(
                        from: root,
                        to: target,
                        dependenciesByImage: dependenciesByPath,
                        maximumVisitedImages: maximumImages
                    )?.description
                }
            } else {
                routes = []
            }
            let exportCandidate: (provider: String, metadata: X64CachedImageMetadata, export: X64MachOExport)?
            if let dependency = missing.dependency {
                exportCandidate = try findExportCandidate(
                    symbol: action.symbolName,
                    from: dependency,
                    depth: 0,
                    visited: []
                )
            } else {
                exportCandidate = nil
            }

            let stubAddress = exportCandidate.flatMap {
                guestAddress(for: $0.export.addressOffset, in: $0.metadata)
            }
            let resolverAddress = exportCandidate.flatMap {
                guestAddress(for: $0.export.resolverOffset, in: $0.metadata)
            }
            let resolverIsExecutable = exportCandidate.flatMap {
                isExecutableGuestAddress(resolverAddress, in: $0.metadata)
            }

            let blocker: X64DyldUnresolvedBindingReason
            if action.type != 1 {
                blocker = .unsupportedBindType
            } else if let candidate = exportCandidate {
                if candidate.export.isAbsolute {
                    blocker = .absoluteExportRequiresDyldHandling
                } else if candidate.export.isThreadLocal {
                    blocker = .threadLocalExportRequiresTLS
                } else if action.libraryOrdinal == specialOrdinalWeakLookup && !candidate.export.isWeakDefinition {
                    blocker = .weakLookupRequiresWeakDefinition
                } else if candidate.export.hasStubAndResolver && action.stream == .lazy {
                    blocker = .lazyResolverExecutionRequired
                } else if stubAddress == nil {
                    blocker = .exportAddressOverflow
                } else if !candidate.metadata.segments.contains(where: {
                    stubAddress! >= $0.virtualAddress && stubAddress! < $0.virtualEnd
                }) {
                    blocker = .exportAddressOutsideImage
                } else if guestMemory.region(containing: stubAddress!) == nil {
                    blocker = .exportAddressNotMapped
                } else {
                    blocker = .unresolvedForOtherReason
                }
            } else if missing.dependency != nil {
                blocker = .noExportInDeclaredReexportChain
            } else {
                blocker = .unresolvedForOtherReason
            }

            unresolvedBindingDiagnostics.append(X64DyldUnresolvedBindingDiagnostic(
                symbolName: action.symbolName,
                libraryOrdinal: action.libraryOrdinal,
                dependencyInstallName: missing.dependency,
                stream: action.stream.rawValue,
                isWeakImport: action.isWeakImport,
                candidateRoutes: Array(routes.prefix(3)),
                candidateExportProviderInstallName: exportCandidate?.provider,
                candidateExportFlags: exportCandidate?.export.flags,
                candidateStubAddress: stubAddress,
                candidateResolverAddress: resolverAddress,
                candidateResolverIsExecutable: resolverIsExecutable,
                resolutionBlocker: blocker
            ))
        }

        return X64DyldSharedCacheImportResolutionSummary(
            resolver: resolver,
            examinedImageCount: metadataByPath.count,
            dependencyClosureImageCount: dependencyLoadOrder.count,
            dependencyClosureTruncated: dependencyClosureTruncated,
            missingDependencyPaths: missingDependencyPaths.sorted(),
            parsedExportCount: totalExportCount,
            exportTrieBytes: totalExportBytes,
            resolvedImportCount: resolvedImportCount,
            unresolvedImportCount: unresolvedKeys.count,
            flatLookupResolvedCount: flatLookupResolvedCount,
            weakLookupResolvedCount: weakLookupResolvedCount,
            ambiguousFlatLookupSymbols: ambiguousFlatLookupSymbols.sorted(),
            ambiguousWeakLookupSymbols: ambiguousWeakLookupSymbols.sorted(),
            candidateProvidersBySymbol: candidateProvidersBySymbol,
            unresolvedBindingDiagnostics: unresolvedBindingDiagnostics,
            unresolvedByDependency: unresolvedByDependency.mapValues(\.count),
            resolvedByDependency: resolvedByDependency
        )
    }
}
