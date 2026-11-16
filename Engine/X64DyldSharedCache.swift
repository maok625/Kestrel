import Foundation

// MARK: - x86_64 dyld shared-cache inventory

struct X64DyldSharedCacheMapping: Sendable, Equatable {
    let address: UInt64
    let size: UInt64
    let fileOffset: UInt64
    let maximumProtection: UInt32
    let initialProtection: UInt32

    var endAddress: UInt64 { address &+ size }
}

/// The extended mapping record used by modern dyld caches. Unlike the legacy
/// mapping table, this record also points at the compressed slide-info blob
/// used to rebase interior pointers in the mapping.
struct X64DyldSharedCacheSlideMapping: Sendable, Equatable {
    let address: UInt64
    let size: UInt64
    let fileOffset: UInt64
    let slideInfoFileOffset: UInt64
    let slideInfoFileSize: UInt64
    let flags: UInt64
    let maximumProtection: UInt32
    let initialProtection: UInt32
}

/// Read-only validation results for a version-2 shared-cache slide-info blob.
/// Pointer locations are walked and counted but their contents are not changed.
struct X64DyldSharedCacheSlideInfoSummary: Sendable, Equatable {
    let mappingAddress: UInt64
    let mappingSize: UInt64
    let version: UInt32
    let pageSize: UInt32
    let pageCount: UInt64
    let pagesWithRebases: UInt64
    let chainCount: UInt64
    let rebasingPointerCount: UInt64
}

struct X64DyldSharedCacheImageRecord: Sendable, Equatable {
    let installName: String
    let machHeaderAddress: UInt64
    let modificationTime: UInt64
    let inode: UInt64
    let cpuType: UInt32?
    let fileType: UInt32?

    var hasReadableX86_64Header: Bool {
        cpuType == X64DyldSharedCacheReader.cpuTypeX86_64
    }
}

struct X64DyldSharedCacheDependencyMatch: Sendable, Equatable {
    let installName: String
    let image: X64DyldSharedCacheImageRecord?
}

struct X64DyldSharedCacheBackingFile: Sendable {
    let url: URL
    let data: Data
    let mappings: [X64DyldSharedCacheMapping]
    let slideMappings: [X64DyldSharedCacheSlideMapping]
}

struct X64DyldSharedCacheSummary: Sendable {
    let url: URL
    let magic: String
    let uuid: String
    let platform: UInt32
    let cacheType: UInt64
    let sharedRegionStart: UInt64
    let sharedRegionSize: UInt64
    let mappings: [X64DyldSharedCacheMapping]
    let slideMappings: [X64DyldSharedCacheSlideMapping]
    let images: [X64DyldSharedCacheImageRecord]
    let subcachePaths: [String]
    let backingFiles: [X64DyldSharedCacheBackingFile]

    func matchDependencies(_ dependencies: [X64MachODylibDependency]) -> [X64DyldSharedCacheDependencyMatch] {
        let byPath = Dictionary(images.map { ($0.installName, $0) }, uniquingKeysWith: { first, _ in first })
        return dependencies.map { dependency in
            X64DyldSharedCacheDependencyMatch(
                installName: dependency.installName,
                image: byPath[dependency.installName]
            )
        }
    }

    var x86_64ImageCount: Int { images.filter(\.hasReadableX86_64Header).count }

    /// Reads bytes through the cache's VM mapping table. A requested range may
    /// cross adjacent mappings or split-cache files; gaps are rejected rather
    /// than silently filled with zeros.
    func readVMBytes(atVMAddress address: UInt64, count: Int) throws -> Data {
        guard count >= 0, count <= 64 * 1024 * 1024 else {
            throw X64DyldSharedCacheError.malformed("Requested shared-cache VM read is negative or exceeds 64 MiB.")
        }
        if count == 0 { return Data() }
        let (endAddress, overflow) = address.addingReportingOverflow(UInt64(count))
        guard !overflow else {
            throw X64DyldSharedCacheError.malformed("Requested shared-cache VM range overflows.")
        }

        var output = Data()
        output.reserveCapacity(count)
        var cursor = address
        while cursor < endAddress {
            guard let backing = backingFiles.first(where: { file in
                file.mappings.contains(where: { cursor >= $0.address && cursor < $0.endAddress })
            }), let mapping = backing.mappings.first(where: { cursor >= $0.address && cursor < $0.endAddress }) else {
                throw X64DyldSharedCacheError.malformed(String(format: "Shared-cache VM address 0x%016llX is not covered by a file mapping.", cursor))
            }
            let delta = cursor - mapping.address
            let available = mapping.size - delta
            let chunk = min(UInt64(count - output.count), available)
            let (fileOffset, offsetOverflow) = mapping.fileOffset.addingReportingOverflow(delta)
            guard !offsetOverflow, fileOffset <= UInt64(backing.data.count),
                  chunk <= UInt64(backing.data.count) - fileOffset,
                  fileOffset <= UInt64(Int.max), chunk <= UInt64(Int.max) else {
                throw X64DyldSharedCacheError.malformed("Shared-cache VM-to-file translation exceeds its backing file.")
            }
            let start = Int(fileOffset)
            output.append(backing.data.subdata(in: start..<(start + Int(chunk))))
            cursor += chunk
        }
        return output
    }

    func containsVMRange(address: UInt64, size: UInt64) -> Bool {
        guard size > 0 else { return true }
        let (endAddress, overflow) = address.addingReportingOverflow(size)
        guard !overflow else { return false }
        var cursor = address
        while cursor < endAddress {
            guard let mapping = mappings.first(where: { cursor >= $0.address && cursor < $0.endAddress }) else {
                return false
            }
            cursor = min(endAddress, mapping.endAddress)
        }
        return true
    }
}

/// A read-only parser for Apple's on-disk dyld shared-cache format.
///
/// It inventories image paths and Mach-O headers, converts cache VM addresses
/// to file offsets, and can explicitly validate version-2 slide chains. It does
/// not map cache pages into guest memory, apply cache slides, or initialize dyld.
enum X64DyldSharedCacheReader {
    static let cpuTypeX86_64: UInt32 = 0x0100_0007
    private static let machMagic64: UInt32 = 0xFEED_FACF
    private static let machFileTypeDylib: UInt32 = 0x6
    private static let headerMinimumSize = 552
    private static let mappingEntrySize = 32
    private static let mappingWithSlideEntrySize = 56
    private static let imageEntrySize = 32
    private static let subcacheEntrySize = 56
    private static let maximumMappingCount: UInt32 = 256
    private static let maximumImageCount: UInt32 = 200_000
    private static let maximumSubcacheCount: UInt32 = 64
    private static let maximumPathBytes = 4_096

    private struct CacheFile {
        let url: URL
        let data: Data
        let mappings: [X64DyldSharedCacheMapping]
        let slideMappings: [X64DyldSharedCacheSlideMapping]
    }

    /// Known x86_64 cache products, ordered from the full Rosetta cache to
    /// reduced/support and legacy OS locations. Apple Silicon places Intel
    /// compatibility caches in the Rosetta Cryptex rather than necessarily in
    /// the native OS Cryptex tree.
    static func defaultCandidatePaths() -> [String] {
        let cacheName = "dyld_shared_cache_x86_64"
        return [
            // Full Rosetta cache.
            "/System/Volumes/Preboot/Cryptexes/Rosetta/System/Library/dyld/\(cacheName)",
            // Reduced Rosetta x86Support cache.
            "/System/Volumes/Preboot/Cryptexes/Rosetta/System/x86Support/System/Library/dyld/\(cacheName)",
            // Staged Rosetta product during OS updates.
            "/System/Volumes/Preboot/Cryptexes/Incoming/Rosetta/System/Library/dyld/\(cacheName)",
            "/System/Volumes/Preboot/Cryptexes/Incoming/Rosetta/System/x86Support/System/Library/dyld/\(cacheName)",
            // Equivalent Preboot paths used by some mount configurations.
            "/private/preboot/Cryptexes/Rosetta/System/Library/dyld/\(cacheName)",
            "/private/preboot/Cryptexes/Rosetta/System/x86Support/System/Library/dyld/\(cacheName)",
            // Native OS Cryptex and legacy locations. These may contain only
            // the host architecture, so the parser still validates the magic.
            "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/\(cacheName)",
            "/private/preboot/Cryptexes/OS/System/Library/dyld/\(cacheName)",
            "/System/Cryptexes/OS/System/Library/dyld/\(cacheName)",
            "/System/Library/dyld/\(cacheName)",
            "/var/db/dyld/\(cacheName)"
        ]
    }

    static func discoverDefault(
        fileManager: FileManager = .default,
        candidates suppliedCandidates: [URL]? = nil
    ) throws -> X64DyldSharedCacheSummary {
        let candidates = suppliedCandidates ?? defaultCandidatePaths().map { URL(fileURLWithPath: $0) }
        var attempted: [String] = []
        var rejected: [String] = []
        var seenPaths = Set<String>()

        for candidate in candidates {
            let standardized = candidate.standardizedFileURL
            let path = standardized.path
            guard seenPaths.insert(path).inserted else { continue }
            attempted.append(path)
            guard fileManager.fileExists(atPath: path) else { continue }

            do {
                return try open(standardized)
            } catch {
                // A stale, staged, or host-architecture cache must not prevent
                // trying the next known Rosetta product. Every rejection is
                // retained in the final diagnostic rather than hidden.
                rejected.append("\(path): \(error.localizedDescription)")
            }
        }

        if rejected.isEmpty {
            throw X64DyldSharedCacheError.notFound(attempted)
        }
        throw X64DyldSharedCacheError.noUsableCandidate(rejected)
    }

    static func open(_ url: URL) throws -> X64DyldSharedCacheSummary {
        let standardizedURL = url.standardizedFileURL
        let primaryData: Data
        do {
            primaryData = try Data(contentsOf: standardizedURL, options: [.mappedIfSafe])
        } catch {
            throw X64DyldSharedCacheError.unreadable(path: standardizedURL.path, reason: error.localizedDescription)
        }
        guard primaryData.count >= headerMinimumSize else {
            throw X64DyldSharedCacheError.malformed("Shared-cache header is truncated (\(primaryData.count) bytes).")
        }

        let magicData = primaryData.subdata(in: 0..<16)
        let magic = String(data: magicData.prefix { $0 != 0 }, encoding: .ascii) ?? ""
        guard magic.hasPrefix("dyld_v1"), magic.hasSuffix("x86_64") else {
            throw X64DyldSharedCacheError.unsupportedArchitecture(magic)
        }

        let primaryMappings = try parseMappings(primaryData, label: standardizedURL.lastPathComponent)
        let primarySlideMappings = try parseSlideMappings(
            primaryData,
            label: standardizedURL.lastPathComponent,
            mappings: primaryMappings
        )
        let imageOffset = UInt64(readLE32(primaryData, at: 448))
        let imageCount = readLE32(primaryData, at: 452)
        guard imageCount <= maximumImageCount else {
            throw X64DyldSharedCacheError.malformed("Shared-cache image count exceeds the safety limit.")
        }
        try validateRange(
            offset: imageOffset,
            count: UInt64(imageCount),
            stride: UInt64(imageEntrySize),
            dataCount: primaryData.count,
            label: "image-info array"
        )

        let subcacheOffset = UInt64(readLE32(primaryData, at: 392))
        let subcacheCount = readLE32(primaryData, at: 396)
        guard subcacheCount <= maximumSubcacheCount else {
            throw X64DyldSharedCacheError.malformed("Shared-cache subcache count exceeds the safety limit.")
        }
        var cacheFiles = [CacheFile(
            url: standardizedURL,
            data: primaryData,
            mappings: primaryMappings,
            slideMappings: primarySlideMappings
        )]
        var subcachePaths: [String] = []
        if subcacheCount > 0 {
            try validateRange(
                offset: subcacheOffset,
                count: UInt64(subcacheCount),
                stride: UInt64(subcacheEntrySize),
                dataCount: primaryData.count,
                label: "subcache-entry array"
            )
            for index in 0..<Int(subcacheCount) {
                let entry = Int(subcacheOffset) + index * subcacheEntrySize
                let suffixBytes = primaryData.subdata(in: (entry + 24)..<(entry + subcacheEntrySize))
                guard let nul = suffixBytes.firstIndex(of: 0), nul > 0,
                      let suffix = String(data: suffixBytes[..<nul], encoding: .ascii),
                      suffix.first == ".",
                      suffix.utf8.allSatisfy({ ($0 >= 48 && $0 <= 57) || ($0 >= 65 && $0 <= 90) || ($0 >= 97 && $0 <= 122) || $0 == 46 || $0 == 95 || $0 == 45 }) else {
                    throw X64DyldSharedCacheError.unsupportedFormat("This cache uses a legacy subcache entry without a filename suffix; split-cache mapping is not safe to guess.")
                }
                let subcacheURL = standardizedURL.deletingLastPathComponent()
                    .appendingPathComponent(standardizedURL.lastPathComponent + suffix)
                let subcacheData: Data
                do {
                    subcacheData = try Data(contentsOf: subcacheURL, options: [.mappedIfSafe])
                } catch {
                    throw X64DyldSharedCacheError.unreadable(path: subcacheURL.path, reason: error.localizedDescription)
                }
                guard subcacheData.count >= headerMinimumSize else {
                    throw X64DyldSharedCacheError.malformed("Subcache \(suffix) has a truncated header.")
                }
                let subMagicBytes = subcacheData.subdata(in: 0..<16)
                let subMagic = String(data: subMagicBytes.prefix { $0 != 0 }, encoding: .ascii) ?? ""
                guard subMagic.hasPrefix("dyld_v1"), subMagic.hasSuffix("x86_64") else {
                    throw X64DyldSharedCacheError.unsupportedArchitecture("Subcache \(suffix): \(subMagic)")
                }
                let expectedUUID = primaryData.subdata(in: entry..<(entry + 16))
                let actualUUID = subcacheData.subdata(in: 88..<104)
                guard expectedUUID == actualUUID else {
                    throw X64DyldSharedCacheError.malformed("Subcache \(suffix) UUID does not match its primary-cache entry.")
                }
                let subMappings = try parseMappings(subcacheData, label: subcacheURL.lastPathComponent)
                let subSlideMappings = try parseSlideMappings(
                    subcacheData,
                    label: subcacheURL.lastPathComponent,
                    mappings: subMappings
                )
                cacheFiles.append(CacheFile(
                    url: subcacheURL,
                    data: subcacheData,
                    mappings: subMappings,
                    slideMappings: subSlideMappings
                ))
                subcachePaths.append(subcacheURL.path)
            }
        }

        let allMappings = cacheFiles.flatMap(\.mappings).sorted { $0.address < $1.address }
        try validateNonOverlappingMappings(allMappings)
        let allSlideMappings = cacheFiles.flatMap(\.slideMappings).sorted { $0.address < $1.address }

        let imageArrayStart = Int(imageOffset)
        var images: [X64DyldSharedCacheImageRecord] = []
        images.reserveCapacity(Int(imageCount))
        var seenPaths = Set<String>()
        for index in 0..<Int(imageCount) {
            let recordOffset = imageArrayStart + index * imageEntrySize
            let address = readLE64(primaryData, at: recordOffset)
            let modificationTime = readLE64(primaryData, at: recordOffset + 8)
            let inode = readLE64(primaryData, at: recordOffset + 16)
            let pathOffset = UInt64(readLE32(primaryData, at: recordOffset + 24))
            let path = try readCString(primaryData, offset: pathOffset, label: "image path")
            guard seenPaths.insert(path).inserted else { continue }

            let headerBytes = readVMBytes(address: address, count: 32, files: cacheFiles)
            let cpuType: UInt32?
            let fileType: UInt32?
            if let headerBytes, readLE32(headerBytes, at: 0) == machMagic64 {
                cpuType = readLE32(headerBytes, at: 4)
                fileType = readLE32(headerBytes, at: 12)
            } else {
                cpuType = nil
                fileType = nil
            }
            images.append(X64DyldSharedCacheImageRecord(
                installName: path,
                machHeaderAddress: address,
                modificationTime: modificationTime,
                inode: inode,
                cpuType: cpuType,
                fileType: fileType
            ))
        }

        let uuidBytes = primaryData.subdata(in: 88..<104)
        let uuid = uuidBytes.map { String(format: "%02x", $0) }.joined()
        return X64DyldSharedCacheSummary(
            url: standardizedURL,
            magic: magic,
            uuid: uuid,
            platform: readLE32(primaryData, at: 216),
            cacheType: readLE64(primaryData, at: 104),
            sharedRegionStart: readLE64(primaryData, at: 224),
            sharedRegionSize: readLE64(primaryData, at: 232),
            mappings: allMappings,
            slideMappings: allSlideMappings,
            images: images.sorted { $0.installName < $1.installName },
            subcachePaths: subcachePaths,
            backingFiles: cacheFiles.map {
                X64DyldSharedCacheBackingFile(
                    url: $0.url,
                    data: $0.data,
                    mappings: $0.mappings,
                    slideMappings: $0.slideMappings
                )
            }
        )
    }

    static func fileLocation(
        forVMAddress address: UInt64,
        mappings: [X64DyldSharedCacheMapping]
    ) -> (fileOffset: UInt64, mapping: X64DyldSharedCacheMapping)? {
        guard let mapping = mappings.first(where: { address >= $0.address && address - $0.address < $0.size }) else {
            return nil
        }
        let delta = address - mapping.address
        let (fileOffset, overflow) = mapping.fileOffset.addingReportingOverflow(delta)
        guard !overflow else { return nil }
        return (fileOffset, mapping)
    }

    /// Performs the potentially expensive read-only slide-chain walk on demand.
    /// Inventory and dependency lookup therefore do not scan every cache page.
    static func analyzeSlideInfo(in cache: X64DyldSharedCacheSummary) throws -> [X64DyldSharedCacheSlideInfoSummary] {
        try cache.backingFiles.flatMap { backing in
            try parseSlideInfoSummaries(in: CacheFile(
                url: backing.url,
                data: backing.data,
                mappings: backing.mappings,
                slideMappings: backing.slideMappings
            ))
        }
    }

    private static func parseMappings(_ data: Data, label: String) throws -> [X64DyldSharedCacheMapping] {
        let offset = UInt64(readLE32(data, at: 16))
        let count = readLE32(data, at: 20)
        guard count > 0, count <= maximumMappingCount else {
            throw X64DyldSharedCacheError.malformed("\(label) has an invalid mapping count (\(count)).")
        }
        try validateRange(offset: offset, count: UInt64(count), stride: UInt64(mappingEntrySize), dataCount: data.count, label: "\(label) mapping array")
        var mappings: [X64DyldSharedCacheMapping] = []
        mappings.reserveCapacity(Int(count))
        for index in 0..<Int(count) {
            let cursor = Int(offset) + index * mappingEntrySize
            let address = readLE64(data, at: cursor)
            let size = readLE64(data, at: cursor + 8)
            let fileOffset = readLE64(data, at: cursor + 16)
            let maximumProtection = readLE32(data, at: cursor + 24)
            let initialProtection = readLE32(data, at: cursor + 28)
            guard size > 0, address <= UInt64.max - size else {
                throw X64DyldSharedCacheError.malformed("\(label) mapping \(index) has an empty or overflowing VM range.")
            }
            guard fileOffset <= UInt64(data.count), size <= UInt64(data.count) - fileOffset else {
                throw X64DyldSharedCacheError.malformed("\(label) mapping \(index) points outside its cache file.")
            }
            mappings.append(X64DyldSharedCacheMapping(
                address: address,
                size: size,
                fileOffset: fileOffset,
                maximumProtection: maximumProtection,
                initialProtection: initialProtection
            ))
        }
        return mappings
    }

    /// Parses the modern mapping-with-slide array. Each row must refer to one
    /// exact legacy mapping in the same cache file; accepting approximate
    /// matches could associate slide chains with the wrong file pages.
    private static func parseSlideMappings(
        _ data: Data,
        label: String,
        mappings: [X64DyldSharedCacheMapping]
    ) throws -> [X64DyldSharedCacheSlideMapping] {
        let offset = UInt64(readLE32(data, at: 312))
        let count = readLE32(data, at: 316)
        guard count <= maximumMappingCount else {
            throw X64DyldSharedCacheError.malformed("\(label) has an invalid mapping-with-slide count (\(count)).")
        }
        try validateRange(
            offset: offset,
            count: UInt64(count),
            stride: UInt64(mappingWithSlideEntrySize),
            dataCount: data.count,
            label: "\(label) mapping-with-slide array"
        )

        var result: [X64DyldSharedCacheSlideMapping] = []
        result.reserveCapacity(Int(count))
        var seenAddresses = Set<UInt64>()
        for index in 0..<Int(count) {
            let cursor = Int(offset) + index * mappingWithSlideEntrySize
            let address = readLE64(data, at: cursor)
            let size = readLE64(data, at: cursor + 8)
            let fileOffset = readLE64(data, at: cursor + 16)
            let slideInfoFileOffset = readLE64(data, at: cursor + 24)
            let slideInfoFileSize = readLE64(data, at: cursor + 32)
            let flags = readLE64(data, at: cursor + 40)
            let maximumProtection = readLE32(data, at: cursor + 48)
            let initialProtection = readLE32(data, at: cursor + 52)

            let (_, endOverflow) = address.addingReportingOverflow(size)
            guard size > 0, !endOverflow else {
                throw X64DyldSharedCacheError.malformed("\(label) mapping-with-slide row \(index) has an empty or overflowing VM range.")
            }
            guard seenAddresses.insert(address).inserted else {
                throw X64DyldSharedCacheError.malformed(String(format: "%@ has duplicate mapping-with-slide address 0x%016llX.", label, address))
            }
            guard let legacy = mappings.first(where: {
                $0.address == address && $0.size == size && $0.fileOffset == fileOffset
                    && $0.maximumProtection == maximumProtection
                    && $0.initialProtection == initialProtection
            }) else {
                throw X64DyldSharedCacheError.malformed(String(format: "%@ mapping-with-slide row %d does not exactly match a legacy mapping (0x%016llX + 0x%llX).", label, index, address, size))
            }
            _ = legacy
            guard fileOffset <= UInt64(data.count), size <= UInt64(data.count) - fileOffset else {
                throw X64DyldSharedCacheError.malformed("\(label) mapping-with-slide row \(index) exceeds its backing file.")
            }
            if slideInfoFileSize == 0 {
                guard slideInfoFileOffset == 0 else {
                    throw X64DyldSharedCacheError.malformed("\(label) mapping-with-slide row \(index) has a slide-info offset but an empty slide-info range.")
                }
            } else {
                guard slideInfoFileOffset <= UInt64(data.count),
                      slideInfoFileSize <= UInt64(data.count) - slideInfoFileOffset,
                      slideInfoFileSize >= 4 else {
                    throw X64DyldSharedCacheError.malformed("\(label) mapping-with-slide row \(index) has an invalid slide-info file range.")
                }
            }
            result.append(X64DyldSharedCacheSlideMapping(
                address: address,
                size: size,
                fileOffset: fileOffset,
                slideInfoFileOffset: slideInfoFileOffset,
                slideInfoFileSize: slideInfoFileSize,
                flags: flags,
                maximumProtection: maximumProtection,
                initialProtection: initialProtection
            ))
        }
        return result
    }

    /// Walks version-2 slide chains without mutating the cache. This validates
    /// the page-start/extra arrays and every pointer-sized chain read so later
    /// page materialization can reuse the same decoding rules safely.
    private static func parseSlideInfoSummaries(in cacheFile: CacheFile) throws -> [X64DyldSharedCacheSlideInfoSummary] {
        var summaries: [X64DyldSharedCacheSlideInfoSummary] = []
        for mapping in cacheFile.slideMappings where mapping.slideInfoFileSize > 0 {
            let blobOffset = Int(mapping.slideInfoFileOffset)
            let blobSize = Int(mapping.slideInfoFileSize)
            let blob = cacheFile.data.subdata(in: blobOffset..<(blobOffset + blobSize))
            guard blob.count >= 40 else {
                throw X64DyldSharedCacheError.malformed("Slide-info blob for mapping 0x\(String(mapping.address, radix: 16)) is shorter than the version-2 header.")
            }
            let version = readLE32(blob, at: 0)
            guard version == 2 else {
                throw X64DyldSharedCacheError.unsupportedFormat("The x86_64 cache uses slide-info version \(version) at mapping 0x\(String(mapping.address, radix: 16)); this Kestrel build currently validates version 2 only.")
            }

            let pageSize = readLE32(blob, at: 4)
            let pageStartsOffset = UInt64(readLE32(blob, at: 8))
            let pageStartsCount = UInt64(readLE32(blob, at: 12))
            let pageExtrasOffset = UInt64(readLE32(blob, at: 16))
            let pageExtrasCount = UInt64(readLE32(blob, at: 20))
            let deltaMask = readLE64(blob, at: 24)
            let valueAdd = readLE64(blob, at: 32)

            guard pageSize == 4096 || pageSize == 16_384 else {
                throw X64DyldSharedCacheError.unsupportedFormat("Slide-info v2 declares unsupported page size \(pageSize); expected 4096 or 16384 bytes.")
            }
            guard mapping.size % UInt64(pageSize) == 0 else {
                throw X64DyldSharedCacheError.malformed("Slide-info mapping size is not an exact multiple of its page size.")
            }
            let expectedPageCount = mapping.size / UInt64(pageSize)
            guard pageStartsCount == expectedPageCount, pageStartsCount <= 50_000_000 else {
                throw X64DyldSharedCacheError.malformed("Slide-info page-start count does not match the mapped page count or exceeds the safety limit.")
            }
            guard deltaMask != 0 else {
                throw X64DyldSharedCacheError.malformed("Slide-info v2 has an empty pointer delta mask.")
            }
            let trailingZeros = deltaMask.trailingZeroBitCount
            guard trailingZeros >= 2, trailingZeros < 64 else {
                throw X64DyldSharedCacheError.malformed("Slide-info v2 pointer delta mask has an invalid shift.")
            }
            let shiftedDeltaMask = deltaMask >> trailingZeros
            guard (shiftedDeltaMask & (shiftedDeltaMask &+ 1)) == 0 else {
                throw X64DyldSharedCacheError.malformed("Slide-info v2 pointer delta mask is not a contiguous bit field.")
            }
            let deltaShift = trailingZeros - 2

            try validateRange(
                offset: pageStartsOffset,
                count: pageStartsCount,
                stride: 2,
                dataCount: blob.count,
                label: "slide-info page-start array"
            )
            try validateRange(
                offset: pageExtrasOffset,
                count: pageExtrasCount,
                stride: 2,
                dataCount: blob.count,
                label: "slide-info page-extras array"
            )
            let pageStartsEnd = pageStartsOffset + pageStartsCount * 2
            let pageExtrasEnd = pageExtrasOffset + pageExtrasCount * 2
            guard pageStartsOffset >= 40,
                  pageExtrasCount == 0 || pageExtrasOffset >= 40,
                  pageExtrasCount == 0 || pageStartsEnd <= pageExtrasOffset || pageExtrasEnd <= pageStartsOffset else {
                throw X64DyldSharedCacheError.malformed("Slide-info v2 arrays overlap the header or each other.")
            }

            var pagesWithRebases: UInt64 = 0
            var chainCount: UInt64 = 0
            var rebasingPointerCount: UInt64 = 0
            let valueMask = ~deltaMask
            let maximumFixupCount: UInt64 = 50_000_000

            func readPointer(at pageIndex: UInt64, pageOffset: UInt64) throws -> UInt64 {
                let (pageDelta, pageOverflow) = pageIndex.multipliedReportingOverflow(by: UInt64(pageSize))
                let (mappingOffset, mappingOverflow) = mapping.fileOffset.addingReportingOverflow(pageDelta)
                let (pointerOffset, pointerOverflow) = mappingOffset.addingReportingOverflow(pageOffset)
                guard !pageOverflow, !mappingOverflow, !pointerOverflow,
                      pointerOffset <= UInt64(cacheFile.data.count),
                      8 <= UInt64(cacheFile.data.count) - pointerOffset,
                      pointerOffset <= UInt64(Int.max) else {
                    throw X64DyldSharedCacheError.malformed("Slide-info chain pointer exceeds its backing cache mapping.")
                }
                return readLE64(cacheFile.data, at: Int(pointerOffset))
            }

            for pageIndex in 0..<pageStartsCount {
                let startWordOffset = Int(pageStartsOffset + pageIndex * 2)
                let pageStart = readLE16(blob, at: startWordOffset)
                if pageStart == 0x4000 { continue } // DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE
                if (pageStart & 0x4000) != 0 {
                    throw X64DyldSharedCacheError.malformed("Slide-info page-start entry combines the no-rebase flag with unsupported bits.")
                }

                var chainStarts: [UInt64] = []
                if (pageStart & 0x8000) != 0 {
                    let extrasIndex = UInt64(pageStart & 0x3FFF)
                    guard extrasIndex < pageExtrasCount else {
                        throw X64DyldSharedCacheError.malformed("Slide-info page-start references an out-of-range page-extras entry.")
                    }
                    var extraIndex = extrasIndex
                    var foundEnd = false
                    while extraIndex < pageExtrasCount {
                        let wordOffset = Int(pageExtrasOffset + extraIndex * 2)
                        let extra = readLE16(blob, at: wordOffset)
                        chainStarts.append(UInt64(extra & 0x7FFF) * 4)
                        if (extra & 0x8000) != 0 {
                            foundEnd = true
                            break
                        }
                        extraIndex += 1
                    }
                    guard foundEnd else {
                        throw X64DyldSharedCacheError.malformed("Slide-info page-extras chain list has no terminating END flag.")
                    }
                    guard chainStarts.count >= 2 else {
                        throw X64DyldSharedCacheError.malformed("Slide-info page-extras encoding must provide at least two chain starts.")
                    }
                } else {
                    chainStarts = [UInt64(pageStart) * 4]
                }

                var pageHasRebases = false
                var seenOffsets = Set<UInt64>()
                for chainStart in chainStarts {
                    guard chainStart % 4 == 0,
                          chainStart + 8 <= UInt64(pageSize) else {
                        throw X64DyldSharedCacheError.malformed("Slide-info chain begins outside its page or is not four-byte aligned.")
                    }
                    chainCount += 1
                    guard chainCount <= maximumFixupCount else {
                        throw X64DyldSharedCacheError.malformed("Slide-info chain count exceeds the safety limit.")
                    }
                    var location = chainStart
                    var steps: UInt64 = 0
                    while true {
                        guard seenOffsets.insert(location).inserted else {
                            throw X64DyldSharedCacheError.malformed("Slide-info contains duplicate or cyclic pointer chains within one page.")
                        }
                        let rawValue = try readPointer(at: pageIndex, pageOffset: location)
                        let encodedValue = rawValue & valueMask
                        if encodedValue != 0 {
                            let (_, addOverflow) = encodedValue.addingReportingOverflow(valueAdd)
                            guard !addOverflow else {
                                throw X64DyldSharedCacheError.malformed("Slide-info pointer value plus value-add overflows 64 bits.")
                            }
                            rebasingPointerCount += 1
                            pageHasRebases = true
                            guard rebasingPointerCount <= maximumFixupCount else {
                                throw X64DyldSharedCacheError.malformed("Slide-info rebasing pointer count exceeds the safety limit.")
                            }
                        }
                        let delta = (rawValue & deltaMask) >> deltaShift
                        if delta == 0 { break }
                        guard delta % 4 == 0 else {
                            throw X64DyldSharedCacheError.malformed("Slide-info pointer chain delta is not four-byte aligned.")
                        }
                        let (nextLocation, nextOverflow) = location.addingReportingOverflow(delta)
                        let (nextLocationEnd, nextEndOverflow) = nextLocation.addingReportingOverflow(8)
                        guard !nextOverflow, !nextEndOverflow, nextLocation > location,
                              nextLocationEnd <= UInt64(pageSize) else {
                            throw X64DyldSharedCacheError.malformed("Slide-info pointer chain leaves its page or overflows.")
                        }
                        location = nextLocation
                        steps += 1
                        guard steps < UInt64(pageSize / 4) else {
                            throw X64DyldSharedCacheError.malformed("Slide-info pointer chain exceeds its per-page step limit.")
                        }
                    }
                }
                if pageHasRebases { pagesWithRebases += 1 }
            }

            summaries.append(X64DyldSharedCacheSlideInfoSummary(
                mappingAddress: mapping.address,
                mappingSize: mapping.size,
                version: version,
                pageSize: pageSize,
                pageCount: pageStartsCount,
                pagesWithRebases: pagesWithRebases,
                chainCount: chainCount,
                rebasingPointerCount: rebasingPointerCount
            ))
        }
        return summaries
    }

    private static func validateNonOverlappingMappings(_ mappings: [X64DyldSharedCacheMapping]) throws {
        guard !mappings.isEmpty else { throw X64DyldSharedCacheError.malformed("Shared cache contains no mappings.") }
        for pair in zip(mappings, mappings.dropFirst()) where pair.0.endAddress > pair.1.address {
            throw X64DyldSharedCacheError.malformed("Shared-cache VM mappings overlap at 0x\(String(pair.1.address, radix: 16)).")
        }
    }

    private static func readVMBytes(address: UInt64, count: Int, files: [CacheFile]) -> Data? {
        guard count >= 0 else { return nil }
        for file in files {
            for mapping in file.mappings where address >= mapping.address {
                let delta = address - mapping.address
                guard delta <= mapping.size, UInt64(count) <= mapping.size - delta else { continue }
                let (offset, overflow) = mapping.fileOffset.addingReportingOverflow(delta)
                guard !overflow, offset <= UInt64(file.data.count), UInt64(count) <= UInt64(file.data.count) - offset,
                      offset <= UInt64(Int.max) else { continue }
                let start = Int(offset)
                return file.data.subdata(in: start..<(start + count))
            }
        }
        return nil
    }

    private static func readCString(_ data: Data, offset: UInt64, label: String) throws -> String {
        guard offset < UInt64(data.count), offset <= UInt64(Int.max) else {
            throw X64DyldSharedCacheError.malformed("\(label) offset is outside the primary cache file.")
        }
        let start = Int(offset)
        let endLimit = min(data.count, start + maximumPathBytes)
        guard let terminator = data[start..<endLimit].firstIndex(of: 0), terminator > start,
              let value = String(data: data[start..<terminator], encoding: .utf8), value.hasPrefix("/") else {
            throw X64DyldSharedCacheError.malformed("\(label) is unterminated, empty, too long, or not an absolute path.")
        }
        return value
    }

    private static func validateRange(offset: UInt64, count: UInt64, stride: UInt64, dataCount: Int, label: String) throws {
        let (bytes, multiplyOverflow) = count.multipliedReportingOverflow(by: stride)
        let (end, addOverflow) = offset.addingReportingOverflow(bytes)
        guard !multiplyOverflow, !addOverflow, end <= UInt64(dataCount) else {
            throw X64DyldSharedCacheError.malformed("\(label) extends beyond the cache file.")
        }
    }

    private static func readLE32(_ data: Data, at offset: Int) -> UInt32 {
        UInt32(data[offset])
            | (UInt32(data[offset + 1]) << 8)
            | (UInt32(data[offset + 2]) << 16)
            | (UInt32(data[offset + 3]) << 24)
    }

    private static func readLE16(_ data: Data, at offset: Int) -> UInt16 {
        UInt16(data[offset]) | (UInt16(data[offset + 1]) << 8)
    }

    private static func readLE64(_ data: Data, at offset: Int) -> UInt64 {
        UInt64(readLE32(data, at: offset)) | (UInt64(readLE32(data, at: offset + 4)) << 32)
    }
}

enum X64DyldSharedCacheError: LocalizedError {
    case notFound([String])
    case noUsableCandidate([String])
    case unreadable(path: String, reason: String)
    case unsupportedArchitecture(String)
    case unsupportedFormat(String)
    case malformed(String)

    var errorDescription: String? {
        switch self {
        case .notFound(let paths):
            return "No x86_64 dyld shared cache was found. Checked: \(paths.joined(separator: ", "))"
        case .noUsableCandidate(let failures):
            return "Found candidate dyld shared-cache files, but none was a usable baseline x86_64 cache: \(failures.joined(separator: " | "))"
        case .unreadable(let path, let reason):
            return "Cannot read dyld shared cache at \(path): \(reason)"
        case .unsupportedArchitecture(let magic):
            return "Unsupported dyld shared-cache architecture (magic: \(magic)). Kestrel requires an x86_64 cache."
        case .unsupportedFormat(let message), .malformed(let message):
            return message
        }
    }
}

// MARK: - x86_64 dyld image and __dyld_start discovery

struct X64DyldSharedCacheDylinkerEntry: Sendable, Equatable {
    let installName: String
    let machHeaderAddress: UInt64
    let entryPoint: UInt64
    let executableSegments: [Range<UInt64>]
}

/// Finds the real x86_64 dynamic linker in the Rosetta shared cache and reads
/// its kernel entrypoint. LC_UNIXTHREAD's x86_THREAD_STATE64.rip is the
/// preferred source; LC_MAIN is accepted only as a validated fallback.
enum X64DyldSharedCacheDylinkerReader {
    private static let machMagic64: UInt32 = 0xFEED_FACF
    private static let cpuTypeX86_64: UInt32 = 0x0100_0007
    private static let fileTypeDylinker: UInt32 = 0x7
    private static let lcUnixThread: UInt32 = 0x5
    private static let lcSegment64: UInt32 = 0x19
    private static let lcMain: UInt32 = 0x8000_0028
    private static let x86ThreadState64Flavor: UInt32 = 4
    private static let x86ThreadState64WordCount: UInt32 = 42
    private static let x86ThreadState64RIPIndex = 16
    private static let machHeaderSize = 32
    private static let segmentCommandSize = 72
    private static let maximumLoadCommands: UInt32 = 65_536
    private static let maximumCommandBytes: UInt32 = 16 * 1024 * 1024

    private struct Segment {
        let name: String
        let virtualAddress: UInt64
        let virtualSize: UInt64
        let fileOffset: UInt64
        let fileSize: UInt64
        let initialProtection: UInt32

        var virtualEnd: UInt64 { virtualAddress + virtualSize }
        var fileEnd: UInt64 { fileOffset + fileSize }
        var isExecutable: Bool { (initialProtection & 0x4) != 0 }
    }

    static func find(in cache: X64DyldSharedCacheSummary) throws -> X64DyldSharedCacheDylinkerEntry? {
        let candidates = cache.images.filter {
            $0.hasReadableX86_64Header && $0.fileType == fileTypeDylinker
        }
        guard !candidates.isEmpty else { return nil }

        let canonical = candidates.filter { $0.installName == "/usr/lib/dyld" }
        let selected: X64DyldSharedCacheImageRecord
        if canonical.count == 1, let image = canonical.first {
            selected = image
        } else if canonical.count > 1 {
            throw X64DyldSharedCacheError.malformed("The x86_64 shared cache contains multiple /usr/lib/dyld image records.")
        } else if candidates.count == 1, let image = candidates.first {
            selected = image
        } else {
            let names = candidates.prefix(8).map(\.installName).joined(separator: ", ")
            throw X64DyldSharedCacheError.malformed("The x86_64 shared cache contains multiple MH_DYLINKER candidates and none is the canonical /usr/lib/dyld image: \(names).")
        }

        return try parse(cache: cache, image: selected)
    }

    private static func parse(
        cache: X64DyldSharedCacheSummary,
        image: X64DyldSharedCacheImageRecord
    ) throws -> X64DyldSharedCacheDylinkerEntry {
        let header = try cache.readVMBytes(atVMAddress: image.machHeaderAddress, count: machHeaderSize)
        guard readLE32(header, 0) == machMagic64,
              readLE32(header, 4) == cpuTypeX86_64,
              readLE32(header, 12) == fileTypeDylinker else {
            throw X64DyldSharedCacheError.malformed("Cached dynamic linker \(image.installName) has an invalid x86_64 MH_DYLINKER header.")
        }

        let commandCount = readLE32(header, 16)
        let commandBytes = readLE32(header, 20)
        guard commandCount <= maximumLoadCommands, commandBytes <= maximumCommandBytes else {
            throw X64DyldSharedCacheError.malformed("Cached dynamic linker \(image.installName) has unreasonable Mach-O load-command dimensions.")
        }
        let (totalBytes, overflow) = UInt64(machHeaderSize).addingReportingOverflow(UInt64(commandBytes))
        guard !overflow, totalBytes <= UInt64(Int.max) else {
            throw X64DyldSharedCacheError.malformed("Cached dynamic linker \(image.installName) load-command range overflows.")
        }
        let commands = try cache.readVMBytes(atVMAddress: image.machHeaderAddress, count: Int(totalBytes))
        let commandEnd = machHeaderSize + Int(commandBytes)
        var cursor = machHeaderSize
        var segments: [Segment] = []
        var threadEntryPoint: UInt64?
        var mainEntryOffset: UInt64?

        for commandIndex in 0..<Int(commandCount) {
            guard cursor <= commandEnd - 8 else {
                throw X64DyldSharedCacheError.malformed("Cached dynamic linker load command \(commandIndex) is truncated.")
            }
            let command = readLE32(commands, cursor)
            let commandSize = readLE32(commands, cursor + 4)
            guard commandSize >= 8, UInt64(commandSize) <= UInt64(commandEnd - cursor) else {
                throw X64DyldSharedCacheError.malformed("Cached dynamic linker load command \(commandIndex) has an invalid size.")
            }

            switch command {
            case lcSegment64:
                guard commandSize >= segmentCommandSize else {
                    throw X64DyldSharedCacheError.malformed("Cached dynamic linker contains a truncated LC_SEGMENT_64 command.")
                }
                let sectionCount = readLE32(commands, cursor + 64)
                let (sectionBytes, sectionOverflow) = UInt64(sectionCount).multipliedReportingOverflow(by: 80)
                let (minimumSize, commandOverflow) = UInt64(segmentCommandSize).addingReportingOverflow(sectionBytes)
                guard !sectionOverflow, !commandOverflow, minimumSize <= UInt64(commandSize) else {
                    throw X64DyldSharedCacheError.malformed("Cached dynamic linker segment sections exceed their load command.")
                }
                let nameBytes = commands[(cursor + 8)..<(cursor + 24)]
                let name = String(decoding: nameBytes.prefix { $0 != 0 }, as: UTF8.self)
                let vmAddress = readLE64(commands, cursor + 24)
                let vmSize = readLE64(commands, cursor + 32)
                let fileOffset = readLE64(commands, cursor + 40)
                let fileSize = readLE64(commands, cursor + 48)
                let maximumProtection = readLE32(commands, cursor + 56)
                let initialProtection = readLE32(commands, cursor + 60)
                let (_, vmOverflow) = vmAddress.addingReportingOverflow(vmSize)
                let (_, fileOverflow) = fileOffset.addingReportingOverflow(fileSize)
                guard !vmOverflow, !fileOverflow, fileSize <= vmSize,
                      (maximumProtection & ~UInt32(0x7)) == 0,
                      (initialProtection & ~UInt32(0x7)) == 0,
                      (initialProtection & ~maximumProtection) == 0 else {
                    throw X64DyldSharedCacheError.malformed("Cached dynamic linker segment \(name) has an invalid VM range, file range, or protection mask.")
                }
                if vmSize > 0, name != "__PAGEZERO" {
                    segments.append(Segment(
                        name: name,
                        virtualAddress: vmAddress,
                        virtualSize: vmSize,
                        fileOffset: fileOffset,
                        fileSize: fileSize,
                        initialProtection: initialProtection
                    ))
                }

            case lcUnixThread:
                guard commandSize >= 16 else {
                    throw X64DyldSharedCacheError.malformed("Cached dynamic linker contains a truncated LC_UNIXTHREAD command.")
                }
                let flavor = readLE32(commands, cursor + 8)
                let wordCount = readLE32(commands, cursor + 12)
                let (stateBytes, stateOverflow) = UInt64(wordCount).multipliedReportingOverflow(by: 4)
                guard !stateOverflow, stateBytes <= UInt64(commandSize - 16) else {
                    throw X64DyldSharedCacheError.malformed("Cached dynamic linker LC_UNIXTHREAD state exceeds its command.")
                }
                if flavor == x86ThreadState64Flavor {
                    guard wordCount >= x86ThreadState64WordCount else {
                        throw X64DyldSharedCacheError.malformed("Cached dynamic linker x86_THREAD_STATE64 is too short to contain RIP.")
                    }
                    let ripOffset = cursor + 16 + x86ThreadState64RIPIndex * 8
                    guard ripOffset <= cursor + Int(commandSize) - 8 else {
                        throw X64DyldSharedCacheError.malformed("Cached dynamic linker x86_THREAD_STATE64 RIP is outside LC_UNIXTHREAD.")
                    }
                    let value = readLE64(commands, ripOffset)
                    if let previous = threadEntryPoint, previous != value {
                        throw X64DyldSharedCacheError.malformed("Cached dynamic linker advertises conflicting x86_64 LC_UNIXTHREAD entrypoints.")
                    }
                    threadEntryPoint = value
                }

            case lcMain:
                guard commandSize >= 24 else {
                    throw X64DyldSharedCacheError.malformed("Cached dynamic linker contains a truncated LC_MAIN command.")
                }
                let value = readLE64(commands, cursor + 8)
                if let previous = mainEntryOffset, previous != value {
                    throw X64DyldSharedCacheError.malformed("Cached dynamic linker advertises conflicting LC_MAIN entry offsets.")
                }
                mainEntryOffset = value

            default:
                break
            }

            cursor += Int(commandSize)
        }

        guard cursor == commandEnd else {
            throw X64DyldSharedCacheError.malformed("Cached dynamic linker load commands do not consume sizeofcmds exactly.")
        }
        let executableSegments = segments.filter(\.isExecutable)
        guard !executableSegments.isEmpty else {
            throw X64DyldSharedCacheError.malformed("Cached dynamic linker has no executable Mach-O segment.")
        }

        let entryPoint: UInt64
        if let threadEntryPoint {
            entryPoint = threadEntryPoint
        } else if let mainEntryOffset {
            guard let segment = segments.first(where: {
                mainEntryOffset >= $0.fileOffset && mainEntryOffset - $0.fileOffset < $0.fileSize
            }) else {
                throw X64DyldSharedCacheError.malformed("Cached dynamic linker's LC_MAIN offset is outside every file-backed segment.")
            }
            let delta = mainEntryOffset - segment.fileOffset
            let (address, addressOverflow) = segment.virtualAddress.addingReportingOverflow(delta)
            guard !addressOverflow else {
                throw X64DyldSharedCacheError.malformed("Cached dynamic linker's LC_MAIN address overflows.")
            }
            entryPoint = address
        } else {
            throw X64DyldSharedCacheError.malformed("Cached x86_64 MH_DYLINKER has neither an x86_THREAD_STATE64 LC_UNIXTHREAD entry nor LC_MAIN.")
        }

        guard executableSegments.contains(where: {
            entryPoint >= $0.virtualAddress && entryPoint < $0.virtualEnd
        }) else {
            throw X64DyldSharedCacheError.malformed(String(format: "Cached dynamic linker entrypoint 0x%016llX is not inside an executable segment.", entryPoint))
        }

        return X64DyldSharedCacheDylinkerEntry(
            installName: image.installName,
            machHeaderAddress: image.machHeaderAddress,
            entryPoint: entryPoint,
            executableSegments: executableSegments.map { $0.virtualAddress..<$0.virtualEnd }
        )
    }

    private static func readLE32(_ data: Data, _ offset: Int) -> UInt32 {
        UInt32(data[offset])
            | (UInt32(data[offset + 1]) << 8)
            | (UInt32(data[offset + 2]) << 16)
            | (UInt32(data[offset + 3]) << 24)
    }

    private static func readLE64(_ data: Data, _ offset: Int) -> UInt64 {
        UInt64(readLE32(data, offset))
            | (UInt64(readLE32(data, offset + 4)) << 32)
    }
}

// MARK: - Cached-image Mach-O segment inspection and mapping preflight

struct X64DyldSharedCacheImageSegmentPlan: Sendable, Equatable {
    let name: String
    /// Exact LC_SEGMENT_64 virtual range. Mach-O segment sizes need not be a
    /// multiple of the guest page size.
    let virtualAddress: UInt64
    let virtualSize: UInt64
    /// Base of the guest-page range containing this exact segment. Shared-cache
    /// Mach-O segments may begin inside a 4 KiB guest page.
    let pageRoundedAddress: UInt64
    /// Guest reservation span covering the exact segment after rounding its
    /// start down and end up to the 4 KiB x86_64 guest page boundaries.
    let pageRoundedSize: UInt64
    let maximumProtection: UInt32
    let initialProtection: UInt32

    var virtualEnd: UInt64 { virtualAddress + virtualSize }
    var pageRoundedEnd: UInt64 { pageRoundedAddress + pageRoundedSize }
    var isExecutable: Bool { (initialProtection & 0x4) != 0 }
}

struct X64DyldSharedCacheImagePlan: Sendable, Equatable {
    let installName: String
    let machHeaderAddress: UInt64
    let segmentPlans: [X64DyldSharedCacheImageSegmentPlan]

    var virtualBytes: UInt64 {
        segmentPlans.reduce(0) { total, segment in
            let (sum, overflow) = total.addingReportingOverflow(segment.virtualSize)
            return overflow ? UInt64.max : sum
        }
    }

    var pageRoundedReservationBytes: UInt64 {
        let sorted = segmentPlans.sorted { $0.pageRoundedAddress < $1.pageRoundedAddress }
        guard let first = sorted.first else { return 0 }
        var rangeStart = first.pageRoundedAddress
        var rangeEnd = first.pageRoundedEnd
        var total: UInt64 = 0
        for segment in sorted.dropFirst() {
            if segment.pageRoundedAddress <= rangeEnd {
                rangeEnd = max(rangeEnd, segment.pageRoundedEnd)
            } else {
                let (sum, overflow) = total.addingReportingOverflow(rangeEnd - rangeStart)
                if overflow { return UInt64.max }
                total = sum
                rangeStart = segment.pageRoundedAddress
                rangeEnd = segment.pageRoundedEnd
            }
        }
        let (sum, overflow) = total.addingReportingOverflow(rangeEnd - rangeStart)
        return overflow ? UInt64.max : sum
    }

    var textBytes: UInt64 {
        segmentPlans.filter { $0.isExecutable }.reduce(0) { total, segment in
            let (sum, overflow) = total.addingReportingOverflow(segment.virtualSize)
            return overflow ? UInt64.max : sum
        }
    }

    var linkeditBytes: UInt64 {
        segmentPlans.filter { $0.name == "__LINKEDIT" }.reduce(0) { total, segment in
            let (sum, overflow) = total.addingReportingOverflow(segment.virtualSize)
            return overflow ? UInt64.max : sum
        }
    }
}

struct X64DyldSharedCacheMappingPlan: Sendable {
    let cacheUUID: String
    let images: [X64DyldSharedCacheImagePlan]
    let slideInfoSummaries: [X64DyldSharedCacheSlideInfoSummary]
    let reservedMappingCount: Int
    let totalVirtualBytes: UInt64
    let totalPageRoundedReservationBytes: UInt64
    let executableSegmentCount: Int
    let linkeditSegmentCount: Int

    var totalSegmentCount: Int { images.reduce(0) { $0 + $1.segmentPlans.count } }
}

enum X64DyldSharedCacheImageMapper {
    private static let machMagic64: UInt32 = 0xFEED_FACF
    private static let cpuTypeX86_64: UInt32 = 0x0100_0007
    private static let fileTypeDylib: UInt32 = 0x6
    private static let fileTypeDylinker: UInt32 = 0x7
    private static let lcSegment64: UInt32 = 0x19
    private static let machHeaderSize = 32
    private static let segmentCommandSize = 72
    private static let sectionSize = 80
    private static let maximumLoadCommands: UInt32 = 65_536
    private static let maximumCommandBytes: UInt32 = 16 * 1024 * 1024

    /// Parses the Mach-O load commands of exact dependency matches and verifies
    /// that each non-PAGEZERO segment is covered by cache VM mappings. This is
    /// a preflight only: it does not mutate guest memory or make cached code
    /// executable. Cache slide-info application is a required later step.
    static func makePlan(
        cache: X64DyldSharedCacheSummary,
        dependencies: [X64MachODylibDependency],
        maximumVirtualBytes: UInt64 = 16 * 1024 * 1024 * 1024
    ) throws -> X64DyldSharedCacheMappingPlan {
        let matches = cache.matchDependencies(dependencies)
        guard !matches.isEmpty else {
            throw X64DyldSharedCacheError.malformed("The executable has no dependency images to inspect.")
        }
        var plans: [X64DyldSharedCacheImagePlan] = []
        var missing: [String] = []
        var totalVirtualBytes: UInt64 = 0
        var totalPageRoundedReservationBytes: UInt64 = 0
        var allPageSegments: [X64DyldSharedCacheImageSegmentPlan] = []
        var seenInstallNames = Set<String>()

        for match in matches {
            guard let image = match.image, image.hasReadableX86_64Header else {
                missing.append(match.installName)
                continue
            }
            guard seenInstallNames.insert(image.installName).inserted else { continue }
            guard image.fileType == fileTypeDylib || image.fileType == fileTypeDylinker else {
                throw X64DyldSharedCacheError.malformed("Cached image \(image.installName) is neither an MH_DYLIB nor an MH_DYLINKER image.")
            }

            let header = try cache.readVMBytes(atVMAddress: image.machHeaderAddress, count: machHeaderSize)
            guard readLE32(header, at: 0) == machMagic64,
                  readLE32(header, at: 4) == cpuTypeX86_64 else {
                throw X64DyldSharedCacheError.malformed("Cached image \(image.installName) has an invalid x86_64 Mach-O header.")
            }
            let commandCount = readLE32(header, at: 16)
            let commandBytes = readLE32(header, at: 20)
            guard commandCount <= maximumLoadCommands, commandBytes <= maximumCommandBytes else {
                throw X64DyldSharedCacheError.malformed("Cached image \(image.installName) has unreasonable load-command counts.")
            }
            let (headerAndCommands, addOverflow) = UInt64(machHeaderSize).addingReportingOverflow(UInt64(commandBytes))
            guard !addOverflow, headerAndCommands <= UInt64(Int.max) else {
                throw X64DyldSharedCacheError.malformed("Cached image \(image.installName) load-command range overflows.")
            }
            let commandData = try cache.readVMBytes(atVMAddress: image.machHeaderAddress, count: Int(headerAndCommands))
            var cursor = machHeaderSize
            let commandEnd = machHeaderSize + Int(commandBytes)
            var segments: [X64DyldSharedCacheImageSegmentPlan] = []

            for commandIndex in 0..<Int(commandCount) {
                guard cursor <= commandEnd - 8 else {
                    throw X64DyldSharedCacheError.malformed("Cached image \(image.installName) load command \(commandIndex) is truncated.")
                }
                let command = readLE32(commandData, at: cursor)
                let commandSize = readLE32(commandData, at: cursor + 4)
                guard commandSize >= 8, UInt64(commandSize) <= UInt64(commandEnd - cursor) else {
                    throw X64DyldSharedCacheError.malformed("Cached image \(image.installName) load command \(commandIndex) has an invalid size.")
                }

                if command == lcSegment64 {
                    guard commandSize >= segmentCommandSize else {
                        throw X64DyldSharedCacheError.malformed("Cached image \(image.installName) has a truncated LC_SEGMENT_64 command.")
                    }
                    let sectionCount = readLE32(commandData, at: cursor + 64)
                    let (sectionBytes, multiplyOverflow) = UInt64(sectionCount).multipliedReportingOverflow(by: UInt64(sectionSize))
                    let (minimumCommandSize, addSectionOverflow) = UInt64(segmentCommandSize).addingReportingOverflow(sectionBytes)
                    guard !multiplyOverflow, !addSectionOverflow, minimumCommandSize <= UInt64(commandSize) else {
                        throw X64DyldSharedCacheError.malformed("Cached image \(image.installName) segment section table exceeds its load command.")
                    }
                    let nameBytes = commandData[(cursor + 8)..<(cursor + 24)]
                    let segmentName = String(decoding: nameBytes.prefix { $0 != 0 }, as: UTF8.self)
                    let vmAddress = readLE64(commandData, at: cursor + 24)
                    let vmSize = readLE64(commandData, at: cursor + 32)
                    let maxProtection = readLE32(commandData, at: cursor + 56)
                    let initialProtection = readLE32(commandData, at: cursor + 60)
                    if vmSize > 0 && segmentName != "__PAGEZERO" {
                        let pageSize = X64GuestVirtualMemoryConstants.pageSize
                        let (end, endOverflow) = vmAddress.addingReportingOverflow(vmSize)
                        guard !endOverflow else {
                            throw X64DyldSharedCacheError.malformed(String(format: "Cached image %@ segment %@ exact range overflows (0x%016llX + 0x%llX).", image.installName, segmentName, vmAddress, vmSize))
                        }
                        // Mach-O segments in the dyld shared cache are not
                        // necessarily guest-page aligned. Reserve from floor(start)
                        // through ceil(end), while retaining the exact byte range.
                        let roundedAddress = vmAddress & ~(pageSize - 1)
                        let (roundedInput, roundOverflow) = end.addingReportingOverflow(pageSize - 1)
                        guard !roundOverflow else {
                            throw X64DyldSharedCacheError.malformed(String(format: "Cached image %@ segment %@ page-rounded end overflows (0x%016llX + 0x%llX).", image.installName, segmentName, vmAddress, vmSize))
                        }
                        let roundedEnd = roundedInput & ~(pageSize - 1)
                        guard roundedEnd >= roundedAddress else {
                            throw X64DyldSharedCacheError.malformed(String(format: "Cached image %@ segment %@ page-rounded range underflows (0x%016llX + 0x%llX).", image.installName, segmentName, vmAddress, vmSize))
                        }
                        let roundedSize = roundedEnd - roundedAddress
                        guard cache.containsVMRange(address: roundedAddress, size: roundedSize) else {
                            throw X64DyldSharedCacheError.malformed(String(format: "Cached image %@ segment %@ exact range (0x%016llX + 0x%llX) requires guest page range (0x%016llX + 0x%llX), which is not fully covered by cache mappings.", image.installName, segmentName, vmAddress, vmSize, roundedAddress, roundedSize))
                        }
                        segments.append(X64DyldSharedCacheImageSegmentPlan(
                            name: segmentName,
                            virtualAddress: vmAddress,
                            virtualSize: vmSize,
                            pageRoundedAddress: roundedAddress,
                            pageRoundedSize: roundedSize,
                            maximumProtection: maxProtection,
                            initialProtection: initialProtection
                        ))
                    }
                }
                cursor += Int(commandSize)
            }
            guard cursor == commandEnd else {
                throw X64DyldSharedCacheError.malformed("Cached image \(image.installName) load commands do not consume sizeofcmds exactly.")
            }
            guard !segments.isEmpty else {
                throw X64DyldSharedCacheError.malformed("Cached image \(image.installName) has no loadable non-PAGEZERO segments.")
            }
            let sortedSegments = segments.sorted { $0.virtualAddress < $1.virtualAddress }
            // Exact VM ranges must not overlap. Their page-rounded spans may
            // overlap legitimately when adjacent shared-cache segments occupy
            // different byte ranges in the same guest page; the later mapper
            // must coalesce that backing page rather than reserve it twice.
            for pair in zip(sortedSegments, sortedSegments.dropFirst()) where pair.0.virtualEnd > pair.1.virtualAddress {
                throw X64DyldSharedCacheError.malformed("Cached image \(image.installName) has byte-overlapping VM segments \(pair.0.name) and \(pair.1.name).")
            }
            var imageVirtualBytes: UInt64 = 0
            for segment in sortedSegments {
                let (sum, overflow) = imageVirtualBytes.addingReportingOverflow(segment.virtualSize)
                guard !overflow else {
                    throw X64DyldSharedCacheError.malformed("Cached image \(image.installName) segment size total overflows.")
                }
                imageVirtualBytes = sum
            }
            let (newTotal, totalOverflow) = totalVirtualBytes.addingReportingOverflow(imageVirtualBytes)
            let combinedPageSegments = allPageSegments + sortedSegments
            let newReservedTotal = uniqueRoundedPageBytes(for: combinedPageSegments)
            guard !totalOverflow, newReservedTotal != UInt64.max, newReservedTotal <= maximumVirtualBytes else {
                throw X64DyldSharedCacheError.malformed("Matched dependency page-rounded reservations exceed the configured 16 GiB preflight limit or overflow.")
            }
            totalVirtualBytes = newTotal
            allPageSegments = combinedPageSegments
            totalPageRoundedReservationBytes = newReservedTotal
            plans.append(X64DyldSharedCacheImagePlan(
                installName: image.installName,
                machHeaderAddress: image.machHeaderAddress,
                segmentPlans: sortedSegments
            ))
        }

        guard missing.isEmpty else {
            let preview = missing.prefix(5).joined(separator: ", ")
            throw X64DyldSharedCacheError.malformed("Cannot plan cached dependency mappings: \(missing.count) exact install-name matches are missing or have invalid headers (\(preview)).")
        }
        guard plans.count == seenInstallNames.count, plans.count == matches.compactMap(\.image).count else {
            throw X64DyldSharedCacheError.malformed("Not every dependency has one unique cached image mapping plan.")
        }
        let segments = plans.flatMap(\.segmentPlans)
        let slideInfoSummaries = try X64DyldSharedCacheReader.analyzeSlideInfo(in: cache)
        return X64DyldSharedCacheMappingPlan(
            cacheUUID: cache.uuid,
            images: plans,
            slideInfoSummaries: slideInfoSummaries,
            reservedMappingCount: cache.mappings.count,
            totalVirtualBytes: totalVirtualBytes,
            totalPageRoundedReservationBytes: totalPageRoundedReservationBytes,
            executableSegmentCount: segments.filter(\.isExecutable).count,
            linkeditSegmentCount: segments.filter { $0.name == "__LINKEDIT" }.count
        )
    }

    /// Counts each guest page once when two exact Mach-O segments share a
    /// boundary page. Segments are sorted by exact virtual address, which also
    /// keeps their page-rounded bases ordered.
    private static func uniqueRoundedPageBytes(for segments: [X64DyldSharedCacheImageSegmentPlan]) -> UInt64 {
        let sorted = segments.sorted { $0.pageRoundedAddress < $1.pageRoundedAddress }
        guard let first = sorted.first else { return 0 }
        var rangeStart = first.pageRoundedAddress
        var rangeEnd = first.pageRoundedEnd
        var total: UInt64 = 0
        for segment in sorted.dropFirst() {
            if segment.pageRoundedAddress <= rangeEnd {
                rangeEnd = max(rangeEnd, segment.pageRoundedEnd)
            } else {
                let (sum, overflow) = total.addingReportingOverflow(rangeEnd - rangeStart)
                if overflow { return UInt64.max }
                total = sum
                rangeStart = segment.pageRoundedAddress
                rangeEnd = segment.pageRoundedEnd
            }
        }
        let (sum, overflow) = total.addingReportingOverflow(rangeEnd - rangeStart)
        return overflow ? UInt64.max : sum
    }

    private static func readLE32(_ data: Data, at offset: Int) -> UInt32 {
        UInt32(data[offset]) | (UInt32(data[offset + 1]) << 8)
            | (UInt32(data[offset + 2]) << 16) | (UInt32(data[offset + 3]) << 24)
    }

    private static func readLE64(_ data: Data, at offset: Int) -> UInt64 {
        UInt64(readLE32(data, at: offset)) | (UInt64(readLE32(data, at: offset + 4)) << 32)
    }
}
