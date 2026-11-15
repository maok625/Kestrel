import Foundation

// MARK: - Guest-owned dyld shared-cache pages

struct X64DyldSharedCacheMaterializationSummary: Sendable, Equatable {
    let cacheUUID: String
    let imageCount: Int
    let pageCount: UInt64
    let byteCount: UInt64
    let reservedRegionCount: Int
    let rebasedPointerCount: UInt64
    let cacheSlideAmount: UInt64
}

/// Applies Apple's x86_64 shared-cache slide-info v2 encoding to one guest page.
/// The source cache remains immutable: all pointer writes target this private
/// page buffer before it is copied into Kestrel's guest-owned backing.
private struct X64DyldSharedCacheSlideInfoV2PageDecoder: Sendable {
    let mapping: X64DyldSharedCacheSlideMapping
    let pageSize: UInt32
    let deltaMask: UInt64
    let valueAdd: UInt64
    let deltaShift: UInt64
    let pageStarts: [UInt16]
    let pageExtras: [UInt16]

    init(backing: X64DyldSharedCacheBackingFile, mapping: X64DyldSharedCacheSlideMapping) throws {
        guard mapping.slideInfoFileSize >= 40,
              mapping.slideInfoFileOffset <= UInt64(backing.data.count),
              mapping.slideInfoFileSize <= UInt64(backing.data.count) - mapping.slideInfoFileOffset,
              mapping.slideInfoFileOffset <= UInt64(Int.max),
              mapping.slideInfoFileSize <= UInt64(Int.max) else {
            throw X64DyldSharedCacheError.malformed("Slide-info v2 blob has an invalid backing-file range.")
        }
        let blobStart = Int(mapping.slideInfoFileOffset)
        let blobEnd = blobStart + Int(mapping.slideInfoFileSize)
        let blob = backing.data.subdata(in: blobStart..<blobEnd)
        guard Self.readLE32(blob, at: 0) == 2 else {
            throw X64DyldSharedCacheError.unsupportedFormat("Cached-page materialization currently supports slide-info version 2 only.")
        }

        let parsedPageSize = Self.readLE32(blob, at: 4)
        let startsOffset = UInt64(Self.readLE32(blob, at: 8))
        let startsCount = UInt64(Self.readLE32(blob, at: 12))
        let extrasOffset = UInt64(Self.readLE32(blob, at: 16))
        let extrasCount = UInt64(Self.readLE32(blob, at: 20))
        let parsedDeltaMask = Self.readLE64(blob, at: 24)
        let parsedValueAdd = Self.readLE64(blob, at: 32)

        guard parsedPageSize == 4096 else {
            throw X64DyldSharedCacheError.unsupportedFormat("Guest cache-page mapping currently requires 4 KiB slide-info pages; found \(parsedPageSize)-byte pages.")
        }
        guard mapping.size % UInt64(parsedPageSize) == 0,
              startsCount == mapping.size / UInt64(parsedPageSize),
              startsCount <= 50_000_000 else {
            throw X64DyldSharedCacheError.malformed("Slide-info v2 page-start count does not match its mapping.")
        }
        guard parsedDeltaMask != 0 else {
            throw X64DyldSharedCacheError.malformed("Slide-info v2 has an empty pointer delta mask.")
        }
        let trailingZeros = parsedDeltaMask.trailingZeroBitCount
        guard trailingZeros >= 2, trailingZeros < 64 else {
            throw X64DyldSharedCacheError.malformed("Slide-info v2 pointer delta mask has an invalid shift.")
        }
        let shiftedMask = parsedDeltaMask >> trailingZeros
        guard (shiftedMask & (shiftedMask &+ 1)) == 0 else {
            throw X64DyldSharedCacheError.malformed("Slide-info v2 pointer delta mask is not a contiguous bit field.")
        }

        try Self.validateArray(offset: startsOffset, count: startsCount, blobCount: blob.count, label: "page-start")
        try Self.validateArray(offset: extrasOffset, count: extrasCount, blobCount: blob.count, label: "page-extras")
        let startsEnd = startsOffset + startsCount * 2
        let extrasEnd = extrasOffset + extrasCount * 2
        guard startsOffset >= 40,
              extrasCount == 0 || extrasOffset >= 40,
              extrasCount == 0 || startsEnd <= extrasOffset || extrasEnd <= startsOffset else {
            throw X64DyldSharedCacheError.malformed("Slide-info v2 arrays overlap their header or each other.")
        }

        var starts: [UInt16] = []
        starts.reserveCapacity(Int(startsCount))
        for index in 0..<Int(startsCount) {
            starts.append(Self.readLE16(blob, at: Int(startsOffset) + index * 2))
        }
        var extras: [UInt16] = []
        extras.reserveCapacity(Int(extrasCount))
        for index in 0..<Int(extrasCount) {
            extras.append(Self.readLE16(blob, at: Int(extrasOffset) + index * 2))
        }

        self.mapping = mapping
        self.pageSize = parsedPageSize
        self.deltaMask = parsedDeltaMask
        self.valueAdd = parsedValueAdd
        self.deltaShift = UInt64(trailingZeros - 2)
        self.pageStarts = starts
        self.pageExtras = extras
    }

    /// Rebases the pointer words in this page buffer. A return value of zero
    /// means this page has no pointer words that require a value-add/slide.
    func applyFixups(
        to page: inout Data,
        at pageAddress: UInt64,
        cacheSlideAmount: UInt64
    ) throws -> UInt64 {
        guard page.count == Int(pageSize), pageAddress % UInt64(pageSize) == 0,
              pageAddress >= mapping.address,
              pageAddress - mapping.address < mapping.size else {
            throw X64DyldSharedCacheError.malformed("Requested guest page does not belong to the slide-info mapping or has the wrong size/alignment.")
        }
        let pageIndex = (pageAddress - mapping.address) / UInt64(pageSize)
        guard pageIndex < UInt64(pageStarts.count) else {
            throw X64DyldSharedCacheError.malformed("Slide-info page index exceeds the page-start table.")
        }
        let pageStart = pageStarts[Int(pageIndex)]
        if pageStart == 0x4000 { return 0 } // DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE
        if (pageStart & 0x4000) != 0 {
            throw X64DyldSharedCacheError.malformed("Slide-info page-start combines NO_REBASE with unsupported flags.")
        }

        var chainStarts: [UInt64] = []
        if (pageStart & 0x8000) != 0 {
            let firstExtra = Int(pageStart & 0x3FFF)
            guard firstExtra < pageExtras.count else {
                throw X64DyldSharedCacheError.malformed("Slide-info page-start references a page-extras index outside the table.")
            }
            var extraIndex = firstExtra
            var foundEnd = false
            while extraIndex < pageExtras.count {
                let extra = pageExtras[extraIndex]
                chainStarts.append(UInt64(extra & 0x7FFF) * 4)
                if (extra & 0x8000) != 0 {
                    foundEnd = true
                    break
                }
                extraIndex += 1
            }
            guard foundEnd, chainStarts.count >= 2 else {
                throw X64DyldSharedCacheError.malformed("Slide-info page-extras list is unterminated or has fewer than two chain starts.")
            }
        } else {
            chainStarts = [UInt64(pageStart) * 4]
        }

        var seenOffsets = Set<UInt64>()
        var rebased: UInt64 = 0
        let valueMask = ~deltaMask
        for chainStart in chainStarts {
            guard chainStart % 4 == 0, chainStart + 8 <= UInt64(pageSize) else {
                throw X64DyldSharedCacheError.malformed("Slide-info chain starts outside the guest page or is not four-byte aligned.")
            }
            var location = chainStart
            var steps: UInt64 = 0
            while true {
                guard seenOffsets.insert(location).inserted else {
                    throw X64DyldSharedCacheError.malformed("Slide-info page contains duplicate or cyclic pointer-chain locations.")
                }
                let offset = Int(location)
                let rawValue = Self.readLE64(page, at: offset)
                let encodedValue = rawValue & valueMask
                var newValue = encodedValue
                if encodedValue != 0 {
                    let (withValueAdd, valueOverflow) = encodedValue.addingReportingOverflow(valueAdd)
                    let (withSlide, slideOverflow) = withValueAdd.addingReportingOverflow(cacheSlideAmount)
                    guard !valueOverflow, !slideOverflow else {
                        throw X64DyldSharedCacheError.malformed("Slide-info pointer reconstruction overflows 64 bits.")
                    }
                    newValue = withSlide
                    rebased += 1
                }
                Self.writeLE64(newValue, to: &page, at: offset)

                let delta = (rawValue & deltaMask) >> deltaShift
                if delta == 0 { break }
                guard delta % 4 == 0 else {
                    throw X64DyldSharedCacheError.malformed("Slide-info pointer-chain delta is not four-byte aligned.")
                }
                let (nextLocation, nextOverflow) = location.addingReportingOverflow(delta)
                let (nextEnd, endOverflow) = nextLocation.addingReportingOverflow(8)
                guard !nextOverflow, !endOverflow, nextLocation > location,
                      nextEnd <= UInt64(pageSize) else {
                    throw X64DyldSharedCacheError.malformed("Slide-info pointer chain leaves its guest page or overflows.")
                }
                location = nextLocation
                steps += 1
                guard steps < UInt64(pageSize / 4) else {
                    throw X64DyldSharedCacheError.malformed("Slide-info pointer chain exceeds its per-page safety limit.")
                }
            }
        }
        return rebased
    }

    private static func validateArray(offset: UInt64, count: UInt64, blobCount: Int, label: String) throws {
        let (bytes, multiplyOverflow) = count.multipliedReportingOverflow(by: 2)
        let (end, addOverflow) = offset.addingReportingOverflow(bytes)
        guard !multiplyOverflow, !addOverflow, end <= UInt64(blobCount), offset <= UInt64(Int.max) else {
            throw X64DyldSharedCacheError.malformed("Slide-info v2 \(label) array extends beyond its blob.")
        }
    }

    private static func readLE16(_ data: Data, at offset: Int) -> UInt16 {
        UInt16(data[offset]) | (UInt16(data[offset + 1]) << 8)
    }

    private static func readLE32(_ data: Data, at offset: Int) -> UInt32 {
        UInt32(data[offset]) | (UInt32(data[offset + 1]) << 8)
            | (UInt32(data[offset + 2]) << 16) | (UInt32(data[offset + 3]) << 24)
    }

    private static func readLE64(_ data: Data, at offset: Int) -> UInt64 {
        UInt64(readLE32(data, at: offset)) | (UInt64(readLE32(data, at: offset + 4)) << 32)
    }

    private static func writeLE64(_ value: UInt64, to data: inout Data, at offset: Int) {
        for index in 0..<8 {
            data[offset + index] = UInt8(truncatingIfNeeded: value >> (index * 8))
        }
    }
}

private struct X64DyldSharedCacheGuestPagePlan: Sendable {
    let address: UInt64
    let mapping: X64DyldSharedCacheMapping
    let finalPermissions: X64GuestMemoryPermissions
}

enum X64DyldSharedCacheMaterializer {
    private static let guestPageSize = X64GuestVirtualMemoryConstants.pageSize
    private static let maximumMaterializedBytes: UInt64 = 2 * 1024 * 1024 * 1024

    /// Materializes the union of all pages used by the selected cached images.
    /// Pages are copied into guest-owned allocations, rebased in private page
    /// buffers, then protected according to the cache mapping table. The
    /// caller's VM is only replaced after every page succeeds.
    @discardableResult
    static func materialize(
        cache: X64DyldSharedCacheSummary,
        plan: X64DyldSharedCacheMappingPlan,
        into guestMemory: inout X64GuestVirtualMemory,
        cacheSlideAmount: UInt64 = 0
    ) throws -> X64DyldSharedCacheMaterializationSummary {
        guard plan.cacheUUID == cache.uuid else {
            throw X64DyldSharedCacheError.malformed("Cached-image plan UUID does not match the supplied shared cache.")
        }
        guard !plan.images.isEmpty else {
            throw X64DyldSharedCacheError.malformed("There are no cached dependency images to materialize.")
        }

        let pageRanges = mergedPageRanges(from: plan.images.flatMap(\.segmentPlans))
        guard !pageRanges.isEmpty else {
            throw X64DyldSharedCacheError.malformed("The selected cached dependency plan contains no materializable segment pages.")
        }
        var pageCount: UInt64 = 0
        for range in pageRanges {
            let rangePageCount = (range.upperBound - range.lowerBound) / guestPageSize
            let (nextCount, overflow) = pageCount.addingReportingOverflow(rangePageCount)
            guard !overflow else {
                throw X64DyldSharedCacheError.malformed("Materialized cache guest-page count overflows.")
            }
            pageCount = nextCount
        }
        let (byteCount, byteOverflow) = pageCount.multipliedReportingOverflow(by: guestPageSize)
        guard !byteOverflow, byteCount <= maximumMaterializedBytes,
              byteCount == plan.totalPageRoundedReservationBytes,
              pageCount <= UInt64(Int.max) else {
            throw X64DyldSharedCacheError.malformed("Materialized cache pages exceed the 2 GiB allocation safety limit or disagree with the validated mapping plan.")
        }

        let pagePlans = try makeGuestPagePlans(ranges: pageRanges, mappings: cache.mappings, expectedCount: Int(pageCount))
        let slideDecoders = try makeSlideDecoders(cache: cache)

        // Work on a value copy and publish only after every reserve, copy,
        // slide fixup, and protection transition succeeds. Existing guest
        // pages are never modified by this transaction.
        var workingMemory = guestMemory
        let reservationRuns = contiguousRuns(pagePlans.map(\.address))
        for run in reservationRuns {
            try workingMemory.reserve(at: run.lowerBound, byteCount: run.upperBound - run.lowerBound, kind: .shared)
            try workingMemory.commit(
                at: run.lowerBound,
                byteCount: run.upperBound - run.lowerBound,
                permissions: .readWrite
            )
        }

        var rebasedPointerCount: UInt64 = 0
        for pagePlan in pagePlans {
            var pageBytes = try cache.readVMBytes(atVMAddress: pagePlan.address, count: Int(guestPageSize))
            guard pageBytes.count == Int(guestPageSize) else {
                throw X64DyldSharedCacheError.malformed(String(format: "Cache page 0x%016llX did not produce exactly 4096 source bytes.", pagePlan.address))
            }
            if let decoder = slideDecoders[pagePlan.mapping.address] {
                let count = try decoder.applyFixups(
                    to: &pageBytes,
                    at: pagePlan.address,
                    cacheSlideAmount: cacheSlideAmount
                )
                let (total, overflow) = rebasedPointerCount.addingReportingOverflow(count)
                guard !overflow else {
                    throw X64DyldSharedCacheError.malformed("Materialized cache pointer-fixup count overflows.")
                }
                rebasedPointerCount = total
            }
            try workingMemory.writePageData(pageBytes, at: pagePlan.address)
        }

        for run in permissionRuns(pagePlans) {
            try workingMemory.protect(
                at: run.lowerBound,
                byteCount: run.upperBound - run.lowerBound,
                permissions: run.permissions
            )
        }

        guestMemory = workingMemory
        return X64DyldSharedCacheMaterializationSummary(
            cacheUUID: cache.uuid,
            imageCount: plan.images.count,
            pageCount: pageCount,
            byteCount: byteCount,
            reservedRegionCount: reservationRuns.count,
            rebasedPointerCount: rebasedPointerCount,
            cacheSlideAmount: cacheSlideAmount
        )
    }

    private static func makeSlideDecoders(
        cache: X64DyldSharedCacheSummary
    ) throws -> [UInt64: X64DyldSharedCacheSlideInfoV2PageDecoder] {
        var decoders: [UInt64: X64DyldSharedCacheSlideInfoV2PageDecoder] = [:]
        for backing in cache.backingFiles {
            for mapping in backing.slideMappings where mapping.slideInfoFileSize > 0 {
                guard decoders[mapping.address] == nil else {
                    throw X64DyldSharedCacheError.malformed("Duplicate slide-info decoder for cache mapping 0x\(String(mapping.address, radix: 16)).")
                }
                decoders[mapping.address] = try X64DyldSharedCacheSlideInfoV2PageDecoder(
                    backing: backing,
                    mapping: mapping
                )
            }
        }
        return decoders
    }

    private static func makeGuestPagePlans(
        ranges: [Range<UInt64>],
        mappings: [X64DyldSharedCacheMapping],
        expectedCount: Int
    ) throws -> [X64DyldSharedCacheGuestPagePlan] {
        var pages: [X64DyldSharedCacheGuestPagePlan] = []
        pages.reserveCapacity(expectedCount)
        var mappingIndex = 0

        for range in ranges {
            var pageAddress = range.lowerBound
            while pageAddress < range.upperBound {
                while mappingIndex < mappings.count && mappings[mappingIndex].endAddress <= pageAddress {
                    mappingIndex += 1
                }
                guard mappingIndex < mappings.count else {
                    throw X64DyldSharedCacheError.malformed(String(format: "Cache page 0x%016llX is outside all cache mappings.", pageAddress))
                }
                let mapping = mappings[mappingIndex]
                let (pageEnd, endOverflow) = pageAddress.addingReportingOverflow(guestPageSize)
                guard !endOverflow, pageAddress >= mapping.address, pageEnd <= mapping.endAddress else {
                    throw X64DyldSharedCacheError.malformed(String(format: "Guest page 0x%016llX is not wholly contained in one cache mapping.", pageAddress))
                }
                guard (mapping.maximumProtection & ~UInt32(0x7)) == 0,
                      (mapping.initialProtection & ~UInt32(0x7)) == 0,
                      (mapping.initialProtection & ~mapping.maximumProtection) == 0 else {
                    throw X64DyldSharedCacheError.malformed(String(format: "Cache mapping at 0x%016llX has invalid or inconsistent VM protections.", mapping.address))
                }
                pages.append(X64DyldSharedCacheGuestPagePlan(
                    address: pageAddress,
                    mapping: mapping,
                    finalPermissions: guestPermissions(mapping.initialProtection)
                ))
                pageAddress = pageEnd
            }
        }
        guard pages.count == expectedCount else {
            throw X64DyldSharedCacheError.malformed("Unique cache guest-page count changed during materialization planning.")
        }
        return pages
    }

    private static func mergedPageRanges(
        from segments: [X64DyldSharedCacheImageSegmentPlan]
    ) -> [Range<UInt64>] {
        let sorted = segments
            .filter { $0.pageRoundedSize > 0 }
            .sorted { $0.pageRoundedAddress < $1.pageRoundedAddress }
        guard let first = sorted.first else { return [] }
        var result: [Range<UInt64>] = []
        var start = first.pageRoundedAddress
        var end = first.pageRoundedEnd
        for segment in sorted.dropFirst() {
            if segment.pageRoundedAddress <= end {
                end = max(end, segment.pageRoundedEnd)
            } else {
                result.append(start..<end)
                start = segment.pageRoundedAddress
                end = segment.pageRoundedEnd
            }
        }
        result.append(start..<end)
        return result
    }

    private static func contiguousRuns(_ addresses: [UInt64]) -> [Range<UInt64>] {
        guard let first = addresses.first else { return [] }
        var result: [Range<UInt64>] = []
        var start = first
        var end = first + guestPageSize
        for address in addresses.dropFirst() {
            if address == end {
                end += guestPageSize
            } else {
                result.append(start..<end)
                start = address
                end = address + guestPageSize
            }
        }
        result.append(start..<end)
        return result
    }

    private static func permissionRuns(
        _ pages: [X64DyldSharedCacheGuestPagePlan]
    ) -> [(lowerBound: UInt64, upperBound: UInt64, permissions: X64GuestMemoryPermissions)] {
        guard let first = pages.first else { return [] }
        var result: [(UInt64, UInt64, X64GuestMemoryPermissions)] = []
        var start = first.address
        var end = first.address + guestPageSize
        var permissions = first.finalPermissions
        for page in pages.dropFirst() {
            if page.address == end && page.finalPermissions == permissions {
                end += guestPageSize
            } else {
                result.append((start, end, permissions))
                start = page.address
                end = page.address + guestPageSize
                permissions = page.finalPermissions
            }
        }
        result.append((start, end, permissions))
        return result.map { (lowerBound: $0.0, upperBound: $0.1, permissions: $0.2) }
    }

    private static func guestPermissions(_ machProtection: UInt32) -> X64GuestMemoryPermissions {
        var result = X64GuestMemoryPermissions(rawValue: 0)
        if (machProtection & 0x1) != 0 { result.insert(.read) }
        if (machProtection & 0x2) != 0 { result.insert(.write) }
        if (machProtection & 0x4) != 0 { result.insert(.execute) }
        return result
    }
}
