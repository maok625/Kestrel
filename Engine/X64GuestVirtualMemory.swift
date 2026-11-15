import Foundation

// MARK: - Guest virtual-memory model

/// x86-64 Darwin/Linux user processes use 4 KiB guest pages. This is a guest
/// architectural property and is intentionally independent of the host Mac's
/// physical/virtual page size (which may be 16 KiB on Apple Silicon).
enum X64GuestVirtualMemoryConstants {
    static let pageSize: UInt64 = 4_096
}

struct X64GuestMemoryPermissions: OptionSet, Sendable, Equatable, CustomStringConvertible {
    let rawValue: UInt8

    init(rawValue: UInt8) { self.rawValue = rawValue }

    static let read = X64GuestMemoryPermissions(rawValue: 1 << 0)
    static let write = X64GuestMemoryPermissions(rawValue: 1 << 1)
    static let execute = X64GuestMemoryPermissions(rawValue: 1 << 2)
    static let readWrite: X64GuestMemoryPermissions = [.read, .write]
    static let readExecute: X64GuestMemoryPermissions = [.read, .execute]
    static let readWriteExecute: X64GuestMemoryPermissions = [.read, .write, .execute]

    var description: String {
        if isEmpty { return "---" }
        return "\(contains(.read) ? "r" : "-")\(contains(.write) ? "w" : "-")\(contains(.execute) ? "x" : "-")"
    }
}

enum X64GuestMemoryAccess: String, Sendable, Equatable {
    case read
    case write
    case execute

    var requiredPermission: X64GuestMemoryPermissions {
        switch self {
        case .read: return .read
        case .write: return .write
        case .execute: return .execute
        }
    }
}

enum X64GuestMemoryRegionKind: String, Sendable, Equatable {
    case anonymous
    case image
    case heap
    case stack
    case shared
}

struct X64GuestVirtualRegionInfo: Sendable, Equatable {
    let baseAddress: UInt64
    let byteCount: UInt64
    let kind: X64GuestMemoryRegionKind

    var endAddress: UInt64 { baseAddress + byteCount }
}

struct X64GuestStackReservation: Sendable, Equatable {
    let reservation: X64GuestVirtualRegionInfo
    let usableBase: UInt64
    let usableByteCount: UInt64
    let lowGuardBase: UInt64
    let highGuardBase: UInt64

    var usableEnd: UInt64 { usableBase + usableByteCount }
    /// x86-64 stacks grow down; the initial RSP points at the high end.
    var initialStackPointer: UInt64 { usableEnd }
}

struct X64GuestVirtualMemoryFault: LocalizedError, Sendable {
    let address: UInt64
    let byteCount: Int
    let access: X64GuestMemoryAccess
    let reason: String

    var errorDescription: String? {
        String(
            format: "Guest %@ fault at 0x%016llX (%d byte(s)): %@",
            access.rawValue,
            address,
            byteCount,
            reason
        )
    }
}

/// Stable host backing for one committed guest page. Native JIT helpers need
/// a pointer that remains valid for the complete execution window; keeping the
/// allocation outside Swift Array copy-on-write storage provides that guarantee.
private final class X64GuestPageBacking: @unchecked Sendable {
    let pointer: UnsafeMutablePointer<UInt8>
    let byteCount: Int

    init(byteCount: Int) {
        self.byteCount = byteCount
        pointer = .allocate(capacity: byteCount)
        pointer.initialize(repeating: 0, count: byteCount)
    }

    deinit {
        pointer.deinitialize(count: byteCount)
        pointer.deallocate()
    }
}

private struct X64GuestCommittedPage: @unchecked Sendable {
    let backing: X64GuestPageBacking
    var permissions: X64GuestMemoryPermissions
    var generation: UInt64
}

/// Sorted page table exported to the native JIT bridge. It is rebuilt only when
/// the mapping changes (`mappingGeneration`) instead of on every block
/// execution, which previously sorted and re-hashed every committed page.
private struct X64GuestNativePageTable: @unchecked Sendable {
    var mappingGeneration: UInt64
    var pageBases: [UInt64]
    var hostPages: [UnsafeMutablePointer<UInt8>?]
    var permissions: [UInt8]
    /// Generations as seen by native code (mutated by generated writes).
    var generations: [UInt64]
    /// Generations currently recorded in `committedPages`.
    var storedGenerations: [UInt64]
}

/// Metadata-only range whose pages are backed with zero-filled host memory
/// on their first permitted guest access. Ranges remain sparse even when they
/// span hundreds of gigabytes.
private struct X64GuestDemandZeroRange: Sendable, Equatable {
    let baseAddress: UInt64
    let byteCount: UInt64
    let permissions: X64GuestMemoryPermissions

    var endAddress: UInt64 { baseAddress + byteCount }
}

/// Sparse, multi-region x86-64 guest virtual address space.
///
/// Reservations consume metadata only. Physical backing is allocated a page
/// at a time by `commit`, so reserving a multi-gigabyte heap or address-space
/// window does not allocate that amount of host RAM. Guest virtual addresses
/// are keys in this model; they are never dereferenced as host pointers.
///
/// This manager is deliberately separate from Kestrel's host MAP_JIT arena.
/// During native execution, `withNativePageTable` pins each committed page's
/// stable backing pointer and exports a sorted page table to the C/JIT bridge.
/// The generated ARM64 block resolves guest addresses through native helpers;
/// guest pages are never made executable host memory.
struct X64GuestVirtualMemory: Sendable {
    let pageSize: UInt64
    private(set) var regions: [X64GuestVirtualRegionInfo] = []
    private var committedPages: [UInt64: X64GuestCommittedPage] = [:]
    private var demandZeroRanges: [X64GuestDemandZeroRange] = []
    private(set) var mappingGeneration: UInt64 = 0
    private(set) var writeGeneration: UInt64 = 0
    private var pageGenerationClock: UInt64 = 0
    private var nativePageTable: X64GuestNativePageTable?

    init(pageSize: UInt64 = X64GuestVirtualMemoryConstants.pageSize) throws {
        guard pageSize == X64GuestVirtualMemoryConstants.pageSize else {
            throw ConfigurationError.invalidPageSize(pageSize)
        }
        self.pageSize = pageSize
    }

    enum ConfigurationError: LocalizedError {
        case invalidPageSize(UInt64)
        var errorDescription: String? {
            switch self {
            case .invalidPageSize(let value):
                return "Kestrel currently models the x86-64 guest page size as exactly 4096 bytes; got \(value)."
            }
        }
    }

    var reservedRegionCount: Int { regions.count }
    var committedPageCount: Int { committedPages.count }
    var demandZeroRangeCount: Int { demandZeroRanges.count }
    var demandZeroReservedByteCount: UInt64 {
        demandZeroRanges.reduce(UInt64(0)) { total, range in
            let (sum, overflow) = total.addingReportingOverflow(range.byteCount)
            return overflow ? UInt64.max : sum
        }
    }
    var demandZeroReservedPageCount: UInt64 {
        demandZeroReservedByteCount / pageSize
    }

    // MARK: Reservation and allocation

    @discardableResult
    mutating func reserve(
        at baseAddress: UInt64,
        byteCount: UInt64,
        kind: X64GuestMemoryRegionKind = .anonymous
    ) throws -> X64GuestVirtualRegionInfo {
        try validatePageAlignedRange(address: baseAddress, byteCount: byteCount, access: .write)
        guard byteCount <= UInt64.max - baseAddress else {
            throw fault(baseAddress, intLength(byteCount), .write, "reservation address range overflows")
        }
        let endAddress = baseAddress + byteCount

        let insertionIndex = lowerBound(for: baseAddress)
        if insertionIndex > 0, regions[insertionIndex - 1].endAddress > baseAddress {
            throw fault(baseAddress, intLength(byteCount), .write, "reservation overlaps an existing guest region")
        }
        if insertionIndex < regions.count, endAddress > regions[insertionIndex].baseAddress {
            throw fault(baseAddress, intLength(byteCount), .write, "reservation overlaps an existing guest region")
        }

        let region = X64GuestVirtualRegionInfo(baseAddress: baseAddress, byteCount: byteCount, kind: kind)
        regions.insert(region, at: insertionIndex)
        mappingGeneration &+= 1
        return region
    }

    /// First-fit allocation in [minimumAddress, maximumAddress). `alignment`
    /// must be a power of two and at least one guest page.
    @discardableResult
    mutating func reserveAnywhere(
        byteCount: UInt64,
        alignment: UInt64? = nil,
        minimumAddress: UInt64,
        maximumAddress: UInt64,
        kind: X64GuestMemoryRegionKind = .anonymous
    ) throws -> X64GuestVirtualRegionInfo {
        guard byteCount > 0, byteCount % pageSize == 0 else {
            throw fault(minimumAddress, intLength(byteCount), .write, "allocation size must be a positive page multiple")
        }
        let actualAlignment = alignment ?? pageSize
        guard actualAlignment >= pageSize,
              actualAlignment.nonzeroBitCount == 1,
              actualAlignment % pageSize == 0 else {
            throw fault(minimumAddress, intLength(byteCount), .write, "allocation alignment must be a page-sized power of two")
        }
        guard minimumAddress < maximumAddress, byteCount <= maximumAddress - minimumAddress else {
            throw fault(minimumAddress, intLength(byteCount), .write, "no address-space range can satisfy the allocation")
        }

        var candidate = try alignUp(minimumAddress, to: actualAlignment, address: minimumAddress)
        for region in regions {
            if candidate <= maximumAddress, byteCount <= maximumAddress - candidate,
               candidate + byteCount <= region.baseAddress {
                return try reserve(at: candidate, byteCount: byteCount, kind: kind)
            }
            if candidate < region.endAddress {
                candidate = try alignUp(region.endAddress, to: actualAlignment, address: region.endAddress)
            }
        }

        guard candidate <= maximumAddress, byteCount <= maximumAddress - candidate else {
            throw fault(candidate, intLength(byteCount), .write, "no free guest address range is large enough")
        }
        return try reserve(at: candidate, byteCount: byteCount, kind: kind)
    }

    /// Reserves a stack with one uncommitted guard page at each end. Only the
    /// usable interior is committed RW; the JIT arena is never involved.
    mutating func reserveStack(
        at baseAddress: UInt64,
        usableByteCount: UInt64,
        guardPageCount: UInt64 = 1
    ) throws -> X64GuestStackReservation {
        guard usableByteCount > 0, usableByteCount % pageSize == 0, guardPageCount > 0 else {
            throw fault(baseAddress, intLength(usableByteCount), .write, "stack size must be a positive page multiple and guard count must be positive")
        }
        let guardBytes = guardPageCount.multipliedReportingOverflow(by: pageSize)
        let bothGuards = guardBytes.partialValue.multipliedReportingOverflow(by: 2)
        let total = usableByteCount.addingReportingOverflow(bothGuards.partialValue)
        guard !guardBytes.overflow, !bothGuards.overflow, !total.overflow else {
            throw fault(baseAddress, intLength(usableByteCount), .write, "stack reservation size overflows")
        }
        let reservation = try reserve(at: baseAddress, byteCount: total.partialValue, kind: .stack)
        let usableBase = baseAddress + guardBytes.partialValue
        do {
            try commit(at: usableBase, byteCount: usableByteCount, permissions: .readWrite)
        } catch {
            try? release(at: baseAddress)
            throw error
        }
        return X64GuestStackReservation(
            reservation: reservation,
            usableBase: usableBase,
            usableByteCount: usableByteCount,
            lowGuardBase: baseAddress,
            highGuardBase: usableBase + usableByteCount
        )
    }

    mutating func release(at baseAddress: UInt64) throws {
        guard let index = regions.firstIndex(where: { $0.baseAddress == baseAddress }) else {
            throw fault(baseAddress, 0, .write, "no reservation begins at this address")
        }
        let region = regions.remove(at: index)
        // Reservations can be enormous and sparse (for example Mach-O
        // __PAGEZERO). Iterate only the pages that actually have backing.
        let committedBases = committedPages.keys.filter {
            $0 >= region.baseAddress && $0 < region.endAddress
        }
        for pageBase in committedBases {
            committedPages.removeValue(forKey: pageBase)
        }
        demandZeroRanges.removeAll { $0.baseAddress >= region.baseAddress && $0.endAddress <= region.endAddress }
        mappingGeneration &+= 1
    }

    // MARK: Commit, decommit, and permissions

    /// Marks an aligned subrange of an existing reservation as demand-zero.
    /// No host backing is allocated until `resolveDemandZeroPage` handles a
    /// permitted guest access to one of its pages.
    mutating func registerDemandZeroRange(
        at address: UInt64,
        byteCount: UInt64,
        permissions: X64GuestMemoryPermissions
    ) throws {
        guard byteCount > 0 else { return }
        _ = try validateRegionRange(address: address, byteCount: byteCount, access: .write)
        let endAddress = address + byteCount
        guard !demandZeroRanges.contains(where: { $0.baseAddress < endAddress && address < $0.endAddress }) else {
            throw fault(address, intLength(byteCount), .write, "demand-zero range overlaps existing lazy metadata")
        }
        guard !committedPages.keys.contains(where: { $0 >= address && $0 < endAddress }) else {
            throw fault(address, intLength(byteCount), .write, "demand-zero range overlaps an already committed page")
        }
        demandZeroRanges.append(X64GuestDemandZeroRange(
            baseAddress: address,
            byteCount: byteCount,
            permissions: permissions
        ))
        demandZeroRanges.sort { $0.baseAddress < $1.baseAddress }
        mappingGeneration &+= 1
    }

    /// Resolves one missing guest page if it belongs to a registered
    /// demand-zero range and the requested access is permitted. Returns false
    /// for ordinary uncommitted reservations or permission mismatches.
    @discardableResult
    mutating func resolveDemandZeroPage(
        at address: UInt64,
        access: X64GuestMemoryAccess
    ) throws -> Bool {
        let pageBase = address & ~(pageSize - 1)
        if let existing = committedPages[pageBase] {
            return existing.permissions.contains(access.requiredPermission)
        }
        guard regionIndex(containing: pageBase) != nil,
              let rangeIndex = demandZeroRanges.firstIndex(where: {
                  pageBase >= $0.baseAddress && pageBase < $0.endAddress
              }) else {
            return false
        }
        let range = demandZeroRanges[rangeIndex]
        guard range.permissions.contains(access.requiredPermission) else { return false }

        // Backing allocations are zero-initialized by X64GuestPageBacking.
        pageGenerationClock &+= 1
        committedPages[pageBase] = X64GuestCommittedPage(
            backing: X64GuestPageBacking(byteCount: Int(pageSize)),
            permissions: range.permissions,
            generation: pageGenerationClock
        )

        // Remove exactly this page from the metadata range, retaining up to
        // two sparse fragments. A single huge range therefore costs O(1)
        // metadata per page that is actually faulted in.
        demandZeroRanges.remove(at: rangeIndex)
        if pageBase > range.baseAddress {
            demandZeroRanges.append(X64GuestDemandZeroRange(
                baseAddress: range.baseAddress,
                byteCount: pageBase - range.baseAddress,
                permissions: range.permissions
            ))
        }
        let pageEnd = pageBase + pageSize
        if pageEnd < range.endAddress {
            demandZeroRanges.append(X64GuestDemandZeroRange(
                baseAddress: pageEnd,
                byteCount: range.endAddress - pageEnd,
                permissions: range.permissions
            ))
        }
        demandZeroRanges.sort { $0.baseAddress < $1.baseAddress }
        mappingGeneration &+= 1
        return true
    }

    func isDemandZero(address: UInt64) -> Bool {
        let pageBase = address & ~(pageSize - 1)
        return demandZeroRanges.contains { pageBase >= $0.baseAddress && pageBase < $0.endAddress }
    }

    mutating func commit(
        at address: UInt64,
        byteCount: UInt64,
        permissions: X64GuestMemoryPermissions
    ) throws {
        let region = try validateRegionRange(address: address, byteCount: byteCount, access: .write)
        _ = region
        let pageBases = pageBases(in: address, byteCount: byteCount)
        for pageBase in pageBases where isDemandZero(address: pageBase) {
            throw fault(pageBase, Int(pageSize), .write, "page is registered for demand-zero materialization; resolve its first guest access instead")
        }
        for pageBase in pageBases where committedPages[pageBase] != nil {
            throw fault(pageBase, Int(pageSize), .write, "page is already committed")
        }
        pageGenerationClock &+= 1
        for pageBase in pageBases {
            committedPages[pageBase] = X64GuestCommittedPage(
                backing: X64GuestPageBacking(byteCount: Int(pageSize)),
                permissions: permissions,
                generation: pageGenerationClock
            )
        }
        mappingGeneration &+= 1
    }

    mutating func decommit(at address: UInt64, byteCount: UInt64) throws {
        _ = try validateRegionRange(address: address, byteCount: byteCount, access: .write)
        let pageBases = pageBases(in: address, byteCount: byteCount)
        for pageBase in pageBases where committedPages[pageBase] == nil {
            throw fault(pageBase, Int(pageSize), .write, "cannot decommit a page that is not committed")
        }
        for pageBase in pageBases { committedPages.removeValue(forKey: pageBase) }
        mappingGeneration &+= 1
    }

    mutating func protect(
        at address: UInt64,
        byteCount: UInt64,
        permissions: X64GuestMemoryPermissions
    ) throws {
        _ = try validateRegionRange(address: address, byteCount: byteCount, access: .write)
        let pageBases = pageBases(in: address, byteCount: byteCount)
        for pageBase in pageBases where committedPages[pageBase] == nil {
            throw fault(pageBase, Int(pageSize), .write, "cannot change permissions on an uncommitted page")
        }
        pageGenerationClock &+= 1
        for pageBase in pageBases {
            committedPages[pageBase]?.permissions = permissions
            committedPages[pageBase]?.generation = pageGenerationClock
        }
        mappingGeneration &+= 1
    }

    // MARK: Native JIT page-table bridge

    /// Pins the current committed-page backing pointers for one native JIT
    /// execution. The C bridge receives sorted guest page bases, host backing
    /// pointers, permissions, and mutable page generations. Every backing
    /// allocation remains stable while the closure executes.
    mutating func withNativePageTable<R>(
        _ body: (
            UnsafeBufferPointer<UInt64>,
            UnsafeBufferPointer<UnsafeMutablePointer<UInt8>?>,
            UnsafeBufferPointer<UInt8>,
            UnsafeMutableBufferPointer<UInt64>,
            UnsafeMutablePointer<UInt64>
        ) throws -> R
    ) rethrows -> R {
        var table: X64GuestNativePageTable
        if let cached = nativePageTable, cached.mappingGeneration == mappingGeneration {
            table = cached
        } else {
            table = makeNativePageTable()
        }
        // Drop the stored copy and detach the generation array so both are
        // uniquely referenced; native writes then update them without copying.
        nativePageTable = nil
        var generations = table.generations
        table.generations = []
        var nativeWriteCount: UInt64 = 0

        defer {
            // Propagate only the generations that native writes changed.
            if nativeWriteCount > 0 {
                for index in 0..<generations.count where generations[index] != table.storedGenerations[index] {
                    let pageBase = table.pageBases[index]
                    if var page = committedPages[pageBase] {
                        page.generation = generations[index]
                        committedPages[pageBase] = page
                    }
                    table.storedGenerations[index] = generations[index]
                    pageGenerationClock = max(pageGenerationClock, generations[index])
                }
            }
            table.generations = generations
            nativePageTable = table
            writeGeneration &+= nativeWriteCount
        }

        return try table.pageBases.withUnsafeBufferPointer { baseBuffer in
            try table.hostPages.withUnsafeBufferPointer { hostBuffer in
                try table.permissions.withUnsafeBufferPointer { permissionBuffer in
                    try generations.withUnsafeMutableBufferPointer { generationBuffer in
                        try withUnsafeMutablePointer(to: &nativeWriteCount) { writeCountPointer in
                            try body(baseBuffer, hostBuffer, permissionBuffer, generationBuffer, writeCountPointer)
                        }
                    }
                }
            }
        }
    }

    private func makeNativePageTable() -> X64GuestNativePageTable {
        let sortedBases = committedPages.keys.sorted()
        var pageBases: [UInt64] = []
        var hostPages: [UnsafeMutablePointer<UInt8>?] = []
        var permissions: [UInt8] = []
        var generations: [UInt64] = []
        pageBases.reserveCapacity(sortedBases.count)
        hostPages.reserveCapacity(sortedBases.count)
        permissions.reserveCapacity(sortedBases.count)
        generations.reserveCapacity(sortedBases.count)
        for pageBase in sortedBases {
            guard let page = committedPages[pageBase] else { continue }
            pageBases.append(pageBase)
            hostPages.append(page.backing.pointer)
            permissions.append(page.permissions.rawValue)
            generations.append(page.generation)
        }
        return X64GuestNativePageTable(
            mappingGeneration: mappingGeneration,
            pageBases: pageBases,
            hostPages: hostPages,
            permissions: permissions,
            generations: generations,
            storedGenerations: generations
        )
    }

    /// Keeps the cached native table in step with a Swift-side page write,
    /// which changes a page generation but not the mapping itself.
    private mutating func noteNativePageTableGeneration(pageBase: UInt64, generation: UInt64) {
        guard var table = nativePageTable, table.mappingGeneration == mappingGeneration else { return }
        nativePageTable = nil
        var low = 0
        var high = table.pageBases.count
        while low < high {
            let middle = low + (high - low) / 2
            if table.pageBases[middle] < pageBase { low = middle + 1 } else { high = middle }
        }
        if low < table.pageBases.count, table.pageBases[low] == pageBase {
            table.generations[low] = generation
            table.storedGenerations[low] = generation
        }
        nativePageTable = table
    }

    /// Returns executable bytes up to the requested maximum. If the range
    /// crosses into a page that is not executable, bytes from the preceding
    /// executable pages are returned; an instruction that actually needs the
    /// inaccessible byte will then fail decoding at the boundary.
    mutating func fetchAvailableBytes(at address: UInt64, maximumCount: Int) throws -> [UInt8] {
        guard maximumCount >= 0 else {
            throw fault(address, maximumCount, .execute, "negative instruction-fetch length")
        }
        if maximumCount == 0 { return [] }
        guard UInt64(maximumCount - 1) <= UInt64.max - address else {
            throw fault(address, maximumCount, .execute, "instruction-fetch range overflows")
        }

        var result: [UInt8] = []
        result.reserveCapacity(maximumCount)
        var cursor = address
        while result.count < maximumCount {
            let pageBase = cursor & ~(pageSize - 1)
            if committedPages[pageBase] == nil {
                _ = try resolveDemandZeroPage(at: cursor, access: .execute)
            }
            guard let page = committedPages[pageBase], page.permissions.contains(.execute) else {
                if result.isEmpty {
                    throw fault(cursor, maximumCount, .execute, "page is unmapped, uncommitted, or lacks execute permission")
                }
                break
            }
            let pageOffset = Int(cursor - pageBase)
            let chunkCount = min(maximumCount - result.count, Int(pageSize) - pageOffset)
            let source = UnsafeBufferPointer(start: page.backing.pointer.advanced(by: pageOffset), count: chunkCount)
            result.append(contentsOf: source)
            cursor += UInt64(chunkCount)
        }
        return result
    }

    // MARK: Accessors

    func readBytes(at address: UInt64, count: Int) throws -> [UInt8] {
        try readAccessBytes(at: address, count: count, access: .read)
    }

    func fetchBytes(at address: UInt64, maximumCount: Int) throws -> [UInt8] {
        try readAccessBytes(at: address, count: maximumCount, access: .execute)
    }

    mutating func writeBytes(_ values: [UInt8], at address: UInt64) throws {
        let count = values.count
        guard count > 0 else { return }
        guard UInt64(count - 1) <= UInt64.max - address else {
            throw fault(address, count, .write, "access address range overflows")
        }

        // Validate every participating page before changing any page. This
        // prevents partial mutation if a scalar guest store crosses into a
        // reserved-but-uncommitted or read-only page.
        var validationCursor = address
        var validated = 0
        while validated < count {
            let pageBase = validationCursor & ~(pageSize - 1)
            guard regionIndex(containing: pageBase) != nil else {
                throw fault(validationCursor, count - validated, .write, "address is not reserved")
            }
            if committedPages[pageBase] == nil {
                _ = try resolveDemandZeroPage(at: validationCursor, access: .write)
            }
            guard let page = committedPages[pageBase] else {
                throw fault(validationCursor, count - validated, .write, "page is reserved but not committed")
            }
            guard page.permissions.contains(.write) else {
                throw fault(validationCursor, count - validated, .write, "page permissions are \(page.permissions), required write")
            }
            let pageOffset = Int(validationCursor - pageBase)
            let chunkCount = min(count - validated, Int(pageSize) - pageOffset)
            validated += chunkCount
            validationCursor += UInt64(chunkCount)
        }

        pageGenerationClock &+= 1
        var cursor = address
        var written = 0
        while written < count {
            let pageBase = cursor & ~(pageSize - 1)
            guard var page = committedPages[pageBase] else {
                // The full range was checked above; this indicates an internal
                // invariant violation rather than a guest-generated fault.
                throw fault(cursor, count - written, .write, "committed page disappeared during a serialized write")
            }
            let pageOffset = Int(cursor - pageBase)
            let chunkCount = min(count - written, Int(pageSize) - pageOffset)
            for index in 0..<chunkCount {
                page.backing.pointer[pageOffset + index] = values[written + index]
            }
            page.generation = pageGenerationClock
            committedPages[pageBase] = page
            noteNativePageTableGeneration(pageBase: pageBase, generation: pageGenerationClock)
            written += chunkCount
            cursor += UInt64(chunkCount)
        }
        writeGeneration &+= 1
    }

    /// Copies one complete page into an already committed writable guest page.
    /// This is the loader's fast path for file-backed images and shared-cache
    /// pages; it avoids allocating an intermediate `[UInt8]` copy per page.
    mutating func writePageData(_ data: Data, at address: UInt64) throws {
        guard address % pageSize == 0, data.count == Int(pageSize) else {
            throw fault(address, data.count, .write, "page initialization requires one complete page at a page-aligned guest address")
        }
        guard regionIndex(containing: address) != nil else {
            throw fault(address, data.count, .write, "page initialization address is not reserved")
        }
        guard var page = committedPages[address] else {
            throw fault(address, data.count, .write, "page initialization requires committed backing")
        }
        guard page.permissions.contains(.write) else {
            throw fault(address, data.count, .write, "page initialization requires temporary write permission")
        }
        try data.withUnsafeBytes { rawBytes in
            guard let source = rawBytes.bindMemory(to: UInt8.self).baseAddress else {
                throw fault(address, data.count, .write, "page initialization source buffer is empty")
            }
            page.backing.pointer.update(from: source, count: Int(pageSize))
        }
        pageGenerationClock &+= 1
        page.generation = pageGenerationClock
        committedPages[address] = page
        noteNativePageTableGeneration(pageBase: address, generation: pageGenerationClock)
        writeGeneration &+= 1
    }

    func readUnsigned(at address: UInt64, byteCount: Int, access: X64GuestMemoryAccess = .read) throws -> UInt64 {
        guard (1...8).contains(byteCount) else {
            throw fault(address, byteCount, access, "integer access width must be between 1 and 8 bytes")
        }
        let data = try readAccessBytes(at: address, count: byteCount, access: access)
        return data.enumerated().reduce(UInt64(0)) { partial, element in
            partial | (UInt64(element.element) << (element.offset * 8))
        }
    }

    mutating func writeUnsigned(_ value: UInt64, at address: UInt64, byteCount: Int) throws {
        guard (1...8).contains(byteCount) else {
            throw fault(address, byteCount, .write, "integer access width must be between 1 and 8 bytes")
        }
        let data = (0..<byteCount).map { UInt8(truncatingIfNeeded: value >> ($0 * 8)) }
        try writeBytes(data, at: address)
    }

    /// Removes write access from every page/range that existed before an
    /// isolated guest-execution snapshot was created. The VM value can share
    /// committed page backing with its source, so speculative execution must
    /// not be allowed to mutate those shared allocations.
    ///
    /// Callers may reserve and commit fresh writable pages after this method;
    /// those pages belong only to the snapshot. The cached native page table is
    /// invalidated so the JIT observes the tightened permissions.
    @discardableResult
    mutating func restrictExistingWritesForIsolatedExecution() -> Int {
        var protectedPageCount = 0
        var changed = false

        // Mutating the dictionary detaches its value storage from any source
        // VM copy. The page backing objects remain shared, but every such page
        // is now non-writable in this snapshot before native code can access it.
        for pageBase in Array(committedPages.keys) {
            guard var page = committedPages[pageBase],
                  page.permissions.contains(.write) else { continue }
            page.permissions.remove(.write)
            committedPages[pageBase] = page
            protectedPageCount += 1
            changed = true
        }

        // Also prevent a write from materializing a new writable page inside
        // a demand-zero range that belonged to the source VM.
        for index in demandZeroRanges.indices {
            let range = demandZeroRanges[index]
            guard range.permissions.contains(.write) else { continue }
            var permissions = range.permissions
            permissions.remove(.write)
            demandZeroRanges[index] = X64GuestDemandZeroRange(
                baseAddress: range.baseAddress,
                byteCount: range.byteCount,
                permissions: permissions
            )
            changed = true
        }

        if changed {
            mappingGeneration &+= 1
            nativePageTable = nil
        }
        return protectedPageCount
    }

    func permissions(at address: UInt64) -> X64GuestMemoryPermissions? {
        let pageBase = address & ~(pageSize - 1)
        return committedPages[pageBase]?.permissions
    }

    func isReserved(address: UInt64) -> Bool {
        regionIndex(containing: address) != nil
    }

    func isCommitted(address: UInt64) -> Bool {
        let pageBase = address & ~(pageSize - 1)
        return committedPages[pageBase] != nil
    }

    func pageGeneration(at address: UInt64) -> UInt64? {
        let pageBase = address & ~(pageSize - 1)
        return committedPages[pageBase]?.generation
    }

    func region(containing address: UInt64) -> X64GuestVirtualRegionInfo? {
        guard let index = regionIndex(containing: address) else { return nil }
        return regions[index]
    }

    // MARK: Internal range validation

    private func readAccessBytes(
        at address: UInt64,
        count: Int,
        access: X64GuestMemoryAccess
    ) throws -> [UInt8] {
        guard count >= 0 else { throw fault(address, count, access, "negative access length") }
        if count == 0 { return [] }
        guard UInt64(count - 1) <= UInt64.max - address else {
            throw fault(address, count, access, "access address range overflows")
        }

        var result = Array(repeating: UInt8(0), count: count)
        var cursor = address
        var completed = 0
        while completed < count {
            let pageBase = cursor & ~(pageSize - 1)
            guard regionIndex(containing: pageBase) != nil else {
                throw fault(cursor, count - completed, access, "address is not reserved")
            }
            guard let page = committedPages[pageBase] else {
                throw fault(cursor, count - completed, access, "page is reserved but not committed")
            }
            guard page.permissions.contains(access.requiredPermission) else {
                throw fault(cursor, count - completed, access, "page permissions are \(page.permissions), required \(access.requiredPermission)")
            }

            let pageOffset = Int(cursor - pageBase)
            let chunkCount = min(count - completed, Int(pageSize) - pageOffset)
            let source = UnsafeBufferPointer(
                start: page.backing.pointer.advanced(by: pageOffset),
                count: chunkCount
            )
            result.replaceSubrange(completed..<(completed + chunkCount), with: source)
            completed += chunkCount
            cursor += UInt64(chunkCount)
        }
        return result
    }

    private func validatePageAlignedRange(
        address: UInt64,
        byteCount: UInt64,
        access: X64GuestMemoryAccess
    ) throws {
        guard byteCount > 0 else { throw fault(address, 0, access, "range size must be positive") }
        guard address % pageSize == 0 else { throw fault(address, intLength(byteCount), access, "address is not guest-page aligned") }
        guard byteCount % pageSize == 0 else { throw fault(address, intLength(byteCount), access, "range size is not a guest-page multiple") }
        guard byteCount / pageSize <= UInt64(Int.max) else { throw fault(address, intLength(byteCount), access, "range contains too many pages for this host process") }
        guard byteCount <= UInt64.max - address else { throw fault(address, intLength(byteCount), access, "address range overflows") }
    }

    private func validateRegionRange(
        address: UInt64,
        byteCount: UInt64,
        access: X64GuestMemoryAccess
    ) throws -> X64GuestVirtualRegionInfo {
        try validatePageAlignedRange(address: address, byteCount: byteCount, access: access)
        guard let index = regionIndex(containing: address) else {
            throw fault(address, intLength(byteCount), access, "range is not inside a reserved region")
        }
        let region = regions[index]
        guard byteCount <= region.endAddress - address else {
            throw fault(address, intLength(byteCount), access, "range crosses its reservation boundary")
        }
        return region
    }

    private func pageBases(in address: UInt64, byteCount: UInt64) -> [UInt64] {
        let count = Int(byteCount / pageSize)
        return (0..<count).map { address + UInt64($0) * pageSize }
    }

    private func lowerBound(for address: UInt64) -> Int {
        var low = 0
        var high = regions.count
        while low < high {
            let middle = low + (high - low) / 2
            if regions[middle].baseAddress < address { low = middle + 1 } else { high = middle }
        }
        return low
    }

    private func regionIndex(containing address: UInt64) -> Int? {
        let insertion = lowerBound(for: address)
        if insertion < regions.count, regions[insertion].baseAddress == address {
            return insertion
        }
        guard insertion > 0 else { return nil }
        let candidate = insertion - 1
        return address < regions[candidate].endAddress ? candidate : nil
    }

    private func alignUp(_ value: UInt64, to alignment: UInt64, address: UInt64) throws -> UInt64 {
        let mask = alignment - 1
        guard value <= UInt64.max - mask else {
            throw fault(address, 0, .write, "alignment calculation overflows")
        }
        return (value + mask) & ~mask
    }

    private func intLength(_ value: UInt64) -> Int {
        value > UInt64(Int.max) ? Int.max : Int(value)
    }

    private func fault(_ address: UInt64, _ count: Int, _ access: X64GuestMemoryAccess, _ reason: String) -> X64GuestVirtualMemoryFault {
        X64GuestVirtualMemoryFault(address: address, byteCount: count, access: access, reason: reason)
    }
}
