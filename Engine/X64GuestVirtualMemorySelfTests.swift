import Foundation

enum X64GuestVirtualMemorySelfTests {
    private static let page = X64GuestVirtualMemoryConstants.pageSize
    private static let base: UInt64 = 0x0000_0001_0000_0000

    static func run() throws -> [String] {
        var passed: [String] = []

        do {
            _ = try X64GuestVirtualMemory(pageSize: 2_048)
            throw TestError.failed("non-x86 guest page size was accepted")
        } catch is X64GuestVirtualMemory.ConfigurationError {
            passed.append("Guest page size is fixed at the x86-64 4 KiB architectural page size")
        }

        var memory = try X64GuestVirtualMemory()
        let first = try memory.reserve(at: base, byteCount: page * 4, kind: .image)
        try expect(first.baseAddress == base && first.endAddress == base + page * 4, "reservation metadata is incorrect")
        try expect(memory.reservedRegionCount == 1 && memory.committedPageCount == 0, "reservation allocated committed backing")
        passed.append("Page-aligned reservations are metadata-only and do not allocate committed backing")

        try expectFault("overlapping reservations") {
            try memory.reserve(at: base + page * 2, byteCount: page * 2)
        }
        try expectFault("unaligned reservation") {
            try memory.reserve(at: base + 1, byteCount: page)
        }
        passed.append("Overlapping and unaligned reservations are rejected")

        let second = try memory.reserveAnywhere(
            byteCount: page * 2,
            alignment: page * 2,
            minimumAddress: base,
            maximumAddress: base + page * 32,
            kind: .heap
        )
        try expect(second.baseAddress == base + page * 4, "first-fit allocation did not choose the first aligned gap")
        passed.append("First-fit address allocation respects free gaps and requested alignment")

        try memory.commit(at: base, byteCount: page * 2, permissions: .readWrite)
        try expect(memory.committedPageCount == 2, "commit did not allocate both pages")
        try expect(try memory.readBytes(at: base + 13, count: 8) == Array(repeating: 0, count: 8), "newly committed memory is not zero-filled")
        passed.append("Commit allocates zero-filled pages with independent page metadata")

        try expectFault("partially overlapping commit") {
            try memory.commit(at: base, byteCount: page * 3, permissions: .readWrite)
        }
        try expect(!memory.isCommitted(address: base + page * 2), "failed multi-page commit partially committed later pages")
        passed.append("Multi-page commit prevalidates all pages and fails without partial allocation")

        try expectFault("reserved but uncommitted access") {
            _ = try memory.readBytes(at: base + page * 2, count: 1)
        }
        passed.append("Access to reserved but uncommitted pages faults deterministically")

        try memory.writeUnsigned(0x8877_6655_4433_2211, at: base + page - 4, byteCount: 8)
        try expect(try memory.readUnsigned(at: base + page - 4, byteCount: 8) == 0x8877_6655_4433_2211, "cross-page little-endian access mismatch")
        passed.append("Reads and writes cross committed page boundaries with little-endian semantics")

        try memory.protect(at: base, byteCount: page, permissions: .read)
        try expectFault("write to read-only page") {
            try memory.writeBytes([0xAA], at: base + 4)
        }
        try expect(try memory.readBytes(at: base + 4, count: 1) == [0x00], "read-only page read failed")
        passed.append("Per-page read/write permissions are enforced independently")

        try memory.protect(at: base, byteCount: page, permissions: .readExecute)
        try expect(try memory.fetchBytes(at: base + 4, maximumCount: 1) == [0x00], "executable page fetch failed")
        try expectFault("read from execute-only page") {
            try memory.protect(at: base, byteCount: page, permissions: .execute)
            _ = try memory.readBytes(at: base + 4, count: 1)
        }
        passed.append("Instruction fetch requires execute permission and ordinary reads require read permission")

        try memory.protect(at: base, byteCount: page, permissions: .readWrite)
        try memory.writeBytes([0xC3], at: base + page - 1)
        try memory.commit(at: base + page * 3, byteCount: page, permissions: .readWrite)
        try memory.commit(at: base + page * 4, byteCount: page, permissions: .readWrite)
        try memory.writeBytes([0xA1, 0xA2], at: base + page * 4 - 1)
        try expect(try memory.readBytes(at: base + page * 4 - 1, count: 2) == [0xA1, 0xA2], "adjacent committed reservations did not support cross-page access")
        passed.append("Committed pages in adjacent independent reservations support contiguous accesses")

        try memory.protect(at: base + page * 4, byteCount: page, permissions: .read)
        try expectFault("cross-page write with read-only second page") {
            try memory.writeBytes([0xB1, 0xB2], at: base + page * 4 - 1)
        }
        try expect(try memory.readBytes(at: base + page * 4 - 1, count: 2) == [0xA1, 0xA2], "faulting cross-page store partially modified the first page")
        try memory.protect(at: base + page * 4, byteCount: page, permissions: .readWrite)
        passed.append("Cross-page writes validate all target pages before modifying any bytes")

        let beforeProtectGeneration = memory.pageGeneration(at: base + page)
        try memory.protect(at: base + page, byteCount: page, permissions: .read)
        try expect(memory.pageGeneration(at: base + page) != beforeProtectGeneration, "protection change did not advance page generation")
        passed.append("Page mapping generations change when permissions change")

        try memory.decommit(at: base + page, byteCount: page)
        try expect(!memory.isCommitted(address: base + page), "decommit retained page backing")
        try expectFault("access after decommit") {
            _ = try memory.readBytes(at: base + page, count: 1)
        }
        try memory.commit(at: base + page, byteCount: page, permissions: .readWrite)
        try expect(try memory.readBytes(at: base + page, count: 1) == [0], "recommitted page did not return as zero-filled")
        passed.append("Decommit releases page backing; recommit returns zero-filled memory")

        let stackBase = base + 0x10_0000
        let stack = try memory.reserveStack(at: stackBase, usableByteCount: page * 4, guardPageCount: 1)
        try expect(stack.usableBase == stackBase + page && stack.initialStackPointer == stackBase + page * 5, "stack usable bounds are incorrect")
        try expectFault("low stack guard") {
            try memory.writeBytes([0xAA], at: stack.lowGuardBase)
        }
        try expectFault("high stack guard") {
            try memory.writeBytes([0xAA], at: stack.highGuardBase)
        }
        try memory.writeBytes([0x5A], at: stack.initialStackPointer - 1)
        passed.append("Stack allocation commits only its RW interior and leaves low/high guard pages inaccessible")

        let largeBase = base + 0x20_0000
        _ = try memory.reserve(at: largeBase, byteCount: page * 1_048_576, kind: .anonymous)
        try memory.commit(at: largeBase + page * 7, byteCount: page, permissions: .readWrite)
        try expect(memory.committedPageCount < 16, "sparse multi-gigabyte reservation unexpectedly committed too much backing")
        passed.append("A 4 GiB guest reservation remains sparse when only one page is committed")

        let generationBeforeWrite = memory.writeGeneration
        let pageGenerationBeforeWrite = memory.pageGeneration(at: base + 8) ?? 0
        try memory.writeBytes([0x01], at: base + 8)
        try expect(memory.writeGeneration > generationBeforeWrite, "write generation did not advance")
        try expect((memory.pageGeneration(at: base + 8) ?? 0) > pageGenerationBeforeWrite, "page generation did not advance after a write")
        passed.append("Guest writes advance global and per-page generations for translation-cache coherence")

        let lazyBase = base + 0x1_1000_0000
        _ = try memory.reserve(at: lazyBase, byteCount: page * 8, kind: .image)
        try memory.registerDemandZeroRange(at: lazyBase, byteCount: page * 8, permissions: .readWrite)
        try expect(memory.demandZeroRangeCount == 1, "demand-zero registration did not retain one metadata range")
        try expect(memory.demandZeroReservedPageCount == 8, "demand-zero page count is incorrect")
        try expect(!memory.isCommitted(address: lazyBase) && memory.isDemandZero(address: lazyBase), "demand-zero registration eagerly allocated backing")
        try expectFault("manual commit of a registered demand-zero page") {
            try memory.commit(at: lazyBase, byteCount: page, permissions: .readWrite)
        }
        try expect(!memory.isCommitted(address: lazyBase), "manual commit bypassed demand-zero resolution")
        try expect(try memory.resolveDemandZeroPage(at: lazyBase + 17, access: .read), "permitted demand-zero read did not resolve")
        try expect(memory.isCommitted(address: lazyBase) && memory.permissions(at: lazyBase) == .readWrite, "demand-zero page permissions or commitment are incorrect")
        try expect(try memory.readBytes(at: lazyBase + 17, count: 8) == Array(repeating: 0, count: 8), "demand-zero page did not contain zeroes")
        try expect(memory.demandZeroReservedPageCount == 7, "resolving one page did not split the lazy range")
        passed.append("Demand-zero ranges remain metadata-only until first permitted access, then allocate one zero-filled page")

        let executeLazyBase = lazyBase + page * 16
        _ = try memory.reserve(at: executeLazyBase, byteCount: page * 2, kind: .image)
        try memory.registerDemandZeroRange(at: executeLazyBase, byteCount: page * 2, permissions: .readExecute)
        try expect(!(try memory.resolveDemandZeroPage(at: executeLazyBase, access: .write)), "write unexpectedly resolved a read-execute demand-zero page")
        try expect(!memory.isCommitted(address: executeLazyBase), "permission-denied demand-zero access allocated backing")
        let fetchedZeros = try memory.fetchAvailableBytes(at: executeLazyBase, maximumCount: 4)
        try expect(fetchedZeros == [0, 0, 0, 0] && memory.isCommitted(address: executeLazyBase), "instruction fetch did not materialize an executable zero page")
        passed.append("Demand-zero page-in honors segment protections and instruction fetch lazily commits executable pages")

        let writableLazyBase = executeLazyBase + page * 4
        _ = try memory.reserve(at: writableLazyBase, byteCount: page, kind: .image)
        try memory.registerDemandZeroRange(at: writableLazyBase, byteCount: page, permissions: .readWrite)
        try memory.writeBytes([0x5A, 0xA5], at: writableLazyBase + 3)
        try expect(memory.isCommitted(address: writableLazyBase), "write to demand-zero page did not commit it")
        try expect(try memory.readBytes(at: writableLazyBase + 3, count: 2) == [0x5A, 0xA5], "demand-zero write did not persist")
        passed.append("Guest writes transparently materialize writable demand-zero pages without changing neighbouring bytes")

        let hugeLazyBase = writableLazyBase + page * 4
        let hugeLazySize = page * 1_048_576
        _ = try memory.reserve(at: hugeLazyBase, byteCount: hugeLazySize, kind: .image)
        try memory.registerDemandZeroRange(at: hugeLazyBase, byteCount: hugeLazySize, permissions: .readWrite)
        let beforeHugePageIn = memory.committedPageCount
        try expect(try memory.resolveDemandZeroPage(at: hugeLazyBase + hugeLazySize - page, access: .read), "far demand-zero page did not resolve")
        try expect(memory.committedPageCount == beforeHugePageIn + 1, "resolving one page in a 4 GiB lazy range committed more than one page")
        try expect(memory.demandZeroReservedByteCount >= hugeLazySize - page, "large lazy range metadata was not preserved")
        passed.append("Demand-zero paging of a 4 GiB reservation backs only the single page actually touched")

        let lazyBackedBase = hugeLazyBase + hugeLazySize + page * 4
        let lazyBackedSize = page * 1_048_576
        _ = try memory.reserve(at: lazyBackedBase, byteCount: lazyBackedSize, kind: .shared)
        try memory.registerLazyBackedRange(
            at: lazyBackedBase,
            byteCount: lazyBackedSize,
            permissions: .readWrite
        ) { pageAddress in
            Data(repeating: UInt8(truncatingIfNeeded: pageAddress >> 12), count: Int(page))
        }
        try expect(memory.lazyBackedRangeCount == 1, "large cache-backed range was not retained as compact metadata")
        try expect(memory.lazyBackedReservedPageCount == 1_048_576, "large lazy-backed page count is incorrect")
        try expect(memory.committedPageCount == beforeHugePageIn + 1, "registering a 4 GiB lazy-backed range allocated host pages")
        try expect(memory.permissions(at: lazyBackedBase) == .readWrite, "uncommitted lazy-backed page does not expose its planned permissions")
        let expectedFirstMarker = UInt8(truncatingIfNeeded: lazyBackedBase >> 12)
        try expect(try memory.readBytes(at: lazyBackedBase + 7, count: 2) == [expectedFirstMarker, expectedFirstMarker], "read-only inspection did not retrieve lazy-backed source bytes")
        try expect(!memory.isCommitted(address: lazyBackedBase), "read-only inspection eagerly committed a lazy-backed page")
        let lastLazyPage = lazyBackedBase + lazyBackedSize - page
        let committedBeforeLazyBackedPageIn = memory.committedPageCount
        try expect(try memory.resolveDemandZeroPage(at: lastLazyPage, access: .read), "lazy-backed page-in did not resolve the final page")
        try expect(memory.committedPageCount == committedBeforeLazyBackedPageIn + 1, "resolving a lazy-backed page committed more than one page")
        let expectedLastMarker = UInt8(truncatingIfNeeded: lastLazyPage >> 12)
        try expect(try memory.readBytes(at: lastLazyPage + 31, count: 1) == [expectedLastMarker], "lazy-backed page provider data was not copied into guest backing")
        try memory.writeBytes([0xEE], at: lastLazyPage + 31)
        try expect(try memory.readBytes(at: lastLazyPage + 31, count: 1) == [0xEE], "guest write did not update its private lazy-backed page")
        try expect(memory.lazyBackedReservedPageCount == 1_048_575, "lazy-backed range did not consume exactly one page")
        passed.append("A 4 GiB cache-backed guest range allocates only pages actually touched; guest writes modify private page copies")

        try memory.release(at: lazyBackedBase)
        try memory.release(at: hugeLazyBase)
        try memory.release(at: writableLazyBase)
        try memory.release(at: executeLazyBase)
        try memory.release(at: lazyBase)
        try expect(memory.demandZeroRangeCount == 0, "releasing a reservation retained demand-zero metadata")
        try expect(memory.lazyBackedRangeCount == 0, "releasing a reservation retained lazy-backed metadata")
        passed.append("Releasing image reservations discards their remaining demand-zero and lazy-backed metadata and committed pages")

        try memory.release(at: largeBase)
        try expect(!memory.isReserved(address: largeBase + page * 7), "release did not remove reservation")
        try expectFault("access after release") {
            _ = try memory.readBytes(at: largeBase + page * 7, count: 1)
        }
        passed.append("Release removes reservations and all committed page backing")

        try expectFault("access beyond guest address range") {
            _ = try memory.readBytes(at: UInt64.max - 3, count: 8)
        }
        passed.append("Address arithmetic overflow and unmapped accesses fail safely")

        return passed
    }

    private static func expect(_ condition: @autoclosure () throws -> Bool, _ message: String) throws {
        guard try condition() else { throw TestError.failed(message) }
    }

    private static func expectFault(_ name: String, _ body: () throws -> Void) throws {
        do {
            try body()
            throw TestError.failed("expected guest memory fault: \(name)")
        } catch is X64GuestVirtualMemoryFault {
            return
        }
    }

    enum TestError: LocalizedError {
        case failed(String)
        var errorDescription: String? {
            switch self {
            case .failed(let message): return "Guest virtual-memory test failed: \(message)"
            }
        }
    }
}
