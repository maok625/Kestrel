import Foundation

/// Synthetic Mach-O fixtures exercise parsing and guest-memory mapping without
/// requiring a copyrighted or host-native application binary.
enum X64MachOLoaderSelfTests {
    private static let pageSize: UInt64 = 4_096
    private static let textBase: UInt64 = 0x1_0000_0000
    private static let dataBase: UInt64 = 0x1_0000_1000
    private static let entryOffset: UInt64 = 0x800

    static func run() throws -> [String] {
        var passed: [String] = []

        do {
            let image = try X64MachOParser.parse(data: makeThinExecutable())
            try expect(image.header.cpuType == 0x0100_0007, "thin header CPU type")
            try expect(image.segments.count == 3, "thin segment parsing")
            passed.append("Thin 64-bit x86_64 MH_EXECUTE header and LC_SEGMENT_64 commands parse")
        }

        do {
            let image = try X64MachOParser.parse(data: makeThinExecutable())
            try expect(image.entryOffset == entryOffset, "LC_MAIN entry offset")
            try expect(image.entryAddress == textBase + entryOffset, "LC_MAIN virtual entry")
            try expect(image.preferredLoadAddress == textBase, "preferred image base")
            passed.append("LC_MAIN entryoff resolves relative to the preferred __TEXT base")
        }

        do {
            let image = try X64MachOParser.parse(data: makeFatExecutable())
            try expect(image.header.cpuType == 0x0100_0007, "fat slice architecture")
            try expect(image.entryAddress == textBase + entryOffset, "fat x86_64 entry")
            passed.append("Universal FAT Mach-O selects the x86_64 slice rather than the ARM64 slice")
        }

        do {
            let image = try X64MachOParser.parse(data: makeFat64Executable())
            try expect(image.header.cpuType == 0x0100_0007, "fat64 slice architecture")
            passed.append("Universal FAT64 Mach-O selects and validates its x86_64 slice")
        }

        do {
            let image = try X64MachOParser.parse(data: makeFatCigamExecutable())
            try expect(image.header.cpuType == 0x0100_0007, "swapped FAT slice architecture")
            passed.append("Swapped-endian FAT Mach-O selects the x86_64 slice safely")
        }

        do {
            let image = try X64MachOParser.parse(data: makeThinExecutable())
            var memory = try X64GuestVirtualMemory()
            let loaded = try X64MachOLoader.load(image, into: &memory)
            try expect(loaded.mappedSegments.count == 3, "mapped segment count")
            try expect(memory.region(containing: 0) != nil, "PAGEZERO reservation")
            try expect(memory.permissions(at: 0) == nil, "PAGEZERO remains uncommitted")
            try expect(memory.permissions(at: textBase) == .readExecute, "TEXT final permissions")
            try expect(memory.permissions(at: dataBase) == .readWrite, "DATA final permissions")
            try expect(memory.committedPageCount == 2, "file-backed image page count")
            try expect(loaded.committedBytes == 0x2_000, "file-backed committed image size")
            try expect(loaded.demandZeroBytes == pageSize, "DATA tail demand-zero byte count")
            try expect(memory.demandZeroRangeCount == 1 && memory.demandZeroReservedPageCount == 1, "DATA tail lazy metadata")
            try expect(!memory.isCommitted(address: dataBase + pageSize) && memory.isDemandZero(address: dataBase + pageSize), "DATA tail was not left demand-zero")
            try expect(loaded.reservedVirtualBytes == 0x1_0000_3000, "full virtual image reservation size")
            passed.append("Loader reserves __PAGEZERO and registers segment tails/BSS for sparse demand-zero backing")
        }

        do {
            let image = try X64MachOParser.parse(data: makeThinExecutable())
            var memory = try X64GuestVirtualMemory()
            let loaded = try X64MachOLoader.load(image, into: &memory)
            let dataTail = dataBase + pageSize
            try expect(memory.isDemandZero(address: dataTail) && !memory.isCommitted(address: dataTail), "BSS tail was not sparse before access")
            let bssPageResolved = try memory.resolveDemandZeroPage(at: dataTail + 23, access: .read)
            try expect(bssPageResolved, "BSS demand-zero page resolution failed")
            try expect(memory.permissions(at: dataTail) == .readWrite, "BSS page did not inherit DATA permissions")
            let bssBytes = try memory.readBytes(at: dataTail, count: Int(pageSize))
            try expect(bssBytes == Array(repeating: 0, count: Int(pageSize)), "BSS page did not materialize as zero-filled")
            try expect(loaded.demandZeroBytes == pageSize, "loaded image lazy-page metadata snapshot is incorrect")
            try expect(memory.demandZeroReservedByteCount == 0, "one-page BSS range remained after its only page was materialized")
            passed.append("First BSS access allocates one zero-filled page with the segment's final permissions")
        }

        do {
            let image = try X64MachOParser.parse(data: makeThinExecutable())
            var memory = try X64GuestVirtualMemory()
            _ = try X64MachOLoader.load(image, into: &memory)
            let entryBytes = try memory.fetchBytes(at: image.entryAddress, maximumCount: 2)
            try expect(entryBytes == [0x90, 0xC3], "entry bytes")
            let dataBytes = try memory.readBytes(at: dataBase, count: 4)
            try expect(dataBytes == [0xAA, 0xBB, 0xCC, 0xDD], "DATA bytes")
            passed.append("File-backed segment contents are copied to their guest virtual addresses")
        }

        do {
            let image = try X64MachOParser.parse(data: makeThinExecutable())
            var memory = try X64GuestVirtualMemory()
            _ = try X64MachOLoader.load(image, into: &memory)
            let bssTailOfFilePage = try memory.readBytes(at: dataBase + 0x100, count: 16)
            try expect(bssTailOfFilePage == Array(repeating: 0, count: 16), "zero tail within file-backed page")
            var sparseTailFaulted = false
            do { _ = try memory.readBytes(at: dataBase + pageSize, count: 1) }
            catch { sparseTailFaulted = true }
            try expect(sparseTailFaulted, "uncommitted sparse segment tail")
            passed.append("File-page tail is zero initialized; distant BSS/segment tail remains reserved and uncommitted")
        }

        do {
            let image = try X64MachOParser.parse(data: makeThinExecutable())
            var memory = try X64GuestVirtualMemory()
            _ = try X64MachOLoader.load(image, into: &memory)
            var writeWasRejected = false
            do { try memory.writeBytes([0xCC], at: image.entryAddress) }
            catch { writeWasRejected = true }
            try expect(writeWasRejected, "RX text write denial")
            try memory.writeBytes([0x11], at: dataBase)
            let updatedData = try memory.readBytes(at: dataBase, count: 1)
            try expect(updatedData == [0x11], "RW data write")
            passed.append("Final segment permissions enforce RX __TEXT and RW __DATA")
        }

        do {
            let image = try X64MachOParser.parse(data: makeThinExecutable())
            var memory = try X64GuestVirtualMemory()
            _ = try X64MachOLoader.load(image, into: &memory)
            var faulted = false
            do { _ = try memory.fetchBytes(at: dataBase, maximumCount: 1) }
            catch { faulted = true }
            try expect(faulted, "non-executable data fetch")
            passed.append("Guest instruction fetch rejects non-executable __DATA pages")
        }

        do {
            let image = try X64MachOParser.parse(data: makeThinExecutable())
            var memory = try X64GuestVirtualMemory()
            _ = try memory.reserve(at: dataBase, byteCount: pageSize, kind: .anonymous)
            var loadFailed = false
            do { _ = try X64MachOLoader.load(image, into: &memory) }
            catch { loadFailed = true }
            try expect(loadFailed, "overlapping segment reservation")
            try expect(memory.region(containing: 0) == nil, "PAGEZERO rollback")
            try expect(memory.region(containing: textBase) == nil, "TEXT rollback")
            try expect(memory.region(containing: dataBase) != nil, "pre-existing collision retained")
            passed.append("Failed image mapping rolls back all reservations without disturbing pre-existing guest memory")
        }

        do {
            var data = makeThinExecutable()
            data.replaceSubrange(0..<4, with: littleEndian32(0xFEED_FACF))
            data.replaceSubrange(4..<8, with: littleEndian32(0x0100_000C))
            var rejected = false
            do { _ = try X64MachOParser.parse(data: data) }
            catch { rejected = true }
            try expect(rejected, "ARM64 thin image rejection")
            passed.append("Thin ARM64 images are rejected by the x86_64-only loader")
        }

        do {
            var data = makeThinExecutable()
            // The __DATA command begins after the header and two 72-byte segments.
            data.replaceSubrange(200..<208, with: littleEndian64(textBase))
            var rejected = false
            do { _ = try X64MachOParser.parse(data: data) }
            catch { rejected = true }
            try expect(rejected, "overlapping segment rejection")
            passed.append("Overlapping guest virtual segment ranges are rejected before mapping")
        }

        do {
            let image = try X64MachOParser.parse(data: makeThinExecutable())
            var memory = try X64GuestVirtualMemory()
            var rejected = false
            do { _ = try X64MachOLoader.load(image, into: &memory, maximumCommittedBytes: pageSize) }
            catch { rejected = true }
            try expect(rejected, "loader committed-memory safety limit")
            try expect(memory.reservedRegionCount == 0, "safety limit leaves guest memory untouched")
            passed.append("File-backed committed-memory safety limit is checked before changing guest memory")
        }

        do {
            var data = makeThinExecutable()
            let veryLargeVirtualSize: UInt64 = 0x9BC3_28B000 // 623 GiB, page aligned
            // __DATA is the third LC_SEGMENT_64 command: header (32) + PAGEZERO (72) + TEXT (72).
            data.replaceSubrange(208..<216, with: littleEndian64(veryLargeVirtualSize))
            let image = try X64MachOParser.parse(data: data, sourceName: "large-sparse-fixture")
            var memory = try X64GuestVirtualMemory()
            let loaded = try X64MachOLoader.load(image, into: &memory)
            let dataSegment = loaded.mappedSegments.first { $0.name == "__DATA" }
            try expect(dataSegment?.byteCount == veryLargeVirtualSize, "large DATA virtual reservation")
            try expect(dataSegment?.committedByteCount == pageSize, "only DATA file-backed page is committed")
            try expect(loaded.committedBytes == pageSize * 2, "total eager backing remains two pages")
            try expect(loaded.reservedVirtualBytes > 600 * 1024 * 1024 * 1024, "large virtual address space preserved")
            let farTailAddress = dataBase + veryLargeVirtualSize - pageSize
            try expect(memory.isDemandZero(address: farTailAddress) && !memory.isCommitted(address: farTailAddress), "far reserved tail is not lazy")
            let beforeFarPageIn = memory.committedPageCount
            let farPageResolved = try memory.resolveDemandZeroPage(at: farTailAddress, access: .read)
            try expect(farPageResolved, "far BSS demand-zero page did not resolve")
            try expect(memory.committedPageCount == beforeFarPageIn + 1, "far BSS access allocated more than one page")
            let farPageBytes = try memory.readBytes(at: farTailAddress, count: 32)
            try expect(farPageBytes == Array(repeating: 0, count: 32), "far BSS page was not zero-filled")
            passed.append("A 623 GiB Mach-O segment remains sparse; first access to a far BSS address commits only its 4 KiB page")
        }

        do {
            let data = Data([0xCF, 0xFA, 0xED])
            var rejected = false
            do { _ = try X64MachOParser.parse(data: data) }
            catch { rejected = true }
            try expect(rejected, "truncated header rejection")
            passed.append("Truncated Mach-O headers are rejected before reading load commands")
        }

        do {
            var data = makeThinExecutable()
            // First load command starts immediately after the 32-byte header.
            data.replaceSubrange(36..<40, with: littleEndian32(4))
            var rejected = false
            do { _ = try X64MachOParser.parse(data: data) }
            catch { rejected = true }
            try expect(rejected, "invalid cmdsize rejection")
            passed.append("Malformed and out-of-bounds load commands are rejected safely")
        }

        do {
            let image = try X64MachOParser.parse(data: makeThinExecutable())
            var memory = try X64GuestVirtualMemory()
            let loaded = try X64MachOLoader.load(image, into: &memory)
            try X64MachOLoader.unload(loaded, from: &memory)
            try expect(memory.reservedRegionCount == 0, "unload regions")
            try expect(memory.committedPageCount == 0, "unload pages")
            passed.append("Loaded image can be unloaded, releasing its guest reservations and committed pages")
        }

        do {
            let image = try X64MachOParser.parse(data: makeRebasedThinExecutable())
            try expect(image.hasDyldInfoCommand, "LC_DYLD_INFO_ONLY detection")
            try expect(image.rebaseFixupAddresses == [dataBase], "decoded rebase location")
            passed.append("Classic dyld rebase opcodes decode a validated 64-bit pointer location from the selected segment")
        }

        do {
            let image = try X64MachOParser.parse(data: makeRebasedThinExecutable())
            var memory = try X64GuestVirtualMemory()
            let slide: UInt64 = 0x20_0000
            let loaded = try X64MachOLoader.load(image, into: &memory, slide: slide)
            let expectedPointer = textBase + 0x900 + slide
            let actualPointer = try memory.readUnsigned(at: dataBase + slide, byteCount: 8)
            try expect(loaded.slide == slide, "recorded PIE slide")
            try expect(loaded.entryAddress == image.entryAddress + slide, "slid LC_MAIN")
            try expect(loaded.mappedSegments.first(where: { $0.name == "__TEXT" })?.guestAddress == textBase + slide, "slid TEXT segment")
            try expect(memory.region(containing: 0)?.baseAddress == 0, "PAGEZERO remains at address zero")
            try expect(actualPointer == expectedPointer, "rebased pointer value")
            try expect(loaded.rebaseFixupCount == 1 && loaded.rebasesApplied == 1, "rebase accounting")
            try expect(memory.permissions(at: textBase + slide) == .readExecute, "final TEXT permissions after rebase")
            try expect(memory.permissions(at: dataBase + slide) == .readWrite, "final DATA permissions after rebase")
            passed.append("Explicit page-aligned PIE slide moves image segments and LC_MAIN, rebases 64-bit pointers, and restores final segment permissions")
        }

        do {
            let image = try X64MachOParser.parse(data: makeRebasedThinExecutable(bindOpcodeBytes: [0x00, 0x00, 0x00]))
            try expect(image.bindOpcodeBytes == 3, "bind opcode byte count")
            var memory = try X64GuestVirtualMemory()
            let loaded = try X64MachOLoader.load(image, into: &memory, slide: pageSize)
            try expect(loaded.unresolvedBindOpcodeBytes == 3, "unresolved bind metadata propagated to loaded image")
            try expect(loaded.rebasesApplied == 1, "classic rebase still applies when bind streams are present")
            passed.append("Bind opcode streams are size-validated and reported as unresolved without being mistaken for completed symbol binding")
        }

        do {
            let image = try X64MachOParser.parse(data: makeBoundThinExecutable())
            try expect(image.dependencies.count == 1, "dependency count")
            try expect(image.dependencies[0].ordinal == 1, "dependency ordinal")
            try expect(image.dependencies[0].installName == "/usr/lib/libSystem.B.dylib", "dependency install name")
            try expect(image.bindActions.count == 1, "regular bind action count")
            try expect(image.bindActions[0].symbolName == "_puts", "bound symbol name")
            try expect(image.bindActions[0].libraryOrdinal == 1, "bind dylib ordinal")
            try expect(image.bindActions[0].location == dataBase, "bind guest location")
            passed.append("LC_LOAD_DYLIB records dependency identity and classic BIND opcodes decode symbol, ordinal, addend, and guest slot")
        }

        do {
            let image = try X64MachOParser.parse(data: makeBoundThinExecutable())
            var memory = try X64GuestVirtualMemory()
            var symbols = X64MachOSymbolResolver()
            symbols.register(symbol: "_puts", address: textBase + 0x900) // global, not the named dylib
            let loaded = try X64MachOLoader.load(image, into: &memory, symbolResolver: symbols)
            try expect(loaded.boundFixupCount == 0, "flat namespace entry must not satisfy positive dependency ordinal")
            try expect(loaded.unresolvedBindSymbols == ["_puts"], "strict two-level unresolved import")
            try expect(try memory.readUnsigned(at: dataBase, byteCount: 8) == 0x0000_0000_DDCC_BBAA, "two-level mismatch leaves original slot untouched")
            passed.append("Positive dylib ordinals do not fall back to a same-named global flat-namespace symbol")
        }

        do {
            let image = try X64MachOParser.parse(data: makeBoundThinExecutable())
            var memory = try X64GuestVirtualMemory()
            let loaded = try X64MachOLoader.load(image, into: &memory)
            try expect(loaded.bindFixupCount == 1 && loaded.boundFixupCount == 0, "unresolved bind accounting")
            try expect(loaded.unresolvedBindFixupCount == 1, "unresolved bind slot count")
            try expect(loaded.unresolvedBindSymbols == ["_puts"], "unresolved symbol report")
            let unresolvedValue = try memory.readUnsigned(at: dataBase, byteCount: 8)
            try expect(unresolvedValue == 0x0000_0000_DDCC_BBAA, "unresolved slot remains untouched")
            passed.append("Unknown strong imports remain explicitly unresolved and are not patched with unsafe host addresses")
        }

        do {
            let image = try X64MachOParser.parse(data: makeBoundThinExecutable())
            var memory = try X64GuestVirtualMemory()
            var symbols = X64MachOSymbolResolver()
            symbols.register(symbol: "_puts", address: textBase + 0x900, installName: "/usr/lib/libSystem.B.dylib")
            let loaded = try X64MachOLoader.load(image, into: &memory, symbolResolver: symbols, requireAllBindingsResolved: true)
            try expect(loaded.boundFixupCount == 1, "applied bind count")
            try expect(loaded.unresolvedBindSymbols.isEmpty, "resolved import list")
            try expect(try memory.readUnsigned(at: dataBase, byteCount: 8) == textBase + 0x900, "bound guest pointer")
            try expect(memory.permissions(at: dataBase) == .readWrite, "DATA protection restored")
            passed.append("Injected guest symbol resolver applies a dependency-qualified import before final segment permissions are restored")
        }

        do {
            let image = try X64MachOParser.parse(data: makeBoundThinExecutable())
            var memory = try X64GuestVirtualMemory()
            var rejected = false
            do { _ = try X64MachOLoader.load(image, into: &memory, requireAllBindingsResolved: true) }
            catch { rejected = true }
            try expect(rejected, "strict unresolved import rejection")
            try expect(memory.reservedRegionCount == 0 && memory.committedPageCount == 0, "strict bind failure rollback")
            passed.append("Strict loader mode rejects unresolved required imports and rolls back the entire image")
        }

        do {
            let image = try X64MachOParser.parse(data: makeBoundThinExecutable(weakImport: true))
            try expect(image.bindActions.count == 1 && image.bindActions[0].isWeakImport, "weak import flag")
            var memory = try X64GuestVirtualMemory()
            let loaded = try X64MachOLoader.load(image, into: &memory)
            try expect(loaded.boundFixupCount == 1 && loaded.unresolvedBindSymbols.isEmpty, "weak null bind count")
            try expect(try memory.readUnsigned(at: dataBase, byteCount: 8) == 0, "weak unresolved symbol should bind null")
            passed.append("Undefined weak imports resolve to a null guest pointer when no provider is registered")
        }

        do {
            let image = try X64MachOParser.parse(data: makeExportTrieExecutable())
            try expect(image.exports.count == 1, "export count")
            try expect(image.exports[0].symbolName == "_fixture", "export name")
            try expect(image.exports[0].addressOffset == 0x900, "export address offset")
            passed.append("LC_DYLD_EXPORTS_TRIE decodes regular exported symbols and preferred-image-relative offsets")
        }

        do {
            let image = try X64MachOParser.parse(data: makeSelfBoundExportExecutable())
            var memory = try X64GuestVirtualMemory()
            let loaded = try X64MachOLoader.load(image, into: &memory)
            try expect(loaded.boundFixupCount == 1, "main-image exported symbol bind count")
            try expect(try memory.readUnsigned(at: dataBase, byteCount: 8) == textBase + 0x900, "main-image exported symbol bind value")
            passed.append("Main-image exports automatically resolve self-ordinal classic binds to guest addresses")
        }

        do {
            let image = try X64MachOParser.parse(data: makeRPathExecutable())
            try expect(image.rpaths == ["@executable_path/Frameworks"], "LC_RPATH string parsing")
            let temporaryRoot = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
            let appDirectory = temporaryRoot.appendingPathComponent("Sample.app/Contents/MacOS", isDirectory: true)
            let frameworkDirectory = temporaryRoot.appendingPathComponent("Sample.app/Contents/MacOS/Frameworks", isDirectory: true)
            try FileManager.default.createDirectory(at: frameworkDirectory, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: temporaryRoot) }
            let executableURL = appDirectory.appendingPathComponent("sample")
            let dylibURL = frameworkDirectory.appendingPathComponent("libFixture.dylib")
            try Data([0x01]).write(to: dylibURL)
            let resolved = X64MachODependencyPathResolver.resolve(
                "@rpath/libFixture.dylib",
                rpaths: image.rpaths,
                executableURL: executableURL,
                loaderURL: executableURL
            )
            try expect(resolved?.standardizedFileURL == dylibURL.standardizedFileURL, "@rpath candidate resolution")
            passed.append("LC_RPATH and @executable_path expansion locate an app-bundled dylib without claiming it is loaded")
        }

        do {
            let image = try X64MachOParser.parse(data: makeChainedFixupExecutable())
            try expect(image.chainedFixupsBytes == 4, "chained fixup data size")
            var memory = try X64GuestVirtualMemory()
            var rejected = false
            do { _ = try X64MachOLoader.load(image, into: &memory, slide: pageSize) }
            catch { rejected = true }
            try expect(rejected, "chained fixups slide rejection")
            try expect(memory.reservedRegionCount == 0, "chained fixup rejection leaves memory untouched")
            passed.append("PIE sliding refuses chained-fixup images until their pointer formats are decoded")
        }

        do {
            let data = makeRebasedThinExecutable(rebaseOpcodes: [0x22, 0x80])
            var rejected = false
            do { _ = try X64MachOParser.parse(data: data) }
            catch { rejected = true }
            try expect(rejected, "truncated rebase ULEB128 rejection")
            passed.append("Truncated dyld rebase ULEB128 values are rejected before mapping")
        }

        do {
            let data = makeRebasedThinExecutable(rebaseOpcodes: [0x11, 0x22, 0x00, 0x51, 0x11, 0x22, 0x00, 0x51, 0x00])
            var rejected = false
            do { _ = try X64MachOParser.parse(data: data) }
            catch { rejected = true }
            try expect(rejected, "duplicate rebase location rejection")
            passed.append("Duplicate dyld rebase locations are rejected to prevent a pointer from receiving the slide twice")
        }

        do {
            let data = makeRebasedThinExecutable(rebaseOpcodes: [0x12, 0x22, 0x00, 0x51, 0x00])
            var rejected = false
            do { _ = try X64MachOParser.parse(data: data) }
            catch { rejected = true }
            try expect(rejected, "unsupported rebase type rejection")
            passed.append("Unsupported 32-bit/text dyld rebase types fail closed instead of being applied as pointers")
        }

        do {
            var data = makeRebasedThinExecutable()
            data.replaceSubrange(0x1_000..<0x1_008, with: littleEndian64(0x1234))
            let image = try X64MachOParser.parse(data: data)
            var memory = try X64GuestVirtualMemory()
            var rejected = false
            do { _ = try X64MachOLoader.load(image, into: &memory, slide: pageSize) }
            catch { rejected = true }
            try expect(rejected, "external target pointer rebase rejection")
            try expect(memory.reservedRegionCount == 0 && memory.committedPageCount == 0, "rebase failure rolled image mapping back")
            passed.append("A rebase pointer that does not refer into the image is rejected and all partially mapped guest regions are rolled back")
        }

        do {
            var data = makeRebasedThinExecutable()
            data.replaceSubrange(24..<28, with: littleEndian32(0x0000_0085)) // clear MH_PIE
            let image = try X64MachOParser.parse(data: data)
            var memory = try X64GuestVirtualMemory()
            var rejected = false
            do { _ = try X64MachOLoader.load(image, into: &memory, slide: pageSize) }
            catch { rejected = true }
            try expect(rejected, "non-PIE slide rejection")
            try expect(memory.reservedRegionCount == 0, "non-PIE rejection leaves memory untouched")
            passed.append("Non-PIE executables cannot be assigned an ASLR slide; rejection occurs before guest memory changes")
        }

        do {
            let image = try X64MachOParser.parse(data: makeThinExecutable())
            var memory = try X64GuestVirtualMemory()
            var rejected = false
            do { _ = try X64MachOLoader.load(image, into: &memory, slide: 1) }
            catch { rejected = true }
            try expect(rejected, "unaligned slide rejection")
            try expect(memory.reservedRegionCount == 0, "unaligned slide leaves memory untouched")
            passed.append("PIE slides must be 4 KiB aligned and are validated before reserving guest ranges")
        }

        do {
            var bind = Data([0x40]) // SET_SYMBOL_TRAILING_FLAGS_IMM, ordinal self
            bind.append(contentsOf: Array("_tail_cursor".utf8) + [0])
            bind.append(contentsOf: [0x72, 0x00, 0x90, 0x80]) // DATA+0; DO_BIND; ADD_ADDR_ULEB
            appendULEB(0x20_000, to: &bind) // Move well past __DATA after the final valid bind.
            bind.append(0x00) // DONE
            let image = try X64MachOParser.parse(
                data: makeRebasedThinExecutable(rebaseOpcodes: [0], bindOpcodeBytes: Array(bind))
            )
            try expect(image.bindActions.count == 1, "final post-bind cursor overflow should not invalidate prior action")
            try expect(image.bindActions[0].location == dataBase, "tail cursor overflow preserves valid bind location")
            passed.append("A final dyld bind cursor advance may leave the selected segment after the last valid action without rejecting the image")
        }

        do {
            var bind = Data([0x40])
            bind.append(contentsOf: Array("_after_reset".utf8) + [0])
            bind.append(contentsOf: [0x72, 0x08, 0x80]) // DATA+8; ADD_ADDR_ULEB
            appendULEB(UInt64.max, to: &bind) // Modulo wrap to DATA+7, then reset explicitly.
            bind.append(contentsOf: [0x72, 0x10, 0x90, 0x00]) // New segment cursor resets it; bind DATA+0x10.
            let image = try X64MachOParser.parse(
                data: makeRebasedThinExecutable(rebaseOpcodes: [0], bindOpcodeBytes: Array(bind))
            )
            try expect(image.bindActions.count == 1, "SET_SEGMENT should reset an invalid previous cursor")
            try expect(image.bindActions[0].location == dataBase + 0x10, "post-reset bind target")
            passed.append("BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB resets an out-of-range cursor before the next binding")
        }

        do {
            var bind = Data([0x40])
            bind.append(contentsOf: Array("_wrapped_slot".utf8) + [0])
            bind.append(contentsOf: [0x72, 0x08, 0x80]) // DATA+8; ADD_ADDR_ULEB.
            appendULEB(UInt64.max, to: &bind) // 8 + UINT64_MAX wraps modulo 2^64 to 7.
            bind.append(contentsOf: [0x90, 0x00])
            let image = try X64MachOParser.parse(
                data: makeRebasedThinExecutable(rebaseOpcodes: [0], bindOpcodeBytes: Array(bind))
            )
            try expect(image.bindActions.count == 1, "wrapped in-segment bind must be accepted")
            try expect(image.bindActions[0].location == dataBase + 7, "wrapped cursor result should be DATA+7")
            passed.append("ADD_ADDR_ULEB uses dyld's modulo-2^64 cursor arithmetic and accepts a wrapped cursor when the resulting bind remains inside the segment")
        }

        do {
            var bind = Data([0x40])
            bind.append(contentsOf: Array("_wrapped_outside".utf8) + [0])
            bind.append(contentsOf: [0x72])
            appendULEB(0x2_838, to: &bind)
            bind.append(0x80)
            appendULEB(UInt64.max - 0xFF, to: &bind) // Add -0x100 modulo 2^64 => 0x2738.
            bind.append(contentsOf: [0x90, 0x00])
            var diagnostic = ""
            do {
                _ = try X64MachOParser.parse(
                    data: makeRebasedThinExecutable(rebaseOpcodes: [0], bindOpcodeBytes: Array(bind))
                )
            } catch { diagnostic = error.localizedDescription }
            try expect(diagnostic.contains("segment offset=0x0000000000002738"), "wrapped out-of-range cursor must be checked at bind time")
            passed.append("Modulo-wrapped bind cursors are still rejected when their resulting pointer location is outside the selected segment")
        }

        do {
            var bind = Data([0x40])
            bind.append(contentsOf: Array("_reverse_cursor".utf8) + [0])
            bind.append(contentsOf: [0x72])
            appendULEB(0x2_838, to: &bind)
            bind.append(0x80)
            appendULEB(UInt64.max - 0x2_51F, to: &bind) // 2^64 - 0x2520; 0x2838 -> 0x318.
            bind.append(contentsOf: [0x90, 0x00])
            let image = try X64MachOParser.parse(
                data: makeRebasedThinExecutable(
                    rebaseOpcodes: [0],
                    bindOpcodeBytes: Array(bind),
                    dataVirtualSize: 0x5_000
                )
            )
            try expect(image.bindActions.count == 1, "reverse cursor bind count")
            try expect(image.bindActions[0].location == dataBase + 0x318, "reverse cursor bind should resolve to DATA+0x318")
            var memory = try X64GuestVirtualMemory()
            var resolver = X64MachOSymbolResolver()
            resolver.register(symbol: "_reverse_cursor", address: textBase + 0x900)
            let loaded = try X64MachOLoader.load(
                image,
                into: &memory,
                symbolResolver: resolver,
                requireAllBindingsResolved: true
            )
            try expect(loaded.boundFixupCount == 1, "reverse cursor binding should be applied")
            try expect(
                try memory.readUnsigned(at: dataBase + 0x318, byteCount: 8) == textBase + 0x900,
                "reverse cursor bind wrote the resolved guest pointer to the wrong slot"
            )
            passed.append("Real-world dyld reverse bind-cursor adjustment wraps 0x2838 backwards by 0x2520 to DATA+0x318 and correctly applies the guest-address fixup")
        }

        do {
            var bind = Data([0x40])
            bind.append(contentsOf: Array("_invalid_offset".utf8) + [0])
            bind.append(0x72) // Select __DATA.
            appendULEB(UInt64.max, to: &bind)
            bind.append(contentsOf: [0x90, 0x00]) // A bind at UINT64_MAX is genuinely invalid.
            var diagnostic = ""
            do {
                _ = try X64MachOParser.parse(
                    data: makeRebasedThinExecutable(rebaseOpcodes: [0], bindOpcodeBytes: Array(bind))
                )
            } catch {
                diagnostic = error.localizedDescription
            }
            try expect(diagnostic.contains("selected by opcode") && diagnostic.contains("stream bytes") && diagnostic.contains("segment index=2"), "invalid bind should expose opcode context")
            passed.append("Invalid bind offsets retain fail-closed behavior and report the preceding cursor-setting opcode plus raw stream context")
        }

        do {
            var bind = Data([0x41]) // Weak import, undefined weak resolves to zero.
            bind.append(contentsOf: Array("_weak_bss_slot".utf8) + [0])
            bind.append(0x72) // DATA segment index 2, followed by the ULEB offset.
            appendULEB(0x1_100, to: &bind) // Beyond DATA filesize, inside its demand-zero vmsize.
            bind.append(contentsOf: [0x90, 0x00])
            let image = try X64MachOParser.parse(
                data: makeRebasedThinExecutable(rebaseOpcodes: [0], bindOpcodeBytes: Array(bind))
            )
            try expect(image.bindActions.count == 1 && image.bindActions.first?.location == dataBase + 0x1_100, "BSS bind action parse")
            var memory = try X64GuestVirtualMemory()
            let loaded = try X64MachOLoader.load(image, into: &memory)
            try expect(loaded.boundFixupCount == 1, "undefined weak BSS bind should resolve to null")
            try expect(memory.isCommitted(address: dataBase + 0x1_100), "BSS bind should materialize the demand-zero page")
            try expect(try memory.readUnsigned(at: dataBase + 0x1_100, byteCount: 8) == 0, "BSS weak bind should be zero-filled")
            passed.append("Dyld pointer binds may target valid zero-fill segment tails and materialize a demand-zero page")
        }

        return passed
    }

    // MARK: Fixture construction

    private static func makeThinExecutable() -> Data {
        var data = Data()
        appendLE32(0xFEED_FACF, to: &data)       // MH_MAGIC_64
        appendLE32(0x0100_0007, to: &data)       // CPU_TYPE_X86_64
        appendLE32(3, to: &data)                 // CPU_SUBTYPE_X86_64_ALL
        appendLE32(2, to: &data)                 // MH_EXECUTE
        appendLE32(4, to: &data)                 // ncmds
        appendLE32(72 * 3 + 24, to: &data)       // sizeofcmds
        appendLE32(0x0020_0085, to: &data)       // flags
        appendLE32(0, to: &data)                 // reserved

        appendSegment(
            name: "__PAGEZERO", vmAddress: 0, vmSize: 0x1_0000_0000,
            fileOffset: 0, fileSize: 0, maxProtection: 0, initialProtection: 0,
            to: &data
        )
        appendSegment(
            name: "__TEXT", vmAddress: textBase, vmSize: pageSize,
            fileOffset: 0, fileSize: pageSize, maxProtection: 5, initialProtection: 5,
            to: &data
        )
        appendSegment(
            name: "__DATA", vmAddress: dataBase, vmSize: pageSize * 2,
            fileOffset: pageSize, fileSize: 0x100, maxProtection: 3, initialProtection: 3,
            to: &data
        )

        appendLE32(0x8000_0028, to: &data)      // LC_MAIN
        appendLE32(24, to: &data)
        appendLE64(entryOffset, to: &data)
        appendLE64(0x1_0000, to: &data)         // stacksize hint

        if data.count < 0x1_100 { data.append(contentsOf: repeatElement(0, count: 0x1_100 - data.count)) }
        data.replaceSubrange(Int(entryOffset)..<(Int(entryOffset) + 2), with: [0x90, 0xC3])
        data.replaceSubrange(0x1_000..<0x1_004, with: [0xAA, 0xBB, 0xCC, 0xDD])
        return data
    }

    private static func makeRebasedThinExecutable(
        rebaseOpcodes: [UInt8] = [0x11, 0x22, 0x00, 0x51, 0x00],
        bindOpcodeBytes: [UInt8] = [],
        dataVirtualSize: UInt64 = pageSize * 2
    ) -> Data {
        var data = makeThinExecutable()
        // __DATA is the third LC_SEGMENT_64 command (header + two segments).
        // Keep a larger sparse tail available for bind-cursor wrap fixtures.
        data.replaceSubrange(208..<216, with: littleEndian64(dataVirtualSize))
        // Extend the command table in the existing __TEXT file page without
        // shifting file offsets for __DATA or changing the synthetic layout.
        data.replaceSubrange(16..<20, with: littleEndian32(5))
        data.replaceSubrange(20..<24, with: littleEndian32(72 * 3 + 24 + 48))

        var command = Data()
        appendLE32(0x8000_0022, to: &command) // LC_DYLD_INFO_ONLY
        appendLE32(48, to: &command)
        appendLE32(0x1_100, to: &command) // rebase_off
        appendLE32(UInt32(rebaseOpcodes.count), to: &command) // rebase_size
        appendLE32(UInt32(0x1_100 + rebaseOpcodes.count), to: &command) // bind_off
        appendLE32(UInt32(bindOpcodeBytes.count), to: &command) // bind_size
        appendLE32(0, to: &command) // weak_bind_off
        appendLE32(0, to: &command) // weak_bind_size
        appendLE32(0, to: &command) // lazy_bind_off
        appendLE32(0, to: &command) // lazy_bind_size
        appendLE32(0, to: &command) // export_off
        appendLE32(0, to: &command) // export_size
        data.replaceSubrange(272..<320, with: command)

        // DATA's first pointer initially refers to a location in preferred
        // __TEXT. dyld's rebase opcodes identify this slot in segment index 2.
        data.replaceSubrange(0x1_000..<0x1_008, with: littleEndian64(textBase + 0x900))
        data.append(contentsOf: rebaseOpcodes)
        data.append(contentsOf: bindOpcodeBytes)
        return data
    }

    private static func makeSelfBoundExportExecutable() -> Data {
        var data = makeExportTrieExecutable()
        let bindOffset: UInt32 = 0x1_300
        var bind = Data([0x40]) // SET_SYMBOL_TRAILING_FLAGS_IMM, library ordinal 0 = self
        bind.append(contentsOf: Array("_fixture".utf8) + [0])
        bind.append(contentsOf: [0x72, 0x00, 0x90, 0x00]) // DATA + 0; DO_BIND; DONE

        var dyld = Data()
        appendLE32(0x8000_0022, to: &dyld)
        appendLE32(48, to: &dyld)
        appendLE32(0, to: &dyld); appendLE32(0, to: &dyld) // rebase
        appendLE32(bindOffset, to: &dyld); appendLE32(UInt32(bind.count), to: &dyld) // regular bind
        appendLE32(0, to: &dyld); appendLE32(0, to: &dyld) // weak bind
        appendLE32(0, to: &dyld); appendLE32(0, to: &dyld) // lazy bind
        appendLE32(0, to: &dyld); appendLE32(0, to: &dyld) // no export range here

        let oldCommandBytes = 72 * 3 + 24 + 16
        data.replaceSubrange(16..<20, with: littleEndian32(6))
        data.replaceSubrange(20..<24, with: littleEndian32(UInt32(oldCommandBytes + 48)))
        var rebuilt = Data(data.prefix(32 + oldCommandBytes))
        rebuilt.append(dyld)
        if rebuilt.count < 0x1_000 {
            rebuilt.append(contentsOf: repeatElement(0, count: 0x1_000 - rebuilt.count))
        }
        rebuilt.append(data[0x1_000..<data.count])
        if rebuilt.count < Int(bindOffset) {
            rebuilt.append(contentsOf: repeatElement(0, count: Int(bindOffset) - rebuilt.count))
        }
        rebuilt.append(bind)
        return rebuilt
    }

    private static func makeRPathExecutable() -> Data {
        var data = makeThinExecutable()
        let path = "@executable_path/Frameworks"
        let stringBytes = Array(path.utf8) + [0]
        let padded = (stringBytes.count + 3) & ~3
        var command = Data()
        appendLE32(0x8000_001C, to: &command) // LC_RPATH
        appendLE32(UInt32(12 + padded), to: &command)
        appendLE32(12, to: &command)
        command.append(contentsOf: stringBytes)
        if stringBytes.count < padded { command.append(contentsOf: repeatElement(0, count: padded - stringBytes.count)) }
        let oldCommandBytes = 72 * 3 + 24
        data.replaceSubrange(16..<20, with: littleEndian32(5))
        data.replaceSubrange(20..<24, with: littleEndian32(UInt32(oldCommandBytes + command.count)))
        var rebuilt = Data(data.prefix(32 + oldCommandBytes))
        rebuilt.append(command)
        if rebuilt.count < 0x1_000 { rebuilt.append(contentsOf: repeatElement(0, count: 0x1_000 - rebuilt.count)) }
        rebuilt.append(data[0x1_000..<data.count])
        return rebuilt
    }

    static func makeBoundThinExecutable(
        weakImport: Bool = false,
        libraryOrdinal: Int = 1,
        installName: String = "/usr/lib/libSystem.B.dylib"
    ) -> Data {
        var data = makeThinExecutable()
        var dylib = Data()
        appendLE32(0x0C, to: &dylib) // LC_LOAD_DYLIB
        let stringBytes = Array(installName.utf8) + [0]
        let paddedStringLength = (stringBytes.count + 3) & ~3
        appendLE32(UInt32(24 + paddedStringLength), to: &dylib)
        appendLE32(24, to: &dylib) // lc_str.offset
        appendLE32(2, to: &dylib) // timestamp
        appendLE32(0x1_0000, to: &dylib) // current version
        appendLE32(0x1_0000, to: &dylib) // compatibility version
        dylib.append(contentsOf: stringBytes)
        if stringBytes.count < paddedStringLength {
            dylib.append(contentsOf: repeatElement(0, count: paddedStringLength - stringBytes.count))
        }

        let bindOffset: UInt32 = 0x1_200
        var bind = Data()
        if libraryOrdinal > 0 {
            precondition(libraryOrdinal <= 15)
            bind.append(UInt8(0x10 | libraryOrdinal)) // SET_DYLIB_ORDINAL_IMM
        } else {
            precondition(libraryOrdinal >= -3)
            bind.append(UInt8(0x30 | (libraryOrdinal & 0x0F))) // SET_DYLIB_SPECIAL_IMM
        }
        bind.append(weakImport ? 0x41 : 0x40) // symbol + optional weak-import flag
        bind.append(contentsOf: Array("_puts".utf8) + [0])
        bind.append(contentsOf: [0x51, 0x72, 0x00, 0x90, 0x00]) // pointer type; DATA + 0; DO_BIND; DONE

        var dyld = Data()
        appendLE32(0x8000_0022, to: &dyld) // LC_DYLD_INFO_ONLY
        appendLE32(48, to: &dyld)
        appendLE32(0, to: &dyld) // rebase_off
        appendLE32(0, to: &dyld) // rebase_size
        appendLE32(bindOffset, to: &dyld)
        appendLE32(UInt32(bind.count), to: &dyld)
        appendLE32(0, to: &dyld) // weak bind offset
        appendLE32(0, to: &dyld) // weak bind size
        appendLE32(0, to: &dyld) // lazy bind offset
        appendLE32(0, to: &dyld) // lazy bind size
        appendLE32(0, to: &dyld) // export offset
        appendLE32(0, to: &dyld) // export size

        data.replaceSubrange(16..<20, with: littleEndian32(6))
        data.replaceSubrange(20..<24, with: littleEndian32(UInt32(72 * 3 + 24 + dylib.count + dyld.count)))
        var rebuilt = Data(data.prefix(272))
        rebuilt.append(dylib)
        rebuilt.append(dyld)
        if rebuilt.count < 0x1_000 {
            rebuilt.append(contentsOf: repeatElement(0, count: 0x1_000 - rebuilt.count))
        }
        rebuilt.append(data[0x1_000..<data.count]) // preserve original segment file offsets
        if rebuilt.count < Int(bindOffset) {
            rebuilt.append(contentsOf: repeatElement(0, count: Int(bindOffset) - rebuilt.count))
        }
        rebuilt.append(bind)
        return rebuilt
    }

    private static func makeExportTrieExecutable() -> Data {
        var data = makeThinExecutable()
        var trie = Data([0x00, 0x01]) // root: empty terminal, one edge
        let edge = Array("_fixture".utf8) + [0x00]
        trie.append(contentsOf: edge)
        trie.append(UInt8(2 + edge.count + 1)) // child node offset, ULEB128
        trie.append(contentsOf: [0x03, 0x00, 0x80, 0x12, 0x00]) // terminal size=3, flags=0, address=0x900, no children

        var command = Data()
        appendLE32(0x8000_0033, to: &command) // LC_DYLD_EXPORTS_TRIE
        appendLE32(16, to: &command)
        appendLE32(0x1_200, to: &command)
        appendLE32(UInt32(trie.count), to: &command)
        data.replaceSubrange(16..<20, with: littleEndian32(5))
        data.replaceSubrange(20..<24, with: littleEndian32(72 * 3 + 24 + 16))
        var rebuilt = Data(data.prefix(272))
        rebuilt.append(command)
        if rebuilt.count < 0x1_000 {
            rebuilt.append(contentsOf: repeatElement(0, count: 0x1_000 - rebuilt.count))
        }
        rebuilt.append(data[0x1_000..<data.count])
        if rebuilt.count < 0x1_200 { rebuilt.append(contentsOf: repeatElement(0, count: 0x1_200 - rebuilt.count)) }
        rebuilt.append(trie)
        return rebuilt
    }

    private static func makeChainedFixupExecutable() -> Data {
        var data = makeRebasedThinExecutable()
        data.replaceSubrange(16..<20, with: littleEndian32(6))
        data.replaceSubrange(20..<24, with: littleEndian32(72 * 3 + 24 + 48 + 16))
        var command = Data()
        appendLE32(0x8000_0034, to: &command) // LC_DYLD_CHAINED_FIXUPS
        appendLE32(16, to: &command)
        appendLE32(0x1_105, to: &command)
        appendLE32(4, to: &command)
        data.replaceSubrange(320..<336, with: command)
        data.append(contentsOf: [0, 0, 0, 0])
        return data
    }

    private static func makeFatExecutable() -> Data {
        let x86 = makeThinExecutable()
        var arm = x86
        arm.replaceSubrange(4..<8, with: littleEndian32(0x0100_000C))

        let armOffset: UInt32 = 0x1_000
        let x86Offset = UInt32((Int(armOffset) + arm.count + 0xFFF) & ~0xFFF)
        var fat = Data()
        appendBE32(0xCAFEBABE, to: &fat)
        appendBE32(2, to: &fat)
        appendBE32(0x0100_000C, to: &fat) // ARM64 first
        appendBE32(0, to: &fat)
        appendBE32(armOffset, to: &fat)
        appendBE32(UInt32(arm.count), to: &fat)
        appendBE32(12, to: &fat)
        appendBE32(0x0100_0007, to: &fat) // x86_64 second
        appendBE32(3, to: &fat)
        appendBE32(x86Offset, to: &fat)
        appendBE32(UInt32(x86.count), to: &fat)
        appendBE32(12, to: &fat)

        if fat.count < Int(armOffset) { fat.append(contentsOf: repeatElement(0, count: Int(armOffset) - fat.count)) }
        fat.append(arm)
        if fat.count < Int(x86Offset) { fat.append(contentsOf: repeatElement(0, count: Int(x86Offset) - fat.count)) }
        fat.append(x86)
        return fat
    }

    private static func makeFatCigamExecutable() -> Data {
        let x86 = makeThinExecutable()
        var fat = Data()
        // FAT_CIGAM: the same universal header and architecture entries encoded
        // little-endian rather than the conventional big-endian representation.
        fat.append(contentsOf: littleEndian32(0xCAFEBABE))
        fat.append(contentsOf: littleEndian32(1))
        fat.append(contentsOf: littleEndian32(0x0100_0007))
        fat.append(contentsOf: littleEndian32(3))
        fat.append(contentsOf: littleEndian32(0x1_000))
        fat.append(contentsOf: littleEndian32(UInt32(x86.count)))
        fat.append(contentsOf: littleEndian32(12))
        if fat.count < 0x1_000 { fat.append(contentsOf: repeatElement(0, count: 0x1_000 - fat.count)) }
        fat.append(x86)
        return fat
    }

    private static func makeFat64Executable() -> Data {
        let x86 = makeThinExecutable()
        var fat = Data()
        appendBE32(0xCAFEBABF, to: &fat)
        appendBE32(1, to: &fat)
        appendBE32(0x0100_0007, to: &fat)
        appendBE32(3, to: &fat)
        appendBE64(0x1_000, to: &fat)
        appendBE64(UInt64(x86.count), to: &fat)
        appendBE32(12, to: &fat)
        appendBE32(0, to: &fat)
        if fat.count < 0x1_000 { fat.append(contentsOf: repeatElement(0, count: 0x1_000 - fat.count)) }
        fat.append(x86)
        return fat
    }

    private static func appendSegment(
        name: String,
        vmAddress: UInt64,
        vmSize: UInt64,
        fileOffset: UInt64,
        fileSize: UInt64,
        maxProtection: UInt32,
        initialProtection: UInt32,
        to data: inout Data
    ) {
        appendLE32(0x19, to: &data)
        appendLE32(72, to: &data)
        let nameBytes = Array(name.utf8.prefix(16))
        data.append(contentsOf: nameBytes)
        if nameBytes.count < 16 { data.append(contentsOf: repeatElement(0, count: 16 - nameBytes.count)) }
        appendLE64(vmAddress, to: &data)
        appendLE64(vmSize, to: &data)
        appendLE64(fileOffset, to: &data)
        appendLE64(fileSize, to: &data)
        appendLE32(maxProtection, to: &data)
        appendLE32(initialProtection, to: &data)
        appendLE32(0, to: &data) // nsects
        appendLE32(0, to: &data) // flags
    }

    private static func appendULEB(_ value: UInt64, to data: inout Data) {
        var remaining = value
        repeat {
            var byte = UInt8(remaining & 0x7F)
            remaining >>= 7
            if remaining != 0 { byte |= 0x80 }
            data.append(byte)
        } while remaining != 0
    }

    private static func appendLE32(_ value: UInt32, to data: inout Data) {
        data.append(UInt8(truncatingIfNeeded: value))
        data.append(UInt8(truncatingIfNeeded: value >> 8))
        data.append(UInt8(truncatingIfNeeded: value >> 16))
        data.append(UInt8(truncatingIfNeeded: value >> 24))
    }

    private static func appendLE64(_ value: UInt64, to data: inout Data) {
        appendLE32(UInt32(truncatingIfNeeded: value), to: &data)
        appendLE32(UInt32(truncatingIfNeeded: value >> 32), to: &data)
    }

    private static func appendBE32(_ value: UInt32, to data: inout Data) {
        data.append(UInt8(truncatingIfNeeded: value >> 24))
        data.append(UInt8(truncatingIfNeeded: value >> 16))
        data.append(UInt8(truncatingIfNeeded: value >> 8))
        data.append(UInt8(truncatingIfNeeded: value))
    }

    private static func littleEndian64(_ value: UInt64) -> [UInt8] {
        littleEndian32(UInt32(truncatingIfNeeded: value)) + littleEndian32(UInt32(truncatingIfNeeded: value >> 32))
    }

    private static func appendBE64(_ value: UInt64, to data: inout Data) {
        appendBE32(UInt32(truncatingIfNeeded: value >> 32), to: &data)
        appendBE32(UInt32(truncatingIfNeeded: value), to: &data)
    }

    private static func littleEndian32(_ value: UInt32) -> [UInt8] {
        [UInt8(truncatingIfNeeded: value), UInt8(truncatingIfNeeded: value >> 8), UInt8(truncatingIfNeeded: value >> 16), UInt8(truncatingIfNeeded: value >> 24)]
    }

    private static func expect(_ condition: @autoclosure () throws -> Bool, _ label: String) throws {
        guard try condition() else {
            throw X64MachOFormatError(message: "Mach-O loader self-test failed: \(label).")
        }
    }
}
