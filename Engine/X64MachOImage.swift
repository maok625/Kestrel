import Foundation

// MARK: - 64-bit x86_64 Mach-O image model

struct X64MachOMachHeader: Sendable, Equatable {
    let cpuType: UInt32
    let cpuSubtype: UInt32
    let fileType: UInt32
    let commandCount: UInt32
    let commandBytes: UInt32
    let flags: UInt32
}

struct X64MachOSegment: Sendable, Equatable {
    let name: String
    let virtualAddress: UInt64
    let virtualSize: UInt64
    let fileOffset: UInt64
    let fileSize: UInt64
    let maximumProtection: X64GuestMemoryPermissions
    let initialProtection: X64GuestMemoryPermissions
    let sectionCount: UInt32

    var virtualEnd: UInt64 { virtualAddress + virtualSize }
    var isPageZero: Bool { name == "__PAGEZERO" }
}

enum X64MachODylibKind: String, Sendable, Equatable {
    case load
    case weakLoad
    case reexport
    case upward
    case lazyLoad
}

struct X64MachODylibDependency: Sendable, Equatable {
    /// dyld's one-based ordinal in the order load commands were encountered.
    let ordinal: Int
    let installName: String
    let timestamp: UInt32
    let currentVersion: UInt32
    let compatibilityVersion: UInt32
    let kind: X64MachODylibKind
}

enum X64MachOBindStreamKind: String, Sendable, Equatable {
    case regular
    case weak
    case lazy
}

struct X64MachOBindAction: Sendable, Equatable {
    let location: UInt64
    let symbolName: String
    /// 0=self, positive=LC_LOAD_* ordinal, negative=dyld special ordinal.
    let libraryOrdinal: Int
    let addend: Int64
    let type: UInt8
    let symbolFlags: UInt8
    let stream: X64MachOBindStreamKind

    var isWeakImport: Bool { (symbolFlags & 0x1) != 0 }
}

struct X64MachOExport: Sendable, Equatable {
    let symbolName: String
    let flags: UInt64
    /// Offset from the image's preferred load address for regular exports.
    let addressOffset: UInt64?
    let reexportOrdinal: Int?
    let importedName: String?
    let resolverOffset: UInt64?

    var isReexport: Bool { reexportOrdinal != nil }
    var isAbsolute: Bool { (flags & 0x03) == 0x02 }
    var isThreadLocal: Bool { (flags & 0x03) == 0x01 }
    var isWeakDefinition: Bool { (flags & 0x04) != 0 }
    var hasStubAndResolver: Bool { (flags & 0x10) != 0 }
}

struct X64MachOImage: Sendable {
    let sourceName: String
    let header: X64MachOMachHeader
    let segments: [X64MachOSegment]
    let entryAddress: UInt64
    let entryOffset: UInt64
    let preferredLoadAddress: UInt64
    let sliceData: Data
    /// Preferred guest addresses of 64-bit pointer locations described by the
    /// classic LC_DYLD_INFO rebase opcode stream. Chained fixups are detected
    /// separately and are not interpreted by this loader slice.
    let rebaseFixupAddresses: [UInt64]
    let hasDyldInfoCommand: Bool
    let bindOpcodeBytes: UInt64
    let weakBindOpcodeBytes: UInt64
    let lazyBindOpcodeBytes: UInt64
    let chainedFixupsBytes: UInt64
    let dependencies: [X64MachODylibDependency]
    let bindActions: [X64MachOBindAction]
    let weakBindActions: [X64MachOBindAction]
    let lazyBindActions: [X64MachOBindAction]
    let exports: [X64MachOExport]
    let rpaths: [String]

    var hasUnresolvedDyldBindings: Bool {
        bindOpcodeBytes > 0 || weakBindOpcodeBytes > 0 || lazyBindOpcodeBytes > 0
            || chainedFixupsBytes > 0
    }

    /// Upper bound on eager image backing: page-rounded file-backed bytes only.
    /// The rest of each segment remains a registered demand-zero guest range
    /// until its first permitted access materializes an individual page.
    var committedImageBytes: UInt64 {
        let pageSize = X64GuestVirtualMemoryConstants.pageSize
        return segments.filter { !$0.isPageZero }.reduce(0) { total, segment in
            guard segment.fileSize > 0 else { return total }
            let (roundedInput, overflow) = segment.fileSize.addingReportingOverflow(pageSize - 1)
            guard !overflow else { return UInt64.max }
            let backed = roundedInput & ~(pageSize - 1)
            let (sum, sumOverflow) = total.addingReportingOverflow(backed)
            return sumOverflow ? UInt64.max : sum
        }
    }
}

struct X64MachOFormatError: LocalizedError, Sendable {
    let message: String
    var errorDescription: String? { message }
}

/// Parses a thin or universal Mach-O and selects its x86_64 slice. This
/// experimental loader accepts MH_EXECUTE with LC_MAIN and an initial subset
/// of classic dyld pointer-rebase metadata.
enum X64MachOParser {
    private static let mhMagic64: UInt32 = 0xFEED_FACF
    private static let cpuTypeX86_64: UInt32 = 0x0100_0007
    private static let fileTypeExecute: UInt32 = 0x2
    private static let lcSegment64: UInt32 = 0x19
    private static let lcMain: UInt32 = 0x8000_0028
    private static let lcDyldInfo: UInt32 = 0x22
    private static let lcDyldInfoOnly: UInt32 = 0x8000_0022
    private static let lcDyldChainedFixups: UInt32 = 0x8000_0034
    private static let lcDyldExportsTrie: UInt32 = 0x8000_0033
    private static let lcLoadDylib: UInt32 = 0x0C
    private static let lcLoadWeakDylib: UInt32 = 0x8000_0018
    private static let lcReexportDylib: UInt32 = 0x8000_001F
    private static let lcLoadUpwardDylib: UInt32 = 0x8000_0023
    private static let lcLazyLoadDylib: UInt32 = 0x20
    private static let lcRpath: UInt32 = 0x8000_001C
    static let mhPie: UInt32 = 0x0020_0000
    private static let fatMagic: UInt32 = 0xCAFEBABE
    private static let fatMagic64: UInt32 = 0xCAFEBABF
    private static let fatCigam: UInt32 = 0xBEBAFECA
    private static let fatCigam64: UInt32 = 0xBFBAFECA
    private static let machHeader64Size = 32
    private static let segment64Size = 72
    private static let section64Size = 80
    private static let entryPointCommandSize = 24
    private static let maximumLoadCommands: UInt32 = 65_536
    private static let maximumFatArchitectures: UInt32 = 64

    static func parse(data: Data, sourceName: String = "<memory>") throws -> X64MachOImage {
        guard data.count >= 4 else {
            throw format("File is too short to contain a Mach-O magic value.")
        }

        let firstWord = readBE32(data, at: 0)
        let selectedData: Data
        switch firstWord {
        case fatMagic, fatMagic64, fatCigam, fatCigam64:
            selectedData = try selectX86_64Slice(from: data, magic: firstWord)
        default:
            selectedData = data
        }

        return try parseThinX86_64(selectedData, sourceName: sourceName)
    }

    private static func selectX86_64Slice(from data: Data, magic: UInt32) throws -> Data {
        guard data.count >= 8 else { throw format("Universal Mach-O header is truncated.") }
        let swapped = magic == fatCigam || magic == fatCigam64
        let is64 = magic == fatMagic64 || magic == fatCigam64
        let architectureCount = read32(data, at: 4, swapped: swapped)
        guard architectureCount > 0, architectureCount <= maximumFatArchitectures else {
            throw format("Universal Mach-O has an invalid architecture count (\(architectureCount)).")
        }

        let entrySize = is64 ? 32 : 20
        let tableBytes = UInt64(architectureCount) * UInt64(entrySize)
        let tableEnd = UInt64(8) + tableBytes
        guard tableEnd <= UInt64(data.count) else {
            throw format("Universal Mach-O architecture table extends beyond the file.")
        }

        for index in 0..<Int(architectureCount) {
            let offset = 8 + index * entrySize
            let cpuType = read32(data, at: offset, swapped: swapped)
            guard cpuType == cpuTypeX86_64 else { continue }

            let sliceOffset: UInt64
            let sliceSize: UInt64
            if is64 {
                sliceOffset = read64(data, at: offset + 8, swapped: swapped)
                sliceSize = read64(data, at: offset + 16, swapped: swapped)
            } else {
                sliceOffset = UInt64(read32(data, at: offset + 8, swapped: swapped))
                sliceSize = UInt64(read32(data, at: offset + 12, swapped: swapped))
            }

            guard sliceSize >= UInt64(machHeader64Size),
                  sliceOffset <= UInt64(data.count),
                  sliceSize <= UInt64(data.count) - sliceOffset,
                  sliceOffset <= UInt64(Int.max),
                  sliceSize <= UInt64(Int.max) else {
                throw format("Universal Mach-O contains an out-of-bounds x86_64 slice.")
            }
            let start = Int(sliceOffset)
            let end = start + Int(sliceSize)
            return data.subdata(in: start..<end)
        }

        throw format("Universal Mach-O does not contain an x86_64 slice.")
    }

    private static func parseThinX86_64(_ data: Data, sourceName: String) throws -> X64MachOImage {
        guard data.count >= machHeader64Size else {
            throw format("Mach-O header is truncated (\(data.count) bytes; need 32).")
        }
        guard readLE32(data, at: 0) == mhMagic64 else {
            throw format("Expected a little-endian 64-bit Mach-O header.")
        }

        let cpuType = readLE32(data, at: 4)
        guard cpuType == cpuTypeX86_64 else {
            throw format(String(format: "Unsupported Mach-O CPU type 0x%08X; Kestrel loader requires x86_64.", cpuType))
        }

        let header = X64MachOMachHeader(
            cpuType: cpuType,
            cpuSubtype: readLE32(data, at: 8),
            fileType: readLE32(data, at: 12),
            commandCount: readLE32(data, at: 16),
            commandBytes: readLE32(data, at: 20),
            flags: readLE32(data, at: 24)
        )

        guard header.fileType == fileTypeExecute else {
            throw format(String(format: "Unsupported Mach-O file type 0x%X; only MH_EXECUTE is supported in this milestone.", header.fileType))
        }
        guard header.commandCount <= maximumLoadCommands else {
            throw format("Mach-O load-command count exceeds the safety limit.")
        }

        let commandStart = UInt64(machHeader64Size)
        let commandEnd = commandStart + UInt64(header.commandBytes)
        guard commandEnd >= commandStart, commandEnd <= UInt64(data.count) else {
            throw format("Mach-O load-command region extends beyond the file.")
        }

        var cursor = machHeader64Size
        var segments: [X64MachOSegment] = []
        var entryOffset: UInt64?
        var rebaseStreamRange: Range<Int>?
        var hasDyldInfoCommand = false
        var bindOpcodeBytes: UInt64 = 0
        var weakBindOpcodeBytes: UInt64 = 0
        var lazyBindOpcodeBytes: UInt64 = 0
        var chainedFixupsBytes: UInt64 = 0
        var bindStreamRange: Range<Int>?
        var weakBindStreamRange: Range<Int>?
        var lazyBindStreamRange: Range<Int>?
        var exportTrieRange: Range<Int>?
        var dependencies: [X64MachODylibDependency] = []
        var rpaths: [String] = []

        for commandIndex in 0..<Int(header.commandCount) {
            guard cursor <= Int(commandEnd), Int(commandEnd) - cursor >= 8 else {
                throw format("Load command \(commandIndex) has a truncated header.")
            }
            let command = readLE32(data, at: cursor)
            let commandSize = readLE32(data, at: cursor + 4)
            guard commandSize >= 8,
                  commandSize % 4 == 0,
                  UInt64(cursor) + UInt64(commandSize) <= commandEnd else {
                throw format("Load command \(commandIndex) has an invalid cmdsize (\(commandSize)).")
            }

            let commandEndIndex = cursor + Int(commandSize)
            switch command {
            case lcSegment64:
                segments.append(try parseSegment(data, commandOffset: cursor, commandSize: Int(commandSize)))
            case lcMain:
                guard commandSize >= entryPointCommandSize else {
                    throw format("LC_MAIN is shorter than its 24-byte structure.")
                }
                guard entryOffset == nil else { throw format("Mach-O contains more than one LC_MAIN command.") }
                entryOffset = readLE64(data, at: cursor + 8)
            case lcDyldInfo, lcDyldInfoOnly:
                guard commandSize >= 48 else {
                    throw format("LC_DYLD_INFO(_ONLY) is shorter than its 48-byte structure.")
                }
                guard !hasDyldInfoCommand else {
                    throw format("Mach-O contains more than one LC_DYLD_INFO command.")
                }
                hasDyldInfoCommand = true
                rebaseStreamRange = try checkedLinkEditRange(
                    data,
                    offset: readLE32(data, at: cursor + 8),
                    size: readLE32(data, at: cursor + 12),
                    label: "rebase opcode"
                )
                bindOpcodeBytes = UInt64(readLE32(data, at: cursor + 20))
                weakBindOpcodeBytes = UInt64(readLE32(data, at: cursor + 28))
                lazyBindOpcodeBytes = UInt64(readLE32(data, at: cursor + 36))
                bindStreamRange = try checkedLinkEditRange(data, offset: readLE32(data, at: cursor + 16), size: readLE32(data, at: cursor + 20), label: "bind opcode")
                weakBindStreamRange = try checkedLinkEditRange(data, offset: readLE32(data, at: cursor + 24), size: readLE32(data, at: cursor + 28), label: "weak-bind opcode")
                lazyBindStreamRange = try checkedLinkEditRange(data, offset: readLE32(data, at: cursor + 32), size: readLE32(data, at: cursor + 36), label: "lazy-bind opcode")
                if let dyldInfoExportRange = try checkedLinkEditRange(
                    data,
                    offset: readLE32(data, at: cursor + 40),
                    size: readLE32(data, at: cursor + 44),
                    label: "export trie"
                ) {
                    // LC_DYLD_INFO may coexist with LC_DYLD_EXPORTS_TRIE.
                    // A zero-sized legacy export range must not erase the
                    // dedicated export-trie command parsed earlier.
                    exportTrieRange = dyldInfoExportRange
                }
            case lcDyldExportsTrie:
                guard commandSize >= 16 else { throw format("LC_DYLD_EXPORTS_TRIE is shorter than its 16-byte structure.") }
                let range = try checkedLinkEditRange(data, offset: readLE32(data, at: cursor + 8), size: readLE32(data, at: cursor + 12), label: "exports trie")
                if let range {
                    guard exportTrieRange == nil else { throw format("Mach-O contains duplicate export-trie commands.") }
                    exportTrieRange = range
                }
            case lcLoadDylib, lcLoadWeakDylib, lcReexportDylib, lcLoadUpwardDylib, lcLazyLoadDylib:
                guard commandSize >= 24 else { throw format("LC_LOAD_DYLIB-family command is shorter than its 24-byte structure.") }
                let nameOffset = readLE32(data, at: cursor + 8)
                guard nameOffset >= 24 else {
                    throw format("Dylib install-name offset points inside its fixed load-command fields.")
                }
                let installName = try readLoadCommandString(data, commandOffset: cursor, commandSize: Int(commandSize), stringOffset: nameOffset, label: "dylib install name")
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
                    timestamp: readLE32(data, at: cursor + 12),
                    currentVersion: readLE32(data, at: cursor + 16),
                    compatibilityVersion: readLE32(data, at: cursor + 20),
                    kind: kind
                ))
            case lcRpath:
                guard commandSize >= 12 else { throw format("LC_RPATH is shorter than its 12-byte structure.") }
                let pathOffset = readLE32(data, at: cursor + 8)
                guard pathOffset >= 12 else {
                    throw format("LC_RPATH string offset points inside its fixed load-command fields.")
                }
                rpaths.append(try readLoadCommandString(data, commandOffset: cursor, commandSize: Int(commandSize), stringOffset: pathOffset, label: "runtime search path"))
            case lcDyldChainedFixups:
                guard commandSize >= 16 else {
                    throw format("LC_DYLD_CHAINED_FIXUPS is shorter than its 16-byte structure.")
                }
                let chainOffset = readLE32(data, at: cursor + 8)
                let chainSize = readLE32(data, at: cursor + 12)
                _ = try checkedLinkEditRange(data, offset: chainOffset, size: chainSize, label: "chained-fixups")
                chainedFixupsBytes = UInt64(chainSize)
            default:
                break // Other load commands are validated structurally but not interpreted yet.
            }
            cursor = commandEndIndex
        }

        guard UInt64(cursor) <= commandEnd else {
            throw format("Mach-O load commands exceed sizeofcmds.")
        }
        guard !segments.isEmpty else { throw format("Mach-O contains no LC_SEGMENT_64 commands.") }
        guard let text = segments.first(where: { $0.name == "__TEXT" }) else {
            throw format("Mach-O executable has no __TEXT segment.")
        }
        guard let entryOffset else { throw format("Mach-O executable has no LC_MAIN entry point.") }
        guard text.fileOffset == 0 else {
            throw format("This loader slice requires __TEXT to begin at file offset zero.")
        }
        guard entryOffset < text.fileSize else {
            throw format("LC_MAIN entryoff lies outside the file-backed __TEXT segment.")
        }
        guard text.initialProtection.contains(.execute) else {
            throw format("LC_MAIN points into a __TEXT segment that is not executable.")
        }
        guard entryOffset <= UInt64.max - text.virtualAddress else {
            throw format("LC_MAIN entry address overflows the guest address space.")
        }

        try validateSegmentLayout(segments)
        let rebaseFixupAddresses = try rebaseStreamRange.map {
            try parseRebaseOpcodes(data, range: $0, segments: segments)
        } ?? []
        let bindActions = try bindStreamRange.map {
            try parseBindOpcodes(data, range: $0, segments: segments, dependencies: dependencies, stream: .regular)
        } ?? []
        let weakBindActions = try weakBindStreamRange.map {
            try parseBindOpcodes(data, range: $0, segments: segments, dependencies: dependencies, stream: .weak)
        } ?? []
        let lazyBindActions = try lazyBindStreamRange.map {
            try parseBindOpcodes(data, range: $0, segments: segments, dependencies: dependencies, stream: .lazy)
        } ?? []
        let exports = try exportTrieRange.map {
            try parseExportTrie(data, range: $0)
        } ?? []
        let entryAddress = text.virtualAddress + entryOffset
        guard segments.contains(where: { segment in
            segment.initialProtection.contains(.execute)
                && entryAddress >= segment.virtualAddress
                && entryAddress < segment.virtualEnd
        }) else {
            throw format("LC_MAIN does not resolve into an executable segment.")
        }

        return X64MachOImage(
            sourceName: sourceName,
            header: header,
            segments: segments.sorted { $0.virtualAddress < $1.virtualAddress },
            entryAddress: entryAddress,
            entryOffset: entryOffset,
            preferredLoadAddress: text.virtualAddress,
            sliceData: data,
            rebaseFixupAddresses: rebaseFixupAddresses,
            hasDyldInfoCommand: hasDyldInfoCommand,
            bindOpcodeBytes: bindOpcodeBytes,
            weakBindOpcodeBytes: weakBindOpcodeBytes,
            lazyBindOpcodeBytes: lazyBindOpcodeBytes,
            chainedFixupsBytes: chainedFixupsBytes,
            dependencies: dependencies,
            bindActions: bindActions,
            weakBindActions: weakBindActions,
            lazyBindActions: lazyBindActions,
            exports: exports,
            rpaths: rpaths
        )
    }

    private static func checkedLinkEditRange(
        _ data: Data,
        offset: UInt32,
        size: UInt32,
        label: String
    ) throws -> Range<Int>? {
        if size == 0 { return nil }
        let start = UInt64(offset)
        let count = UInt64(size)
        let (end, overflow) = start.addingReportingOverflow(count)
        guard !overflow, end <= UInt64(data.count), start <= UInt64(Int.max), end <= UInt64(Int.max) else {
            throw format("Mach-O \(label) data range extends beyond the selected file slice.")
        }
        return Int(start)..<Int(end)
    }

    /// Decodes the classic dyld rebase bytecode into validated preferred
    /// guest addresses. Only 64-bit pointer rebases are accepted; text absolute
    /// and PC-relative 32-bit rebases fail closed until their semantics exist.
    private static func parseRebaseOpcodes(
        _ data: Data,
        range: Range<Int>,
        segments: [X64MachOSegment]
    ) throws -> [UInt64] {
        let opcodeDone: UInt8 = 0x00
        let opcodeSetTypeImmediate: UInt8 = 0x10
        let opcodeSetSegmentAndOffsetULEB: UInt8 = 0x20
        let opcodeAddAddressULEB: UInt8 = 0x30
        let opcodeAddAddressImmediateScaled: UInt8 = 0x40
        let opcodeDoRebaseImmediateTimes: UInt8 = 0x50
        let opcodeDoRebaseULEBTimes: UInt8 = 0x60
        let opcodeDoRebaseAddAddressULEB: UInt8 = 0x70
        let opcodeDoRebaseULEBTimesSkippingULEB: UInt8 = 0x80
        let pointerType: UInt8 = 1
        let pointerSize: UInt64 = 8
        let maximumFixups = 4_000_000

        var cursor = range.lowerBound
        let end = range.upperBound
        var rebaseType: UInt8 = 0
        var currentSegmentIndex: Int?
        var segmentOffset: UInt64 = 0
        var addresses: [UInt64] = []
        var seenAddresses = Set<UInt64>()

        func advanceOffset(_ amount: UInt64) throws {
            let (next, overflow) = segmentOffset.addingReportingOverflow(amount)
            guard !overflow else { throw format("Dyld rebase segment offset overflows.") }
            segmentOffset = next
        }

        func emitRebase() throws {
            guard rebaseType == pointerType else {
                throw format("Unsupported dyld rebase type \(rebaseType); only 64-bit pointers are supported.")
            }
            guard let index = currentSegmentIndex, segments.indices.contains(index) else {
                throw format("Dyld rebase opcode uses a segment index before selecting a valid segment.")
            }
            let segment = segments[index]
            guard segmentOffset <= segment.fileSize, pointerSize <= segment.fileSize - segmentOffset,
                  segmentOffset <= segment.virtualSize, pointerSize <= segment.virtualSize - segmentOffset else {
                throw format("Dyld rebase location is outside file-backed bytes of segment \(segment.name).")
            }
            let (address, overflow) = segment.virtualAddress.addingReportingOverflow(segmentOffset)
            guard !overflow else { throw format("Dyld rebase target address overflows.") }
            guard addresses.count < maximumFixups else {
                throw format("Dyld rebase stream exceeds the \(maximumFixups)-fixup safety limit.")
            }
            guard seenAddresses.insert(address).inserted else {
                throw format(String(format: "Dyld rebase stream repeats fixup location 0x%016llX.", address))
            }
            addresses.append(address)
            try advanceOffset(pointerSize)
        }

        while cursor < end {
            let byte = data[cursor]
            cursor += 1
            let opcode = byte & 0xF0
            let immediate = byte & 0x0F

            switch opcode {
            case opcodeDone:
                // dyld permits up to 15 bytes of alignment padding after DONE.
                guard end - cursor <= 15,
                      data[cursor..<end].allSatisfy({ $0 == 0 }) else {
                    throw format("Dyld rebase stream has invalid bytes after REBASE_OPCODE_DONE.")
                }
                return addresses

            case opcodeSetTypeImmediate:
                rebaseType = immediate

            case opcodeSetSegmentAndOffsetULEB:
                let index = Int(immediate)
                guard segments.indices.contains(index) else {
                    throw format("Dyld rebase stream selects invalid segment index \(index).")
                }
                currentSegmentIndex = index
                segmentOffset = try readULEB128(data, cursor: &cursor, end: end)

            case opcodeAddAddressULEB:
                try advanceOffset(readULEB128(data, cursor: &cursor, end: end))

            case opcodeAddAddressImmediateScaled:
                try advanceOffset(UInt64(immediate) * pointerSize)

            case opcodeDoRebaseImmediateTimes:
                for _ in 0..<Int(immediate) { try emitRebase() }

            case opcodeDoRebaseULEBTimes:
                let count = try readULEB128(data, cursor: &cursor, end: end)
                guard count <= UInt64(maximumFixups - addresses.count) else {
                    throw format("Dyld rebase count exceeds the safety limit.")
                }
                for _ in 0..<Int(count) { try emitRebase() }

            case opcodeDoRebaseAddAddressULEB:
                try emitRebase()
                try advanceOffset(readULEB128(data, cursor: &cursor, end: end))

            case opcodeDoRebaseULEBTimesSkippingULEB:
                let count = try readULEB128(data, cursor: &cursor, end: end)
                let skip = try readULEB128(data, cursor: &cursor, end: end)
                guard count <= UInt64(maximumFixups - addresses.count) else {
                    throw format("Dyld rebase count exceeds the safety limit.")
                }
                for _ in 0..<Int(count) {
                    try emitRebase()
                    try advanceOffset(skip)
                }

            default:
                throw format(String(format: "Unsupported dyld rebase opcode 0x%02X.", opcode))
            }
        }
        return addresses
    }

    private static func readULEB128(_ data: Data, cursor: inout Int, end: Int) throws -> UInt64 {
        var value: UInt64 = 0
        var shift: UInt64 = 0
        for _ in 0..<10 {
            guard cursor < end else { throw format("Dyld rebase stream ends inside a ULEB128 value.") }
            let byte = data[cursor]
            cursor += 1
            let payload = UInt64(byte & 0x7F)
            guard shift < 64, payload <= (UInt64.max >> shift) else {
                throw format("Dyld rebase ULEB128 value overflows 64 bits.")
            }
            value |= payload << shift
            if byte & 0x80 == 0 { return value }
            shift += 7
        }
        throw format("Dyld rebase ULEB128 value is longer than ten bytes.")
    }

    private static func readLoadCommandString(
        _ data: Data,
        commandOffset: Int,
        commandSize: Int,
        stringOffset: UInt32,
        label: String
    ) throws -> String {
        let offset = Int(stringOffset)
        guard offset >= 8, offset < commandSize else {
            throw format("Mach-O \(label) offset is outside its load command.")
        }
        let start = commandOffset + offset
        let end = commandOffset + commandSize
        guard let nul = data[start..<end].firstIndex(of: 0), nul > start else {
            throw format("Mach-O \(label) is empty or not NUL-terminated inside its load command.")
        }
        let bytes = data[start..<nul]
        guard let value = String(bytes: bytes, encoding: .utf8), !value.isEmpty else {
            throw format("Mach-O \(label) is not valid UTF-8.")
        }
        return value
    }

    private static func parseBindOpcodes(
        _ data: Data,
        range: Range<Int>,
        segments: [X64MachOSegment],
        dependencies: [X64MachODylibDependency],
        stream: X64MachOBindStreamKind
    ) throws -> [X64MachOBindAction] {
        let maxActions = 4_000_000
        let pointerSize: UInt64 = 8
        var cursor = range.lowerBound
        let end = range.upperBound
        var actions: [X64MachOBindAction] = []
        var libraryOrdinal = 0
        var symbolName: String?
        var symbolFlags: UInt8 = 0
        var bindType: UInt8 = 1
        var addend: Int64 = 0
        var segmentIndex: Int?
        var segmentOffset: UInt64 = 0
        // dyld performs bind-cursor arithmetic in an unsigned 64-bit address
        // type. ADD_ADDR_ULEB therefore uses modulo-2^64 arithmetic: linkers
        // can encode a backwards move as the two's-complement distance in a
        // ULEB value. Do not reject arithmetic wrap by itself. The cursor is
        // validated against the selected segment at the next actual bind,
        // before a guest address or memory write is produced.
        var segmentOffsetDidWrap = false
        var currentOpcodeOffset = range.lowerBound
        var segmentSelectionOpcodeOffset: Int?
        var segmentSelectionValue: UInt64?
        var lastCursorMutation = "initial cursor 0"

        func advance(_ amount: UInt64, operation: String) {
            let previous = segmentOffset
            let (next, wrapped) = segmentOffset.addingReportingOverflow(amount)
            segmentOffset = next // UInt64 partialValue is the modulo-2^64 result.
            if wrapped {
                segmentOffsetDidWrap = true
                lastCursorMutation = String(
                    format: "%@ added 0x%llX to 0x%llX with modulo-2^64 wrap to 0x%llX",
                    operation, amount, previous, next
                )
            } else {
                lastCursorMutation = String(format: "%@ added 0x%llX to 0x%llX", operation, amount, previous)
            }
        }

        func invalidLocationDiagnostic(segment: X64MachOSegment, index: Int) -> String {
            let relativeOpcodeOffset = currentOpcodeOffset - range.lowerBound
            let contextStart = max(range.lowerBound, currentOpcodeOffset - 20)
            let contextEnd = min(end, currentOpcodeOffset + 28)
            let contextBytes = data[contextStart..<contextEnd]
                .map { String(format: "%02X", $0) }
                .joined(separator: " ")
            let selection = segmentSelectionOpcodeOffset.map { String(format: "0x%X", $0) } ?? "unknown"
            let selectedValue = segmentSelectionValue.map { String(format: "0x%llX", $0) } ?? "unknown"
            return String(
                format: "Dyld %@ bind location is outside segment %@ at opcode offset 0x%X; segment index=%d; segment offset=0x%016llX; selected by opcode 0x%@ with initial offset 0x%@; cursor state: %@; wrapped-since-selection=%@; stream bytes [0x%X..<0x%X]: %@.",
                stream.rawValue,
                segment.name,
                relativeOpcodeOffset,
                index,
                segmentOffset,
                selection,
                selectedValue,
                lastCursorMutation,
                segmentOffsetDidWrap ? "yes" : "no",
                contextStart - range.lowerBound,
                contextEnd - range.lowerBound,
                contextBytes
            )
        }

        func resetLazyState() {
            libraryOrdinal = 0
            symbolName = nil
            symbolFlags = 0
            bindType = 1
            addend = 0
            segmentIndex = nil
            segmentOffset = 0
            segmentOffsetDidWrap = false
            segmentSelectionOpcodeOffset = nil
            segmentSelectionValue = nil
            lastCursorMutation = "lazy-bind record reset"
        }

        func emit() throws {
            guard bindType == 1 else {
                throw format("Unsupported dyld bind type \(bindType); only 64-bit pointer binds are supported.")
            }
            guard let name = symbolName, !name.isEmpty else {
                throw format("Dyld bind opcode attempts to bind without a symbol name.")
            }
            if libraryOrdinal > 0, !dependencies.contains(where: { $0.ordinal == libraryOrdinal }) {
                throw format("Dyld bind references missing dylib ordinal \(libraryOrdinal).")
            }
            guard let index = segmentIndex, segments.indices.contains(index) else {
                throw format("Dyld bind opcode uses a segment index before selecting a valid segment.")
            }
            let segment = segments[index]
            guard segmentOffset <= segment.virtualSize,
                  pointerSize <= segment.virtualSize - segmentOffset else {
                throw format(invalidLocationDiagnostic(segment: segment, index: index))
            }
            let (address, overflow) = segment.virtualAddress.addingReportingOverflow(segmentOffset)
            guard !overflow else { throw format("Dyld bind location overflows guest address space.") }
            guard actions.count < maxActions else {
                throw format("Dyld bind stream exceeds the \(maxActions)-action safety limit.")
            }
            actions.append(X64MachOBindAction(
                location: address,
                symbolName: name,
                libraryOrdinal: libraryOrdinal,
                addend: addend,
                type: bindType,
                symbolFlags: symbolFlags,
                stream: stream
            ))
            advance(pointerSize, operation: "implicit pointer-size advance after DO_BIND")
        }

        while cursor < end {
            currentOpcodeOffset = cursor
            let byte = data[cursor]
            cursor += 1
            let opcode = byte & 0xF0
            let immediate = byte & 0x0F

            switch opcode {
            case 0x00: // BIND_OPCODE_DONE
                if stream != .lazy {
                    guard end - cursor <= 15, data[cursor..<end].allSatisfy({ $0 == 0 }) else {
                        throw format("Dyld bind stream contains bytes after BIND_OPCODE_DONE.")
                    }
                    return actions
                }
                if cursor == end || data[cursor..<end].allSatisfy({ $0 == 0 }) { return actions }
                resetLazyState() // Each lazy-bind record is terminated by DONE.

            case 0x10: // SET_DYLIB_ORDINAL_IMM
                libraryOrdinal = Int(immediate)

            case 0x20: // SET_DYLIB_ORDINAL_ULEB
                let value = try readULEB128(data, cursor: &cursor, end: end)
                guard value <= UInt64(Int.max) else { throw format("Dyld bind library ordinal overflows Int.") }
                libraryOrdinal = Int(value)

            case 0x30: // SET_DYLIB_SPECIAL_IMM
                libraryOrdinal = immediate == 0 ? 0 : Int(immediate) - 16
                guard libraryOrdinal >= -3 else { throw format("Dyld bind uses an unsupported special dylib ordinal.") }

            case 0x40: // SET_SYMBOL_TRAILING_FLAGS_IMM
                symbolFlags = immediate
                guard immediate & ~UInt8(0x9) == 0 else {
                    throw format("Dyld bind uses unsupported symbol flags 0x\(String(immediate, radix: 16)).")
                }
                let start = cursor
                guard let nul = data[start..<end].firstIndex(of: 0), nul > start else {
                    throw format("Dyld bind symbol name is unterminated or empty.")
                }
                guard let name = String(bytes: data[start..<nul], encoding: .utf8) else {
                    throw format("Dyld bind symbol name is not valid UTF-8.")
                }
                symbolName = name
                cursor = nul + 1

            case 0x50: // SET_TYPE_IMM
                bindType = immediate

            case 0x60: // SET_ADDEND_SLEB
                addend = try readSLEB128(data, cursor: &cursor, end: end)

            case 0x70: // SET_SEGMENT_AND_OFFSET_ULEB
                let index = Int(immediate)
                guard segments.indices.contains(index) else {
                    throw format("Dyld bind selects invalid segment index \(index).")
                }
                segmentIndex = index
                segmentOffset = try readULEB128(data, cursor: &cursor, end: end)
                segmentOffsetDidWrap = false
                segmentSelectionOpcodeOffset = currentOpcodeOffset - range.lowerBound
                segmentSelectionValue = segmentOffset
                lastCursorMutation = String(format: "SET_SEGMENT_AND_OFFSET selected segment %d with offset 0x%llX", index, segmentOffset)

            case 0x80: // ADD_ADDR_ULEB
                advance(try readULEB128(data, cursor: &cursor, end: end), operation: "ADD_ADDR_ULEB at opcode 0x\(String(currentOpcodeOffset - range.lowerBound, radix: 16))")

            case 0x90: // DO_BIND
                try emit()

            case 0xA0: // DO_BIND_ADD_ADDR_ULEB
                try emit()
                advance(try readULEB128(data, cursor: &cursor, end: end), operation: "DO_BIND_ADD_ADDR_ULEB at opcode 0x\(String(currentOpcodeOffset - range.lowerBound, radix: 16))")

            case 0xB0: // DO_BIND_ADD_ADDR_IMM_SCALED
                try emit()
                advance(UInt64(immediate) * pointerSize, operation: "DO_BIND_ADD_ADDR_IMM_SCALED at opcode 0x\(String(currentOpcodeOffset - range.lowerBound, radix: 16))")

            case 0xC0: // DO_BIND_ULEB_TIMES_SKIPPING_ULEB
                let count = try readULEB128(data, cursor: &cursor, end: end)
                let skip = try readULEB128(data, cursor: &cursor, end: end)
                guard count <= UInt64(maxActions - actions.count) else {
                    throw format("Dyld bind repetition exceeds the action safety limit.")
                }
                for _ in 0..<Int(count) {
                    try emit()
                    advance(skip, operation: "DO_BIND_ULEB_TIMES_SKIPPING_ULEB at opcode 0x\(String(currentOpcodeOffset - range.lowerBound, radix: 16))")
                }

            case 0xD0:
                throw format("Threaded dyld bind opcodes are not supported in this release.")

            default:
                throw format(String(format: "Unsupported dyld bind opcode 0x%02X.", opcode))
            }
        }
        return actions
    }

    /// Parses a standalone export-trie payload read from a dyld shared-cache
    /// image's __LINKEDIT mapping. The parser applies the same bounds and
    /// traversal limits used for an executable's embedded export trie.
    static func parseExportTriePayload(_ payload: Data) throws -> [X64MachOExport] {
        guard payload.count <= 64 * 1024 * 1024 else {
            throw format("Shared-cache export trie exceeds the 64 MiB safety limit.")
        }
        return try parseExportTrie(payload, range: 0..<payload.count)
    }

    private static func parseExportTrie(_ data: Data, range: Range<Int>) throws -> [X64MachOExport] {
        guard !range.isEmpty else { return [] }
        let maxExports = 1_000_000
        let maxNodeVisits = 4_000_000
        var exports: [X64MachOExport] = []
        var stack: [(offset: Int, prefix: String)] = [(0, "")]
        var visits = 0
        var emitted = Set<String>()

        while let item = stack.popLast() {
            visits += 1
            guard visits <= maxNodeVisits else { throw format("Export trie exceeds the node-visit safety limit.") }
            guard item.offset >= 0, item.offset < range.count else {
                throw format("Export trie child offset is outside the trie payload.")
            }
            let node = range.lowerBound + item.offset
            var cursor = node
            let terminalSizeValue = try readULEB128(data, cursor: &cursor, end: range.upperBound)
            guard terminalSizeValue <= UInt64(range.upperBound - cursor) else {
                throw format("Export trie terminal payload extends beyond the trie.")
            }
            let terminalEnd = cursor + Int(terminalSizeValue)

            if terminalSizeValue > 0 {
                let flags = try readULEB128(data, cursor: &cursor, end: terminalEnd)
                let reexport = (flags & 0x08) != 0
                let stubResolver = (flags & 0x10) != 0
                let addressOffset: UInt64?
                let reexportOrdinal: Int?
                let importedName: String?
                let resolverOffset: UInt64?
                if reexport {
                    let ordinalValue = try readULEB128(data, cursor: &cursor, end: terminalEnd)
                    guard ordinalValue <= UInt64(Int.max) else { throw format("Export reexport ordinal overflows Int.") }
                    reexportOrdinal = Int(ordinalValue)
                    importedName = try readCString(data, cursor: &cursor, end: terminalEnd, label: "export reexport name", allowEmpty: true)
                    addressOffset = nil
                    resolverOffset = nil
                } else {
                    addressOffset = try readULEB128(data, cursor: &cursor, end: terminalEnd)
                    reexportOrdinal = nil
                    importedName = nil
                    resolverOffset = stubResolver ? try readULEB128(data, cursor: &cursor, end: terminalEnd) : nil
                }
                guard cursor == terminalEnd else { throw format("Export trie terminal has unexpected trailing bytes.") }
                if !item.prefix.isEmpty {
                    guard emitted.insert(item.prefix).inserted else { throw format("Export trie contains duplicate symbol terminals.") }
                    exports.append(X64MachOExport(
                        symbolName: item.prefix,
                        flags: flags,
                        addressOffset: addressOffset,
                        reexportOrdinal: reexportOrdinal,
                        importedName: importedName,
                        resolverOffset: resolverOffset
                    ))
                    guard exports.count <= maxExports else { throw format("Export trie exceeds the export safety limit.") }
                }
            }

            cursor = terminalEnd
            guard cursor < range.upperBound else { throw format("Export trie node is missing its child count.") }
            let childCount = Int(data[cursor])
            cursor += 1
            var children: [(offset: Int, prefix: String)] = []
            for _ in 0..<childCount {
                let edge = try readCString(data, cursor: &cursor, end: range.upperBound, label: "export trie edge", allowEmpty: false)
                let childOffsetValue = try readULEB128(data, cursor: &cursor, end: range.upperBound)
                guard childOffsetValue <= UInt64(Int.max) else { throw format("Export trie child offset overflows Int.") }
                let childPrefix = item.prefix + edge
                guard childPrefix.utf8.count <= 4_096 else { throw format("Export trie symbol path exceeds 4096 bytes.") }
                children.append((Int(childOffsetValue), childPrefix))
            }
            // Preserve source order when the stack is popped.
            stack.append(contentsOf: children.reversed())
        }
        return exports.sorted { $0.symbolName < $1.symbolName }
    }

    private static func readCString(
        _ data: Data,
        cursor: inout Int,
        end: Int,
        label: String,
        allowEmpty: Bool
    ) throws -> String {
        guard cursor <= end, cursor < end,
              let nul = data[cursor..<end].firstIndex(of: 0), allowEmpty || nul > cursor else {
            throw format("\(label) is missing or not NUL-terminated.")
        }
        guard let string = String(bytes: data[cursor..<nul], encoding: .utf8) else {
            throw format("\(label) is not valid UTF-8.")
        }
        cursor = nul + 1
        return string
    }

    private static func readSLEB128(_ data: Data, cursor: inout Int, end: Int) throws -> Int64 {
        var result: UInt64 = 0
        var shift: UInt64 = 0
        for index in 0..<10 {
            guard cursor < end else { throw format("Dyld bind stream ends inside a SLEB128 value.") }
            let byte = data[cursor]
            cursor += 1
            let payload = UInt64(byte & 0x7F)

            if shift == 63 {
                // Only the sign-extension encodings 0x00 and 0x7f fit in the
                // tenth byte of a signed 64-bit LEB128 integer.
                guard payload == 0 || payload == 0x7F else {
                    throw format("Dyld bind SLEB128 value overflows 64 bits.")
                }
                result |= (payload & 0x01) << 63
            } else if shift < 63 {
                result |= payload << shift
            } else if payload != 0 {
                throw format("Dyld bind SLEB128 value overflows 64 bits.")
            }

            shift += 7
            if byte & 0x80 == 0 {
                if shift < 64 && (byte & 0x40) != 0 {
                    result |= UInt64.max << shift
                }
                return Int64(bitPattern: result)
            }
            if index == 9 {
                throw format("Dyld bind SLEB128 value is longer than ten bytes.")
            }
        }
        throw format("Dyld bind SLEB128 value is longer than ten bytes.")
    }

    private static func parseSegment(_ data: Data, commandOffset: Int, commandSize: Int) throws -> X64MachOSegment {
        guard commandSize >= segment64Size else {
            throw format("LC_SEGMENT_64 is shorter than its 72-byte structure.")
        }
        let sectionCount = readLE32(data, at: commandOffset + 64)
        let requiredSectionBytes = UInt64(sectionCount) * UInt64(section64Size)
        guard UInt64(segment64Size) + requiredSectionBytes <= UInt64(commandSize) else {
            throw format("LC_SEGMENT_64 section table exceeds cmdsize.")
        }

        let nameBytes = data[(commandOffset + 8)..<(commandOffset + 24)]
        let name = String(decoding: nameBytes.prefix { $0 != 0 }, as: UTF8.self)
        let vmAddress = readLE64(data, at: commandOffset + 24)
        let vmSize = readLE64(data, at: commandOffset + 32)
        let fileOffset = readLE64(data, at: commandOffset + 40)
        let fileSize = readLE64(data, at: commandOffset + 48)
        let maximumProtectionRaw = readLE32(data, at: commandOffset + 56)
        let initialProtectionRaw = readLE32(data, at: commandOffset + 60)

        guard maximumProtectionRaw & ~UInt32(0x7) == 0,
              initialProtectionRaw & ~UInt32(0x7) == 0,
              initialProtectionRaw & ~maximumProtectionRaw == 0 else {
            throw format("Segment \(name) has invalid maxprot/initprot flags.")
        }
        guard fileSize <= vmSize else {
            throw format("Segment \(name) has filesize larger than vmsize.")
        }
        guard vmSize == 0 || (vmAddress % X64GuestVirtualMemoryConstants.pageSize == 0 && vmSize % X64GuestVirtualMemoryConstants.pageSize == 0) else {
            throw format("Segment \(name) is not aligned to the 4 KiB x86_64 guest page size.")
        }
        guard vmSize <= UInt64.max - vmAddress else {
            throw format("Segment \(name) virtual address range overflows.")
        }
        guard fileOffset <= UInt64(data.count), fileSize <= UInt64(data.count) - fileOffset else {
            throw format("Segment \(name) file range extends beyond the selected Mach-O slice.")
        }
        guard vmSize <= UInt64(Int.max), fileSize <= UInt64(Int.max) else {
            throw format("Segment \(name) exceeds the host process's supported size.")
        }

        return X64MachOSegment(
            name: name,
            virtualAddress: vmAddress,
            virtualSize: vmSize,
            fileOffset: fileOffset,
            fileSize: fileSize,
            maximumProtection: X64GuestMemoryPermissions(rawValue: UInt8(maximumProtectionRaw)),
            initialProtection: X64GuestMemoryPermissions(rawValue: UInt8(initialProtectionRaw)),
            sectionCount: sectionCount
        )
    }

    private static func validateSegmentLayout(_ segments: [X64MachOSegment]) throws {
        let nonEmpty = segments.filter { $0.virtualSize > 0 }.sorted { $0.virtualAddress < $1.virtualAddress }
        for index in nonEmpty.indices {
            let segment = nonEmpty[index]
            guard segment.virtualSize <= UInt64.max - segment.virtualAddress else {
                throw format("Segment \(segment.name) virtual range overflows.")
            }
            if index > 0, nonEmpty[index - 1].virtualEnd > segment.virtualAddress {
                throw format("Mach-O segments \(nonEmpty[index - 1].name) and \(segment.name) overlap in guest virtual memory.")
            }
        }
    }

    private static func format(_ message: String) -> X64MachOFormatError {
        X64MachOFormatError(message: message)
    }

    private static func readLE32(_ data: Data, at offset: Int) -> UInt32 {
        guard offset >= 0, offset <= data.count - 4 else { return 0 }
        return UInt32(data[offset])
            | (UInt32(data[offset + 1]) << 8)
            | (UInt32(data[offset + 2]) << 16)
            | (UInt32(data[offset + 3]) << 24)
    }

    private static func readLE64(_ data: Data, at offset: Int) -> UInt64 {
        UInt64(readLE32(data, at: offset)) | (UInt64(readLE32(data, at: offset + 4)) << 32)
    }

    private static func readBE32(_ data: Data, at offset: Int) -> UInt32 {
        guard offset >= 0, offset <= data.count - 4 else { return 0 }
        return (UInt32(data[offset]) << 24)
            | (UInt32(data[offset + 1]) << 16)
            | (UInt32(data[offset + 2]) << 8)
            | UInt32(data[offset + 3])
    }

    private static func read32(_ data: Data, at offset: Int, swapped: Bool) -> UInt32 {
        let value = readBE32(data, at: offset)
        return swapped ? value.byteSwapped : value
    }

    private static func read64(_ data: Data, at offset: Int, swapped: Bool) -> UInt64 {
        let high = UInt64(read32(data, at: offset, swapped: swapped))
        let low = UInt64(read32(data, at: offset + 4, swapped: swapped))
        return swapped ? (low << 32) | high : (high << 32) | low
    }
}

// MARK: - Guest-memory image loader

struct X64MachOMappedSegment: Sendable, Equatable {
    let name: String
    let guestAddress: UInt64
    /// Full Mach-O virtual size reserved in the guest address space.
    let byteCount: UInt64
    /// Host backing eagerly allocated for file-backed pages. May be much
    /// smaller than byteCount; the remaining virtual tail is sparse.
    let committedByteCount: UInt64
    /// Bytes reserved for zero-filled pages that are materialized only when
    /// first accessed with a permission allowed by the segment.
    let demandZeroByteCount: UInt64
    let committed: Bool
    let permissions: X64GuestMemoryPermissions
}

struct X64MachOLoadedImage: Sendable {
    let sourceName: String
    let entryAddress: UInt64
    let preferredLoadAddress: UInt64
    let slide: UInt64
    let mappedSegments: [X64MachOMappedSegment]
    let committedBytes: UInt64
    let demandZeroBytes: UInt64
    let rebaseFixupCount: Int
    let rebasesApplied: Int
    let unresolvedBindOpcodeBytes: UInt64
    let unresolvedChainedFixupsBytes: UInt64
    let dependencies: [X64MachODylibDependency]
    let bindFixupCount: Int
    let weakBindFixupCount: Int
    let lazyBindFixupCount: Int
    let boundFixupCount: Int
    let unresolvedBindFixupCount: Int
    let unresolvedBindSymbols: [String]
    let exports: [X64MachOExport]

    var demandZeroPageCount: UInt64 {
        demandZeroBytes / X64GuestVirtualMemoryConstants.pageSize
    }

    var reservedSegmentCount: Int { mappedSegments.count }
    var reservedVirtualBytes: UInt64 {
        mappedSegments.reduce(0) { partial, segment in
            let (sum, overflow) = partial.addingReportingOverflow(segment.byteCount)
            return overflow ? UInt64.max : sum
        }
    }
}

/// Explicit guest-address symbol map. Kestrel never substitutes host ARM64
/// function pointers for guest x86_64 addresses; callers must register guest
/// export addresses or guest ABI-thunk addresses here.
struct X64MachOSymbolResolver: Sendable {
    private(set) var addresses: [String: UInt64] = [:]
    /// Resolver-returned implementations override ordinary exports only for lazy-bind actions.
    private(set) var lazyAddresses: [String: UInt64] = [:]
    /// Keys for lazy STUB_AND_RESOLVER exports must never fall back to the ordinary stub.
    private var lazyResolverRequiredKeys: Set<String> = []
    /// Weak definitions occupy a separate namespace so BIND_SPECIAL_DYLIB_WEAK_LOOKUP
    /// cannot accidentally accept an ordinary strong export or a host ABI thunk.
    private(set) var weakAddresses: [String: UInt64] = [:]

    init() {}

    mutating func register(symbol: String, address: UInt64, installName: String? = nil) {
        addresses[key(symbol: symbol, installName: installName)] = address
    }

    mutating func registerIfAbsent(symbol: String, address: UInt64, installName: String? = nil) {
        let lookupKey = key(symbol: symbol, installName: installName)
        if addresses[lookupKey] == nil { addresses[lookupKey] = address }
    }

    mutating func registerLazy(symbol: String, address: UInt64, installName: String? = nil) {
        lazyAddresses[key(symbol: symbol, installName: installName)] = address
    }

    mutating func requireLazyResolverImplementation(symbol: String, installName: String? = nil) {
        lazyResolverRequiredKeys.insert(key(symbol: symbol, installName: installName))
    }

    mutating func registerWeak(symbol: String, address: UInt64, installName: String? = nil) {
        weakAddresses[key(symbol: symbol, installName: installName)] = address
    }

    mutating func registerWeakIfAbsent(symbol: String, address: UInt64, installName: String? = nil) {
        let lookupKey = key(symbol: symbol, installName: installName)
        if weakAddresses[lookupKey] == nil { weakAddresses[lookupKey] = address }
    }

    func resolve(symbol: String, dependency: X64MachODylibDependency?) -> UInt64? {
        if let dependency,
           let exact = addresses[key(symbol: symbol, installName: dependency.installName)] {
            return exact
        }
        return addresses[key(symbol: symbol, installName: nil)]
    }

    func resolveExact(symbol: String, installName: String) -> UInt64? {
        addresses[key(symbol: symbol, installName: installName)]
    }

    /// Lazy binds prefer a resolver-returned implementation, then fall back to
    /// the ordinary export (the stub for STUB_AND_RESOLVER).
    func resolveLazyExact(symbol: String, installName: String) -> UInt64? {
        let lookupKey = key(symbol: symbol, installName: installName)
        if lazyResolverRequiredKeys.contains(lookupKey) {
            return lazyAddresses[lookupKey]
        }
        return lazyAddresses[lookupKey] ?? addresses[lookupKey]
    }

    func resolveLazy(symbol: String, dependency: X64MachODylibDependency? = nil) -> UInt64? {
        if let dependency {
            let exactKey = key(symbol: symbol, installName: dependency.installName)
            if lazyResolverRequiredKeys.contains(exactKey) {
                return lazyAddresses[exactKey]
            }
            if let exact = lazyAddresses[exactKey] ?? addresses[exactKey] {
                return exact
            }
        }
        let globalKey = key(symbol: symbol, installName: nil)
        if lazyResolverRequiredKeys.contains(globalKey) {
            return lazyAddresses[globalKey]
        }
        return lazyAddresses[globalKey] ?? addresses[globalKey]
    }

    func resolveWeakExact(symbol: String, installName: String) -> UInt64? {
        weakAddresses[key(symbol: symbol, installName: installName)]
    }

    func resolveWeak(symbol: String, dependency: X64MachODylibDependency? = nil) -> UInt64? {
        if let dependency,
           let exact = weakAddresses[key(symbol: symbol, installName: dependency.installName)] {
            return exact
        }
        return weakAddresses[key(symbol: symbol, installName: nil)]
    }

    private func key(symbol: String, installName: String?) -> String {
        "\(installName ?? "*")|\(symbol)"
    }
}

enum X64MachOLoader {
    /// Maximum eager host backing for file-backed Mach-O pages. This is not a
    /// limit on guest virtual-address reservations: large segment tails and
    /// __PAGEZERO remain sparse and consume metadata only.
    static let defaultMaximumCommittedBytes: UInt64 = 512 * 1024 * 1024

    static func load(
        _ image: X64MachOImage,
        into memory: inout X64GuestVirtualMemory,
        slide: UInt64 = 0,
        maximumCommittedBytes: UInt64 = defaultMaximumCommittedBytes,
        symbolResolver: X64MachOSymbolResolver? = nil,
        requireAllBindingsResolved: Bool = false
    ) throws -> X64MachOLoadedImage {
        let pageSize = X64GuestVirtualMemoryConstants.pageSize
        let loadableSegments = image.segments.filter { $0.virtualSize > 0 }
        guard slide % pageSize == 0 else {
            throw X64MachOFormatError(message: "Mach-O load slide must be aligned to the 4 KiB guest page size.")
        }
        if slide > 0 {
            guard image.header.flags & X64MachOParser.mhPie != 0 else {
                throw X64MachOFormatError(message: "A non-PIE MH_EXECUTE image cannot be assigned a load slide.")
            }
            guard image.chainedFixupsBytes == 0 else {
                throw X64MachOFormatError(message: "Cannot slide this image yet: LC_DYLD_CHAINED_FIXUPS is present and chained-fixup decoding is not implemented.")
            }
            guard image.hasDyldInfoCommand else {
                throw X64MachOFormatError(message: "Cannot slide this PIE image safely: it has no classic LC_DYLD_INFO rebase metadata.")
            }
        }
        for segment in loadableSegments where !segment.isPageZero {
            let (shiftedBase, baseOverflow) = segment.virtualAddress.addingReportingOverflow(slide)
            let (_, endOverflow) = shiftedBase.addingReportingOverflow(segment.virtualSize)
            guard !baseOverflow, !endOverflow else {
                throw X64MachOFormatError(message: "Mach-O load slide overflows segment \(segment.name)'s guest address range.")
            }
        }

        // Commit only pages that contain bytes from the executable file. The
        // remainder of each vmSize is registered below as a permission-aware
        // demand-zero range and backed one page at a time on first access.
        // Large Mach-O __DATA/__BSS tails therefore remain sparse.
        var committedBySegment: [UInt64: UInt64] = [:]
        var totalCommitted: UInt64 = 0
        for segment in loadableSegments where !segment.isPageZero && segment.fileSize > 0 {
            let (roundedInput, roundOverflow) = segment.fileSize.addingReportingOverflow(pageSize - 1)
            guard !roundOverflow else {
                throw X64MachOFormatError(message: "Segment \(segment.name) file-backed size overflows page rounding.")
            }
            let committedBytes = roundedInput & ~(pageSize - 1)
            guard committedBytes <= segment.virtualSize else {
                throw X64MachOFormatError(message: "Segment \(segment.name) file-backed pages exceed its virtual size.")
            }
            let (sum, sumOverflow) = totalCommitted.addingReportingOverflow(committedBytes)
            guard !sumOverflow else {
                throw X64MachOFormatError(message: "Total file-backed image size overflows.")
            }
            totalCommitted = sum
            committedBySegment[segment.virtualAddress] = committedBytes
        }

        guard totalCommitted <= maximumCommittedBytes else {
            throw X64MachOFormatError(message: "Image requires \(totalCommitted) bytes of eager file-backed memory; loader safety limit is \(maximumCommittedBytes) bytes. Guest virtual reservations are sparse and are not counted.")
        }

        var effectiveResolver = symbolResolver ?? X64MachOSymbolResolver()
        // Symbols exported by the main executable are available to self and
        // flat-namespace binds. Reexports, TLS exports, absolute exports, and
        // resolver-stub exports need additional dyld semantics and are not
        // silently treated as ordinary image-relative function addresses.
        for export in image.exports where !export.isReexport && !export.isAbsolute
            && !export.isThreadLocal && !export.hasStubAndResolver {
            guard let offset = export.addressOffset else { continue }
            let (preferredAddress, preferredOverflow) = image.preferredLoadAddress.addingReportingOverflow(offset)
            let (runtimeAddress, slideOverflow) = preferredAddress.addingReportingOverflow(slide)
            guard !preferredOverflow, !slideOverflow else {
                throw X64MachOFormatError(message: "Export address overflows for symbol \(export.symbolName).")
            }
            effectiveResolver.registerIfAbsent(symbol: export.symbolName, address: runtimeAddress)
            if export.isWeakDefinition {
                effectiveResolver.registerWeakIfAbsent(symbol: export.symbolName, address: runtimeAddress)
            }
        }

        var reservedBases: [UInt64] = []
        var mapped: [X64MachOMappedSegment] = []
        var totalDemandZeroBytes: UInt64 = 0
        var rebasesApplied = 0
        var boundFixupCount = 0
        var unresolvedBindSymbols: [String] = []
        func runtimeBase(for segment: X64MachOSegment) -> UInt64 {
            segment.isPageZero ? segment.virtualAddress : segment.virtualAddress + slide
        }

        do {
            // Reserve all virtual ranges first so collisions are detected before
            // any guest bytes are copied into the new image. __PAGEZERO remains
            // at zero; other segments receive the caller-selected PIE slide.
            for segment in loadableSegments {
                let guestBase = runtimeBase(for: segment)
                _ = try memory.reserve(at: guestBase, byteCount: segment.virtualSize, kind: .image)
                reservedBases.append(guestBase)
            }

            // Stage every file-backed page as RW while bytes and rebases are
            // installed. Final Mach-O protections are applied only afterwards,
            // allowing fixups in read-only __DATA_CONST-like segments.
            for segment in loadableSegments {
                let guestBase = runtimeBase(for: segment)
                let committedBytes = segment.isPageZero
                    ? 0
                    : (committedBySegment[segment.virtualAddress] ?? 0)

                if committedBytes > 0 {
                    try memory.commit(at: guestBase, byteCount: committedBytes, permissions: .readWrite)
                    if segment.fileSize > 0 {
                        let fileStart = Int(segment.fileOffset)
                        let fileCount = Int(segment.fileSize)
                        let bytes = Array(image.sliceData[fileStart..<(fileStart + fileCount)])
                        try memory.writeBytes(bytes, at: guestBase)
                    }
                }

                let demandZeroBytes = segment.isPageZero ? 0 : segment.virtualSize - committedBytes
                if demandZeroBytes > 0 {
                    try memory.registerDemandZeroRange(
                        at: guestBase + committedBytes,
                        byteCount: demandZeroBytes,
                        permissions: segment.initialProtection
                    )
                    let (sum, overflow) = totalDemandZeroBytes.addingReportingOverflow(demandZeroBytes)
                    guard !overflow else {
                        throw X64MachOFormatError(message: "Total demand-zero image range size overflows.")
                    }
                    totalDemandZeroBytes = sum
                }

                mapped.append(X64MachOMappedSegment(
                    name: segment.name,
                    guestAddress: guestBase,
                    byteCount: segment.virtualSize,
                    committedByteCount: committedBytes,
                    demandZeroByteCount: demandZeroBytes,
                    committed: committedBytes > 0,
                    permissions: segment.initialProtection
                ))
            }

            if slide > 0 {
                for preferredFixupAddress in image.rebaseFixupAddresses {
                    let (fixupAddress, fixupOverflow) = preferredFixupAddress.addingReportingOverflow(slide)
                    guard !fixupOverflow else {
                        throw X64MachOFormatError(message: "A dyld rebase target overflows after applying the PIE slide.")
                    }
                    let pointerValue = try memory.readUnsigned(at: fixupAddress, byteCount: 8)
                    if pointerValue == 0 { continue }
                    guard image.segments.contains(where: { segment in
                        !segment.isPageZero && pointerValue >= segment.virtualAddress && pointerValue < segment.virtualEnd
                    }) else {
                        throw X64MachOFormatError(message: String(format: "Dyld rebase target 0x%016llX does not point into this image; refusing to slide it.", pointerValue))
                    }
                    let (slidPointer, pointerOverflow) = pointerValue.addingReportingOverflow(slide)
                    guard !pointerOverflow else {
                        throw X64MachOFormatError(message: "A rebased pointer overflows after applying the PIE slide.")
                    }
                    try memory.writeUnsigned(slidPointer, at: fixupAddress, byteCount: 8)
                    rebasesApplied += 1
                }
            }

            // This prototype applies decoded lazy-bind locations eagerly when
            // the caller already supplied a guest resolver. It does not yet
            // implement dyld's lazy binder entrypoint or on-first-call rebinding.
            let allBindActions = image.bindActions + image.weakBindActions + image.lazyBindActions
            for action in allBindActions {
                // BIND_TYPE_POINTER is the only write format implemented by
                // this loader. Text/absolute/threaded bind forms must not be
                // treated as eight-byte pointers or silently corrupt guest code.
                guard action.type == 1 else {
                    unresolvedBindSymbols.append(action.symbolName)
                    continue
                }
                let dependency = action.libraryOrdinal > 0
                    ? image.dependencies.first(where: { $0.ordinal == action.libraryOrdinal })
                    : nil
                let resolvedAddress: UInt64?
                if action.libraryOrdinal == -3 {
                    resolvedAddress = effectiveResolver.resolveWeak(symbol: action.symbolName)
                } else if let dependency {
                    // Positive ordinals are strict two-level lookups. Lazy binds
                    // prefer the resolver-returned implementation; regular binds
                    // retain the ordinary export address (the stub).
                    if action.stream == .lazy {
                        resolvedAddress = effectiveResolver.resolveLazyExact(
                            symbol: action.symbolName,
                            installName: dependency.installName
                        )
                    } else {
                        resolvedAddress = effectiveResolver.resolveExact(
                            symbol: action.symbolName,
                            installName: dependency.installName
                        )
                    }
                } else {
                    resolvedAddress = action.stream == .lazy
                        ? effectiveResolver.resolveLazy(symbol: action.symbolName, dependency: nil)
                        : effectiveResolver.resolve(symbol: action.symbolName, dependency: nil)
                }
                let bindLocation = action.location.addingReportingOverflow(slide)
                guard !bindLocation.overflow else {
                    throw X64MachOFormatError(message: "Dyld bind location overflows after applying the PIE slide.")
                }
                if let resolvedAddress {
                    guard memory.region(containing: resolvedAddress) != nil else {
                        throw X64MachOFormatError(message: String(format: "Resolved symbol %@ points to unmapped guest address 0x%016llX.", action.symbolName, resolvedAddress))
                    }
                    let boundValue: UInt64
                    if action.addend >= 0 {
                        let (value, overflow) = resolvedAddress.addingReportingOverflow(UInt64(action.addend))
                        guard !overflow else { throw X64MachOFormatError(message: "Dyld bind addend overflows for symbol \(action.symbolName).") }
                        boundValue = value
                    } else {
                        let magnitude = UInt64(-(action.addend + 1)) + 1
                        let (value, overflow) = resolvedAddress.subtractingReportingOverflow(magnitude)
                        guard !overflow else { throw X64MachOFormatError(message: "Dyld bind addend underflows for symbol \(action.symbolName).") }
                        boundValue = value
                    }
                    guard memory.region(containing: boundValue) != nil else {
                        throw X64MachOFormatError(message: String(format: "Bound value for %@ points to unmapped guest address 0x%016llX.", action.symbolName, boundValue))
                    }
                    try memory.writeUnsigned(boundValue, at: bindLocation.partialValue, byteCount: 8)
                    boundFixupCount += 1
                } else if action.isWeakImport {
                    // Undefined weak imports have a null resolution under
                    // dyld's weak-import semantics.
                    try memory.writeUnsigned(0, at: bindLocation.partialValue, byteCount: 8)
                    boundFixupCount += 1
                } else {
                    unresolvedBindSymbols.append(action.symbolName)
                }
            }
            if requireAllBindingsResolved && !unresolvedBindSymbols.isEmpty {
                let preview = unresolvedBindSymbols.prefix(5).joined(separator: ", ")
                throw X64MachOFormatError(message: "Unable to resolve \(unresolvedBindSymbols.count) required imports (for example: \(preview)). No partially bound image was retained.")
            }

            // Restore each segment's declared initial permissions after all
            // file bytes and classic pointer rebases have been applied.
            for segment in loadableSegments {
                let committedBytes = segment.isPageZero
                    ? 0
                    : (committedBySegment[segment.virtualAddress] ?? 0)
                if committedBytes > 0 {
                    try memory.protect(
                        at: runtimeBase(for: segment),
                        byteCount: committedBytes,
                        permissions: segment.initialProtection
                    )
                }
            }

            let entryAddress = image.entryAddress + slide
            guard memory.permissions(at: entryAddress)?.contains(.execute) == true else {
                throw X64MachOFormatError(message: "Loaded LC_MAIN entry point is not executable in guest memory.")
            }
            _ = try memory.fetchBytes(at: entryAddress, maximumCount: 1)
        } catch {
            for base in reservedBases.reversed() {
                try? memory.release(at: base)
            }
            throw error
        }

        return X64MachOLoadedImage(
            sourceName: image.sourceName,
            entryAddress: image.entryAddress + slide,
            preferredLoadAddress: image.preferredLoadAddress,
            slide: slide,
            mappedSegments: mapped,
            committedBytes: totalCommitted,
            demandZeroBytes: totalDemandZeroBytes,
            rebaseFixupCount: image.rebaseFixupAddresses.count,
            rebasesApplied: rebasesApplied,
            unresolvedBindOpcodeBytes: image.bindOpcodeBytes + image.weakBindOpcodeBytes + image.lazyBindOpcodeBytes,
            unresolvedChainedFixupsBytes: image.chainedFixupsBytes,
            dependencies: image.dependencies,
            bindFixupCount: image.bindActions.count,
            weakBindFixupCount: image.weakBindActions.count,
            lazyBindFixupCount: image.lazyBindActions.count,
            boundFixupCount: boundFixupCount,
            unresolvedBindFixupCount: unresolvedBindSymbols.count,
            unresolvedBindSymbols: Array(Set(unresolvedBindSymbols)).sorted(),
            exports: image.exports
        )
    }

    static func unload(_ image: X64MachOLoadedImage, from memory: inout X64GuestVirtualMemory) throws {
        for segment in image.mappedSegments.reversed() {
            try memory.release(at: segment.guestAddress)
        }
    }
}


// MARK: - Dylib install-name path discovery

struct X64MachODependencyResolution {
    let dependency: X64MachODylibDependency
    let resolvedURL: URL?
}

enum X64MachODependencyPathResolver {
    /// Resolves install names against the main executable's LC_RPATH entries.
    /// This locates candidate files only; it does not map dylibs or process the
    /// dyld shared cache. The caller must still parse and load each dependency.
    static func resolveAll(
        in image: X64MachOImage,
        executableURL: URL,
        fileManager: FileManager = .default
    ) -> [X64MachODependencyResolution] {
        image.dependencies.map { dependency in
            X64MachODependencyResolution(
                dependency: dependency,
                resolvedURL: resolve(
                    dependency.installName,
                    rpaths: image.rpaths,
                    executableURL: executableURL,
                    loaderURL: executableURL,
                    fileManager: fileManager
                )
            )
        }
    }

    static func resolve(
        _ installName: String,
        rpaths: [String],
        executableURL: URL,
        loaderURL: URL,
        fileManager: FileManager = .default
    ) -> URL? {
        let executableDirectory = executableURL.deletingLastPathComponent().standardizedFileURL
        let loaderDirectory = loaderURL.deletingLastPathComponent().standardizedFileURL
        var candidates: [URL] = []

        func expand(_ value: String) -> String {
            value
                .replacingOccurrences(of: "@executable_path", with: executableDirectory.path)
                .replacingOccurrences(of: "@loader_path", with: loaderDirectory.path)
        }

        if installName.hasPrefix("@rpath/") {
            let suffix = String(installName.dropFirst("@rpath/".count))
            for rpath in rpaths {
                let expandedRPath = expand(rpath)
                candidates.append(URL(fileURLWithPath: expandedRPath).appendingPathComponent(suffix).standardizedFileURL)
            }
        } else if installName.hasPrefix("@executable_path/") || installName.hasPrefix("@loader_path/") {
            candidates.append(URL(fileURLWithPath: expand(installName)).standardizedFileURL)
        } else if installName.hasPrefix("/") {
            candidates.append(URL(fileURLWithPath: installName).standardizedFileURL)
        } else {
            candidates.append(executableDirectory.appendingPathComponent(installName).standardizedFileURL)
        }

        var seen = Set<String>()
        for candidate in candidates where seen.insert(candidate.path).inserted {
            var isDirectory: ObjCBool = false
            if fileManager.fileExists(atPath: candidate.path, isDirectory: &isDirectory), !isDirectory.boolValue {
                return candidate
            }
        }
        return nil
    }
}
