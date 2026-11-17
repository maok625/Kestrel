import Foundation

// MARK: - Translated block and cache

struct X64ARM64CompiledBlock: Sendable {
    let startAddress: UInt64
    let endAddress: UInt64
    let guestBytes: [UInt8]
    let instructions: [X64IRInstruction]
    let arm64Words: [UInt32]

    var instructionCount: Int { instructions.count }
    var byteCount: Int { guestBytes.count }
}

struct X64TranslationCacheStatistics: Sendable, Equatable {
    let hits: Int
    let misses: Int
    let compilations: Int
    let staleEntries: Int
    let evictions: Int
    let entryCount: Int
}

/// A small bounded LRU cache. Entries are validated against the actual guest
/// bytes every time they are looked up, so self-modifying code cannot silently
/// reuse a stale translation at a later dispatcher boundary.
struct X64ARM64TranslationCache {
    private var entries: [UInt64: X64ARM64CompiledBlock] = [:]
    /// Monotonic last-use stamp per entry. Hits are O(1); the least recently
    /// used entry is located only when an insertion actually overflows.
    private var lastUsed: [UInt64: UInt64] = [:]
    private var useClock: UInt64 = 0
    private let capacity: Int

    private(set) var hits = 0
    private(set) var misses = 0
    private(set) var compilations = 0
    private(set) var staleEntries = 0
    private(set) var evictions = 0

    init(capacity: Int = 256) {
        self.capacity = max(1, capacity)
    }

    var statistics: X64TranslationCacheStatistics {
        X64TranslationCacheStatistics(
            hits: hits,
            misses: misses,
            compilations: compilations,
            staleEntries: staleEntries,
            evictions: evictions,
            entryCount: entries.count
        )
    }

    mutating func block(
        at startAddress: UInt64,
        memory: X64GuestMemory,
        maximumInstructions: Int = 64,
        maximumBytes: Int = 256,
        stopAddress: UInt64? = nil
    ) throws -> X64ARM64CompiledBlock {
        guard maximumInstructions > 0, maximumBytes >= 15 else {
            throw X64ARM64DispatcherError.invalidLimits
        }

        // A halt RIP is a sentinel, not an upper bound on the guest address
        // space: CALL/JMP may legitimately transfer above it and later return.
        // Enforce the boundary only while decoding a sequential block that
        // begins below the sentinel.
        let linearStopAddress = stopAddress.flatMap { startAddress < $0 ? $0 : nil }
        if let cached = entries[startAddress],
           cached.instructionCount <= maximumInstructions,
           cached.byteCount <= maximumBytes,
           linearStopAddress.map({ cached.endAddress <= $0 }) ?? true {
            let currentBytes = try memory.readBytes(at: startAddress, maximumCount: cached.byteCount)
            if currentBytes == cached.guestBytes {
                hits += 1
                touch(startAddress)
                return cached
            }
            staleEntries += 1
            remove(startAddress)
        }

        misses += 1
        let compiled = try buildBlock(
            at: startAddress,
            memory: memory,
            maximumInstructions: maximumInstructions,
            maximumBytes: maximumBytes,
            stopAddress: linearStopAddress
        )
        compilations += 1
        insert(compiled)
        return compiled
    }

    /// Page-table-backed cache lookup. Instruction bytes are fetched with the
    /// guest execute permission, unlike the legacy test-memory overload.
    mutating func block(
        at startAddress: UInt64,
        memory: inout X64GuestVirtualMemory,
        maximumInstructions: Int = 64,
        maximumBytes: Int = 256,
        stopAddress: UInt64? = nil
    ) throws -> X64ARM64CompiledBlock {
        guard maximumInstructions > 0, maximumBytes >= 15 else {
            throw X64ARM64DispatcherError.invalidLimits
        }
        let linearStopAddress = stopAddress.flatMap { startAddress < $0 ? $0 : nil }
        if let cached = entries[startAddress],
           cached.instructionCount <= maximumInstructions,
           cached.byteCount <= maximumBytes,
           linearStopAddress.map({ cached.endAddress <= $0 }) ?? true {
            let currentBytes = try memory.fetchAvailableBytes(at: startAddress, maximumCount: cached.byteCount)
            if currentBytes.count == cached.guestBytes.count && currentBytes == cached.guestBytes {
                hits += 1
                touch(startAddress)
                return cached
            }
            staleEntries += 1
            remove(startAddress)
        }

        misses += 1
        let compiled = try buildBlock(
            at: startAddress,
            memory: &memory,
            maximumInstructions: maximumInstructions,
            maximumBytes: maximumBytes,
            stopAddress: linearStopAddress
        )
        compilations += 1
        insert(compiled)
        return compiled
    }

    /// Explicit invalidation is available to the future guest-memory manager.
    /// The dispatcher also detects changes by comparing code bytes at lookup.
    mutating func invalidate(addressRange: Range<UInt64>) {
        guard !addressRange.isEmpty else { return }
        let addresses = entries.compactMap { address, block -> UInt64? in
            let blockRange = block.startAddress..<block.endAddress
            return blockRange.overlaps(addressRange) ? address : nil
        }
        for address in addresses { remove(address) }
    }

    mutating func removeAll() {
        entries.removeAll(keepingCapacity: false)
        lastUsed.removeAll(keepingCapacity: false)
    }

    private mutating func insert(_ block: X64ARM64CompiledBlock) {
        remove(block.startAddress)
        entries[block.startAddress] = block
        touch(block.startAddress)
        while entries.count > capacity,
              let oldest = lastUsed.min(by: { $0.value < $1.value })?.key {
            remove(oldest)
            evictions += 1
        }
    }

    private mutating func touch(_ address: UInt64) {
        useClock &+= 1
        lastUsed[address] = useClock
    }

    private mutating func remove(_ address: UInt64) {
        entries.removeValue(forKey: address)
        lastUsed.removeValue(forKey: address)
    }

    private func buildBlock(
        at startAddress: UInt64,
        memory: X64GuestMemory,
        maximumInstructions: Int,
        maximumBytes: Int,
        stopAddress: UInt64?
    ) throws -> X64ARM64CompiledBlock {
        let decoder = X64InstructionDecoder()
        var cursor = startAddress
        var guestBytes: [UInt8] = []
        var instructions: [X64IRInstruction] = []

        while instructions.count < maximumInstructions {
            if let stopAddress {
                if cursor == stopAddress { break }
            }
            let instructionBytes = try memory.readBytes(at: cursor, maximumCount: 15)
            let decoded = try decoder.decode(instructionBytes, at: cursor)
            let ir = try decoded.lowerToIR()

            if let stopAddress, decoded.nextAddress > stopAddress {
                throw X64ARM64DispatcherError.haltAddressNotInstructionBoundary(
                    haltAddress: stopAddress, instructionAddress: cursor, instructionEnd: decoded.nextAddress
                )
            }

            if guestBytes.count + decoded.length > maximumBytes {
                if instructions.isEmpty {
                    throw X64ARM64DispatcherError.instructionExceedsBlockByteLimit(
                        address: cursor,
                        instructionBytes: decoded.length,
                        maximumBytes: maximumBytes
                    )
                }
                break
            }

            guestBytes.append(contentsOf: decoded.bytes)
            instructions.append(ir)
            cursor = decoded.nextAddress

            if Self.isControlFlowTerminator(ir.operation) || cursor == stopAddress { break }
        }

        guard !instructions.isEmpty else {
            throw X64ARM64DispatcherError.emptyBlock(address: startAddress)
        }

        let words = try X64ARM64Runtime.compile(instructions)
        return X64ARM64CompiledBlock(
            startAddress: startAddress,
            endAddress: cursor,
            guestBytes: guestBytes,
            instructions: instructions,
            arm64Words: words
        )
    }

    private func buildBlock(
        at startAddress: UInt64,
        memory: inout X64GuestVirtualMemory,
        maximumInstructions: Int,
        maximumBytes: Int,
        stopAddress: UInt64?
    ) throws -> X64ARM64CompiledBlock {
        let decoder = X64InstructionDecoder()
        var cursor = startAddress
        var guestBytes: [UInt8] = []
        var instructions: [X64IRInstruction] = []

        while instructions.count < maximumInstructions {
            if cursor == stopAddress { break }

            let instructionBytes: [UInt8]
            do {
                instructionBytes = try memory.fetchAvailableBytes(at: cursor, maximumCount: 15)
            } catch let fault as X64GuestVirtualMemoryFault {
                // Finish the already-decoded block. The dispatcher will retry
                // at this RIP and report the instruction-fetch fault there.
                if !instructions.isEmpty { break }
                throw fault
            }

            let decoded: X64DecodedInstruction
            do {
                decoded = try decoder.decode(instructionBytes, at: cursor)
            } catch let error as X64InstructionDecoderError {
                // A partial byte window caused by an inaccessible next page is
                // a guest execute fault, not a malformed x86 instruction.
                if case .truncated = error.kind, instructionBytes.count < 15 {
                    let missingByteAddress = cursor &+ UInt64(instructionBytes.count)
                    _ = try memory.fetchAvailableBytes(at: missingByteAddress, maximumCount: 1)
                }
                throw error
            }
            let ir = try decoded.lowerToIR()

            if let stopAddress, decoded.nextAddress > stopAddress {
                throw X64ARM64DispatcherError.haltAddressNotInstructionBoundary(
                    haltAddress: stopAddress,
                    instructionAddress: cursor,
                    instructionEnd: decoded.nextAddress
                )
            }
            if guestBytes.count + decoded.length > maximumBytes {
                if instructions.isEmpty {
                    throw X64ARM64DispatcherError.instructionExceedsBlockByteLimit(
                        address: cursor,
                        instructionBytes: decoded.length,
                        maximumBytes: maximumBytes
                    )
                }
                break
            }

            guestBytes.append(contentsOf: decoded.bytes)
            instructions.append(ir)
            cursor = decoded.nextAddress
            if Self.isControlFlowTerminator(ir.operation) || cursor == stopAddress { break }
        }

        guard !instructions.isEmpty else {
            throw X64ARM64DispatcherError.emptyBlock(address: startAddress)
        }
        let words = try X64ARM64Runtime.compile(instructions)
        return X64ARM64CompiledBlock(
            startAddress: startAddress,
            endAddress: cursor,
            guestBytes: guestBytes,
            instructions: instructions,
            arm64Words: words
        )
    }

    private static func isControlFlowTerminator(_ operation: X64IROperation) -> Bool {
        switch operation {
        case .returnFromFunction, .branchRelative, .callRelative, .callIndirect, .branchIndirect, .conditionalBranch, .systemCall:
            return true
        default:
            return false
        }
    }
}

// MARK: - Dispatcher

enum X64ARM64DispatchExit: Sendable, Equatable {
    case halted
    case processExit(status: Int32)
    case memoryFault(address: UInt64)
}

struct X64ARM64DispatchReport: Sendable {
    let instructionsExecuted: Int
    let blocksExecuted: Int
    let finalRIP: UInt64
    let exit: X64ARM64DispatchExit
    let cache: X64TranslationCacheStatistics
    let nativeMemoryFault: X64ARM64NativeMemoryFault?
    let faultingInstructionBytes: [UInt8]?

    init(
        instructionsExecuted: Int,
        blocksExecuted: Int,
        finalRIP: UInt64,
        exit: X64ARM64DispatchExit,
        cache: X64TranslationCacheStatistics,
        nativeMemoryFault: X64ARM64NativeMemoryFault? = nil,
        faultingInstructionBytes: [UInt8]? = nil
    ) {
        self.instructionsExecuted = instructionsExecuted
        self.blocksExecuted = blocksExecuted
        self.finalRIP = finalRIP
        self.exit = exit
        self.cache = cache
        self.nativeMemoryFault = nativeMemoryFault
        self.faultingInstructionBytes = faultingInstructionBytes
    }
}

enum X64ARM64DispatcherError: LocalizedError {
    case invalidLimits
    case systemCallRequiresSparseGuestVM
    case systemCallNotAllowed(rip: UInt64)
    case emptyBlock(address: UInt64)
    case haltAddressNotInstructionBoundary(haltAddress: UInt64, instructionAddress: UInt64, instructionEnd: UInt64)
    case instructionExceedsBlockByteLimit(address: UInt64, instructionBytes: Int, maximumBytes: Int)
    case instructionLimit(limit: Int, rip: UInt64)
    case blockLimit(limit: Int, rip: UInt64)

    var errorDescription: String? {
        switch self {
        case .invalidLimits:
            return "Dispatcher limits must be positive; maximum block bytes must be at least 15."
        case .systemCallRequiresSparseGuestVM:
            return "Darwin syscalls require the sparse guest virtual-memory dispatcher."
        case .systemCallNotAllowed(let rip):
            return String(format: "Guest syscall at return RIP 0x%016llX was rejected by isolated execution policy.", rip)
        case .emptyBlock(let address):
            return String(format: "The dispatcher could not construct a block at guest RIP 0x%016llX.", address)
        case .haltAddressNotInstructionBoundary(let haltAddress, let instructionAddress, let instructionEnd):
            return String(format: "Halt address 0x%016llX falls inside instruction 0x%016llX...0x%016llX.", haltAddress, instructionAddress, instructionEnd)
        case .instructionExceedsBlockByteLimit(let address, let instructionBytes, let maximumBytes):
            return String(format: "Instruction at 0x%016llX is %d byte(s), exceeding the block byte limit of %d.", address, instructionBytes, maximumBytes)
        case .instructionLimit(let limit, let rip):
            return String(format: "Guest instruction limit reached (%d) at RIP 0x%016llX.", limit, rip)
        case .blockLimit(let limit, let rip):
            return String(format: "Guest block-dispatch limit reached (%d) at RIP 0x%016llX.", limit, rip)
        }
    }
}

/// Executes one translated basic block at a time. Control-flow exits always
/// return to this Swift dispatcher, which selects the next block by guest RIP.
/// No guest instruction branches directly into a host-generated block.
struct X64ARM64BlockDispatcher {
    private(set) var cache: X64ARM64TranslationCache
    private let maximumInstructionsPerBlock: Int
    private let maximumBytesPerBlock: Int

    init(
        cacheCapacity: Int = 256,
        maximumInstructionsPerBlock: Int = 64,
        maximumBytesPerBlock: Int = 256
    ) {
        cache = X64ARM64TranslationCache(capacity: cacheCapacity)
        self.maximumInstructionsPerBlock = max(1, maximumInstructionsPerBlock)
        self.maximumBytesPerBlock = max(15, maximumBytesPerBlock)
    }

    mutating func invalidateGuestCode(at address: UInt64, byteCount: Int) {
        guard byteCount > 0, UInt64(byteCount) <= UInt64.max - address else { return }
        cache.invalidate(addressRange: address..<(address + UInt64(byteCount)))
    }

    mutating func invalidateAllTranslations() {
        cache.removeAll()
    }

    mutating func run(
        state: inout X64CPUState,
        memory: inout X64GuestMemory,
        until haltAddress: UInt64,
        maximumInstructions: Int = 100_000,
        maximumBlocks: Int = 100_000
    ) throws -> X64ARM64DispatchReport {
        guard maximumInstructions > 0, maximumBlocks > 0 else {
            throw X64ARM64DispatcherError.invalidLimits
        }

        var instructionsExecuted = 0
        var blocksExecuted = 0

        while state.rip != haltAddress {
            guard instructionsExecuted < maximumInstructions else {
                throw X64ARM64DispatcherError.instructionLimit(limit: maximumInstructions, rip: state.rip)
            }
            guard blocksExecuted < maximumBlocks else {
                throw X64ARM64DispatcherError.blockLimit(limit: maximumBlocks, rip: state.rip)
            }

            let remainingBudget = maximumInstructions - instructionsExecuted
            let block = try cache.block(
                at: state.rip,
                memory: memory,
                maximumInstructions: min(maximumInstructionsPerBlock, remainingBudget),
                maximumBytes: maximumBytesPerBlock,
                stopAddress: haltAddress
            )
            let nativeResult = try X64ARM64Runtime.execute(
                arm64Words: block.arm64Words,
                state: &state,
                memory: &memory
            )
            blocksExecuted += 1

            switch nativeResult.exit {
            case .completed, .controlFlow:
                // The native block has committed the next guest RIP. Every IR
                // instruction in this basic block completed successfully.
                instructionsExecuted += block.instructionCount
                continue
            case .systemCall:
                throw X64ARM64DispatcherError.systemCallRequiresSparseGuestVM
            case .missingPageFault:
                // The contiguous compatibility fixture is always eagerly
                // committed when adapted to the sparse VM, so this exit is
                // not expected from its execution path.
                instructionsExecuted += block.instructions.prefix { $0.address < state.rip }.count
                return X64ARM64DispatchReport(
                    instructionsExecuted: instructionsExecuted,
                    blocksExecuted: blocksExecuted,
                    finalRIP: state.rip,
                    exit: .memoryFault(address: state.rip),
                    cache: cache.statistics,
                    nativeMemoryFault: nativeResult.nativeMemoryFault,
                    faultingInstructionBytes: faultingInstructionBytes(in: block, at: state.rip)
                )
            case .memoryFault:
                // On a data fault, codegen leaves RIP at the faulting guest
                // instruction. Count only the preceding linear instructions.
                instructionsExecuted += block.instructions.prefix { $0.address < state.rip }.count
                return X64ARM64DispatchReport(
                    instructionsExecuted: instructionsExecuted,
                    blocksExecuted: blocksExecuted,
                    finalRIP: state.rip,
                    exit: .memoryFault(address: state.rip),
                    cache: cache.statistics,
                    nativeMemoryFault: nativeResult.nativeMemoryFault,
                    faultingInstructionBytes: faultingInstructionBytes(in: block, at: state.rip)
                )
            }
        }

        return X64ARM64DispatchReport(
            instructionsExecuted: instructionsExecuted,
            blocksExecuted: blocksExecuted,
            finalRIP: state.rip,
            exit: .halted,
            cache: cache.statistics
        )
    }


    private func faultingInstructionBytes(
        in block: X64ARM64CompiledBlock,
        at address: UInt64
    ) -> [UInt8]? {
        guard address >= block.startAddress, address < block.endAddress else { return nil }
        let nextAddress = block.instructions.first(where: { $0.address > address })?.address ?? block.endAddress
        guard nextAddress > address else { return nil }
        let startOffset = Int(address - block.startAddress)
        let byteCount = Int(nextAddress - address)
        let endOffset = startOffset + byteCount
        guard startOffset >= 0, endOffset <= block.guestBytes.count else { return nil }
        return Array(block.guestBytes[startOffset..<endOffset])
    }

    /// Executes with the sparse page-based guest VM. Each instruction fetch
    /// requires X permission, and each translated data access is checked by
    /// the C/JIT page-table helpers against R/W permissions.
    mutating func run(
        state: inout X64CPUState,
        memory: inout X64GuestVirtualMemory,
        until haltAddress: UInt64,
        maximumInstructions: Int = 100_000,
        maximumBlocks: Int = 100_000,
        syscallHost: any X64DarwinSyscallHost = X64ConsoleDarwinSyscallHost(),
        hostThunks: X64DarwinHostThunkTable? = nil,
        allowSystemCalls: Bool = true
    ) throws -> X64ARM64DispatchReport {
        guard maximumInstructions > 0, maximumBlocks > 0 else {
            throw X64ARM64DispatcherError.invalidLimits
        }
        var instructionsExecuted = 0
        var blocksExecuted = 0

        while state.rip != haltAddress {
            guard instructionsExecuted < maximumInstructions else {
                throw X64ARM64DispatcherError.instructionLimit(limit: maximumInstructions, rip: state.rip)
            }
            guard blocksExecuted < maximumBlocks else {
                throw X64ARM64DispatcherError.blockLimit(limit: maximumBlocks, rip: state.rip)
            }
            if let hostThunks, let symbol = hostThunks.symbol(at: state.rip) {
                let disposition = try X64DarwinHostThunkDispatcher.invoke(
                    symbol: symbol,
                    state: &state,
                    memory: &memory,
                    host: syscallHost
                )
                blocksExecuted += 1
                instructionsExecuted += 1
                if case .processExit(let status) = disposition {
                    return X64ARM64DispatchReport(
                        instructionsExecuted: instructionsExecuted,
                        blocksExecuted: blocksExecuted,
                        finalRIP: state.rip,
                        exit: .processExit(status: status),
                        cache: cache.statistics
                    )
                }
                continue
            }
            let remainingBudget = maximumInstructions - instructionsExecuted
            let block = try cache.block(
                at: state.rip,
                memory: &memory,
                maximumInstructions: min(maximumInstructionsPerBlock, remainingBudget),
                maximumBytes: maximumBytesPerBlock,
                stopAddress: haltAddress
            )
            let nativeResult = try X64ARM64Runtime.execute(
                arm64Words: block.arm64Words,
                state: &state,
                memory: &memory
            )
            blocksExecuted += 1
            switch nativeResult.exit {
            case .completed, .controlFlow:
                instructionsExecuted += block.instructionCount
            case .systemCall:
                instructionsExecuted += block.instructionCount
                guard allowSystemCalls else {
                    throw X64ARM64DispatcherError.systemCallNotAllowed(rip: state.rip)
                }
                // x86-64 SYSCALL saves the next guest RIP in RCX and the
                // pre-entry RFLAGS image in R11. The Darwin syscall shim
                // then writes the syscall result to RAX and uses CF for error.
                let syscallReturnRIP = state.rip
                let savedFlags = state.rflags
                try state.writeRegister(.rcx, value: syscallReturnRIP, width: .qword)
                try state.writeRegister(.r11, value: savedFlags, width: .qword)
                let disposition = try X64DarwinSyscallDispatcher.dispatch(
                    state: &state,
                    memory: &memory,
                    host: syscallHost
                )
                if case .processExit(let status) = disposition {
                    return X64ARM64DispatchReport(
                        instructionsExecuted: instructionsExecuted,
                        blocksExecuted: blocksExecuted,
                        finalRIP: state.rip,
                        exit: .processExit(status: status),
                        cache: cache.statistics
                    )
                }
            case .missingPageFault(let address, let access):
                // Earlier instructions in this block completed and committed
                // their guest state. The faulting instruction kept RIP, so
                // resolve exactly one demand-zero or cache-backed page and retry from that instruction.
                instructionsExecuted += block.instructions.prefix { $0.address < state.rip }.count
                if try memory.resolveDemandZeroPage(at: address, access: access) {
                    continue
                }
                return X64ARM64DispatchReport(
                    instructionsExecuted: instructionsExecuted,
                    blocksExecuted: blocksExecuted,
                    finalRIP: state.rip,
                    exit: .memoryFault(address: state.rip),
                    cache: cache.statistics,
                    nativeMemoryFault: nativeResult.nativeMemoryFault,
                    faultingInstructionBytes: faultingInstructionBytes(in: block, at: state.rip)
                )
            case .memoryFault:
                instructionsExecuted += block.instructions.prefix { $0.address < state.rip }.count
                return X64ARM64DispatchReport(
                    instructionsExecuted: instructionsExecuted,
                    blocksExecuted: blocksExecuted,
                    finalRIP: state.rip,
                    exit: .memoryFault(address: state.rip),
                    cache: cache.statistics,
                    nativeMemoryFault: nativeResult.nativeMemoryFault,
                    faultingInstructionBytes: faultingInstructionBytes(in: block, at: state.rip)
                )
            }
        }
        return X64ARM64DispatchReport(
            instructionsExecuted: instructionsExecuted,
            blocksExecuted: blocksExecuted,
            finalRIP: state.rip,
            exit: .halted,
            cache: cache.statistics
        )
    }
}
