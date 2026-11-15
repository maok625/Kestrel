import Foundation

/// Result returned by a translated guest block. A control-flow exit is normal:
/// the dispatcher should continue at the updated guest RIP. A memory fault is
/// deterministic and leaves the faulting instruction's RIP available in state.
enum X64ARM64BlockExit: Equatable, Sendable {
    case completed
    case controlFlow
    case systemCall
    case memoryFault
    case demandZeroFault(address: UInt64, access: X64GuestMemoryAccess)
}

struct X64ARM64BlockResult {
    let arm64Words: [UInt32]
    let exit: X64ARM64BlockExit
}

/// Bridges Swift guest CPU/memory state to the C MAP_JIT executor. The guest
/// context remains 18 UInt64 words; guest memory is exposed as a pinned sparse
/// page table whose entries carry independent host backing and page permissions.
enum X64ARM64Runtime {
    enum RuntimeError: LocalizedError {
        case executionFailed(Int32)
        case invalidBlockResult(Int32)
        case stateMismatch(String)

        var errorDescription: String? {
            switch self {
            case .executionFailed(let code):
                return "Native AArch64 block execution failed with error code \(code)."
            case .invalidBlockResult(let code):
                return "Native AArch64 block returned an invalid exit reason \(code)."
            case .stateMismatch(let detail):
                return "Native x86_64/AArch64 differential mismatch: \(detail)"
            }
        }
    }

    static func compile(_ instructions: [X64IRInstruction]) throws -> [UInt32] {
        let flagHelperAddress = UInt64(kestrel_x64_flag_helper_address())
        let readHelperAddress = UInt64(kestrel_guest_memory_read_helper_address())
        let writeHelperAddress = UInt64(kestrel_guest_memory_write_helper_address())
        let faultOffset = UInt32(kestrel_guest_memory_fault_offset())
        return try X64ARM64CodeGenerator.compile(
            instructions,
            flagHelperAddress: flagHelperAddress,
            guestMemoryReadHelperAddress: readHelperAddress,
            guestMemoryWriteHelperAddress: writeHelperAddress,
            guestMemoryFaultOffset: faultOffset
        )
    }

    static func execute(
        _ instructions: [X64IRInstruction],
        state: inout X64CPUState,
        memory: inout X64GuestVirtualMemory
    ) throws -> X64ARM64BlockResult {
        let words = try compile(instructions)
        return try execute(arm64Words: words, state: &state, memory: &memory)
    }

    static func execute(
        _ instructions: [X64IRInstruction],
        state: inout X64CPUState,
        memory: inout X64GuestMemory
    ) throws -> X64ARM64BlockResult {
        // Compatibility adapter for the existing differential fixture. The
        // native JIT itself now always uses the sparse page-table ABI.
        let pageSize = X64GuestVirtualMemoryConstants.pageSize
        guard UInt64(memory.byteCount) <= UInt64.max - memory.baseAddress else {
            throw RuntimeError.stateMismatch("legacy fixture address range overflows")
        }
        let legacyEnd = memory.baseAddress + UInt64(memory.byteCount)
        let mappedBase = memory.baseAddress & ~(pageSize - 1)
        let remainder = legacyEnd % pageSize
        let roundUp = remainder == 0 ? UInt64(0) : pageSize - remainder
        guard legacyEnd <= UInt64.max - roundUp else {
            throw RuntimeError.stateMismatch("legacy fixture page-aligned range overflows")
        }
        let mappedEnd = legacyEnd + roundUp
        guard mappedEnd > mappedBase else {
            throw RuntimeError.stateMismatch("legacy fixture range could not be represented as guest pages")
        }

        var guestVM = try X64GuestVirtualMemory()
        let mappedSize = mappedEnd - mappedBase
        try guestVM.reserve(at: mappedBase, byteCount: mappedSize, kind: .anonymous)
        try guestVM.commit(at: mappedBase, byteCount: mappedSize, permissions: .readWriteExecute)
        try guestVM.writeBytes(memory.bytes, at: memory.baseAddress)

        let result = try execute(instructions, state: &state, memory: &guestVM)
        let updatedBytes = try guestVM.readBytes(at: memory.baseAddress, count: memory.byteCount)
        try memory.writeBytes(updatedBytes, at: memory.baseAddress)
        return result
    }

    /// Executes an already compiled block against the sparse multi-region
    /// virtual-memory manager. Page backing pointers remain pinned for the
    /// complete C/JIT call; the C helpers perform per-page permission checks.
    static func execute(
        arm64Words words: [UInt32],
        state: inout X64CPUState,
        memory: inout X64GuestVirtualMemory
    ) throws -> X64ARM64BlockResult {
        guard !words.isEmpty else {
            throw RuntimeError.stateMismatch("attempted to execute an empty translated block")
        }
        var context = makeContext(from: state)
        var blockResult: Int32 = -1
        var faultAddress: UInt64 = 0
        var faultPermission: UInt8 = 0
        let status = words.withUnsafeBufferPointer { codeBuffer in
            context.withUnsafeMutableBufferPointer { contextBuffer in
                memory.withNativePageTable { pageBases, hostPages, permissions, generations, nativeWriteCount in
                    kestrel_jit_execute_block_with_pages(
                        codeBuffer.baseAddress,
                        codeBuffer.count,
                        contextBuffer.baseAddress,
                        pageBases.baseAddress,
                        hostPages.baseAddress,
                        permissions.baseAddress,
                        generations.baseAddress,
                        pageBases.count,
                        nativeWriteCount,
                        &faultAddress,
                        &faultPermission,
                        &blockResult
                    )
                }
            }
        }
        guard status == 0 else {
            throw RuntimeError.executionFailed(status)
        }
        restore(context, into: &state)

        let exit: X64ARM64BlockExit
        switch blockResult {
        case 0: exit = .completed
        case 1: exit = .controlFlow
        case 2: exit = .memoryFault
        case 4: exit = .systemCall
        case 3:
            let access: X64GuestMemoryAccess
            switch faultPermission {
            case 0x01: access = .read
            case 0x02: access = .write
            case 0x04: access = .execute
            default: exit = .memoryFault; return X64ARM64BlockResult(arm64Words: words, exit: exit)
            }
            exit = .demandZeroFault(address: faultAddress, access: access)
        default: throw RuntimeError.invalidBlockResult(blockResult)
        }
        return X64ARM64BlockResult(arm64Words: words, exit: exit)
    }

    /// Legacy compiled-word adapter. This exists only for tests and older
    /// dispatcher fixtures; translated code still executes through the page table.
    static func execute(
        arm64Words words: [UInt32],
        state: inout X64CPUState,
        memory: inout X64GuestMemory
    ) throws -> X64ARM64BlockResult {
        let pageSize = X64GuestVirtualMemoryConstants.pageSize
        guard UInt64(memory.byteCount) <= UInt64.max - memory.baseAddress else {
            throw RuntimeError.stateMismatch("legacy fixture address range overflows")
        }
        let legacyEnd = memory.baseAddress + UInt64(memory.byteCount)
        let mappedBase = memory.baseAddress & ~(pageSize - 1)
        let remainder = legacyEnd % pageSize
        let roundUp = remainder == 0 ? UInt64(0) : pageSize - remainder
        guard legacyEnd <= UInt64.max - roundUp else {
            throw RuntimeError.stateMismatch("legacy fixture page-aligned range overflows")
        }
        let mappedEnd = legacyEnd + roundUp
        guard mappedEnd > mappedBase else {
            throw RuntimeError.stateMismatch("legacy fixture range could not be represented as guest pages")
        }
        var guestVM = try X64GuestVirtualMemory()
        let mappedSize = mappedEnd - mappedBase
        try guestVM.reserve(at: mappedBase, byteCount: mappedSize, kind: .anonymous)
        try guestVM.commit(at: mappedBase, byteCount: mappedSize, permissions: .readWriteExecute)
        try guestVM.writeBytes(memory.bytes, at: memory.baseAddress)
        let result = try execute(arm64Words: words, state: &state, memory: &guestVM)
        let updatedBytes = try guestVM.readBytes(at: memory.baseAddress, count: memory.byteCount)
        try memory.writeBytes(updatedBytes, at: memory.baseAddress)
        return result
    }

    static func makeContext(from state: X64CPUState) -> [UInt64] {
        var context = Array(repeating: UInt64(0), count: 18)
        for register in X64GeneralRegister.allCases {
            context[register.rawValue] = state.registerValue(register)
        }
        context[16] = state.rip
        context[17] = state.rflags
        return context
    }

    static func restore(_ context: [UInt64], into state: inout X64CPUState) {
        guard context.count >= 18 else { return }
        for register in X64GeneralRegister.allCases {
            try? state.writeRegister(register, value: context[register.rawValue], width: .qword)
        }
        state.rip = context[16]
        state.restoreRFLAGS(context[17])
    }
}
