import Foundation

enum X64ARM64DispatcherSelfTests {
    enum TestError: LocalizedError {
        case failed(String)

        var errorDescription: String? {
            switch self {
            case .failed(let message): return message
            }
        }
    }

    private static let guestBase: UInt64 = 0x0000_0001_0000_0000
    private static let memorySize = 0x2000
    private static let haltAddress = guestBase + 19

    static func run() throws -> [String] {
        var passed: [String] = []
        try verifyTakenBranchAcrossBlocks()
        passed.append("Jcc terminates a basic block and dispatcher resumes at the taken guest target")

        try verifyFallthroughBranchAcrossBlocks()
        passed.append("Jcc not-taken path redispatches at the sequential guest RIP")

        try verifyCallAndReturnRedispatch()
        passed.append("CALL enters a guest function and RET returns through the dispatcher using guest stack memory")

        try verifyTranslationCacheReuse()
        passed.append("Translated basic blocks are reused from the bounded cache on subsequent runs")

        try verifySelfModifyingCodeInvalidation()
        passed.append("Changed guest code invalidates the stale block translation before execution")

        try verifyLoopInstructionLimit()
        passed.append("A guest loop redispatches through the cached block and stops at the instruction budget")

        try verifyMemoryFaultStopsDispatch()
        passed.append("Native guest-memory fault is surfaced to the dispatcher without advancing faulting RIP")

        try verifyIsolatedResolverReturn()
        passed.append("Isolated resolver probe executes a bounded guest function and captures its RAX return value")

        try verifyIsolatedResolverWriteProtection()
        passed.append("Isolated resolver probe rejects writes to shared guest pages without changing source memory")

        try verifyIsolatedResolverSyscallRejection()
        passed.append("Isolated resolver probe rejects guest syscalls before any host syscall or thunk is invoked")

        try verifyBlockCacheCapacity()
        passed.append("Translation cache enforces its configured entry capacity with LRU eviction")
        return passed
    }

    private static func verifyTakenBranchAcrossBlocks() throws {
        var memory = try makeBranchProgram()
        var state = X64CPUState(rip: guestBase, rflags: 0x202)
        var dispatcher = X64ARM64BlockDispatcher(cacheCapacity: 8)

        let report = try dispatcher.run(
            state: &state,
            memory: &memory,
            until: haltAddress,
            maximumInstructions: 32,
            maximumBlocks: 16
        )

        guard report.exit == .halted,
              report.finalRIP == haltAddress,
              report.blocksExecuted == 2,
              report.instructionsExecuted == 4 else {
            throw TestError.failed("taken-branch program expected 4 instructions across 2 blocks; got \(report.instructionsExecuted) instructions, \(report.blocksExecuted) blocks, exit \(report.exit)")
        }
        guard try state.readRegister(.rax, width: .dword) == 2,
              try state.readRegister(.rbx, width: .dword) == 7 else {
            throw TestError.failed("taken branch did not skip MOV EAX,99 and execute MOV EBX,7")
        }
    }


    private static func verifyFallthroughBranchAcrossBlocks() throws {
        var memory = try X64GuestMemory(baseAddress: guestBase, size: memorySize)
        let program: [UInt8] = [
            0xB8, 0x02, 0x00, 0x00, 0x00, // mov eax, 2
            0x83, 0xF8, 0x01,             // cmp eax, 1
            0x74, 0x05,                   // jz +5 (not taken)
            0xB8, 0x63, 0x00, 0x00, 0x00, // mov eax, 99
            0xBB, 0x07, 0x00, 0x00, 0x00  // mov ebx, 7
        ]
        let halt = guestBase + UInt64(program.count)
        try memory.writeBytes(program, at: guestBase)
        var state = X64CPUState(rip: guestBase, rflags: 0x202)
        var dispatcher = X64ARM64BlockDispatcher(cacheCapacity: 8)
        let report = try dispatcher.run(state: &state, memory: &memory, until: halt)

        guard report.exit == .halted, report.blocksExecuted == 2, report.instructionsExecuted == 5,
              try state.readRegister(.rax, width: .dword) == 99,
              try state.readRegister(.rbx, width: .dword) == 7 else {
            throw TestError.failed("Jcc fallthrough did not execute the sequential block correctly")
        }
    }

    private static func verifyCallAndReturnRedispatch() throws {
        var memory = try X64GuestMemory(baseAddress: guestBase, size: memorySize)
        // CALL rel32 from +0 to +6. The return address (+5) is the halt point.
        let program: [UInt8] = [
            0xE8, 0x01, 0x00, 0x00, 0x00, // call +1 -> guest function at +6
            0x90,                         // return address / halt point (+5)
            0xB8, 0x2A, 0x00, 0x00, 0x00, // function: mov eax, 42
            0xC3                          // ret
        ]
        try memory.writeBytes(program, at: guestBase)
        let stackTop = guestBase + 0x1000
        var state = X64CPUState(rip: guestBase, rflags: 0x202)
        try state.writeRegister(.rsp, value: stackTop, width: .qword)
        var dispatcher = X64ARM64BlockDispatcher(cacheCapacity: 8)
        let report = try dispatcher.run(state: &state, memory: &memory, until: guestBase + 5)

        guard report.exit == .halted, report.blocksExecuted == 2, report.instructionsExecuted == 3,
              try state.readRegister(.rax, width: .dword) == 42,
              try state.readRegister(.rsp, width: .qword) == stackTop,
              try memory.readUnsigned(at: stackTop - 8, width: .qword) == guestBase + 5 else {
            throw TestError.failed("CALL/RET did not round-trip the guest return address and stack pointer")
        }
    }

    private static func verifyTranslationCacheReuse() throws {
        var memory = try makeBranchProgram()
        var dispatcher = X64ARM64BlockDispatcher(cacheCapacity: 8)

        var firstState = X64CPUState(rip: guestBase, rflags: 0x202)
        _ = try dispatcher.run(state: &firstState, memory: &memory, until: haltAddress)
        let firstStats = dispatcher.cache.statistics
        guard firstStats.compilations == 2, firstStats.misses == 2 else {
            throw TestError.failed("first run expected 2 compilations/2 misses, got \(firstStats.compilations)/\(firstStats.misses)")
        }

        var secondState = X64CPUState(rip: guestBase, rflags: 0x202)
        _ = try dispatcher.run(state: &secondState, memory: &memory, until: haltAddress)
        let secondStats = dispatcher.cache.statistics
        guard secondStats.hits >= 2, secondStats.compilations == 2 else {
            throw TestError.failed("second run did not reuse both cached blocks (hits=\(secondStats.hits), compilations=\(secondStats.compilations))")
        }
    }

    private static func verifySelfModifyingCodeInvalidation() throws {
        var memory = try makeBranchProgram()
        var dispatcher = X64ARM64BlockDispatcher(cacheCapacity: 8)

        var firstState = X64CPUState(rip: guestBase, rflags: 0x202)
        _ = try dispatcher.run(state: &firstState, memory: &memory, until: haltAddress)

        // Change MOV EAX,2 to MOV EAX,3 without changing instruction length.
        try memory.writeBytes([0xB8, 0x03, 0x00, 0x00, 0x00], at: guestBase)
        var secondState = X64CPUState(rip: guestBase, rflags: 0x202)
        _ = try dispatcher.run(state: &secondState, memory: &memory, until: haltAddress)

        guard try secondState.readRegister(.rax, width: .dword) == 3 else {
            throw TestError.failed("dispatcher executed stale code after guest bytes changed")
        }
        guard dispatcher.cache.statistics.staleEntries == 1 else {
            throw TestError.failed("expected one stale block rejection, got \(dispatcher.cache.statistics.staleEntries)")
        }
    }

    private static func verifyLoopInstructionLimit() throws {
        var memory = try X64GuestMemory(baseAddress: guestBase, size: memorySize)
        try memory.writeBytes([0xEB, 0xFE], at: guestBase) // JMP to itself
        var state = X64CPUState(rip: guestBase)
        var dispatcher = X64ARM64BlockDispatcher(cacheCapacity: 4)

        do {
            _ = try dispatcher.run(
                state: &state,
                memory: &memory,
                until: guestBase + 0x100,
                maximumInstructions: 5,
                maximumBlocks: 20
            )
            throw TestError.failed("infinite guest loop did not stop at the instruction budget")
        } catch X64ARM64DispatcherError.instructionLimit(let limit, let rip) {
            guard limit == 5, rip == guestBase, dispatcher.cache.statistics.hits >= 4 else {
                throw TestError.failed("loop budget stopped at unexpected state (limit=\(limit), RIP=0x\(String(rip, radix: 16)))")
            }
        }
    }


    private static func verifyMemoryFaultStopsDispatch() throws {
        var memory = try X64GuestMemory(baseAddress: guestBase, size: memorySize)
        try memory.writeBytes([0x48, 0x8B, 0x03], at: guestBase) // mov rax, [rbx]
        var state = X64CPUState(rip: guestBase)
        try state.writeRegister(.rbx, value: guestBase + UInt64(memorySize - 4), width: .qword)
        var dispatcher = X64ARM64BlockDispatcher(cacheCapacity: 4)
        let report = try dispatcher.run(state: &state, memory: &memory, until: guestBase + 3)

        guard report.exit == .memoryFault(address: guestBase),
              report.finalRIP == guestBase, report.instructionsExecuted == 0,
              state.rip == guestBase else {
            throw TestError.failed("memory fault should stop dispatch at the faulting guest instruction")
        }
    }

    private static func verifyIsolatedResolverReturn() throws {
        let memory = try makeExecutableVirtualMemory(
            code: [
                0xB8, 0x2A, 0x00, 0x00, 0x00, // mov eax, 42
                0xC3                          // ret
            ]
        )
        var session = try X64DyldLazyResolverProbeSession(sourceMemory: memory)
        let result = session.probe(address: guestBase)

        guard result.status == .returned,
              result.returnedAddress == 42,
              result.instructionsExecuted == 2,
              result.returnedAddressIsMappedExecutable == false else {
            throw TestError.failed("isolated resolver return expected RAX=42; got status=\(result.status.rawValue), RAX=\(String(describing: result.returnedAddress))")
        }
        guard memory.permissions(at: guestBase)?.contains(.execute) == true else {
            throw TestError.failed("isolated resolver probe changed source code permissions")
        }
    }

    private static func verifyIsolatedResolverWriteProtection() throws {
        var memory = try makeExecutableVirtualMemory(code: [
            0x48, 0x89, 0x07, // mov [rdi], rax
            0xC3              // ret
        ])
        let dataAddress = guestBase + 0x2000
        try memory.reserve(at: dataAddress, byteCount: 0x1000, kind: .anonymous)
        try memory.commit(at: dataAddress, byteCount: 0x1000, permissions: .readWrite)
        let originalValue: UInt64 = 0x1122_3344_5566_7788
        try memory.writeUnsigned(originalValue, at: dataAddress, byteCount: 8)

        var session = try X64DyldLazyResolverProbeSession(sourceMemory: memory)
        let result = session.probe(address: guestBase, rdi: dataAddress)

        guard result.status == .memoryFault else {
            throw TestError.failed("isolated resolver write should fault, got status=\(result.status.rawValue)")
        }
        guard try memory.readUnsigned(at: dataAddress, byteCount: 8) == originalValue,
              memory.permissions(at: dataAddress)?.contains(.write) == true else {
            throw TestError.failed("isolated resolver write changed source data or its permissions")
        }
    }

    private static func verifyIsolatedResolverSyscallRejection() throws {
        let memory = try makeExecutableVirtualMemory(code: [
            0x0F, 0x05, // syscall
            0xC3        // ret (must not be reached)
        ])
        var session = try X64DyldLazyResolverProbeSession(sourceMemory: memory)
        let result = session.probe(address: guestBase)

        guard result.status == .systemCallBlocked else {
            throw TestError.failed("isolated resolver syscall should be rejected, got status=\(result.status.rawValue)")
        }
    }

    private static func makeExecutableVirtualMemory(code: [UInt8]) throws -> X64GuestVirtualMemory {
        var memory = try X64GuestVirtualMemory()
        try memory.reserve(at: guestBase, byteCount: 0x1000, kind: .image)
        try memory.commit(at: guestBase, byteCount: 0x1000, permissions: .readWrite)
        try memory.writeBytes(code, at: guestBase)
        try memory.protect(at: guestBase, byteCount: 0x1000, permissions: .readExecute)
        return memory
    }

    private static func verifyBlockCacheCapacity() throws {
        var memory = try X64GuestMemory(baseAddress: guestBase, size: memorySize)
        // Three independent NOP blocks followed by RET terminators. Each block
        // is requested through the cache directly to exercise LRU eviction.
        try memory.writeBytes([0x90, 0xC3, 0x90, 0xC3, 0x90, 0xC3], at: guestBase)
        var cache = X64ARM64TranslationCache(capacity: 2)

        // Cache lookup accepts X64GuestMemory by value (read-only); unlike the
        // dispatcher execution API, this call does not take an inout argument.
        _ = try cache.block(at: guestBase, memory: memory)
        _ = try cache.block(at: guestBase + 2, memory: memory)
        _ = try cache.block(at: guestBase + 4, memory: memory)
        guard cache.statistics.entryCount == 2,
              cache.statistics.evictions == 1 else {
            throw TestError.failed("cache capacity 2 should evict one of three blocks")
        }
    }

    private static func makeBranchProgram() throws -> X64GuestMemory {
        var memory = try X64GuestMemory(baseAddress: guestBase, size: memorySize)
        let program: [UInt8] = [
            0xB8, 0x02, 0x00, 0x00, 0x00, // mov eax, 2
            0x39, 0xC0,                   // cmp eax, eax
            0x74, 0x05,                   // jz +5 -> offset 14
            0xB8, 0x63, 0x00, 0x00, 0x00, // mov eax, 99 (skipped)
            0xBB, 0x07, 0x00, 0x00, 0x00  // mov ebx, 7
        ]
        try memory.writeBytes(program, at: guestBase)
        return memory
    }
}
