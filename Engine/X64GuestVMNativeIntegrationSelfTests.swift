import Foundation

/// End-to-end checks for the sparse guest VM -> native page-table ABI -> MAP_JIT
/// helper path. These tests must run on Apple Silicon because they execute the
/// generated AArch64 blocks through Apple's MAP_JIT implementation.
enum X64GuestVMNativeIntegrationSelfTests {
    private final class MockDarwinHost: X64DarwinSyscallHost {
        let processIdentifier: UInt32 = 9876
        var output: [UInt8] = []
        var input: [UInt8] = [0x41, 0x42]

        func read(fileDescriptor: Int32, maximumCount: Int) throws -> [UInt8] {
            guard fileDescriptor == 0 else { throw X64DarwinSyscallHostError(errno: 9) }
            let count = min(maximumCount, input.count)
            let bytes = Array(input.prefix(count))
            input.removeFirst(count)
            return bytes
        }

        func write(fileDescriptor: Int32, bytes: [UInt8]) throws -> Int {
            guard fileDescriptor == 1 || fileDescriptor == 2 else {
                throw X64DarwinSyscallHostError(errno: 9)
            }
            output.append(contentsOf: bytes)
            return bytes.count
        }
    }

    private static let page = X64GuestVirtualMemoryConstants.pageSize
    private static let codeBase: UInt64 = 0x0000_0001_0000_0000
    private static let sourceBase: UInt64 = 0x0000_0002_0000_0000
    private static let destinationBase: UInt64 = 0x0000_0004_0000_0000
    private static let stackBase: UInt64 = 0x0000_0006_0000_0000
    private static let haltAddress: UInt64 = 0x0000_0007_0000_0000

    static func run() throws -> [String] {
        var passed: [String] = []
        try verifyNativeMemoryAcrossIndependentRegionsAndStack()
        passed.append("Native JIT reads and writes pages in widely separated guest regions and RET uses a separate guest stack page")

        try verifyCrossPageWriteIsAtomicAcrossReservations()
        passed.append("Native cross-page stores prevalidate permissions across adjacent independent reservations before modifying either page")

        try verifyExecutePermissionOnInstructionFetch()
        passed.append("Guest instruction fetch is rejected when the code page lacks execute permission")

        try verifyNativeCrossPageReadAcrossAdjacentRegions()
        passed.append("Native little-endian loads cross adjacent reservations using separate host page backing")

        try verifyCallReturnAcrossGuestStack()
        passed.append("Native CALL/RET uses page-table-backed guest stack memory and returns through the multi-region dispatcher")

        try verifyBlockBuilderStopsAtExecutableRegionBoundary()
        passed.append("Block construction completes valid instructions at an executable-region boundary and leaves the next RIP for dispatcher fault handling")

        try verifyNativeDemandZeroDataPageRetry()
        passed.append("Native data-page faults materialize one demand-zero BSS page and retry the faulting instruction without losing guest state")

        try verifyTranslatedDarwinSyscallBoundary()
        passed.append("Translated SYSCALL exits to the Darwin dispatcher, saves RCX/R11, and returns process-exit status")

        try verifyImportedDarwinWriteThunk()
        passed.append("Imported _write guest thunk marshals x86_64 arguments, translates guest buffer memory, and returns through guest CALL/RET")

        return passed
    }

    private static func verifyNativeMemoryAcrossIndependentRegionsAndStack() throws {
        var memory = try X64GuestVirtualMemory()
        try mapCode([0x48, 0x8B, 0x03, 0x48, 0x89, 0x01, 0xC3], in: &memory)
        try mapRegion(at: sourceBase, permissions: .readWrite, in: &memory)
        try mapRegion(at: destinationBase, permissions: .readWrite, in: &memory)
        try mapRegion(at: stackBase, permissions: .readWrite, in: &memory)

        let value: UInt64 = 0x8877_6655_4433_2211
        try memory.writeUnsigned(value, at: sourceBase + 0x80, byteCount: 8)
        try memory.protect(at: sourceBase, byteCount: page, permissions: .read)
        let stackPointer = stackBase + page - 8
        try memory.writeUnsigned(haltAddress, at: stackPointer, byteCount: 8)

        let pageGenerationBefore = memory.pageGeneration(at: destinationBase)
        let writeGenerationBefore = memory.writeGeneration
        var state = X64CPUState(rip: codeBase, rflags: 0x202)
        try state.writeRegister(.rbx, value: sourceBase + 0x80, width: .qword)
        try state.writeRegister(.rcx, value: destinationBase + 0x100, width: .qword)
        try state.writeRegister(.rsp, value: stackPointer, width: .qword)
        var dispatcher = X64ARM64BlockDispatcher(cacheCapacity: 8)
        let report = try dispatcher.run(state: &state, memory: &memory, until: haltAddress)

        try expect(report.exit == .halted && report.finalRIP == haltAddress, "multi-region memory test did not halt at the RET target")
        try expect(try memory.readUnsigned(at: destinationBase + 0x100, byteCount: 8) == value, "native store wrote an incorrect value to the distant guest region")
        try expect(try state.readRegister(.rsp, width: .qword) == stackBase + page, "RET did not restore guest RSP")
        try expect(memory.writeGeneration > writeGenerationBefore, "native store did not advance guest write generation")
        try expect(memory.pageGeneration(at: destinationBase) != pageGenerationBefore, "native store did not advance destination page generation")
    }

    private static func verifyCrossPageWriteIsAtomicAcrossReservations() throws {
        var memory = try X64GuestVirtualMemory()
        try mapCode([0x48, 0x89, 0x03], in: &memory) // mov [rbx], rax
        try mapRegion(at: sourceBase, permissions: .readWrite, in: &memory)
        try mapRegion(at: sourceBase + page, permissions: .readWrite, in: &memory)
        try memory.writeBytes([0xA1, 0xA2, 0xA3, 0xA4], at: sourceBase + page - 4)
        try memory.writeBytes([0xB1, 0xB2, 0xB3, 0xB4], at: sourceBase + page)
        try memory.protect(at: sourceBase + page, byteCount: page, permissions: .read)

        var state = X64CPUState(rip: codeBase, rflags: 0x202)
        try state.writeRegister(.rbx, value: sourceBase + page - 4, width: .qword)
        try state.writeRegister(.rax, value: 0x1122_3344_5566_7788, width: .qword)
        var dispatcher = X64ARM64BlockDispatcher(cacheCapacity: 4)
        let report = try dispatcher.run(state: &state, memory: &memory, until: haltAddress)

        try expect(report.exit == .memoryFault(address: codeBase), "cross-page store did not surface a native memory fault at the faulting instruction")
        try expect(state.rip == codeBase, "faulting native store advanced guest RIP")
        try expect(try memory.readBytes(at: sourceBase + page - 4, count: 4) == [0xA1, 0xA2, 0xA3, 0xA4], "cross-page native store partially modified the writable first page")
        try expect(try memory.readBytes(at: sourceBase + page, count: 4) == [0xB1, 0xB2, 0xB3, 0xB4], "cross-page native store modified the read-only second page")
    }

    private static func verifyExecutePermissionOnInstructionFetch() throws {
        var memory = try X64GuestVirtualMemory()
        try memory.reserve(at: codeBase, byteCount: page, kind: .image)
        try memory.commit(at: codeBase, byteCount: page, permissions: .readWrite)
        try memory.writeBytes([0x90], at: codeBase)
        var state = X64CPUState(rip: codeBase)
        var dispatcher = X64ARM64BlockDispatcher(cacheCapacity: 2)
        do {
            _ = try dispatcher.run(state: &state, memory: &memory, until: codeBase + 1)
            throw TestError.failed("instruction fetch executed from a non-executable guest page")
        } catch let fault as X64GuestVirtualMemoryFault {
            try expect(fault.access == .execute, "non-executable code page raised the wrong guest access type")
        }
    }

    private static func verifyNativeCrossPageReadAcrossAdjacentRegions() throws {
        var memory = try X64GuestVirtualMemory()
        try mapCode([0x48, 0x8B, 0x03, 0xC3], in: &memory) // mov rax,[rbx]; ret
        try mapRegion(at: sourceBase, permissions: .readWrite, in: &memory)
        try mapRegion(at: sourceBase + page, permissions: .readWrite, in: &memory)
        try mapRegion(at: stackBase, permissions: .readWrite, in: &memory)
        try memory.writeBytes([0x88, 0x77, 0x66, 0x55], at: sourceBase + page - 4)
        try memory.writeBytes([0x44, 0x33, 0x22, 0x11], at: sourceBase + page)
        try memory.protect(at: sourceBase, byteCount: page, permissions: .read)
        try memory.protect(at: sourceBase + page, byteCount: page, permissions: .read)
        let stackPointer = stackBase + page - 8
        try memory.writeUnsigned(haltAddress, at: stackPointer, byteCount: 8)

        var state = X64CPUState(rip: codeBase, rflags: 0x202)
        try state.writeRegister(.rbx, value: sourceBase + page - 4, width: .qword)
        try state.writeRegister(.rsp, value: stackPointer, width: .qword)
        var dispatcher = X64ARM64BlockDispatcher(cacheCapacity: 4)
        let report = try dispatcher.run(state: &state, memory: &memory, until: haltAddress)
        try expect(report.exit == .halted, "cross-page read program did not return")
        try expect(try state.readRegister(.rax, width: .qword) == 0x1122_3344_5566_7788, "cross-page native read produced an incorrect little-endian value")
    }

    private static func verifyCallReturnAcrossGuestStack() throws {
        var memory = try X64GuestVirtualMemory()
        let program: [UInt8] = [
            0xE8, 0x01, 0x00, 0x00, 0x00, // call +1 -> function at +6
            0x90,                         // return address / halt
            0xB8, 0x2A, 0x00, 0x00, 0x00, // mov eax, 42
            0xC3                          // ret
        ]
        try mapCode(program, in: &memory)
        try mapRegion(at: stackBase, permissions: .readWrite, in: &memory)
        let stackTop = stackBase + page
        var state = X64CPUState(rip: codeBase, rflags: 0x202)
        try state.writeRegister(.rsp, value: stackTop, width: .qword)
        var dispatcher = X64ARM64BlockDispatcher(cacheCapacity: 8)
        let report = try dispatcher.run(state: &state, memory: &memory, until: codeBase + 5)
        try expect(report.exit == .halted && report.blocksExecuted == 2, "CALL/RET did not redispatch through the guest page-table stack")
        try expect(try state.readRegister(.rax, width: .dword) == 42, "guest function did not execute its MOV EAX,42")
        try expect(try state.readRegister(.rsp, width: .qword) == stackTop, "CALL/RET did not restore the guest stack pointer")
        try expect(try memory.readUnsigned(at: stackTop - 8, byteCount: 8) == codeBase + 5, "CALL pushed an incorrect guest return address")
    }

    private static func verifyBlockBuilderStopsAtExecutableRegionBoundary() throws {
        var memory = try X64GuestVirtualMemory()
        try memory.reserve(at: codeBase, byteCount: page, kind: .image)
        try memory.commit(at: codeBase, byteCount: page, permissions: .readWriteExecute)
        try memory.writeBytes([0x90], at: codeBase + page - 1)
        try memory.protect(at: codeBase, byteCount: page, permissions: .readExecute)

        var cache = X64ARM64TranslationCache(capacity: 4)
        let block = try cache.block(
            at: codeBase + page - 1,
            memory: &memory,
            maximumInstructions: 16,
            maximumBytes: 64,
            stopAddress: nil
        )
        try expect(block.instructionCount == 1, "block builder did not stop after the final executable byte")
        try expect(block.byteCount == 1 && block.endAddress == codeBase + page, "block end address did not match the executable region boundary")
    }

    private static func verifyNativeDemandZeroDataPageRetry() throws {
        var memory = try X64GuestVirtualMemory()
        try mapCode([0x48, 0x8B, 0x03, 0x48, 0x89, 0x01, 0xC3], in: &memory) // mov rax,[rbx]; mov [rcx],rax; ret
        try memory.reserve(at: sourceBase, byteCount: page, kind: .image)
        try memory.registerDemandZeroRange(at: sourceBase, byteCount: page, permissions: .readWrite)
        try mapRegion(at: destinationBase, permissions: .readWrite, in: &memory)
        try mapRegion(at: stackBase, permissions: .readWrite, in: &memory)

        let stackPointer = stackBase + page - 8
        try memory.writeUnsigned(haltAddress, at: stackPointer, byteCount: 8)
        var state = X64CPUState(rip: codeBase, rflags: 0x202)
        try state.writeRegister(.rbx, value: sourceBase + 0x100, width: .qword)
        try state.writeRegister(.rcx, value: destinationBase + 0x100, width: .qword)
        try state.writeRegister(.rsp, value: stackPointer, width: .qword)

        var dispatcher = X64ARM64BlockDispatcher(cacheCapacity: 4)
        let report = try dispatcher.run(state: &state, memory: &memory, until: haltAddress)
        try expect(report.exit == .halted && report.finalRIP == haltAddress, "demand-zero retry did not resume and halt")
        try expect(memory.isCommitted(address: sourceBase), "native read did not materialize the source page")
        try expect(!memory.isDemandZero(address: sourceBase), "native page-in did not consume one page of lazy metadata")
        try expect(try memory.readUnsigned(at: sourceBase + 0x100, byteCount: 8) == 0, "materialized source page was not zero-filled")
        try expect(try memory.readUnsigned(at: destinationBase + 0x100, byteCount: 8) == 0, "native retry did not complete the store")
        try expect(report.instructionsExecuted == 3, "demand-zero retry double-counted or skipped a guest instruction")
        try expect(report.blocksExecuted >= 2, "native path did not retry after demand-zero fault")
    }


    private static func verifyTranslatedDarwinSyscallBoundary() throws {
        var memory = try X64GuestVirtualMemory()
        // mov eax, 0x02000001 (Darwin UNIX exit); syscall
        try mapCode([0xB8, 0x01, 0x00, 0x00, 0x02, 0x0F, 0x05], in: &memory)
        var state = X64CPUState(rip: codeBase, rflags: 0x246)
        try state.writeRegister(.rdi, value: 7, width: .qword)
        let originalFlags = state.rflags
        var dispatcher = X64ARM64BlockDispatcher(cacheCapacity: 4)
        let report = try dispatcher.run(
            state: &state,
            memory: &memory,
            until: haltAddress,
            syscallHost: MockDarwinHost()
        )
        try expect(report.exit == .processExit(status: 7), "Darwin exit syscall did not terminate the guest with its status")
        try expect(state.rip == codeBase + 7, "SYSCALL did not leave RIP at the next guest instruction")
        try expect(state.registerValue(.rcx) == codeBase + 7, "SYSCALL did not save the next RIP in RCX")
        try expect(state.registerValue(.r11) == originalFlags, "SYSCALL did not save the pre-entry RFLAGS in R11")
    }

    private static func verifyImportedDarwinWriteThunk() throws {
        var memory = try X64GuestVirtualMemory()
        let installed = try X64DarwinHostThunkTable.install(into: &memory)
        guard let writeThunk = installed.table.address(for: "_write") else {
            throw TestError.failed("_write host thunk was not installed")
        }

        var program: [UInt8] = [0x48, 0xB8] // movabs rax, imm64
        program.append(contentsOf: littleEndian64(writeThunk))
        program.append(contentsOf: [0xFF, 0xD0, 0xC3]) // call rax; ret
        try mapCode(program, in: &memory)
        try mapRegion(at: sourceBase, permissions: .readWrite, in: &memory)
        try mapRegion(at: stackBase, permissions: .readWrite, in: &memory)
        try memory.writeBytes(Array("OK".utf8), at: sourceBase + 0x80)
        try memory.protect(at: sourceBase, byteCount: page, permissions: .read)

        let stackPointer = stackBase + page - 8
        try memory.writeUnsigned(haltAddress, at: stackPointer, byteCount: 8)
        var state = X64CPUState(rip: codeBase, rflags: 0x202)
        try state.writeRegister(.rdi, value: 1, width: .qword)
        try state.writeRegister(.rsi, value: sourceBase + 0x80, width: .qword)
        try state.writeRegister(.rdx, value: 2, width: .qword)
        try state.writeRegister(.rsp, value: stackPointer, width: .qword)

        let host = MockDarwinHost()
        var dispatcher = X64ARM64BlockDispatcher(cacheCapacity: 4)
        let report = try dispatcher.run(
            state: &state,
            memory: &memory,
            until: haltAddress,
            syscallHost: host,
            hostThunks: installed.table
        )
        try expect(report.exit == .halted, "guest did not return from _write thunk to its caller")
        try expect(host.output == Array("OK".utf8), "_write thunk did not forward the guest buffer to the host")
        try expect(state.registerValue(.rax) == 2, "_write thunk returned an incorrect byte count")
        try expect(state.registerValue(.rsp) == stackBase + page, "_write thunk or guest RET did not restore RSP")
        try expect(state.rip == haltAddress, "_write thunk caller did not return to the halt sentinel")
    }

    private static func littleEndian64(_ value: UInt64) -> [UInt8] {
        (0..<8).map { UInt8(truncatingIfNeeded: value >> (UInt64($0) * 8)) }
    }

    private static func mapCode(_ bytes: [UInt8], in memory: inout X64GuestVirtualMemory) throws {
        try memory.reserve(at: codeBase, byteCount: page, kind: .image)
        try memory.commit(at: codeBase, byteCount: page, permissions: .readWriteExecute)
        try memory.writeBytes(bytes, at: codeBase)
        try memory.protect(at: codeBase, byteCount: page, permissions: .readExecute)
    }

    private static func mapRegion(
        at address: UInt64,
        permissions: X64GuestMemoryPermissions,
        in memory: inout X64GuestVirtualMemory
    ) throws {
        try memory.reserve(at: address, byteCount: page, kind: .anonymous)
        try memory.commit(at: address, byteCount: page, permissions: permissions)
    }

    private static func expect(_ condition: @autoclosure () throws -> Bool, _ message: String) throws {
        guard try condition() else { throw TestError.failed(message) }
    }

    enum TestError: LocalizedError {
        case failed(String)
        var errorDescription: String? {
            switch self {
            case .failed(let message): return "Native guest-VM integration test failed: \(message)"
            }
        }
    }
}
