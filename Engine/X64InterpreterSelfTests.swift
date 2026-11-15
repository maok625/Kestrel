import Foundation

enum X64InterpreterSelfTests {
    enum TestError: LocalizedError {
        case failed(String)

        var errorDescription: String? {
            switch self {
            case .failed(let detail): return "Interpreter test failed: \(detail)"
            }
        }
    }

    private static let guestBase: UInt64 = 0x0000_0001_0000_0000
    private static let codeAddress: UInt64 = guestBase + 0x1000
    private static let stackTop: UInt64 = guestBase + 0xF000
    private static let haltAddress: UInt64 = 0xFFFF_FFFF_FFFF_FFF0
    private static let memorySize = 0x10_000

    static func run() throws -> [String] {
        var passed: [String] = []

        // 1. Actual instruction fetch/decode/IR execution and 32-bit zero extension.
        var basic = try makeInterpreter(code: [
            0xB8, 0x28, 0x00, 0x00, 0x00,       // mov eax, 40
            0x83, 0xC0, 0x02,                   // add eax, 2
            0xC3                                // ret
        ])
        let basicReport = try basic.run(until: haltAddress)
        try expect(basicReport.halted && basicReport.instructionsExecuted == 3, "basic program halted after three instructions")
        try expect(basic.state.registerValue(.rax) == 42, "MOV EAX,imm32 then ADD EAX,imm8 returns RAX=42")
        try expect(basic.state.rip == haltAddress, "RET restored sentinel instruction pointer")
        passed.append("Instruction fetch, MOV immediate, ADD immediate, and RET execute against guest CPU state")

        // 2. Register/register MOV, ADD, SUB, CMP, and XOR; flags are architectural.
        var arithmetic = try makeInterpreter(code: [
            0x48, 0xB8, 0x0A, 0, 0, 0, 0, 0, 0, 0, // mov rax, 10
            0x48, 0xB9, 0x03, 0, 0, 0, 0, 0, 0, 0, // mov rcx, 3
            0x48, 0x89, 0xC2,                       // mov rdx, rax
            0x48, 0x01, 0xC8,                       // add rax, rcx
            0x48, 0x29, 0xC8,                       // sub rax, rcx
            0x48, 0x39, 0xC8,                       // cmp rax, rcx
            0x48, 0x31, 0xD2,                       // xor rdx, rdx
            0xC3
        ])
        _ = try arithmetic.run(until: haltAddress)
        try expect(arithmetic.state.registerValue(.rax) == 10, "register arithmetic returns RAX=10")
        try expect(arithmetic.state.registerValue(.rdx) == 0, "XOR clears RDX")
        try expect(arithmetic.state.flagIsSet(.zero), "XOR result sets ZF")
        try expect(arithmetic.state.flagIsSet(.parity), "zero result sets even parity")
        try expect(!arithmetic.state.flagIsSet(.carry) && !arithmetic.state.flagIsSet(.overflow), "XOR clears CF and OF")
        passed.append("Register/register MOV, ADD, SUB, CMP, XOR, and logical/arithmetic flags")

        // 3. Byte and word operations use the decoded register slices exactly.
        var byteMachine = try makeInterpreter(code: [
            0xB4, 0x7F,             // mov ah, 0x7f
            0x80, 0xC4, 0x01,       // add ah, 1
            0xC3
        ])
        _ = try byteMachine.run(until: haltAddress)
        let ahValue = try byteMachine.state.readRegister(.rax, width: .byte, highByte: true)
        try expect(ahValue == 0x80, "AH arithmetic result")
        try expect(byteMachine.state.flagIsSet(.overflow) && byteMachine.state.flagIsSet(.sign), "AH ADD sets OF and SF")

        var wordMachine = try makeInterpreter(code: [
            0x66, 0xB8, 0x34, 0x12, // mov ax, 0x1234
            0x66, 0x83, 0xC0, 0x01, // add ax, 1
            0xC3
        ]) { state in
            try state.writeRegister(.rax, value: 0xAAAA_BBBB_CCCC_0000, width: .qword)
        }
        _ = try wordMachine.run(until: haltAddress)
        try expect(wordMachine.state.registerValue(.rax) == 0xAAAA_BBBB_CCCC_1235, "16-bit instructions preserve upper RAX")
        passed.append("8-bit high-register and 16-bit arithmetic execute with correct partial-register semantics")

        // 4. Guest memory operands use guest addresses and are bounds checked.
        let dataAddress = guestBase + 0x3000
        let memoryCode: [UInt8] = [
            0x48, 0xBB, // mov rbx, imm64
            UInt8(truncatingIfNeeded: dataAddress),
            UInt8(truncatingIfNeeded: dataAddress >> 8),
            UInt8(truncatingIfNeeded: dataAddress >> 16),
            UInt8(truncatingIfNeeded: dataAddress >> 24),
            UInt8(truncatingIfNeeded: dataAddress >> 32),
            UInt8(truncatingIfNeeded: dataAddress >> 40),
            UInt8(truncatingIfNeeded: dataAddress >> 48),
            UInt8(truncatingIfNeeded: dataAddress >> 56),
            0xB8, 0x78, 0x56, 0x34, 0x12, // mov eax, 0x12345678
            0x89, 0x43, 0x04,             // mov [rbx+4], eax
            0x8B, 0x4B, 0x04,             // mov ecx, [rbx+4]
            0xC3
        ]
        var memoryMachine = try makeInterpreter(code: memoryCode)
        _ = try memoryMachine.run(until: haltAddress)
        try expect(memoryMachine.state.registerValue(.rcx) == 0x1234_5678, "memory load returns stored dword")
        let storedMemoryValue = try memoryMachine.memory.readUnsigned(at: dataAddress + 4, width: .dword)
        try expect(storedMemoryValue == 0x1234_5678, "memory store writes expected guest bytes")
        passed.append("Guest memory read/write via base+displacement, without host-pointer dereferencing")

        // 5. LEA computes an address but does not read memory.
        let leaCode: [UInt8] = [
            0x48, 0xBB,
            UInt8(truncatingIfNeeded: dataAddress),
            UInt8(truncatingIfNeeded: dataAddress >> 8),
            UInt8(truncatingIfNeeded: dataAddress >> 16),
            UInt8(truncatingIfNeeded: dataAddress >> 24),
            UInt8(truncatingIfNeeded: dataAddress >> 32),
            UInt8(truncatingIfNeeded: dataAddress >> 40),
            UInt8(truncatingIfNeeded: dataAddress >> 48),
            UInt8(truncatingIfNeeded: dataAddress >> 56),
            0x48, 0x8D, 0x43, 0x10, // lea rax, [rbx+16]
            0xC3
        ]
        var leaMachine = try makeInterpreter(code: leaCode)
        _ = try leaMachine.run(until: haltAddress)
        try expect(leaMachine.state.registerValue(.rax) == dataAddress + 16, "LEA computes base+displacement")
        passed.append("LEA computes effective addresses without performing a memory access")

        // 6. Conditional control flow follows ZF and relative displacement.
        var branchMachine = try makeInterpreter(code: [
            0x48, 0x83, 0xC0, 0x00, // add rax, 0; initial RAX is zero, so ZF=1
            0x74, 0x05,             // jz +5, skip MOV EAX,1
            0xB8, 0x01, 0, 0, 0,
            0xB8, 0x2A, 0, 0, 0,
            0xC3
        ])
        _ = try branchMachine.run(until: haltAddress)
        try expect(branchMachine.state.registerValue(.rax) == 42, "JZ takes branch and skips the first MOV")
        passed.append("Conditional branch evaluates ZF and transfers to the correct guest RIP")

        // 7. 64-bit carry and zero flags are evaluated by the guest ALU.
        var qwordMachine = try makeInterpreter(code: [
            0x48, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // mov rax, -1
            0x48, 0x83, 0xC0, 0x01, // add rax, 1
            0xC3
        ])
        _ = try qwordMachine.run(until: haltAddress)
        try expect(qwordMachine.state.registerValue(.rax) == 0, "64-bit overflow wraps to zero")
        try expect(qwordMachine.state.flagIsSet(.carry) && qwordMachine.state.flagIsSet(.zero), "64-bit ADD sets CF and ZF")
        try expect(!qwordMachine.state.flagIsSet(.overflow), "-1 + 1 does not set signed OF")
        passed.append("64-bit ADD distinguishes unsigned carry from signed overflow")

        // 8. PUSH/POP and nested CALL/RET use the guest stack.
        var stackMachine = try makeInterpreter(code: [0x50, 0x59, 0xC3]) { state in
            try state.writeRegister(.rax, value: 0x1122_3344_5566_7788, width: .qword)
        }
        _ = try stackMachine.run(until: haltAddress)
        try expect(stackMachine.state.registerValue(.rcx) == 0x1122_3344_5566_7788, "PUSH RAX / POP RCX preserves qword")
        try expect(stackMachine.state.registerValue(.rsp) == stackTop, "PUSH/POP restores RSP before RET")

        var callMachine = try makeInterpreter(code: [
            0xE8, 0x01, 0x00, 0x00, 0x00, // call function at offset 6
            0xC3,                         // return from caller
            0xB8, 0x2A, 0, 0, 0,         // function: mov eax,42
            0xC3                          // ret to caller
        ])
        _ = try callMachine.run(until: haltAddress)
        try expect(callMachine.state.registerValue(.rax) == 42, "CALL pushes return address and RET returns to caller")
        try expect(callMachine.state.registerValue(.rsp) == stackTop, "nested CALL/RET restores guest RSP")
        passed.append("Guest PUSH/POP and nested CALL/RET maintain stack and return addresses")

        // 9. Out-of-range guest loads fail as guest memory faults.
        var faultMachine = try makeInterpreter(code: [0x48, 0x8B, 0x03, 0xC3]) { state in
            try state.writeRegister(.rbx, value: guestBase + UInt64(memorySize) + 0x100, width: .qword)
        }
        do {
            _ = try faultMachine.run(until: haltAddress)
            throw TestError.failed("out-of-range guest load should fault")
        } catch is X64GuestMemoryError {
            // Expected: guest memory access outside the mapped test region.
        }
        passed.append("Out-of-range guest memory access raises a deterministic memory fault")

        return passed
    }

    private static func makeInterpreter(
        code: [UInt8],
        configureState: ((inout X64CPUState) throws -> Void)? = nil
    ) throws -> X64Interpreter {
        var memory = try X64GuestMemory(baseAddress: guestBase, size: memorySize)
        try memory.writeBytes(code, at: codeAddress)
        try memory.writeUnsigned(haltAddress, at: stackTop - 8, width: .qword)

        var state = X64CPUState(rip: codeAddress)
        try state.writeRegister(.rsp, value: stackTop - 8, width: .qword)
        if let configureState {
            try configureState(&state)
        }
        return X64Interpreter(state: state, memory: memory)
    }

    private static func expect(_ condition: @autoclosure () -> Bool, _ message: String) throws {
        guard condition() else { throw TestError.failed(message) }
    }
}
