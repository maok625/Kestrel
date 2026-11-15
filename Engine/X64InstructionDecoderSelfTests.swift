import Foundation

enum X64InstructionDecoderSelfTests {
    enum TestError: LocalizedError {
        case failed(String)

        var errorDescription: String? {
            switch self {
            case .failed(let message): return "Instruction-decoder test failed: \(message)"
            }
        }
    }

    static func run() throws -> [String] {
        let decoder = X64InstructionDecoder()
        var passed: [String] = []

        // 1. REX.W + register-register MOV, including IR operand direction.
        let mov = try decoder.decode([0x48, 0x89, 0xD8], at: 0x1000)
        try expect(mov.length == 3 && mov.nextAddress == 0x1003, "MOV instruction length and next RIP")
        let movIR = try mov.lowerToIR()
        try expect(movIR.operation == .move && movIR.width == .qword, "MOV IR operation and width")
        try expect(movIR.destination == .register(try X64RegisterOperand(register: .rax, width: .qword)), "MOV destination RAX")
        try expect(movIR.source == .register(try X64RegisterOperand(register: .rbx, width: .qword)), "MOV source RBX")
        passed.append("REX.W, ModRM register decoding, and MOV semantic lowering")

        // 2. Extended reg field + SIB base/index/scale + signed disp8.
        let sib = try decoder.decode([0x4C, 0x8B, 0x44, 0x8D, 0xF0])
        guard let sibModRM = sib.modRM,
              case .memory(let memory) = sibModRM.rmOperand else {
            throw TestError.failed("SIB memory operand was not decoded")
        }
        try expect(sibModRM.extendedReg == 8, "REX.R extends ModRM.reg to R8")
        try expect(memory.base == .rbp, "SIB base RBP")
        try expect(memory.index == .rcx, "SIB index RCX")
        try expect(memory.scale == 4, "SIB scale 4")
        try expect(memory.displacement == -16, "signed disp8")
        let sibIR = try sib.lowerToIR()
        try expect(sibIR.destination == .register(try X64RegisterOperand(register: .r8, width: .qword)), "SIB MOV destination R8")
        passed.append("ModRM/SIB decoding, REX register extension, scale, and signed displacement")

        // 3. RIP-relative addressing is distinct from an absolute 32-bit address.
        let ripRelative = try decoder.decode([0x48, 0x8B, 0x05, 0x78, 0x56, 0x34, 0x12], at: 0x4000)
        guard case .memory(let ripMemory)? = ripRelative.modRM?.rmOperand else {
            throw TestError.failed("RIP-relative operand was not decoded")
        }
        try expect(ripMemory.ripRelative && ripMemory.base == nil, "RIP-relative mode")
        try expect(ripMemory.displacement == 0x1234_5678, "RIP-relative disp32")
        let absolute32 = try decoder.decode([0x67, 0x8B, 0x05, 0x78, 0x56, 0x34, 0x12])
        guard case .memory(let absoluteMemory)? = absolute32.modRM?.rmOperand else {
            throw TestError.failed("32-bit absolute operand was not decoded")
        }
        try expect(!absoluteMemory.ripRelative && absoluteMemory.addressWidth == .dword, "address-size override selects 32-bit absolute addressing")
        passed.append("RIP-relative addressing and 32-bit address-size override")

        // 4. Legacy high-byte registers versus REX low-byte registers.
        let legacyByte = try decoder.decode([0xB4, 0x7F])
        let rexByte = try decoder.decode([0x40, 0xB4, 0x7F])
        guard case .register(let ah)? = try legacyByte.lowerToIR().destination,
              case .register(let spl)? = try rexByte.lowerToIR().destination else {
            throw TestError.failed("byte-register MOV destination missing")
        }
        try expect(ah.register == .rax && ah.highByte, "legacy B4 selects AH")
        try expect(spl.register == .rsp && !spl.highByte, "REX B4 selects SPL")
        passed.append("Legacy AH and REX SPL byte-register selection")

        // 5. Operand-size override and immediate group extension.
        let wordAdd = try decoder.decode([0x66, 0x81, 0xC3, 0x34, 0x12])
        try expect(wordAdd.operandWidth == .word && wordAdd.immediateByteCount == 2, "16-bit operand and immediate size")
        let wordIR = try wordAdd.lowerToIR()
        try expect(wordIR.operation == .add && wordIR.width == .word, "16-bit group-1 ADD")
        try expect(wordIR.destination == .register(try X64RegisterOperand(register: .rbx, width: .word)), "16-bit ADD destination BX")
        try expect(wordIR.source == .immediate(value: 0x1234, encodedByteCount: 2), "16-bit ADD immediate")
        passed.append("Operand-size override and group-1 immediate decoding")

        // 6. Sign-extension of imm8 for 64-bit arithmetic.
        let addNegative = try decoder.decode([0x48, 0x83, 0xC0, 0xF8])
        let addNegativeIR = try addNegative.lowerToIR()
        try expect(addNegativeIR.source == .immediate(value: 0xFFFF_FFFF_FFFF_FFF8, encodedByteCount: 1), "ADD imm8 sign extension")
        passed.append("Signed imm8 extension into a 64-bit operation")

        // 7. MOV r/m64, imm32 sign-extends to 64 bits.
        let movNegative = try decoder.decode([0x48, 0xC7, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF])
        let movNegativeIR = try movNegative.lowerToIR()
        try expect(movNegativeIR.source == .immediate(value: .max, encodedByteCount: 4), "MOV imm32 sign extension")
        passed.append("C7 imm32 sign extension for a 64-bit destination")

        // 8. Two-byte opcode map and near conditional branch displacement.
        let conditional = try decoder.decode([0x0F, 0x85, 0xFC, 0xFF, 0xFF, 0xFF], at: 0x2000)
        let conditionalIR = try conditional.lowerToIR()
        try expect(conditional.opcodeMap == .map0F && conditional.length == 6, "0F opcode map and length")
        try expect(conditionalIR.operation == .conditionalBranch(condition: .notEqual, displacement: -4), "JNE rel32 lowering")
        passed.append("0F opcode map and relative conditional-branch IR")

        // 9. Prefix ordering: a legacy prefix after REX cancels the earlier REX.
        let rexCancelled = try decoder.decode([0x48, 0x66, 0x89, 0xD8])
        try expect(rexCancelled.prefixes.rex == nil && rexCancelled.operandWidth == .word, "legacy prefix cancels earlier REX")
        let rexExtendedSIB = try decoder.decode([0x4B, 0x8B, 0x44, 0xA4, 0x08])
        guard case .memory(let extendedMemory)? = rexExtendedSIB.modRM?.rmOperand else {
            throw TestError.failed("REX-extended SIB operand missing")
        }
        try expect(extendedMemory.base == .r12 && extendedMemory.index == .r12 && extendedMemory.scale == 4, "REX.B and REX.X extend SIB base/index")
        passed.append("REX prefix ordering and REX.X/REX.B SIB extensions")

        // 10. Return, push/pop register and branch immediate shapes.
        let ret = try decoder.decode([0xC2, 0x10, 0x00])
        try expect(try ret.lowerToIR().operation == .returnFromFunction(stackAdjustment: 16), "RET imm16")
        let push = try decoder.decode([0x41, 0x50])
        let pushIR = try push.lowerToIR()
        try expect(pushIR.operation == .push && pushIR.width == .qword, "PUSH R8 defaults to 64-bit stack width")
        try expect(pushIR.source == .register(try X64RegisterOperand(register: .r8, width: .qword)), "PUSH R8 source")
        let pop = try decoder.decode([0x41, 0x5F])
        let popIR = try pop.lowerToIR()
        try expect(popIR.operation == .pop && popIR.destination == .register(try X64RegisterOperand(register: .r15, width: .qword)), "POP R15")
        let jump = try decoder.decode([0xEB, 0xFE])
        try expect(try jump.lowerToIR().operation == .branchRelative(displacement: -2), "JMP rel8")
        let xchg = try decoder.decode([0x49, 0x90])
        try expect(try xchg.lowerToIR().operation == .exchange, "REX.B 90 decodes as XCHG, not NOP")
        let pause = try decoder.decode([0xF3, 0x90])
        try expect(try pause.lowerToIR().operation == .pause, "PAUSE")
        let indirectCall = try decoder.decode([0x41, 0xFF, 0xD0])
        let indirectCallIR = try indirectCall.lowerToIR()
        try expect(indirectCall.operandWidth == .qword && indirectCallIR.source == .register(try X64RegisterOperand(register: .r8, width: .qword)), "indirect CALL uses qword register operand")
        let indirectPush = try decoder.decode([0xFF, 0xF0])
        try expect(indirectPush.lowerToIR().source == .register(try X64RegisterOperand(register: .rax, width: .qword)), "indirect PUSH uses qword register operand")
        let indirectPop = try decoder.decode([0x8F, 0xC0])
        try expect(indirectPop.lowerToIR().destination == .register(try X64RegisterOperand(register: .rax, width: .qword)), "indirect POP uses qword register operand")
        passed.append("RET, stack-width semantics, PUSH/POP, branches, XCHG, PAUSE, and indirect control transfer")

        // 11. Truncation and the architectural instruction-length limit fail closed.
        try expectThrows({ _ = try decoder.decode([0x48, 0xB8, 0x01, 0x02]) }, "truncated imm64")
        try expectThrows({ _ = try decoder.decode([0x48, 0x8B, 0x84, 0x8D, 0x01]) }, "truncated SIB displacement")
        try expectThrows({ _ = try decoder.decode(Array(repeating: 0x66, count: 15) + [0x90]) }, "instruction longer than 15 bytes")
        try expectThrows({ _ = try decoder.decode([0x0F, 0xFF]) }, "unknown 0F opcode")
        passed.append("Truncated, overlength, and unsupported encodings rejected safely")

        // 12. Decoder consumes one instruction; decodeAll walks the whole stream.
        let twoInstructions = try decoder.decode([0x90, 0xC3])
        try expect(twoInstructions.bytes == [0x90] && twoInstructions.length == 1, "single-instruction decode boundary")
        let stream = try decoder.decodeAll([0x90, 0x48, 0x83, 0xC0, 0x01, 0xC3], at: 0x5000)
        try expect(stream.count == 3, "decodeAll instruction count")
        try expect(stream.map(\.address) == [0x5000, 0x5001, 0x5005], "decodeAll guest addresses")
        passed.append("Single-instruction boundaries and sequential stream decoding")

        let syscall = try decoder.decode([0x0F, 0x05], at: 0x3000)
        let syscallIR = try syscall.lowerToIR()
        try expect(syscall.length == 2 && syscallIR.operation == .systemCall, "SYSCALL boundary decoding")
        passed.append("SYSCALL decodes to an explicit dispatcher boundary rather than an unsupported opcode")

        return passed
    }

    private static func expect(_ condition: Bool, _ message: String) throws {
        guard condition else { throw TestError.failed(message) }
    }

    private static func expectThrows(_ body: () throws -> Void, _ message: String) throws {
        do {
            try body()
            throw TestError.failed("Expected rejection: \(message)")
        } catch is X64InstructionDecoderError {
            // Expected decoder rejection.
        }
    }
}
