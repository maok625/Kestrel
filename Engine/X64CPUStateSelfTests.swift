import Foundation

enum X64CPUStateSelfTests {
    enum TestError: LocalizedError {
        case failed(String)

        var errorDescription: String? {
            switch self {
            case .failed(let details): return "CPU-state test failed: \(details)"
            }
        }
    }

    static func run() throws -> [String] {
        var passed: [String] = []

        // 1. RIP and the architectural reserved RFLAGS bit.
        var state = X64CPUState(rip: 0x1_0000_1234, rflags: 0)
        try expect(state.rip == 0x1_0000_1234, "RIP initialization")
        try expect(state.rflags == 0x2, "RFLAGS reserved bit 1")
        passed.append("RIP and RFLAGS initialization")

        // 2. All 16 GPR slots remain independent and use x86 encoding order.
        for register in X64GeneralRegister.allCases {
            let value = 0xA500_0000_0000_0000 | UInt64(register.rawValue + 1)
            try state.writeRegister(register, value: value, width: .qword)
            try expect(state.registerValue(register) == value, "\(register.name) 64-bit storage")
        }
        try expect(state.registerValue(.rax) != state.registerValue(.rcx), "independent GPR storage")
        passed.append("16 independent 64-bit general-purpose registers")

        // 3. Correct partial-register semantics.
        try state.writeRegister(.rax, value: 0xFFFF_FFFF_FFFF_FFFF, width: .qword)
        try state.writeRegister(.rax, value: 0x1234, width: .word)
        try expect(state.registerValue(.rax) == 0xFFFF_FFFF_FFFF_1234, "16-bit write preserves upper bits")
        try state.writeRegister(.rax, value: 0x56, width: .byte)
        try expect(state.registerValue(.rax) == 0xFFFF_FFFF_FFFF_1256, "8-bit write preserves upper bits")
        try state.writeRegister(.rax, value: 0x89AB_CDEF, width: .dword)
        try expect(state.registerValue(.rax) == 0x0000_0000_89AB_CDEF, "32-bit write zero-extends")
        passed.append("8/16-bit partial writes and 32-bit zero-extension")

        // 4. Legacy high-byte register encoding versus REX byte registers.
        try state.writeRegister(.rax, value: 0x1122_3344_5566_7788, width: .qword)
        let ah = try X64RegisterOperand(encodedIndex: 4, width: .byte, rexPresent: false)
        let spl = try X64RegisterOperand(encodedIndex: 4, width: .byte, rexPresent: true)
        try expect(ah.register == .rax && ah.highByte, "legacy encoding 4 maps to AH")
        try expect(spl.register == .rsp && !spl.highByte, "REX encoding 4 maps to SPL")
        do {
            _ = try X64RegisterOperand(encodedIndex: 8, width: .byte, rexPresent: false)
            throw TestError.failed("R8B encoding without REX should be rejected")
        } catch is X64CPUStateError {
            // Expected: extended registers require a REX prefix.
        }
        state.write(0xAA, to: ah)
        try expect(state.registerValue(.rax) == 0x1122_3344_5566_AA88, "AH write changes bits 8...15")
        state.write(0xBB, to: spl)
        try expect(state.registerValue(.rsp) == 0xA500_0000_0000_00BB, "SPL write changes low byte of RSP")
        passed.append("AH/CH/DH/BH versus SPL/BPL/SIL/DIL decoding")

        // 5. 8-bit ADD: signed overflow and auxiliary carry.
        let addOverflow = state.add(0x7F, 0x01, width: .byte)
        try expect(addOverflow == 0x80, "8-bit ADD result")
        try expect(state.flagIsSet(.overflow), "8-bit ADD OF")
        try expect(state.flagIsSet(.sign), "8-bit ADD SF")
        try expect(state.flagIsSet(.auxiliaryCarry), "8-bit ADD AF")
        try expect(!state.flagIsSet(.carry), "8-bit ADD CF clear")
        try expect(!state.flagIsSet(.zero), "8-bit ADD ZF clear")
        passed.append("ADD signed overflow, sign, and auxiliary-carry flags")

        // 6. Unsigned carry, zero, and even parity.
        let addCarry = state.add(0xFF, 0x01, width: .byte)
        try expect(addCarry == 0, "8-bit ADD wraparound")
        try expect(state.flagIsSet(.carry), "8-bit ADD CF")
        try expect(state.flagIsSet(.zero), "8-bit ADD ZF")
        try expect(state.flagIsSet(.parity), "8-bit ADD PF")
        try expect(state.flagIsSet(.auxiliaryCarry), "8-bit ADD AF at nibble boundary")
        try expect(!state.flagIsSet(.overflow), "8-bit ADD OF clear")
        passed.append("ADD unsigned carry, zero, parity, and nibble carry")

        // 7. SUB: borrow, sign, parity and auxiliary borrow.
        let subtractBorrow = state.subtract(0, 1, width: .byte)
        try expect(subtractBorrow == 0xFF, "8-bit SUB wraparound")
        try expect(state.flagIsSet(.carry), "8-bit SUB CF represents borrow")
        try expect(state.flagIsSet(.sign), "8-bit SUB SF")
        try expect(state.flagIsSet(.parity), "8-bit SUB PF")
        try expect(state.flagIsSet(.auxiliaryCarry), "8-bit SUB AF")
        try expect(!state.flagIsSet(.zero), "8-bit SUB ZF clear")
        passed.append("SUB borrow, sign, parity, and auxiliary-borrow flags")

        // 8. Carry-in / borrow-in variants exercise ADC and SBB semantics.
        let adcResult = state.add(0x7F, 0, width: .byte, carryIn: true)
        try expect(adcResult == 0x80, "ADC carry-in result")
        try expect(state.flagIsSet(.overflow), "ADC signed overflow")
        try expect(state.flagIsSet(.auxiliaryCarry), "ADC auxiliary carry")
        state.setFlag(.direction, to: true)
        let sbbResult = state.subtract(0, 0, width: .byte, borrowIn: true)
        try expect(sbbResult == 0xFF, "SBB borrow-in result")
        try expect(state.flagIsSet(.carry), "SBB borrow flag")
        try expect(state.flagIsSet(.auxiliaryCarry), "SBB auxiliary borrow")
        try expect(state.flagIsSet(.direction), "arithmetic preserves unrelated RFLAGS bits")
        passed.append("ADC/SBB carry-in and borrow-in semantics; unrelated flags preserved")

        // 9. 64-bit overflow and carry are distinct conditions.
        let signedOverflow = state.add(0x7FFF_FFFF_FFFF_FFFF, 1, width: .qword)
        try expect(signedOverflow == 0x8000_0000_0000_0000, "64-bit signed-overflow result")
        try expect(state.flagIsSet(.overflow), "64-bit ADD OF")
        try expect(state.flagIsSet(.sign), "64-bit ADD SF")
        try expect(!state.flagIsSet(.carry), "64-bit ADD CF clear")

        let unsignedCarry = state.add(.max, 1, width: .qword)
        try expect(unsignedCarry == 0, "64-bit unsigned-wrap result")
        try expect(state.flagIsSet(.carry), "64-bit ADD CF")
        try expect(!state.flagIsSet(.overflow), "-1 + 1 does not set signed OF")
        try expect(state.flagIsSet(.zero), "64-bit ADD ZF")
        passed.append("64-bit signed overflow distinguished from unsigned carry")

        try expect((state.rflags & 0x2) != 0, "RFLAGS reserved bit remains set")
        passed.append("RFLAGS invariant preserved after arithmetic")

        return passed
    }

    private static func expect(_ condition: @autoclosure () -> Bool, _ message: String) throws {
        guard condition() else { throw TestError.failed(message) }
    }
}
