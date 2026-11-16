import Foundation

/// Differential tests run identical instruction streams through the reference
/// interpreter and the native AArch64 backend. They are intended for Apple
/// Silicon because they exercise the MAP_JIT runtime.
enum X64ARM64TranslationSelfTests {
    enum TestError: LocalizedError {
        case failed(String)
        var errorDescription: String? {
            switch self {
            case .failed(let detail): return "ARM64 translation test failed: \(detail)"
            }
        }
    }

    private static let guestBase: UInt64 = 0x0000_0001_0000_0000
    private static let codeAddress: UInt64 = guestBase + 0x1000
    private static let memorySize = 0x10_000
    private static let dataAddress = guestBase + 0x4000
    private static let stackAddress = guestBase + 0xF000

    static func run() throws -> [String] {
        let helperAddress = UInt64(kestrel_x64_flag_helper_address())
        guard helperAddress != 0 else {
            throw TestError.failed("native x86 flag helper has a null function address")
        }

        var passed: [String] = []

        try compare(
            name: "32-bit MOV/ADD and EAX zero-extension",
            bytes: [0xB8, 0x2A, 0, 0, 0, 0x83, 0xC0, 0x08],
            initial: configuredState(rflags: 0x202) { state in
                try state.writeRegister(.rax, value: 0xFFFF_FFFF_0000_0000, width: .qword)
            },
            helperAddress: helperAddress
        )
        passed.append("Register/immediate integer block still matches the interpreter")

        try compare(
            name: "64-bit carry and wraparound",
            bytes: [
                0x48, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0x48, 0x83, 0xC0, 0x01
            ],
            initial: configuredState(rflags: 0x246) { _ in },
            helperAddress: helperAddress
        )
        passed.append("64-bit ADD carry/zero flags match the reference interpreter")

        try compare(
            name: "AH partial-register update",
            bytes: [0xB4, 0x7F, 0x80, 0xC4, 0x01],
            initial: configuredState(rflags: 0x202) { state in
                try state.writeRegister(.rax, value: 0x1122_3344_5566_0000, width: .qword)
            },
            helperAddress: helperAddress
        )
        passed.append("AH byte arithmetic preserves unrelated RAX bits and matches flags")

        try compare(
            name: "CMP signed/unsigned status flags",
            bytes: [0xB8, 0x00, 0x00, 0x00, 0x80, 0x83, 0xF8, 0x01],
            initial: configuredState(rflags: 0x202) { _ in },
            helperAddress: helperAddress
        )
        passed.append("CMP updates CF/PF/AF/ZF/SF/OF without changing the destination")

        try compare(
            name: "XOR logical flags and AF preservation",
            bytes: [0x31, 0xC9],
            initial: configuredState(rflags: 0x212) { state in
                try state.writeRegister(.rcx, value: 0x1234_5678_9ABC_DEF0, width: .qword)
            },
            helperAddress: helperAddress
        )
        passed.append("XOR result, defined flags, and undefined-AF preservation match the interpreter")

        try compare(
            name: "XCHG register/register",
            bytes: [0x48, 0x91],
            initial: configuredState(rflags: 0x202) { state in
                try state.writeRegister(.rax, value: 0x1111_2222_3333_4444, width: .qword)
                try state.writeRegister(.rcx, value: 0xAAAA_BBBB_CCCC_DDDD, width: .qword)
            },
            helperAddress: helperAddress
        )
        passed.append("XCHG register operands preserve RFLAGS")

        try compare(
            name: "64-bit memory load through RBX",
            bytes: [0x48, 0x8B, 0x03], // mov rax, [rbx]
            initial: configuredState(rflags: 0x202) { state in
                try state.writeRegister(.rbx, value: dataAddress, width: .qword)
            },
            helperAddress: helperAddress,
            memorySetup: { memory in
                try memory.writeUnsigned(0x1122_3344_5566_7788, at: dataAddress, width: .qword)
            }
        )
        passed.append("Guest memory load maps guest virtual address through checked host backing")

        try compare(
            name: "64-bit memory store through RBX",
            bytes: [0x48, 0x89, 0x03], // mov [rbx], rax
            initial: configuredState(rflags: 0x202) { state in
                try state.writeRegister(.rbx, value: dataAddress, width: .qword)
                try state.writeRegister(.rax, value: 0xAABB_CCDD_EEFF_0011, width: .qword)
            },
            helperAddress: helperAddress
        )
        passed.append("Guest memory store updates the byte-backed guest region")

        try compare(
            name: "ADD memory destination and exact status flags",
            bytes: [0x48, 0x01, 0x03], // add [rbx], rax
            initial: configuredState(rflags: 0x202) { state in
                try state.writeRegister(.rbx, value: dataAddress, width: .qword)
                try state.writeRegister(.rax, value: 1, width: .qword)
            },
            helperAddress: helperAddress,
            memorySetup: { memory in
                try memory.writeUnsigned(UInt64.max, at: dataAddress, width: .qword)
            }
        )
        passed.append("Memory-destination arithmetic matches interpreter memory and RFLAGS")

        try compare(
            name: "SIB indexed memory load",
            bytes: [0x48, 0x8B, 0x44, 0x8B, 0x08], // mov rax, [rbx + rcx*4 + 8]
            initial: configuredState(rflags: 0x202) { state in
                try state.writeRegister(.rbx, value: dataAddress, width: .qword)
                try state.writeRegister(.rcx, value: 3, width: .qword)
            },
            helperAddress: helperAddress,
            memorySetup: { memory in
                try memory.writeUnsigned(0xCAFE_BABE_1234_5678, at: dataAddress + 20, width: .qword)
            }
        )
        passed.append("SIB scale, index, base, and displacement form the correct guest address")

        try compare(
            name: "ADD register destination with memory source",
            bytes: [0x48, 0x03, 0x03], // add rax, [rbx]
            initial: configuredState(rflags: 0x202) { state in
                try state.writeRegister(.rbx, value: dataAddress, width: .qword)
                try state.writeRegister(.rax, value: 0x100, width: .qword)
            },
            helperAddress: helperAddress,
            memorySetup: { memory in
                try memory.writeUnsigned(0x234, at: dataAddress, width: .qword)
            }
        )
        passed.append("Register-destination arithmetic preserves its left operand while reading memory")

        try compare(
            name: "Byte MOV immediate to guest memory",
            bytes: [0xC6, 0x03, 0x7F], // mov byte [rbx], 0x7f
            initial: configuredState(rflags: 0x202) { state in
                try state.writeRegister(.rbx, value: dataAddress, width: .qword)
            },
            helperAddress: helperAddress
        )
        passed.append("Byte-sized guest stores preserve little-endian width semantics")

        try compare(
            name: "RIP-relative memory load",
            bytes: [0x48, 0x8B, 0x05, 0x20, 0x00, 0x00, 0x00],
            initial: configuredState(rflags: 0x202) { _ in },
            helperAddress: helperAddress,
            memorySetup: { memory in
                try memory.writeUnsigned(0x0123_4567_89AB_CDEF, at: codeAddress + 7 + 0x20, width: .qword)
            }
        )
        passed.append("RIP-relative memory operand uses the decoded next-instruction address")

        try compare(
            name: "LEA computes indexed effective address without reading memory",
            bytes: [0x48, 0x8D, 0x44, 0x8B, 0x08], // lea rax, [rbx + rcx*4 + 8]
            initial: configuredState(rflags: 0x202) { state in
                try state.writeRegister(.rbx, value: dataAddress, width: .qword)
                try state.writeRegister(.rcx, value: 5, width: .qword)
            },
            helperAddress: helperAddress
        )
        passed.append("LEA computes the guest effective address without a memory access")

        try compare(
            name: "PUSH RAX then POP RCX",
            bytes: [0x50, 0x59],
            initial: configuredState(rflags: 0x202) { state in
                try state.writeRegister(.rax, value: 0x7654_3210_FEDC_BA98, width: .qword)
                try state.writeRegister(.rsp, value: stackAddress, width: .qword)
            },
            helperAddress: helperAddress
        )
        passed.append("PUSH/POP update guest stack memory and RSP with interpreter-equivalent results")

        try compare(
            name: "16-bit PUSH AX then POP CX",
            bytes: [0x66, 0x50, 0x66, 0x59],
            initial: configuredState(rflags: 0x202) { state in
                try state.writeRegister(.rax, value: 0x1122_3344_5566_AABB, width: .qword)
                try state.writeRegister(.rcx, value: 0xFFFF_FFFF_FFFF_1234, width: .qword)
                try state.writeRegister(.rsp, value: stackAddress, width: .qword)
            },
            helperAddress: helperAddress
        )
        passed.append("16-bit PUSH/POP use two-byte stack adjustments and preserve upper register bits")

        try compare(
            name: "RET reads target and advances RSP",
            bytes: [0xC3],
            initial: configuredState(rflags: 0x202) { state in
                try state.writeRegister(.rsp, value: stackAddress, width: .qword)
            },
            helperAddress: helperAddress,
            expectedExit: .controlFlow,
            memorySetup: { memory in
                try memory.writeUnsigned(codeAddress + 0x500, at: stackAddress, width: .qword)
            }
        )
        passed.append("Guest RET reads the guest return address and exits to the dispatcher")

        try compare(
            name: "JZ takes the guest branch when ZF is set",
            bytes: [0x74, 0x02],
            initial: configuredState(rflags: 0x242) { _ in },
            helperAddress: helperAddress,
            expectedExit: .controlFlow
        )
        passed.append("Conditional branch evaluates x86 ZF and updates guest RIP")

        try compare(
            name: "JZ falls through when ZF is clear",
            bytes: [0x74, 0x02],
            initial: configuredState(rflags: 0x202) { _ in },
            helperAddress: helperAddress,
            expectedExit: .controlFlow
        )
        passed.append("Conditional branch fallthrough is returned as a dispatcher exit")

        try compare(
            name: "Relative CALL pushes return address and transfers RIP",
            bytes: [0xE8, 0x03, 0x00, 0x00, 0x00],
            initial: configuredState(rflags: 0x202) { state in
                try state.writeRegister(.rsp, value: stackAddress, width: .qword)
            },
            helperAddress: helperAddress,
            expectedExit: .controlFlow
        )
        passed.append("Relative CALL pushes the guest return address before dispatch")

        try compare(
            name: "Indirect CALL via RBX",
            bytes: [0xFF, 0xD3],
            initial: configuredState(rflags: 0x202) { state in
                try state.writeRegister(.rbx, value: codeAddress + 0x600, width: .qword)
                try state.writeRegister(.rsp, value: stackAddress, width: .qword)
            },
            helperAddress: helperAddress,
            expectedExit: .controlFlow
        )
        passed.append("Indirect CALL reads its target before pushing the guest return address")

        try compare(
            name: "Indirect CALL through guest memory",
            bytes: [0xFF, 0x13],
            initial: configuredState(rflags: 0x202) { state in
                try state.writeRegister(.rbx, value: dataAddress, width: .qword)
                try state.writeRegister(.rsp, value: stackAddress, width: .qword)
            },
            helperAddress: helperAddress,
            expectedExit: .controlFlow,
            memorySetup: { memory in
                try memory.writeUnsigned(codeAddress + 0x680, at: dataAddress, width: .qword)
            }
        )
        passed.append("Indirect CALL supports a bounded guest-memory target")

        try compare(
            name: "Indirect JMP via RBX",
            bytes: [0xFF, 0xE3],
            initial: configuredState(rflags: 0x202) { state in
                try state.writeRegister(.rbx, value: codeAddress + 0x700, width: .qword)
            },
            helperAddress: helperAddress,
            expectedExit: .controlFlow
        )
        passed.append("Indirect JMP reads the target and exits to the guest dispatcher")

        // Regression for the original bug: JBE (condition 6) must read ZF
        // from the original RFLAGS even after CF has already been extracted.
        // 0x842 has ZF=1, CF=0, OF=1; JBE must therefore be taken.
        try compare(
            name: "JBE reads ZF after extracting CF (RFLAGS 0x842 regression)",
            bytes: [0x76, 0x02],
            initial: configuredState(rflags: 0x842) { _ in },
            helperAddress: helperAddress,
            expectedExit: .controlFlow
        )
        passed.append("JBE compound predicate reads CF and ZF from the unmodified original RFLAGS")

        try compare(
            name: "TEST register operands and logical flags",
            bytes: [0x48, 0x85, 0xD8],
            initial: configuredState(rflags: 0xA13) { state in
                try state.writeRegister(.rax, value: 0xF0, width: .qword)
                try state.writeRegister(.rbx, value: 0x0F, width: .qword)
            },
            helperAddress: helperAddress
        )
        passed.append("TEST updates defined logical flags and leaves its destination untouched")

        try compare(
            name: "Group 1 AND immediate",
            bytes: [0x48, 0x83, 0xE0, 0x0F],
            initial: configuredState(rflags: 0x202) { state in
                try state.writeRegister(.rax, value: 0x1234, width: .qword)
            },
            helperAddress: helperAddress
        )
        passed.append("Group 1 AND register result and flags match the interpreter")

        try compare(
            name: "Group 3 NOT byte",
            bytes: [0xF6, 0xD0],
            initial: configuredState(rflags: 0xA13) { state in
                try state.writeRegister(.rax, value: 0x1122_3344_5566_AA00, width: .qword)
            },
            helperAddress: helperAddress
        )
        try compare(
            name: "Group 3 NEG byte",
            bytes: [0xF6, 0xD8],
            initial: configuredState(rflags: 0x202) { state in
                try state.writeRegister(.rax, value: 0x81, width: .qword)
            },
            helperAddress: helperAddress
        )
        passed.append("Group 3 NOT preserves flags and NEG matches subtraction flag semantics")

        try compare(
            name: "BT register immediate",
            bytes: [0x0F, 0xBA, 0xE0, 0x03],
            initial: configuredState(rflags: 0xA42) { state in
                try state.writeRegister(.rax, value: 0x08, width: .dword)
            },
            helperAddress: helperAddress
        )
        try compare(
            name: "BTS/BTR/BTC register immediate",
            bytes: [0x0F, 0xBA, 0xE8, 0x04, 0x0F, 0xBA, 0xF0, 0x04, 0x0F, 0xBA, 0xF8, 0x01],
            initial: configuredState(rflags: 0x202) { state in
                try state.writeRegister(.rax, value: 0x03, width: .dword)
            },
            helperAddress: helperAddress
        )
        passed.append("BT/BTS/BTR/BTC register operations update CF and data consistently")

        try compare(
            name: "BTS qword memory bit-string offset",
            bytes: [0x48, 0x0F, 0xBA, 0x2B, 0x41],
            initial: configuredState(rflags: 0x202) { state in
                try state.writeRegister(.rbx, value: dataAddress, width: .qword)
            },
            helperAddress: helperAddress,
            memorySetup: { memory in
                try memory.writeUnsigned(0x01, at: dataAddress + 8, width: .qword)
            }
        )
        passed.append("Memory bit-string index 65 addresses the next qword in both engines")

        try verifyAllConditionalBranches(helperAddress: helperAddress)
        passed.append("All 16 x86 conditional-branch predicates match the interpreter across four flag patterns")

        try verifyMemoryFault(helperAddress: helperAddress)
        passed.append("Out-of-range native guest-memory access returns a deterministic memory fault")

        try verifyControlFlowMustEndBlock()
        passed.append("Control-flow instructions are required to terminate a translated block")

        return passed
    }

    private static func compare(
        name: String,
        bytes: [UInt8],
        initial: X64CPUState,
        helperAddress: UInt64,
        expectedExit: X64ARM64BlockExit = .completed,
        memorySetup: ((inout X64GuestMemory) throws -> Void)? = nil
    ) throws {
        var initialMemory = try X64GuestMemory(baseAddress: guestBase, size: memorySize)
        try initialMemory.writeBytes(bytes, at: codeAddress)
        try memorySetup?(&initialMemory)

        var interpreter = X64Interpreter(state: initial, memory: initialMemory)
        let instructions = try X64ARM64CodeGenerator.decodeBlock(bytes, at: codeAddress)
        for _ in instructions {
            _ = try interpreter.step()
        }

        var nativeState = initial
        var nativeMemory = initialMemory
        let nativeResult = try X64ARM64Runtime.execute(instructions, state: &nativeState, memory: &nativeMemory)
        guard nativeResult.exit == expectedExit else {
            throw TestError.failed("\(name): expected exit \(expectedExit), got \(nativeResult.exit)")
        }
        try compareState(name: name, expected: interpreter.state, actual: nativeState)
        guard interpreter.memory.bytes == nativeMemory.bytes else {
            throw TestError.failed("\(name): native guest-memory bytes differ from interpreter")
        }
        _ = helperAddress // compile obtains the same helper through the C ABI.
    }

    private static func verifyAllConditionalBranches(helperAddress: UInt64) throws {
        let flagPatterns: [UInt64] = [
            0x2 | X64Flag.carry.mask | X64Flag.parity.mask | X64Flag.sign.mask,
            0x2 | X64Flag.zero.mask | X64Flag.overflow.mask,
            0x2 | X64Flag.sign.mask | X64Flag.overflow.mask | X64Flag.parity.mask,
            0x2 | X64Flag.carry.mask | X64Flag.zero.mask
        ]
        for condition in X64Condition.allCases {
            for flags in flagPatterns {
                let bytes: [UInt8] = [0x70 | condition.rawValue, 0x02]
                try compare(
                    name: "Jcc condition \(condition.rawValue), RFLAGS=0x\(String(flags, radix: 16))",
                    bytes: bytes,
                    initial: configuredState(rflags: flags) { _ in },
                    helperAddress: helperAddress,
                    expectedExit: .controlFlow
                )
            }
        }
    }

    private static func verifyMemoryFault(helperAddress: UInt64) throws {
        var memory = try X64GuestMemory(baseAddress: guestBase, size: memorySize)
        let bytes: [UInt8] = [0x48, 0x8B, 0x03] // mov rax, [rbx]
        try memory.writeBytes(bytes, at: codeAddress)
        let initial = configuredState(rflags: 0x202) { state in
            try state.writeRegister(.rbx, value: guestBase + UInt64(memorySize - 4), width: .qword)
        }
        var interpreter = X64Interpreter(state: initial, memory: memory)
        do {
            _ = try interpreter.step()
            throw TestError.failed("interpreter unexpectedly accepted a qword read crossing the memory boundary")
        } catch is X64GuestMemoryError {
            // Expected reference fault.
        }

        var nativeState = initial
        let instructions = try X64ARM64CodeGenerator.decodeBlock(bytes, at: codeAddress)
        let result = try X64ARM64Runtime.execute(instructions, state: &nativeState, memory: &memory)
        guard result.exit == .memoryFault else {
            throw TestError.failed("native memory boundary test expected memoryFault, got \(result.exit)")
        }
        try compareState(name: "memory boundary fault", expected: initial, actual: nativeState)
        _ = helperAddress
    }

    private static func verifyControlFlowMustEndBlock() throws {
        let bytes: [UInt8] = [0x74, 0x02, 0x90] // JZ followed by NOP is not one basic block.
        let instructions = try X64ARM64CodeGenerator.decodeBlock(bytes, at: codeAddress)
        do {
            _ = try X64ARM64CodeGenerator.compile(instructions, flagHelperAddress: 1)
            throw TestError.failed("compiler accepted a control-flow terminator followed by another instruction")
        } catch X64ARM64CodeGenerator.CodegenError.controlFlowMustTerminateBlock {
            // Expected: the dispatcher must split the block at the branch.
        }
    }

    private static func compareState(name: String, expected: X64CPUState, actual: X64CPUState) throws {
        for register in X64GeneralRegister.allCases {
            let expectedValue = expected.registerValue(register)
            let actualValue = actual.registerValue(register)
            guard expectedValue == actualValue else {
                throw TestError.failed("\(name): \(register.name) expected 0x\(String(expectedValue, radix: 16)), got 0x\(String(actualValue, radix: 16))")
            }
        }
        guard expected.rip == actual.rip else {
            throw TestError.failed("\(name): RIP expected 0x\(String(expected.rip, radix: 16)), got 0x\(String(actual.rip, radix: 16))")
        }
        guard expected.rflags == actual.rflags else {
            throw TestError.failed("\(name): RFLAGS expected 0x\(String(expected.rflags, radix: 16)), got 0x\(String(actual.rflags, radix: 16))")
        }
    }

    private static func configuredState(
        rflags: UInt64,
        _ configure: (inout X64CPUState) throws -> Void
    ) -> X64CPUState {
        var state = X64CPUState(rip: codeAddress, rflags: rflags)
        try? configure(&state)
        return state
    }
}
