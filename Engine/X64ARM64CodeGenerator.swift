import Foundation

/// Lowers the currently supported x86-64 semantic IR subset into native
/// AArch64 basic blocks. Guest memory is accessed through a pinned sparse
/// page-table view and native helpers that enforce per-page permissions;
/// guest virtual addresses are never used as host pointers.
enum X64ARM64CodeGenerator {
    enum CodegenError: LocalizedError {
        case emptyBlock
        case nonContiguousBlock(expected: UInt64, actual: UInt64)
        case unsupportedInstruction(address: UInt64, reason: String)
        case missingFlagHelper
        case controlFlowMustTerminateBlock(address: UInt64)

        var errorDescription: String? {
            switch self {
            case .emptyBlock:
                return "Cannot compile an empty x86_64 basic block."
            case .nonContiguousBlock(let expected, let actual):
                return String(format: "Non-contiguous IR block: expected guest address 0x%016llX, got 0x%016llX.", expected, actual)
            case .unsupportedInstruction(let address, let reason):
                return String(format: "AArch64 backend does not support instruction at 0x%016llX: %@", address, reason)
            case .missingFlagHelper:
                return "The native x86 flag-update helper address is unavailable."
            case .controlFlowMustTerminateBlock(let address):
                return String(format: "Control-flow instruction at 0x%016llX must terminate its translated block.", address)
            }
        }
    }

    private static let contextRegister: UInt32 = 19
    private static let guestMemoryRegister: UInt32 = 20
    private static let savedLHSRegister: UInt32 = 23
    private static let savedResultRegister: UInt32 = 24
    private static let lhsRegister: UInt32 = 9
    private static let rhsRegister: UInt32 = 10
    private static let scratchRegister: UInt32 = 11
    private static let valueScratchRegister: UInt32 = 12
    private static let hostPointerRegister: UInt32 = 13
    // Preserve the original guest RFLAGS while extracting multiple bits for
    // compound conditions (BE/A, L/GE, LE/G). x9-x11 are scratch outputs.
    private static let conditionFlagsRegister: UInt32 = 14
    private static let ripWordOffset: UInt32 = 16 * 8
    private static let rflagsWordOffset: UInt32 = 17 * 8

    private struct Fixup {
        let instructionIndex: Int
        let targetIndex: Int
    }

    private struct OutputState {
        var words: [UInt32] = []
        var memoryFaultBranches: [Int] = []
        var controlExitBranches: [Int] = []
        var systemCallExitBranches: [Int] = []
        var guestMemoryReadHelperAddress: UInt64 = 0
        var guestMemoryWriteHelperAddress: UInt64 = 0
        var guestMemoryFaultOffset: UInt32 = 0
    }

    static func decodeBlock(_ bytes: [UInt8], at startAddress: UInt64) throws -> [X64IRInstruction] {
        guard !bytes.isEmpty else { throw CodegenError.emptyBlock }
        let decoder = X64InstructionDecoder()
        var result: [X64IRInstruction] = []
        var offset = 0
        while offset < bytes.count {
            let decoded = try decoder.decode(Array(bytes[offset...]), at: startAddress &+ UInt64(offset))
            result.append(try decoded.lowerToIR())
            offset += decoded.length
        }
        return result
    }

    /// The generated entry point has the C ABI:
    /// int block(uint64_t *gprRipRflags, KestrelGuestMemoryView *memoryView)
    /// It returns 0 for ordinary block completion, 1 for a guest control-flow
    /// exit requiring redispatch, and 2 for a guest page-table memory fault.
    static func compile(
        _ instructions: [X64IRInstruction],
        flagHelperAddress: UInt64,
        guestMemoryReadHelperAddress: UInt64 = 1,
        guestMemoryWriteHelperAddress: UInt64 = 1,
        guestMemoryFaultOffset: UInt32 = 40
    ) throws -> [UInt32] {
        guard !instructions.isEmpty else { throw CodegenError.emptyBlock }
        let needsFlagHelper = instructions.contains { instruction in
            switch instruction.operation {
            case .add, .subtract, .compare, .bitwiseXor: return true
            default: return false
            }
        }
        if needsFlagHelper && flagHelperAddress == 0 { throw CodegenError.missingFlagHelper }

        var expectedAddress = instructions[0].address
        for (index, instruction) in instructions.enumerated() {
            guard instruction.address == expectedAddress else {
                throw CodegenError.nonContiguousBlock(expected: expectedAddress, actual: instruction.address)
            }
            if isControlFlow(instruction.operation) && index != instructions.count - 1 {
                throw CodegenError.controlFlowMustTerminateBlock(address: instruction.address)
            }
            expectedAddress = instruction.nextAddress
        }

        var state = OutputState(
            guestMemoryReadHelperAddress: guestMemoryReadHelperAddress,
            guestMemoryWriteHelperAddress: guestMemoryWriteHelperAddress,
            guestMemoryFaultOffset: guestMemoryFaultOffset
        )
        emitPrologue(into: &state.words)

        for instruction in instructions {
            try emit(instruction, helperAddress: flagHelperAddress, state: &state)
        }

        // Normal fallthrough, guest control-flow dispatch, and a memory fault
        // use distinct exits. Faulting instructions leave guest RIP unchanged.
        emitEpilogue(status: 0, into: &state.words)
        let controlExitIndex = state.words.count
        emitEpilogue(status: 1, into: &state.words)
        let memoryFaultIndex = state.words.count
        emitEpilogue(status: 2, into: &state.words)
        let systemCallExitIndex = state.words.count
        emitEpilogue(status: 4, into: &state.words)

        for branch in state.controlExitBranches {
            try patchB(at: branch, to: controlExitIndex, words: &state.words)
        }
        for branch in state.memoryFaultBranches {
            try patchBCond(at: branch, to: memoryFaultIndex, words: &state.words)
        }
        for branch in state.systemCallExitBranches {
            try patchB(at: branch, to: systemCallExitIndex, words: &state.words)
        }
        return state.words
    }

    private static func isControlFlow(_ operation: X64IROperation) -> Bool {
        switch operation {
        case .returnFromFunction, .branchRelative, .callRelative, .callIndirect, .branchIndirect, .conditionalBranch, .systemCall:
            return true
        default:
            return false
        }
    }

    private static func emitPrologue(into words: inout [UInt32]) {
        // Preserve frame pointer/LR and every callee-saved register used here.
        words.append(0xA9BF_7BFD) // STP x29, x30, [sp, #-16]!
        words.append(0xA9BF_53F3) // STP x19, x20, [sp, #-16]!
        words.append(0xA9BF_5BF5) // STP x21, x22, [sp, #-16]!
        words.append(0xA9BF_63F7) // STP x23, x24, [sp, #-16]!
        words.append(0xAA00_03F3) // MOV x19, x0 (guest context)
        words.append(0xAA01_03F4) // MOV x20, x1 (sparse guest-memory view)
    }

    private static func emitEpilogue(status: UInt32, into words: inout [UInt32]) {
        words.append(0xA8C1_63F7) // LDP x23, x24, [sp], #16
        words.append(0xA8C1_5BF5) // LDP x21, x22, [sp], #16
        words.append(0xA8C1_53F3) // LDP x19, x20, [sp], #16
        words.append(0xA8C1_7BFD) // LDP x29, x30, [sp], #16
        words.append(0x5280_0000 | ((status & 0xFFFF) << 5)) // MOV w0, #status
        words.append(0xD65F_03C0) // RET to native dispatcher
    }

    private static func emit(
        _ instruction: X64IRInstruction,
        helperAddress: UInt64,
        state: inout OutputState
    ) throws {
        switch instruction.operation {
        case .move:
            guard let destination = instruction.destination,
                  let source = instruction.source,
                  let width = instruction.width else {
                throw unsupported(instruction, "MOV requires destination, source, and width")
            }
            try emitRead(
                source, width: width, into: lhsRegister, instruction: instruction, state: &state
            )
            try emitWrite(
                lhsRegister, to: destination, width: width, instruction: instruction, state: &state
            )

        case .add, .subtract, .compare, .bitwiseXor:
            guard let destination = instruction.destination,
                  let source = instruction.source,
                  let width = instruction.width else {
                throw unsupported(instruction, "integer operation requires destination, source, and width")
            }
            try emitRead(
                destination, width: width, into: lhsRegister, instruction: instruction, state: &state
            )
            state.words.append(encodeMOVRegister(rd: savedLHSRegister, rn: lhsRegister, is64Bit: true))
            try emitRead(
                source, width: width, into: rhsRegister, instruction: instruction, state: &state
            )
            state.words.append(encodeMOVRegister(rd: lhsRegister, rn: savedLHSRegister, is64Bit: true))

            let is64Bit = width == .qword
            switch instruction.operation {
            case .add:
                state.words.append(encodeAdd(rd: lhsRegister, rn: lhsRegister, rm: rhsRegister, is64Bit: is64Bit))
            case .subtract, .compare:
                state.words.append(encodeSub(rd: lhsRegister, rn: lhsRegister, rm: rhsRegister, is64Bit: is64Bit))
            case .bitwiseXor:
                state.words.append(encodeEor(rd: lhsRegister, rn: lhsRegister, rm: rhsRegister, is64Bit: is64Bit))
            default: break
            }
            if width != .qword {
                state.words.append(encodeUBFX(rd: lhsRegister, rn: lhsRegister, lsb: 0, width: width.bitCount))
            }
            state.words.append(encodeMOVRegister(rd: savedResultRegister, rn: lhsRegister, is64Bit: true))

            let flagKind: UInt32
            switch instruction.operation {
            case .add: flagKind = 0
            case .subtract, .compare: flagKind = 1
            case .bitwiseXor: flagKind = 2
            default: flagKind = 0
            }
            emitFlagHelper(
                helperAddress: helperAddress,
                lhs: savedLHSRegister,
                rhs: rhsRegister,
                result: savedResultRegister,
                width: UInt32(width.bitCount),
                kind: flagKind,
                into: &state.words
            )
            if instruction.operation != .compare {
                try emitWrite(
                    savedResultRegister, to: destination, width: width, instruction: instruction, state: &state
                )
            }

        case .exchange:
            guard let destination = instruction.destination,
                  let source = instruction.source,
                  let width = instruction.width else {
                throw unsupported(instruction, "XCHG requires two operands and a width")
            }
            if case .memory = destination {
                throw unsupported(instruction, "memory XCHG is implicitly atomic and is deferred until atomic guest-memory operations are implemented")
            }
            try emitRead(destination, width: width, into: savedLHSRegister, instruction: instruction, state: &state)
            try emitRead(source, width: width, into: savedResultRegister, instruction: instruction, state: &state)
            try emitWrite(savedResultRegister, to: destination, width: width, instruction: instruction, state: &state)
            try emitWrite(savedLHSRegister, to: source, width: width, instruction: instruction, state: &state)

        case .loadEffectiveAddress:
            guard let destination = instruction.destination,
                  let source = instruction.source,
                  let width = instruction.width,
                  case .memory(let memory) = source,
                  case .register = destination else {
                throw unsupported(instruction, "LEA requires a register destination and memory-form source")
            }
            try emitEffectiveAddress(memory, instruction: instruction, into: lhsRegister, state: &state)
            try emitWrite(lhsRegister, to: destination, width: width, instruction: instruction, state: &state)

        case .noOperation, .pause:
            state.words.append(0xD503_201F) // NOP

        case .push:
            guard let source = instruction.source, let width = instruction.width else {
                throw unsupported(instruction, "PUSH requires a source and width")
            }
            // Read the source before changing RSP (notably PUSH RSP).
            try emitRead(source, width: width, into: savedResultRegister, instruction: instruction, state: &state)
            try emitStackPush(valueRegister: savedResultRegister, width: width, instruction: instruction, state: &state)

        case .pop:
            guard let destination = instruction.destination, let width = instruction.width else {
                throw unsupported(instruction, "POP requires a destination and width")
            }
            try emitStackPop(width: width, into: savedResultRegister, instruction: instruction, state: &state)
            // POP r/m computes an RSP-based effective address after RSP was incremented.
            try emitWrite(savedResultRegister, to: destination, width: width, instruction: instruction, state: &state)

        case .returnFromFunction(let stackAdjustment):
            try emitStackPop(width: .qword, into: savedResultRegister, instruction: instruction, state: &state)
            if stackAdjustment != 0 {
                state.words.append(encodeLDRX(rt: lhsRegister, offset: UInt32(X64GeneralRegister.rsp.rawValue * 8)))
                emitAddImmediate(rd: lhsRegister, rn: lhsRegister, immediate: UInt32(stackAdjustment), into: &state.words)
                state.words.append(encodeSTRX(rt: lhsRegister, offset: UInt32(X64GeneralRegister.rsp.rawValue * 8)))
            }
            emitGuestRIP(from: savedResultRegister, into: &state.words)
            state.controlExitBranches.append(emitBPlaceholder(into: &state.words))
            return

        case .branchRelative(let displacement):
            let target = instruction.nextAddress &+ UInt64(bitPattern: displacement)
            emitGuestRIP(target, into: &state.words)
            state.controlExitBranches.append(emitBPlaceholder(into: &state.words))
            return

        case .callRelative(let displacement):
            emitLoadConstant(instruction.nextAddress, into: savedResultRegister, output: &state.words)
            try emitStackPush(valueRegister: savedResultRegister, width: .qword, instruction: instruction, state: &state)
            emitGuestRIP(instruction.nextAddress &+ UInt64(bitPattern: displacement), into: &state.words)
            state.controlExitBranches.append(emitBPlaceholder(into: &state.words))
            return

        case .callIndirect:
            guard let source = instruction.source else { throw unsupported(instruction, "indirect CALL requires a source") }
            // The target is read before CALL pushes the return address.
            try emitRead(source, width: .qword, into: savedResultRegister, instruction: instruction, state: &state)
            emitLoadConstant(instruction.nextAddress, into: valueScratchRegister, output: &state.words)
            try emitStackPush(valueRegister: valueScratchRegister, width: .qword, instruction: instruction, state: &state)
            emitGuestRIP(from: savedResultRegister, into: &state.words)
            state.controlExitBranches.append(emitBPlaceholder(into: &state.words))
            return

        case .branchIndirect:
            guard let source = instruction.source else { throw unsupported(instruction, "indirect JMP requires a source") }
            try emitRead(source, width: .qword, into: savedResultRegister, instruction: instruction, state: &state)
            emitGuestRIP(from: savedResultRegister, into: &state.words)
            state.controlExitBranches.append(emitBPlaceholder(into: &state.words))
            return

        case .systemCall:
            emitGuestRIP(instruction.nextAddress, into: &state.words)
            state.systemCallExitBranches.append(emitBPlaceholder(into: &state.words))
            return

        case .conditionalBranch(let condition, let displacement):
            let target = instruction.nextAddress &+ UInt64(bitPattern: displacement)
            let branchToTaken = try emitConditionTrueBranch(condition, into: &state.words)
            emitGuestRIP(instruction.nextAddress, into: &state.words)
            state.controlExitBranches.append(emitBPlaceholder(into: &state.words))
            let takenIndex = state.words.count
            try patchBCond(at: branchToTaken, to: takenIndex, words: &state.words)
            emitGuestRIP(target, into: &state.words)
            state.controlExitBranches.append(emitBPlaceholder(into: &state.words))
            return
        }

        emitGuestRIP(instruction.nextAddress, into: &state.words)
    }

    private static func emitRead(
        _ value: X64IRValue,
        width: X64OperandWidth,
        into target: UInt32,
        instruction: X64IRInstruction,
        state: inout OutputState
    ) throws {
        switch value {
        case .register(let operand):
            state.words.append(encodeLDRX(rt: target, offset: UInt32(operand.register.rawValue * 8)))
            let lsb = operand.highByte ? 8 : 0
            if lsb != 0 || width != .qword {
                state.words.append(encodeUBFX(rd: target, rn: target, lsb: lsb, width: width.bitCount))
            }
        case .immediate(let immediate, _):
            emitLoadConstant(immediate & width.mask, into: target, output: &state.words)
        case .memory(let operand):
            try emitEffectiveAddress(operand, instruction: instruction, into: lhsRegister, state: &state)
            try emitGuestMemoryRead(
                addressRegister: lhsRegister,
                byteCount: UInt32(width.bitCount / 8),
                into: target,
                helperAddress: state.guestMemoryReadHelperAddress,
                faultOffset: state.guestMemoryFaultOffset,
                state: &state
            )
        }
    }

    private static func emitWrite(
        _ sourceRegister: UInt32,
        to destination: X64IRValue,
        width: X64OperandWidth,
        instruction: X64IRInstruction,
        state: inout OutputState
    ) throws {
        switch destination {
        case .register(let operand):
            emitWriteRegister(sourceRegister, to: operand, into: &state.words)
        case .memory(let operand):
            // Preserve the value while effective-address calculation uses x9-x12.
            state.words.append(encodeMOVRegister(rd: valueScratchRegister, rn: sourceRegister, is64Bit: true))
            try emitEffectiveAddress(operand, instruction: instruction, into: lhsRegister, state: &state)
            try emitGuestMemoryWrite(
                addressRegister: lhsRegister,
                valueRegister: valueScratchRegister,
                byteCount: UInt32(width.bitCount / 8),
                helperAddress: state.guestMemoryWriteHelperAddress,
                faultOffset: state.guestMemoryFaultOffset,
                state: &state
            )
        case .immediate:
            throw unsupported(instruction, "cannot write to an immediate operand")
        }
    }

    private static func emitWriteRegister(_ source: UInt32, to destination: X64RegisterOperand, into words: inout [UInt32]) {
        let contextOffset = UInt32(destination.register.rawValue * 8)
        switch destination.width {
        case .qword:
            words.append(encodeSTRX(rt: source, offset: contextOffset))
        case .dword:
            // A 32-bit x86 GPR write clears the upper half of its 64-bit GPR.
            words.append(encodeUBFX(rd: source, rn: source, lsb: 0, width: 32))
            words.append(encodeSTRX(rt: source, offset: contextOffset))
        case .word, .byte:
            words.append(encodeLDRX(rt: scratchRegister, offset: contextOffset))
            let lsb = destination.highByte ? 8 : 0
            words.append(encodeBFI(rd: scratchRegister, rn: source, lsb: lsb, width: destination.width.bitCount))
            words.append(encodeSTRX(rt: scratchRegister, offset: contextOffset))
        }
    }

    private static func emitEffectiveAddress(
        _ operand: X64MemoryOperand,
        instruction: X64IRInstruction,
        into target: UInt32,
        state: inout OutputState
    ) throws {
        if let segment = operand.segmentOverride, segment == 0x64 || segment == 0x65 {
            throw unsupported(instruction, String(format: "FS/GS segment-base addressing (prefix 0x%02X) is not implemented", segment))
        }

        if operand.ripRelative {
            emitLoadConstant(instruction.nextAddress, into: target, output: &state.words)
        } else if let base = operand.base {
            state.words.append(encodeLDRX(rt: target, offset: UInt32(base.rawValue * 8)))
        } else {
            emitLoadConstant(0, into: target, output: &state.words)
        }

        if let index = operand.index {
            state.words.append(encodeLDRX(rt: rhsRegister, offset: UInt32(index.rawValue * 8)))
            switch operand.scale {
            case 1: break
            case 2, 4, 8:
                let shift = operand.scale == 2 ? 1 : (operand.scale == 4 ? 2 : 3)
                state.words.append(encodeLSL(rd: rhsRegister, rn: rhsRegister, shift: shift))
            default:
                throw unsupported(instruction, "invalid SIB scale \(operand.scale)")
            }
            state.words.append(encodeAdd(rd: target, rn: target, rm: rhsRegister, is64Bit: true))
        }

        if operand.displacement != 0 {
            emitLoadConstant(UInt64(bitPattern: operand.displacement), into: scratchRegister, output: &state.words)
            state.words.append(encodeAdd(rd: target, rn: target, rm: scratchRegister, is64Bit: true))
        }
        if operand.addressWidth == .dword {
            state.words.append(encodeUBFX(rd: target, rn: target, lsb: 0, width: 32))
        }
    }

    /// Calls the native C page-table helper. x20 is the pinned sparse page
    /// table; the helper validates every participating page and permission.
    private static func emitGuestMemoryRead(
        addressRegister: UInt32,
        byteCount: UInt32,
        into target: UInt32,
        helperAddress: UInt64,
        faultOffset: UInt32,
        state: inout OutputState
    ) throws {
        guard (1...8).contains(byteCount), helperAddress != 0, faultOffset <= 0xFFF else {
            throw CodegenError.unsupportedInstruction(address: 0, reason: "invalid native guest-memory read helper configuration")
        }
        emitLoadConstant(helperAddress, into: 16, output: &state.words)
        state.words.append(encodeMOVRegister(rd: 0, rn: 20, is64Bit: true)) // view
        state.words.append(encodeMOVRegister(rd: 1, rn: addressRegister, is64Bit: true)) // guest address
        state.words.append(0x5280_0002 | ((byteCount & 0xFFFF) << 5)) // MOV w2, #width
        state.words.append(0xD63F_0200) // BLR x16
        state.words.append(encodeLDRW(rt: scratchRegister, offset: faultOffset))
        state.words.append(encodeCMPImmediate(rn: scratchRegister, immediate: 0))
        state.memoryFaultBranches.append(emitBCondPlaceholder(condition: 1, into: &state.words)) // NE: helper fault
        if target != 0 {
            state.words.append(encodeMOVRegister(rd: target, rn: 0, is64Bit: true)) // result in x0
        }
    }

    private static func emitGuestMemoryWrite(
        addressRegister: UInt32,
        valueRegister: UInt32,
        byteCount: UInt32,
        helperAddress: UInt64,
        faultOffset: UInt32,
        state: inout OutputState
    ) throws {
        guard (1...8).contains(byteCount), helperAddress != 0, faultOffset <= 0xFFF else {
            throw CodegenError.unsupportedInstruction(address: 0, reason: "invalid native guest-memory write helper configuration")
        }
        emitLoadConstant(helperAddress, into: 16, output: &state.words)
        state.words.append(encodeMOVRegister(rd: 0, rn: 20, is64Bit: true)) // view
        state.words.append(encodeMOVRegister(rd: 1, rn: addressRegister, is64Bit: true)) // guest address
        state.words.append(encodeMOVRegister(rd: 2, rn: valueRegister, is64Bit: true)) // value
        state.words.append(0x5280_0003 | ((byteCount & 0xFFFF) << 5)) // MOV w3, #width
        state.words.append(0xD63F_0200) // BLR x16
        state.words.append(encodeLDRW(rt: scratchRegister, offset: faultOffset))
        state.words.append(encodeCMPImmediate(rn: scratchRegister, immediate: 0))
        state.memoryFaultBranches.append(emitBCondPlaceholder(condition: 1, into: &state.words)) // NE: helper fault
    }

    private static func emitStackPush(
        valueRegister: UInt32,
        width: X64OperandWidth,
        instruction: X64IRInstruction,
        state: inout OutputState
    ) throws {
        state.words.append(encodeMOVRegister(rd: valueScratchRegister, rn: valueRegister, is64Bit: true))
        state.words.append(encodeLDRX(rt: lhsRegister, offset: UInt32(X64GeneralRegister.rsp.rawValue * 8)))
        emitSubImmediate(rd: lhsRegister, rn: lhsRegister, immediate: UInt32(width.bitCount / 8), into: &state.words)
        // Keep the new RSP in callee-saved x23 across the C helper call.
        state.words.append(encodeMOVRegister(rd: savedLHSRegister, rn: lhsRegister, is64Bit: true))
        // Validate the new stack address before changing architectural RSP.
        try emitGuestMemoryWrite(
            addressRegister: savedLHSRegister,
            valueRegister: valueScratchRegister,
            byteCount: UInt32(width.bitCount / 8),
            helperAddress: state.guestMemoryWriteHelperAddress,
            faultOffset: state.guestMemoryFaultOffset,
            state: &state
        )
        state.words.append(encodeSTRX(rt: savedLHSRegister, offset: UInt32(X64GeneralRegister.rsp.rawValue * 8)))
        _ = instruction
    }

    private static func emitStackPop(
        width: X64OperandWidth,
        into target: UInt32,
        instruction: X64IRInstruction,
        state: inout OutputState
    ) throws {
        state.words.append(encodeLDRX(rt: lhsRegister, offset: UInt32(X64GeneralRegister.rsp.rawValue * 8)))
        try emitGuestMemoryRead(
            addressRegister: lhsRegister,
            byteCount: UInt32(width.bitCount / 8),
            into: target,
            helperAddress: state.guestMemoryReadHelperAddress,
            faultOffset: state.guestMemoryFaultOffset,
            state: &state
        )
        // Reload RSP from guest context before updating it.
        state.words.append(encodeLDRX(rt: lhsRegister, offset: UInt32(X64GeneralRegister.rsp.rawValue * 8)))
        emitAddImmediate(rd: lhsRegister, rn: lhsRegister, immediate: UInt32(width.bitCount / 8), into: &state.words)
        state.words.append(encodeSTRX(rt: lhsRegister, offset: UInt32(X64GeneralRegister.rsp.rawValue * 8)))
        _ = instruction
    }

    private static func emitGuestRIP(_ rip: UInt64, into words: inout [UInt32]) {
        emitLoadConstant(rip, into: lhsRegister, output: &words)
        words.append(encodeSTRX(rt: lhsRegister, offset: ripWordOffset))
    }

    private static func emitGuestRIP(from register: UInt32, into words: inout [UInt32]) {
        words.append(encodeSTRX(rt: register, offset: ripWordOffset))
    }

    private static func emitFlagHelper(
        helperAddress: UInt64,
        lhs: UInt32,
        rhs: UInt32,
        result: UInt32,
        width: UInt32,
        kind: UInt32,
        into words: inout [UInt32]
    ) {
        words.append(encodeMOVRegister(rd: 0, rn: contextRegister, is64Bit: true))
        words.append(encodeMOVRegister(rd: 1, rn: lhs, is64Bit: true))
        words.append(encodeMOVRegister(rd: 2, rn: rhs, is64Bit: true))
        words.append(encodeMOVRegister(rd: 3, rn: result, is64Bit: true))
        words.append(0x5280_0004 | ((width & 0xFFFF) << 5)) // MOV w4, #width
        words.append(0x5280_0005 | ((kind & 0xFFFF) << 5))  // MOV w5, #kind
        let needsPadding = words.count.isMultiple(of: 2)
        words.append(needsPadding ? 0x5800_0090 : 0x5800_0070) // LDR x16, aligned literal
        words.append(0xD63F_0200) // BLR x16
        words.append(needsPadding ? 0x1400_0004 : 0x1400_0003) // B over literal
        if needsPadding { words.append(0xD503_201F) }
        words.append(UInt32(truncatingIfNeeded: helperAddress))
        words.append(UInt32(truncatingIfNeeded: helperAddress >> 32))
    }

    private static func emitConditionTrueBranch(_ condition: X64Condition, into words: inout [UInt32]) throws -> Int {
        // Compound x86 conditions need two or three *original* RFLAGS bits.
        // Do not extract the next bit from lhsRegister: it is overwritten by
        // the preceding UBFX. x14 is caller-saved and remains dedicated to the
        // immutable flag snapshot throughout this predicate calculation.
        words.append(encodeLDRX(rt: conditionFlagsRegister, offset: rflagsWordOffset))
        func flag(_ bit: Int, _ destination: UInt32) {
            words.append(encodeUBFX(rd: destination, rn: conditionFlagsRegister, lsb: bit, width: 1))
        }
        func invert(_ register: UInt32) {
            emitLoadConstant(1, into: scratchRegister, output: &words)
            words.append(encodeEor(rd: register, rn: register, rm: scratchRegister, is64Bit: true))
        }

        switch condition {
        case .overflow, .notOverflow: flag(11, lhsRegister); if condition == .notOverflow { invert(lhsRegister) }
        case .below, .aboveOrEqual: flag(0, lhsRegister); if condition == .aboveOrEqual { invert(lhsRegister) }
        case .equal, .notEqual: flag(6, lhsRegister); if condition == .notEqual { invert(lhsRegister) }
        case .sign, .notSign: flag(7, lhsRegister); if condition == .notSign { invert(lhsRegister) }
        case .parity, .notParity: flag(2, lhsRegister); if condition == .notParity { invert(lhsRegister) }
        case .belowOrEqual, .above:
            flag(0, lhsRegister); flag(6, rhsRegister)
            words.append(encodeORRRegister(rd: lhsRegister, rn: lhsRegister, rm: rhsRegister))
            if condition == .above { invert(lhsRegister) }
        case .less, .greaterOrEqual:
            flag(7, lhsRegister); flag(11, rhsRegister)
            words.append(encodeEor(rd: lhsRegister, rn: lhsRegister, rm: rhsRegister, is64Bit: true))
            if condition == .greaterOrEqual { invert(lhsRegister) }
        case .lessOrEqual, .greater:
            flag(7, lhsRegister); flag(11, rhsRegister)
            words.append(encodeEor(rd: lhsRegister, rn: lhsRegister, rm: rhsRegister, is64Bit: true))
            flag(6, scratchRegister)
            words.append(encodeORRRegister(rd: lhsRegister, rn: lhsRegister, rm: scratchRegister))
            if condition == .greater { invert(lhsRegister) }
        }
        words.append(encodeCMPImmediate(rn: lhsRegister, immediate: 0))
        return emitBCondPlaceholder(condition: 1, into: &words) // NE: condition true
    }

    private static func emitLoadConstant(_ value: UInt64, into register: UInt32, output: inout [UInt32]) {
        var chunks: [(Int, UInt16)] = []
        for shift in stride(from: 0, through: 48, by: 16) {
            let chunk = UInt16(truncatingIfNeeded: value >> shift)
            if chunk != 0 { chunks.append((shift / 16, chunk)) }
        }
        if chunks.isEmpty {
            output.append(0xD280_0000 | register) // MOVZ Xd, #0
            return
        }
        let first = chunks.removeFirst()
        output.append(0xD280_0000 | (UInt32(first.0) << 21) | (UInt32(first.1) << 5) | register)
        for (halfword, chunk) in chunks {
            output.append(0xF280_0000 | (UInt32(halfword) << 21) | (UInt32(chunk) << 5) | register)
        }
    }

    private static func emitAddImmediate(rd: UInt32, rn: UInt32, immediate: UInt32, into words: inout [UInt32]) {
        if immediate <= 4095 {
            words.append(0x9100_0000 | (immediate << 10) | (rn << 5) | rd) // ADD Xd, Xn, #imm
        } else {
            emitLoadConstant(UInt64(immediate), into: scratchRegister, output: &words)
            words.append(encodeAdd(rd: rd, rn: rn, rm: scratchRegister, is64Bit: true))
        }
    }

    private static func emitSubImmediate(rd: UInt32, rn: UInt32, immediate: UInt32, into words: inout [UInt32]) {
        if immediate <= 4095 {
            words.append(0xD100_0000 | (immediate << 10) | (rn << 5) | rd) // SUB Xd, Xn, #imm
        } else {
            emitLoadConstant(UInt64(immediate), into: scratchRegister, output: &words)
            words.append(encodeSub(rd: rd, rn: rn, rm: scratchRegister, is64Bit: true))
        }
    }

    private static func emitBPlaceholder(into words: inout [UInt32]) -> Int {
        let index = words.count
        words.append(0x1400_0000)
        return index
    }

    private static func emitBCondPlaceholder(condition: UInt32, into words: inout [UInt32]) -> Int {
        let index = words.count
        words.append(0x5400_0000 | (condition & 0xF))
        return index
    }

    private static func patchB(at index: Int, to target: Int, words: inout [UInt32]) throws {
        let delta = target - index
        guard delta >= -(1 << 25), delta < (1 << 25) else {
            throw CodegenError.unsupportedInstruction(address: 0, reason: "generated block branch exceeds AArch64 B range")
        }
        words[index] = 0x1400_0000 | (UInt32(bitPattern: Int32(delta)) & 0x03FF_FFFF)
    }

    private static func patchBCond(at index: Int, to target: Int, words: inout [UInt32]) throws {
        let delta = target - index
        guard delta >= -(1 << 18), delta < (1 << 18) else {
            throw CodegenError.unsupportedInstruction(address: 0, reason: "generated conditional branch exceeds AArch64 B.cond range")
        }
        let condition = words[index] & 0xF
        words[index] = 0x5400_0000 | ((UInt32(bitPattern: Int32(delta)) & 0x7_FFFF) << 5) | condition
    }

    private static func encodeLoadMemory(rt: UInt32, rn: UInt32, width: X64OperandWidth) -> UInt32 {
        switch width {
        case .byte: return 0x3940_0000 | (rn << 5) | rt // LDRB Wt, [Xn]
        case .word: return 0x7940_0000 | (rn << 5) | rt // LDRH Wt, [Xn]
        case .dword: return 0xB940_0000 | (rn << 5) | rt // LDR Wt, [Xn]
        case .qword: return 0xF940_0000 | (rn << 5) | rt // LDR Xt, [Xn]
        }
    }

    private static func encodeStoreMemory(rt: UInt32, rn: UInt32, width: X64OperandWidth) -> UInt32 {
        switch width {
        case .byte: return 0x3900_0000 | (rn << 5) | rt // STRB Wt, [Xn]
        case .word: return 0x7900_0000 | (rn << 5) | rt // STRH Wt, [Xn]
        case .dword: return 0xB900_0000 | (rn << 5) | rt // STR Wt, [Xn]
        case .qword: return 0xF900_0000 | (rn << 5) | rt // STR Xt, [Xn]
        }
    }

    private static func encodeLDRW(rt: UInt32, offset: UInt32) -> UInt32 {
        precondition(offset % 4 == 0 && offset <= 16_380)
        return 0xB940_0000 | ((offset / 4) << 10) | (20 << 5) | rt // LDR Wt, [X20, #offset]
    }

    private static func encodeLDRX(rt: UInt32, offset: UInt32) -> UInt32 {
        0xF940_0000 | ((offset / 8) << 10) | (contextRegister << 5) | rt
    }

    private static func encodeSTRX(rt: UInt32, offset: UInt32) -> UInt32 {
        0xF900_0000 | ((offset / 8) << 10) | (contextRegister << 5) | rt
    }

    private static func encodeUBFX(rd: UInt32, rn: UInt32, lsb: Int, width: Int) -> UInt32 {
        let immr = UInt32(lsb & 63)
        let imms = UInt32((lsb + width - 1) & 63)
        return 0xD340_0000 | (immr << 16) | (imms << 10) | (rn << 5) | rd
    }

    private static func encodeBFI(rd: UInt32, rn: UInt32, lsb: Int, width: Int) -> UInt32 {
        let immr = UInt32((64 - lsb) & 63)
        let imms = UInt32(width - 1)
        return 0xB340_0000 | (immr << 16) | (imms << 10) | (rn << 5) | rd
    }

    private static func encodeAdd(rd: UInt32, rn: UInt32, rm: UInt32, is64Bit: Bool) -> UInt32 {
        (is64Bit ? 0x8B00_0000 : 0x0B00_0000) | (rm << 16) | (rn << 5) | rd
    }

    private static func encodeSub(rd: UInt32, rn: UInt32, rm: UInt32, is64Bit: Bool) -> UInt32 {
        (is64Bit ? 0xCB00_0000 : 0x4B00_0000) | (rm << 16) | (rn << 5) | rd
    }

    private static func encodeEor(rd: UInt32, rn: UInt32, rm: UInt32, is64Bit: Bool) -> UInt32 {
        (is64Bit ? 0xCA00_0000 : 0x4A00_0000) | (rm << 16) | (rn << 5) | rd
    }

    private static func encodeORRRegister(rd: UInt32, rn: UInt32, rm: UInt32) -> UInt32 {
        0xAA00_0000 | (rm << 16) | (rn << 5) | rd
    }

    private static func encodeMOVRegister(rd: UInt32, rn: UInt32, is64Bit: Bool) -> UInt32 {
        (is64Bit ? 0xAA00_03E0 : 0x2A00_03E0) | (rn << 16) | rd
    }

    private static func encodeLSL(rd: UInt32, rn: UInt32, shift: Int) -> UInt32 {
        let immr = UInt32((64 - shift) & 63)
        let imms = UInt32(63 - shift)
        return 0xD340_0000 | (immr << 16) | (imms << 10) | (rn << 5) | rd
    }

    private static func encodeCMPRegister(rn: UInt32, rm: UInt32) -> UInt32 {
        0xEB00_001F | (rm << 16) | (rn << 5) // SUBS XZR, Xn, Xm
    }

    private static func encodeCMPImmediate(rn: UInt32, immediate: UInt32) -> UInt32 {
        0xF100_001F | ((immediate & 0xFFF) << 10) | (rn << 5) // SUBS XZR, Xn, #imm
    }

    private static func unsupported(_ instruction: X64IRInstruction, _ reason: String) -> CodegenError {
        .unsupportedInstruction(address: instruction.address, reason: reason)
    }
}
