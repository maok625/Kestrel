import Foundation

// MARK: - Guest memory

struct X64GuestMemoryError: LocalizedError, Sendable {
    let address: UInt64
    let byteCount: Int
    let reason: String

    var errorDescription: String? {
        String(format: "Guest memory fault at 0x%016llX (%d byte(s)): %@", address, byteCount, reason)
    }
}

/// Legacy contiguous guest-memory fixture used by the currently integrated
/// native JIT differential path. Guest addresses are translated to checked
/// byte-array offsets; guest pointers are never dereferenced as host pointers.
/// New process memory should use X64GuestVirtualMemory, which supports sparse
/// multi-region reservations and per-page permissions. The JIT bridge migration
/// from this fixture to the page-based manager is intentionally separate.
struct X64GuestMemory: Sendable {
    let baseAddress: UInt64
    private(set) var bytes: [UInt8]

    init(baseAddress: UInt64, size: Int) throws {
        guard size > 0 else {
            throw X64GuestMemoryError(address: baseAddress, byteCount: size, reason: "region size must be positive")
        }
        guard UInt64(size) <= UInt64.max - baseAddress else {
            throw X64GuestMemoryError(address: baseAddress, byteCount: size, reason: "region address range overflows")
        }
        self.baseAddress = baseAddress
        self.bytes = Array(repeating: 0, count: size)
    }

    var byteCount: Int { bytes.count }
    var endAddress: UInt64 { baseAddress &+ UInt64(bytes.count) }

    /// Temporarily exposes the backing bytes to the native JIT. The caller must
    /// provide guest-address bounds separately; this pointer is never a guest address.
    mutating func withUnsafeMutableBufferPointer<R>(
        _ body: (inout UnsafeMutableBufferPointer<UInt8>) throws -> R
    ) rethrows -> R {
        try bytes.withUnsafeMutableBufferPointer(body)
    }

    func contains(address: UInt64, byteCount requestedCount: Int = 1) -> Bool {
        guard requestedCount >= 0, address >= baseAddress else { return false }
        let offset = address - baseAddress
        guard offset <= UInt64(bytes.count), offset <= UInt64(Int.max) else { return false }
        return requestedCount <= bytes.count - Int(offset)
    }

    func readByte(at address: UInt64) throws -> UInt8 {
        let offset = try checkedOffset(address: address, byteCount: 1)
        return bytes[offset]
    }

    func readUnsigned(at address: UInt64, width: X64OperandWidth) throws -> UInt64 {
        let count = width.bitCount / 8
        let offset = try checkedOffset(address: address, byteCount: count)
        var value: UInt64 = 0
        for index in 0..<count {
            value |= UInt64(bytes[offset + index]) << (index * 8)
        }
        return value
    }

    func readBytes(at address: UInt64, maximumCount: Int) throws -> [UInt8] {
        guard maximumCount >= 0 else {
            throw X64GuestMemoryError(address: address, byteCount: maximumCount, reason: "negative read length")
        }
        guard address >= baseAddress else {
            throw X64GuestMemoryError(address: address, byteCount: maximumCount, reason: "address is below the mapped guest region")
        }
        let offset64 = address - baseAddress
        guard offset64 <= UInt64(bytes.count), offset64 <= UInt64(Int.max) else {
            throw X64GuestMemoryError(address: address, byteCount: maximumCount, reason: "address is outside the mapped guest region")
        }
        let offset = Int(offset64)
        let available = bytes.count - offset
        let count = min(maximumCount, available)
        guard count > 0 else {
            throw X64GuestMemoryError(address: address, byteCount: maximumCount, reason: "no readable guest bytes remain")
        }
        return Array(bytes[offset..<(offset + count)])
    }

    mutating func writeByte(_ value: UInt8, at address: UInt64) throws {
        let offset = try checkedOffset(address: address, byteCount: 1)
        bytes[offset] = value
    }

    mutating func writeUnsigned(_ value: UInt64, at address: UInt64, width: X64OperandWidth) throws {
        let count = width.bitCount / 8
        let offset = try checkedOffset(address: address, byteCount: count)
        for index in 0..<count {
            bytes[offset + index] = UInt8(truncatingIfNeeded: value >> (index * 8))
        }
    }

    mutating func writeBytes(_ values: [UInt8], at address: UInt64) throws {
        let offset = try checkedOffset(address: address, byteCount: values.count)
        guard !values.isEmpty else { return }
        bytes.replaceSubrange(offset..<(offset + values.count), with: values)
    }

    private func checkedOffset(address: UInt64, byteCount requestedCount: Int) throws -> Int {
        guard requestedCount >= 0 else {
            throw X64GuestMemoryError(address: address, byteCount: requestedCount, reason: "negative access length")
        }
        guard address >= baseAddress else {
            throw X64GuestMemoryError(address: address, byteCount: requestedCount, reason: "address is below the mapped guest region")
        }
        let offset64 = address - baseAddress
        guard offset64 <= UInt64(bytes.count), offset64 <= UInt64(Int.max) else {
            throw X64GuestMemoryError(address: address, byteCount: requestedCount, reason: "address is outside the mapped guest region")
        }
        let offset = Int(offset64)
        guard requestedCount <= bytes.count - offset else {
            throw X64GuestMemoryError(address: address, byteCount: requestedCount, reason: "access crosses the mapped guest region boundary")
        }
        return offset
    }
}

// MARK: - Interpreter

struct X64InterpreterError: LocalizedError, Sendable {
    let message: String
    var errorDescription: String? { message }

    static func unsupportedSegment(_ prefix: UInt8) -> Self {
        Self(message: String(format: "FS/GS segment-base addressing (prefix 0x%02X) is not implemented in this interpreter slice.", prefix))
    }

    static func invalidOperand(_ message: String) -> Self {
        Self(message: message)
    }

    static func instructionLimit(_ limit: Int) -> Self {
        Self(message: "Guest instruction limit reached (\(limit)).")
    }
}

struct X64ExecutionReport: Sendable {
    let instructionsExecuted: Int
    let finalRIP: UInt64
    let halted: Bool
}

/// Executes the current semantic-IR subset against guest CPU state and bounded
/// guest memory. This is an interpreter/reference engine; it does not yet
/// translate arbitrary decoded blocks into AArch64 machine code.
struct X64Interpreter {
    private(set) var state: X64CPUState
    private(set) var memory: X64GuestMemory
    private let decoder = X64InstructionDecoder()

    init(state: X64CPUState, memory: X64GuestMemory) {
        self.state = state
        self.memory = memory
    }

    @discardableResult
    mutating func run(until haltAddress: UInt64, maximumInstructions: Int = 100_000) throws -> X64ExecutionReport {
        guard maximumInstructions > 0 else {
            throw X64InterpreterError.invalidOperand("maximumInstructions must be greater than zero")
        }

        var executed = 0
        while state.rip != haltAddress {
            guard executed < maximumInstructions else {
                throw X64InterpreterError.instructionLimit(maximumInstructions)
            }
            _ = try step()
            executed += 1
        }
        return X64ExecutionReport(instructionsExecuted: executed, finalRIP: state.rip, halted: true)
    }

    @discardableResult
    mutating func step() throws -> X64IRInstruction {
        let instructionBytes = try memory.readBytes(at: state.rip, maximumCount: 15)
        let decoded = try decoder.decode(instructionBytes, at: state.rip)
        let instruction = try decoded.lowerToIR()
        try execute(instruction)
        return instruction
    }

    private mutating func execute(_ instruction: X64IRInstruction) throws {
        let fallthroughRIP = instruction.nextAddress
        var nextRIP = fallthroughRIP

        switch instruction.operation {
        case .move, .add, .subtract, .compare, .bitwiseAnd, .bitwiseXor, .test:
            guard let destination = instruction.destination,
                  let source = instruction.source,
                  let width = instruction.width else {
                throw X64InterpreterError.invalidOperand("\(instruction.operation) requires destination, source, and width")
            }
            let rhs = try read(source, width: width, instruction: instruction)
            if instruction.operation == .move {
                // MOV does not read its old destination. This is important for
                // guest memory permissions and avoids inventing a read fault.
                try write(rhs, to: destination, width: width, instruction: instruction)
                break
            }

            let lhs = try read(destination, width: width, instruction: instruction)
            switch instruction.operation {
            case .add:
                let result = state.add(lhs, rhs, width: width)
                try write(result, to: destination, width: width, instruction: instruction)
            case .subtract:
                let result = state.subtract(lhs, rhs, width: width)
                try write(result, to: destination, width: width, instruction: instruction)
            case .compare:
                _ = state.subtract(lhs, rhs, width: width)
            case .bitwiseAnd:
                let result = (lhs & rhs) & width.mask
                updateLogicalFlags(result, width: width)
                try write(result, to: destination, width: width, instruction: instruction)
            case .bitwiseXor:
                let result = (lhs ^ rhs) & width.mask
                updateLogicalFlags(result, width: width)
                try write(result, to: destination, width: width, instruction: instruction)
            case .test:
                updateLogicalFlags(lhs & rhs, width: width)
            default:
                throw X64InterpreterError.invalidOperand("unexpected operation in arithmetic dispatch")
            }

        case .bitwiseNot:
            guard let destination = instruction.destination, let width = instruction.width else {
                throw X64InterpreterError.invalidOperand("NOT requires a destination and width")
            }
            let value = try read(destination, width: width, instruction: instruction)
            try write((~value) & width.mask, to: destination, width: width, instruction: instruction)

        case .negate:
            guard let destination = instruction.destination, let width = instruction.width else {
                throw X64InterpreterError.invalidOperand("NEG requires a destination and width")
            }
            let value = try read(destination, width: width, instruction: instruction)
            let result = state.subtract(0, value, width: width)
            try write(result, to: destination, width: width, instruction: instruction)

        case .bitTest(let kind):
            guard let destination = instruction.destination,
                  let source = instruction.source,
                  let width = instruction.width,
                  case .immediate(let encodedIndex, _) = source else {
                throw X64InterpreterError.invalidOperand("BT/BTS/BTR/BTC requires an r/m destination, imm8 index, and width")
            }
            let bitIndex = Int(encodedIndex & 0xFF)
            let bitPosition = bitIndex % width.bitCount
            var accessDestination = destination
            if case .memory(let memoryOperand) = destination {
                let byteOffset = Int64((bitIndex / width.bitCount) * (width.bitCount / 8))
                let (displacement, overflow) = memoryOperand.displacement.addingReportingOverflow(byteOffset)
                guard !overflow else {
                    throw X64InterpreterError.invalidOperand("bit-string memory offset overflows the decoded displacement")
                }
                accessDestination = .memory(X64MemoryOperand(
                    base: memoryOperand.base,
                    index: memoryOperand.index,
                    scale: memoryOperand.scale,
                    displacement: displacement,
                    ripRelative: memoryOperand.ripRelative,
                    addressWidth: memoryOperand.addressWidth,
                    segmentOverride: memoryOperand.segmentOverride
                ))
            }

            let original = try read(accessDestination, width: width, instruction: instruction)
            let bitMask = UInt64(1) << bitPosition
            let oldBitIsSet = (original & bitMask) != 0
            let updated: UInt64
            switch kind {
            case .test: updated = original
            case .set: updated = original | bitMask
            case .reset: updated = original & ~bitMask
            case .complement: updated = original ^ bitMask
            }
            if kind != .test {
                try write(updated & width.mask, to: accessDestination, width: width, instruction: instruction)
            }
            state.setFlag(.carry, to: oldBitIsSet)

        case .exchange:
            guard let destination = instruction.destination,
                  let source = instruction.source,
                  let width = instruction.width else {
                throw X64InterpreterError.invalidOperand("XCHG requires two operands and a width")
            }
            let destinationValue = try read(destination, width: width, instruction: instruction)
            let sourceValue = try read(source, width: width, instruction: instruction)
            try write(sourceValue, to: destination, width: width, instruction: instruction)
            try write(destinationValue, to: source, width: width, instruction: instruction)

        case .loadEffectiveAddress:
            guard let destination = instruction.destination,
                  let source = instruction.source,
                  let width = instruction.width,
                  case .memory(let memoryOperand) = source else {
                throw X64InterpreterError.invalidOperand("LEA requires a register destination and memory-form source")
            }
            let address = try effectiveAddress(memoryOperand, instruction: instruction)
            try write(address, to: destination, width: width, instruction: instruction)

        case .noOperation, .pause:
            break

        case .push:
            guard let source = instruction.source, let width = instruction.width else {
                throw X64InterpreterError.invalidOperand("PUSH requires a source and stack width")
            }
            // x86 PUSH reads its source before decrementing RSP. This matters
            // for PUSH RSP and memory operands based on RSP.
            let value = try read(source, width: width, instruction: instruction)
            try push(value, width: width)

        case .pop:
            guard let destination = instruction.destination, let width = instruction.width else {
                throw X64InterpreterError.invalidOperand("POP requires a destination and stack width")
            }
            let value = try pop(width: width)
            // POP r/m calculates an RSP-based effective address after RSP has
            // been incremented; writing happens only after pop() updates RSP.
            try write(value, to: destination, width: width, instruction: instruction)

        case .returnFromFunction(let stackAdjustment):
            let target = try memory.readUnsigned(at: state.registerValue(.rsp), width: .qword)
            let updatedStack = state.registerValue(.rsp) &+ 8 &+ UInt64(stackAdjustment)
            try state.writeRegister(.rsp, value: updatedStack, width: .qword)
            nextRIP = target

        case .branchRelative(let displacement):
            nextRIP = fallthroughRIP &+ UInt64(bitPattern: displacement)

        case .callRelative(let displacement):
            try push(fallthroughRIP, width: .qword)
            nextRIP = fallthroughRIP &+ UInt64(bitPattern: displacement)

        case .callIndirect:
            guard let source = instruction.source else {
                throw X64InterpreterError.invalidOperand("indirect CALL requires a source")
            }
            let target = try read(source, width: .qword, instruction: instruction)
            try push(fallthroughRIP, width: .qword)
            nextRIP = target

        case .branchIndirect:
            guard let source = instruction.source else {
                throw X64InterpreterError.invalidOperand("indirect JMP requires a source")
            }
            nextRIP = try read(source, width: .qword, instruction: instruction)

        case .conditionalBranch(let condition, let displacement):
            if conditionIsSatisfied(condition) {
                nextRIP = fallthroughRIP &+ UInt64(bitPattern: displacement)
            }

        case .systemCall:
            throw X64InterpreterError.invalidOperand("SYSCALL requires the sparse guest-VM syscall dispatcher; use X64ARM64BlockDispatcher.")
        }

        state.rip = nextRIP
    }

    private func read(_ value: X64IRValue, width: X64OperandWidth, instruction: X64IRInstruction) throws -> UInt64 {
        switch value {
        case .register(let operand):
            return state.read(operand) & width.mask
        case .memory(let operand):
            let address = try effectiveAddress(operand, instruction: instruction)
            return try memory.readUnsigned(at: address, width: width)
        case .immediate(let immediate, _):
            return immediate & width.mask
        }
    }

    private mutating func write(
        _ value: UInt64,
        to destination: X64IRValue,
        width: X64OperandWidth,
        instruction: X64IRInstruction
    ) throws {
        switch destination {
        case .register(let operand):
            state.write(value, to: operand)
        case .memory(let operand):
            let address = try effectiveAddress(operand, instruction: instruction)
            try memory.writeUnsigned(value, at: address, width: width)
        case .immediate:
            throw X64InterpreterError.invalidOperand("cannot write to an immediate operand")
        }
    }

    private func effectiveAddress(_ operand: X64MemoryOperand, instruction: X64IRInstruction) throws -> UInt64 {
        if let segment = operand.segmentOverride, segment == 0x64 || segment == 0x65 {
            throw X64InterpreterError.unsupportedSegment(segment)
        }

        var address = operand.ripRelative ? instruction.nextAddress : 0
        if let base = operand.base {
            address = address &+ state.registerValue(base)
        }
        if let index = operand.index {
            address = address &+ (state.registerValue(index) &* UInt64(operand.scale))
        }
        address = address &+ UInt64(bitPattern: operand.displacement)

        if operand.addressWidth == .dword {
            address &= 0xFFFF_FFFF
        }
        return address
    }

    private mutating func push(_ value: UInt64, width: X64OperandWidth) throws {
        let byteCount = UInt64(width.bitCount / 8)
        let newStack = state.registerValue(.rsp) &- byteCount
        // Validate/write guest memory before publishing the new RSP.
        try memory.writeUnsigned(value, at: newStack, width: width)
        try state.writeRegister(.rsp, value: newStack, width: .qword)
    }

    private mutating func pop(width: X64OperandWidth) throws -> UInt64 {
        let oldStack = state.registerValue(.rsp)
        let value = try memory.readUnsigned(at: oldStack, width: width)
        let newStack = oldStack &+ UInt64(width.bitCount / 8)
        try state.writeRegister(.rsp, value: newStack, width: .qword)
        return value
    }

    private mutating func updateLogicalFlags(_ result: UInt64, width: X64OperandWidth) {
        // AND/XOR/TEST define CF=0, OF=0, SF/ZF/PF. AF is architecturally undefined;
        // retain its previous value instead of inventing a deterministic rule.
        state.setFlag(.carry, to: false)
        state.setFlag(.overflow, to: false)
        state.setFlag(.zero, to: (result & width.mask) == 0)
        state.setFlag(.sign, to: ((result & width.mask) & width.signBit) != 0)
        state.setFlag(.parity, to: UInt8(truncatingIfNeeded: result).nonzeroBitCount.isMultiple(of: 2))
    }

    private func conditionIsSatisfied(_ condition: X64Condition) -> Bool {
        let carry = state.flagIsSet(.carry)
        let parity = state.flagIsSet(.parity)
        let zero = state.flagIsSet(.zero)
        let sign = state.flagIsSet(.sign)
        let overflow = state.flagIsSet(.overflow)

        switch condition {
        case .overflow: return overflow
        case .notOverflow: return !overflow
        case .below: return carry
        case .aboveOrEqual: return !carry
        case .equal: return zero
        case .notEqual: return !zero
        case .belowOrEqual: return carry || zero
        case .above: return !carry && !zero
        case .sign: return sign
        case .notSign: return !sign
        case .parity: return parity
        case .notParity: return !parity
        case .less: return sign != overflow
        case .greaterOrEqual: return sign == overflow
        case .lessOrEqual: return zero || sign != overflow
        case .greater: return !zero && sign == overflow
        }
    }
}
