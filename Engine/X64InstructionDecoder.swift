import Foundation

// MARK: - Prefixes and decoded instruction representation

enum X64OpcodeMap: Sendable, Equatable {
    case primary
    case map0F
    case map0F38
    case map0F3A
}

struct X64InstructionPrefixes: Sendable, Equatable {
    var legacyBytes: [UInt8] = []
    var rex: UInt8?
    var lock = false
    var repeatPrefix: UInt8?
    var operandSizeOverride = false
    var addressSizeOverride = false
    var segmentOverride: UInt8?

    var rexPresent: Bool { rex != nil }
    var rexW: Bool { (rex ?? 0) & 0x08 != 0 }
    var rexR: UInt8 { ((rex ?? 0) >> 2) & 1 }
    var rexX: UInt8 { ((rex ?? 0) >> 1) & 1 }
    var rexB: UInt8 { (rex ?? 0) & 1 }

    var operandWidth: X64OperandWidth {
        if rexW { return .qword }
        return operandSizeOverride ? .word : .dword
    }

    var addressWidth: X64OperandWidth {
        addressSizeOverride ? .dword : .qword
    }
}

struct X64MemoryOperand: Sendable, Equatable {
    let base: X64GeneralRegister?
    let index: X64GeneralRegister?
    let scale: UInt8
    let displacement: Int64
    let ripRelative: Bool
    let addressWidth: X64OperandWidth
    let segmentOverride: UInt8?
}

enum X64DecodedRMOperand: Sendable, Equatable {
    case register(X64RegisterOperand)
    case memory(X64MemoryOperand)
}

struct X64DecodedModRM: Sendable, Equatable {
    let mode: UInt8
    let rawReg: UInt8
    let extendedReg: UInt8
    let rawRM: UInt8
    let rmOperand: X64DecodedRMOperand
    let sib: UInt8?
}

struct X64DecodedInstruction: Sendable, Equatable {
    let address: UInt64
    let bytes: [UInt8]
    let prefixes: X64InstructionPrefixes
    let opcodeMap: X64OpcodeMap
    let opcode: UInt8
    let operandWidth: X64OperandWidth
    let addressWidth: X64OperandWidth
    let modRM: X64DecodedModRM?
    let immediate: UInt64?
    let immediateByteCount: Int

    var length: Int { bytes.count }
    var nextAddress: UInt64 { address &+ UInt64(length) }

    func lowerToIR() throws -> X64IRInstruction {
        try X64SemanticLowerer.lower(self)
    }
}

struct X64InstructionDecoderError: LocalizedError, Sendable {
    enum Kind: Sendable {
        case truncated(offset: Int, needed: Int)
        case instructionTooLong
        case unsupportedOpcode(map: X64OpcodeMap, opcode: UInt8)
        case invalidEncoding(String)
    }

    let kind: Kind

    var errorDescription: String? {
        switch kind {
        case .truncated(let offset, let needed):
            return String(format: "Truncated x86_64 instruction at byte offset 0x%X (needs %d more byte(s)).", offset, needed)
        case .instructionTooLong:
            return "Invalid x86_64 instruction: instruction length exceeds the architectural 15-byte limit."
        case .unsupportedOpcode(let map, let opcode):
            return String(format: "Unsupported x86_64 opcode 0x%02X in opcode map %@.", opcode, String(describing: map))
        case .invalidEncoding(let reason):
            return "Invalid x86_64 instruction encoding: \(reason)"
        }
    }
}

// MARK: - Decoder

/// A deliberately explicit 64-bit-mode decoder foundation. It decodes the
/// prefix/opcode/ModRM/SIB/displacement/immediate structure for the instruction
/// families listed in `instructionShape`. Unknown instructions are rejected;
/// their length is never guessed.
struct X64InstructionDecoder {
    func decode(_ bytes: [UInt8], at address: UInt64 = 0) throws -> X64DecodedInstruction {
        var cursor = X64ByteCursor(bytes: bytes)
        var prefixes = X64InstructionPrefixes()

        // Legacy prefixes may precede REX. A legacy prefix after a REX byte
        // makes that earlier REX byte ineffective, as required in 64-bit mode.
        while let byte = cursor.peekByte(), isPrefix(byte) {
            let prefix = try cursor.readByte()
            if isLegacyPrefix(prefix) {
                prefixes.legacyBytes.append(prefix)
                prefixes.rex = nil
                switch prefix {
                case 0xF0: prefixes.lock = true
                case 0xF2, 0xF3: prefixes.repeatPrefix = prefix
                case 0x66: prefixes.operandSizeOverride = true
                case 0x67: prefixes.addressSizeOverride = true
                case 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65:
                    prefixes.segmentOverride = prefix
                default: break
                }
            } else {
                prefixes.rex = prefix
            }
        }

        let firstOpcode = try cursor.readByte()
        let opcodeMap: X64OpcodeMap
        let opcode: UInt8
        if firstOpcode == 0x0F {
            let second = try cursor.readByte()
            if second == 0x38 {
                opcodeMap = .map0F38
                opcode = try cursor.readByte()
            } else if second == 0x3A {
                opcodeMap = .map0F3A
                opcode = try cursor.readByte()
            } else {
                opcodeMap = .map0F
                opcode = second
            }
        } else {
            opcodeMap = .primary
            opcode = firstOpcode
        }

        let operandWidth = prefixes.operandWidth
        let stackOperandWidth: X64OperandWidth = prefixes.operandSizeOverride ? .word : .qword
        let addressWidth = prefixes.addressWidth
        let shape = try instructionShape(
            map: opcodeMap,
            opcode: opcode,
            operandWidth: operandWidth,
            prefixes: prefixes
        )

        let effectiveOperandWidth: X64OperandWidth =
            opcodeMap == .primary && (opcode == 0x8F || opcode == 0xFF)
                ? stackOperandWidth
                : operandWidth

        var modRM: X64DecodedModRM?
        if shape.hasModRM {
            modRM = try decodeModRM(
                from: &cursor,
                prefixes: prefixes,
                operandWidth: shape.byteOperation ? .byte : effectiveOperandWidth,
                addressWidth: addressWidth,
                segmentOverride: prefixes.segmentOverride
            )
        }

        var immediate: UInt64?
        if shape.immediateBytes > 0 {
            immediate = try cursor.readUnsigned(shape.immediateBytes)
        }

        let instructionBytes = Array(bytes.prefix(cursor.offset))
        guard !instructionBytes.isEmpty else {
            throw X64InstructionDecoderError(kind: .invalidEncoding("empty instruction"))
        }

        return X64DecodedInstruction(
            address: address,
            bytes: instructionBytes,
            prefixes: prefixes,
            opcodeMap: opcodeMap,
            opcode: opcode,
            operandWidth: shape.byteOperation ? .byte : effectiveOperandWidth,
            addressWidth: addressWidth,
            modRM: modRM,
            immediate: immediate,
            immediateByteCount: shape.immediateBytes
        )
    }

    /// Decodes a contiguous instruction stream. Each instruction is decoded
    /// independently and receives the guest address following the prior one.
    func decodeAll(_ bytes: [UInt8], at startAddress: UInt64 = 0, maximumInstructions: Int = 65_536) throws -> [X64DecodedInstruction] {
        guard maximumInstructions > 0 else {
            throw X64InstructionDecoderError(kind: .invalidEncoding("maximumInstructions must be greater than zero"))
        }
        var result: [X64DecodedInstruction] = []
        var offset = 0
        while offset < bytes.count {
            guard result.count < maximumInstructions else {
                throw X64InstructionDecoderError(kind: .invalidEncoding("instruction stream exceeds the configured instruction limit"))
            }
            let instruction = try decode(Array(bytes[offset...]), at: startAddress &+ UInt64(offset))
            guard instruction.length > 0 else {
                throw X64InstructionDecoderError(kind: .invalidEncoding("decoder produced a zero-length instruction"))
            }
            result.append(instruction)
            offset += instruction.length
        }
        return result
    }

    private struct InstructionShape {
        let hasModRM: Bool
        let immediateBytes: Int
        let byteOperation: Bool
    }

    private func instructionShape(
        map: X64OpcodeMap,
        opcode: UInt8,
        operandWidth: X64OperandWidth,
        prefixes: X64InstructionPrefixes
    ) throws -> InstructionShape {
        switch map {
        case .map0F:
            if opcode == 0x05 { return InstructionShape(hasModRM: false, immediateBytes: 0, byteOperation: false) } // SYSCALL
            if opcode == 0x1F { return InstructionShape(hasModRM: true, immediateBytes: 0, byteOperation: false) }
            if (0x80...0x8F).contains(opcode) { return InstructionShape(hasModRM: false, immediateBytes: 4, byteOperation: false) }
            throw X64InstructionDecoderError(kind: .unsupportedOpcode(map: map, opcode: opcode))
        case .map0F38, .map0F3A:
            throw X64InstructionDecoderError(kind: .unsupportedOpcode(map: map, opcode: opcode))
        case .primary:
            if (0x90...0x97).contains(opcode) || opcode == 0xC3 { return InstructionShape(hasModRM: false, immediateBytes: 0, byteOperation: false) }
            if opcode == 0xC2 { return InstructionShape(hasModRM: false, immediateBytes: 2, byteOperation: false) }
            if (0xB0...0xB7).contains(opcode) { return InstructionShape(hasModRM: false, immediateBytes: 1, byteOperation: true) }
            if (0xB8...0xBF).contains(opcode) {
                return InstructionShape(hasModRM: false, immediateBytes: operandWidth == .qword ? 8 : (operandWidth == .word ? 2 : 4), byteOperation: false)
            }
            if (0x50...0x5F).contains(opcode) { return InstructionShape(hasModRM: false, immediateBytes: 0, byteOperation: false) }
            if opcode == 0x68 { return InstructionShape(hasModRM: false, immediateBytes: operandWidth == .word ? 2 : 4, byteOperation: false) }
            if opcode == 0x6A { return InstructionShape(hasModRM: false, immediateBytes: 1, byteOperation: false) }
            if opcode == 0xEB || (0x70...0x7F).contains(opcode) { return InstructionShape(hasModRM: false, immediateBytes: 1, byteOperation: false) }
            if opcode == 0xE8 || opcode == 0xE9 { return InstructionShape(hasModRM: false, immediateBytes: 4, byteOperation: false) }

            let byteBinary: Set<UInt8> = [0x00, 0x02, 0x04, 0x28, 0x2A, 0x2C, 0x30, 0x32, 0x34, 0x38, 0x3A, 0x3C]
            if byteBinary.contains(opcode) { return InstructionShape(hasModRM: [0x00, 0x02].contains(opcode) || [0x28, 0x2A, 0x30, 0x32, 0x38, 0x3A].contains(opcode), immediateBytes: [0x04, 0x2C, 0x34, 0x3C].contains(opcode) ? 1 : 0, byteOperation: true) }

            let wordDwordBinary: Set<UInt8> = [0x01, 0x03, 0x05, 0x29, 0x2B, 0x2D, 0x31, 0x33, 0x35, 0x39, 0x3B, 0x3D]
            if wordDwordBinary.contains(opcode) {
                let hasModRM = ![0x05, 0x2D, 0x35, 0x3D].contains(opcode)
                let immediate = hasModRM ? 0 : (operandWidth == .word ? 2 : 4)
                return InstructionShape(hasModRM: hasModRM, immediateBytes: immediate, byteOperation: false)
            }

            if [0x80, 0x81, 0x83].contains(opcode) {
                let count = opcode == 0x80 || opcode == 0x83 ? 1 : (operandWidth == .word ? 2 : 4)
                return InstructionShape(hasModRM: true, immediateBytes: count, byteOperation: opcode == 0x80)
            }
            if [0x88, 0x8A].contains(opcode) { return InstructionShape(hasModRM: true, immediateBytes: 0, byteOperation: true) }
            if [0x89, 0x8B, 0x8D].contains(opcode) { return InstructionShape(hasModRM: true, immediateBytes: 0, byteOperation: false) }
            if opcode == 0xC6 { return InstructionShape(hasModRM: true, immediateBytes: 1, byteOperation: true) }
            if opcode == 0xC7 { return InstructionShape(hasModRM: true, immediateBytes: operandWidth == .word ? 2 : 4, byteOperation: false) }
            if opcode == 0xFF || opcode == 0x8F { return InstructionShape(hasModRM: true, immediateBytes: 0, byteOperation: false) }

            throw X64InstructionDecoderError(kind: .unsupportedOpcode(map: map, opcode: opcode))
        }
    }

    private func decodeModRM(
        from cursor: inout X64ByteCursor,
        prefixes: X64InstructionPrefixes,
        operandWidth: X64OperandWidth,
        addressWidth: X64OperandWidth,
        segmentOverride: UInt8?
    ) throws -> X64DecodedModRM {
        let byte = try cursor.readByte()
        let mode = (byte >> 6) & 0x3
        let rawReg = (byte >> 3) & 0x7
        let rawRM = byte & 0x7
        let extendedReg = rawReg | (prefixes.rexR << 3)
        let extendedRM = rawRM | (prefixes.rexB << 3)

        if mode == 3 {
            let register = try X64RegisterOperand(
                encodedIndex: extendedRM,
                width: operandWidth,
                rexPresent: prefixes.rexPresent
            )
            return X64DecodedModRM(
                mode: mode,
                rawReg: rawReg,
                extendedReg: extendedReg,
                rawRM: rawRM,
                rmOperand: .register(register),
                sib: nil
            )
        }

        var base: X64GeneralRegister?
        var index: X64GeneralRegister?
        var scale: UInt8 = 1
        var displacement: Int64 = 0
        var ripRelative = false
        var sibByte: UInt8?

        if rawRM == 4 {
            let sib = try cursor.readByte()
            sibByte = sib
            let scaleBits = (sib >> 6) & 0x3
            let indexLow = (sib >> 3) & 0x7
            let baseLow = sib & 0x7
            scale = UInt8(1 << scaleBits)

            let extendedIndex = indexLow | (prefixes.rexX << 3)
            if !(indexLow == 4 && prefixes.rexX == 0) {
                guard let decodedIndex = X64GeneralRegister(rawValue: Int(extendedIndex)) else {
                    throw X64InstructionDecoderError(kind: .invalidEncoding("invalid SIB index register"))
                }
                index = decodedIndex
            }

            if mode == 0 && baseLow == 5 {
                displacement = try cursor.readSigned(4)
            } else {
                let extendedBase = baseLow | (prefixes.rexB << 3)
                guard let decodedBase = X64GeneralRegister(rawValue: Int(extendedBase)) else {
                    throw X64InstructionDecoderError(kind: .invalidEncoding("invalid SIB base register"))
                }
                base = decodedBase
            }
        } else if mode == 0 && rawRM == 5 {
            displacement = try cursor.readSigned(4)
            ripRelative = addressWidth == .qword
        } else {
            guard let decodedBase = X64GeneralRegister(rawValue: Int(extendedRM)) else {
                throw X64InstructionDecoderError(kind: .invalidEncoding("invalid base register"))
            }
            base = decodedBase
        }

        if mode == 1 {
            displacement &+= try cursor.readSigned(1)
        } else if mode == 2 {
            displacement &+= try cursor.readSigned(4)
        }

        let memory = X64MemoryOperand(
            base: base,
            index: index,
            scale: scale,
            displacement: displacement,
            ripRelative: ripRelative,
            addressWidth: addressWidth,
            segmentOverride: segmentOverride
        )
        return X64DecodedModRM(
            mode: mode,
            rawReg: rawReg,
            extendedReg: extendedReg,
            rawRM: rawRM,
            rmOperand: .memory(memory),
            sib: sibByte
        )
    }

    private func isPrefix(_ byte: UInt8) -> Bool {
        isLegacyPrefix(byte) || (0x40...0x4F).contains(byte)
    }

    private func isLegacyPrefix(_ byte: UInt8) -> Bool {
        [0xF0, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65, 0x66, 0x67].contains(byte)
    }
}

private struct X64ByteCursor {
    let bytes: [UInt8]
    private(set) var offset = 0

    func peekByte() -> UInt8? {
        guard offset < bytes.count else { return nil }
        return bytes[offset]
    }

    mutating func readByte() throws -> UInt8 {
        guard offset < bytes.count else {
            throw X64InstructionDecoderError(kind: .truncated(offset: offset, needed: 1))
        }
        guard offset < 15 else {
            throw X64InstructionDecoderError(kind: .instructionTooLong)
        }
        let value = bytes[offset]
        offset += 1
        return value
    }

    mutating func readUnsigned(_ count: Int) throws -> UInt64 {
        guard count >= 0, count <= 8 else {
            throw X64InstructionDecoderError(kind: .invalidEncoding("invalid immediate length"))
        }
        guard offset + count <= bytes.count else {
            throw X64InstructionDecoderError(kind: .truncated(offset: offset, needed: offset + count - bytes.count))
        }
        guard offset + count <= 15 else {
            throw X64InstructionDecoderError(kind: .instructionTooLong)
        }
        var value: UInt64 = 0
        for index in 0..<count {
            value |= UInt64(bytes[offset + index]) << (index * 8)
        }
        offset += count
        return value
    }

    mutating func readSigned(_ count: Int) throws -> Int64 {
        let raw = try readUnsigned(count)
        guard count > 0 else { return 0 }
        let bits = count * 8
        if bits == 64 { return Int64(bitPattern: raw) }
        let signBit = UInt64(1) << (bits - 1)
        let extended = (raw & signBit) == 0 ? raw : (raw | (~UInt64(0) << bits))
        return Int64(bitPattern: extended)
    }
}

// MARK: - Architecture-independent semantic IR

enum X64Condition: UInt8, Sendable, CaseIterable {
    case overflow = 0
    case notOverflow = 1
    case below = 2
    case aboveOrEqual = 3
    case equal = 4
    case notEqual = 5
    case belowOrEqual = 6
    case above = 7
    case sign = 8
    case notSign = 9
    case parity = 10
    case notParity = 11
    case less = 12
    case greaterOrEqual = 13
    case lessOrEqual = 14
    case greater = 15
}

enum X64IRValue: Sendable, Equatable {
    case register(X64RegisterOperand)
    case memory(X64MemoryOperand)
    case immediate(value: UInt64, encodedByteCount: Int)
}

enum X64IROperation: Sendable, Equatable {
    case move
    case add
    case subtract
    case compare
    case bitwiseXor
    case exchange
    case loadEffectiveAddress
    case noOperation
    case pause
    case push
    case pop
    case returnFromFunction(stackAdjustment: UInt16)
    case branchRelative(displacement: Int64)
    case callRelative(displacement: Int64)
    case callIndirect
    case branchIndirect
    case conditionalBranch(condition: X64Condition, displacement: Int64)
    case systemCall
}

struct X64IRInstruction: Sendable, Equatable {
    let address: UInt64
    let byteCount: Int
    let operation: X64IROperation
    let destination: X64IRValue?
    let source: X64IRValue?
    let width: X64OperandWidth?

    var nextAddress: UInt64 { address &+ UInt64(byteCount) }
}

private enum X64SemanticLowerer {
    static func lower(_ instruction: X64DecodedInstruction) throws -> X64IRInstruction {
        guard instruction.opcodeMap == .primary || instruction.opcodeMap == .map0F else {
            throw X64InstructionDecoderError(kind: .unsupportedOpcode(map: instruction.opcodeMap, opcode: instruction.opcode))
        }
        if instruction.prefixes.lock {
            throw X64InstructionDecoderError(kind: .invalidEncoding("LOCK-prefixed atomic semantics are not part of this IR slice"))
        }

        let opcode = instruction.opcode
        let width = instruction.operandWidth
        // In 64-bit mode stack instructions default to 64-bit operands;
        // 66 selects 16-bit. REX.W does not change this stack width.
        let stackWidth: X64OperandWidth = instruction.prefixes.operandSizeOverride ? .word : .qword
        let rex = instruction.prefixes.rexPresent
        let rm = instruction.modRM?.rmOperand
        let modRM = instruction.modRM
        let immediate = instruction.immediate ?? 0

        func reg(_ index: UInt8, _ width: X64OperandWidth) throws -> X64IRValue {
            .register(try X64RegisterOperand(encodedIndex: index, width: width, rexPresent: rex))
        }
        func rmValue() throws -> X64IRValue {
            guard let rm else { throw X64InstructionDecoderError(kind: .invalidEncoding("missing ModRM r/m operand")) }
            switch rm {
            case .register(let operand): return .register(operand)
            case .memory(let memory): return .memory(memory)
            }
        }
        func modRMReg(_ width: X64OperandWidth) throws -> X64IRValue {
            guard let modRM else { throw X64InstructionDecoderError(kind: .invalidEncoding("missing ModRM.reg operand")) }
            return try reg(modRM.extendedReg, width)
        }
        func imm(_ value: UInt64, _ encodedBytes: Int, signExtend: Bool, targetWidth: X64OperandWidth) -> X64IRValue {
            let converted: UInt64
            if signExtend {
                let bits = encodedBytes * 8
                if bits == 64 { converted = value }
                else {
                    let signBit = UInt64(1) << (bits - 1)
                    let extended = (value & signBit) == 0 ? value : (value | (~UInt64(0) << bits))
                    converted = extended & targetWidth.mask
                }
            } else {
                converted = value & targetWidth.mask
            }
            return .immediate(value: converted, encodedByteCount: encodedBytes)
        }
        func result(_ operation: X64IROperation, _ destination: X64IRValue? = nil, _ source: X64IRValue? = nil, _ resultWidth: X64OperandWidth? = width) -> X64IRInstruction {
            X64IRInstruction(address: instruction.address, byteCount: instruction.length, operation: operation, destination: destination, source: source, width: resultWidth)
        }

        if instruction.opcodeMap == .map0F {
            if opcode == 0x05 {
                return result(.systemCall, nil, nil, nil)
            }
            if opcode == 0x1F {
                guard modRM?.rawReg == 0 else {
                    throw X64InstructionDecoderError(kind: .invalidEncoding("multi-byte NOP requires ModRM /0"))
                }
                return result(.noOperation, nil, nil, nil)
            }
            if (0x80...0x8F).contains(opcode) {
                let condition = X64Condition(rawValue: opcode & 0x0F)!
                let displacement = Int64(Int32(bitPattern: UInt32(truncatingIfNeeded: immediate)))
                return result(.conditionalBranch(condition: condition, displacement: displacement), nil, nil, nil)
            }
        }

        if (0x90...0x97).contains(opcode) {
            if opcode == 0x90 && instruction.prefixes.rexB == 0 && instruction.prefixes.repeatPrefix == 0xF3 {
                return result(.pause, nil, nil, nil)
            }
            let registerIndex = (opcode & 0x7) | (instruction.prefixes.rexB << 3)
            if opcode == 0x90 && registerIndex == 0 {
                return result(.noOperation, nil, nil, nil)
            }
            return result(.exchange, try reg(0, width), try reg(registerIndex, width), width)
        }
        if opcode == 0xC3 { return result(.returnFromFunction(stackAdjustment: 0), nil, nil, nil) }
        if opcode == 0xC2 { return result(.returnFromFunction(stackAdjustment: UInt16(truncatingIfNeeded: immediate)), nil, nil, nil) }
        if opcode == 0xEB {
            return result(.branchRelative(displacement: Int64(Int8(truncatingIfNeeded: immediate))), nil, nil, nil)
        }
        if opcode == 0xE9 {
            return result(.branchRelative(displacement: Int64(Int32(bitPattern: UInt32(truncatingIfNeeded: immediate)))), nil, nil, nil)
        }
        if opcode == 0xE8 {
            return result(.callRelative(displacement: Int64(Int32(bitPattern: UInt32(truncatingIfNeeded: immediate)))), nil, nil, nil)
        }
        if (0x70...0x7F).contains(opcode) {
            let condition = X64Condition(rawValue: opcode & 0x0F)!
            return result(.conditionalBranch(condition: condition, displacement: Int64(Int8(truncatingIfNeeded: immediate))), nil, nil, nil)
        }
        if (0x50...0x57).contains(opcode) {
            let registerIndex = (opcode & 0x7) | (instruction.prefixes.rexB << 3)
            return result(.push, nil, try reg(registerIndex, stackWidth), stackWidth)
        }
        if (0x58...0x5F).contains(opcode) {
            let registerIndex = (opcode & 0x7) | (instruction.prefixes.rexB << 3)
            return result(.pop, try reg(registerIndex, stackWidth), nil, stackWidth)
        }
        if (0xB0...0xB7).contains(opcode) {
            let index = (opcode & 0x7) | (instruction.prefixes.rexB << 3)
            return result(.move, try reg(index, .byte), imm(immediate, 1, signExtend: false, targetWidth: .byte), .byte)
        }
        if (0xB8...0xBF).contains(opcode) {
            let index = (opcode & 0x7) | (instruction.prefixes.rexB << 3)
            return result(.move, try reg(index, width), imm(immediate, instruction.immediateByteCount, signExtend: false, targetWidth: width), width)
        }
        if opcode == 0x68 || opcode == 0x6A {
            let signExtended = opcode == 0x6A || stackWidth == .qword
            return result(.push, nil, imm(immediate, instruction.immediateByteCount, signExtend: signExtended, targetWidth: stackWidth), stackWidth)
        }

        // Register/memory and register/register binary instruction forms.
        let binaryFamilies: [UInt8: X64IROperation] = [
            0x00: .add, 0x01: .add, 0x02: .add, 0x03: .add,
            0x28: .subtract, 0x29: .subtract, 0x2A: .subtract, 0x2B: .subtract,
            0x30: .bitwiseXor, 0x31: .bitwiseXor, 0x32: .bitwiseXor, 0x33: .bitwiseXor,
            0x38: .compare, 0x39: .compare, 0x3A: .compare, 0x3B: .compare
        ]
        if let operation = binaryFamilies[opcode] {
            let byteOperation = [0x00, 0x02, 0x28, 0x2A, 0x30, 0x32, 0x38, 0x3A].contains(opcode)
            let valueWidth: X64OperandWidth = byteOperation ? .byte : width
            if opcode & 0x2 == 0 { // r/m <- r
                return result(operation, try rmValue(), try modRMReg(valueWidth), valueWidth)
            }
            return result(operation, try modRMReg(valueWidth), try rmValue(), valueWidth)
        }

        // Accumulator-immediate forms.
        let accumulatorFamilies: [UInt8: X64IROperation] = [
            0x04: .add, 0x05: .add, 0x2C: .subtract, 0x2D: .subtract,
            0x34: .bitwiseXor, 0x35: .bitwiseXor, 0x3C: .compare, 0x3D: .compare
        ]
        if let operation = accumulatorFamilies[opcode] {
            let byteOperation = [0x04, 0x2C, 0x34, 0x3C].contains(opcode)
            let valueWidth: X64OperandWidth = byteOperation ? .byte : width
            let encodedBytes = instruction.immediateByteCount
            let signed = !byteOperation && valueWidth == .qword
            return result(operation, try reg(0, valueWidth), imm(immediate, encodedBytes, signExtend: signed, targetWidth: valueWidth), valueWidth)
        }

        // Group 1 immediate instructions: /0 ADD, /5 SUB, /6 XOR, /7 CMP.
        if [0x80, 0x81, 0x83].contains(opcode) {
            guard let groupExtension = modRM?.rawReg else { throw X64InstructionDecoderError(kind: .invalidEncoding("missing group-1 opcode extension")) }
            let operation: X64IROperation
            switch groupExtension {
            case 0: operation = .add
            case 5: operation = .subtract
            case 6: operation = .bitwiseXor
            case 7: operation = .compare
            default: throw X64InstructionDecoderError(kind: .invalidEncoding("group-1 opcode extension /\(groupExtension) is not in this IR slice"))
            }
            let signed = opcode == 0x83 || (opcode == 0x81 && width == .qword)
            return result(operation, try rmValue(), imm(immediate, instruction.immediateByteCount, signExtend: signed, targetWidth: instruction.operandWidth), instruction.operandWidth)
        }

        // MOV r/m, r and MOV r, r/m.
        if [0x88, 0x89, 0x8A, 0x8B].contains(opcode) {
            let byteOperation = opcode == 0x88 || opcode == 0x8A
            let valueWidth: X64OperandWidth = byteOperation ? .byte : width
            if opcode == 0x88 || opcode == 0x89 {
                return result(.move, try rmValue(), try modRMReg(valueWidth), valueWidth)
            }
            return result(.move, try modRMReg(valueWidth), try rmValue(), valueWidth)
        }
        if opcode == 0x8D {
            guard case .memory? = rm else {
                throw X64InstructionDecoderError(kind: .invalidEncoding("LEA requires a memory source"))
            }
            return result(.loadEffectiveAddress, try modRMReg(width), try rmValue(), width)
        }
        if opcode == 0xC6 || opcode == 0xC7 {
            guard modRM?.rawReg == 0 else {
                throw X64InstructionDecoderError(kind: .invalidEncoding("MOV immediate requires ModRM /0"))
            }
            let valueWidth: X64OperandWidth = opcode == 0xC6 ? .byte : width
            let signed = opcode == 0xC7 && valueWidth == .qword
            return result(.move, try rmValue(), imm(immediate, instruction.immediateByteCount, signExtend: signed, targetWidth: valueWidth), valueWidth)
        }
        if opcode == 0x8F {
            guard modRM?.rawReg == 0 else {
                throw X64InstructionDecoderError(kind: .invalidEncoding("POP r/m requires ModRM /0"))
            }
            return result(.pop, try rmValue(), nil, stackWidth)
        }
        if opcode == 0xFF {
            guard let groupExtension = modRM?.rawReg else { throw X64InstructionDecoderError(kind: .invalidEncoding("missing FF opcode extension")) }
            switch groupExtension {
            case 2: return result(.callIndirect, nil, try rmValue(), stackWidth)
            case 4: return result(.branchIndirect, nil, try rmValue(), stackWidth)
            case 6: return result(.push, nil, try rmValue(), stackWidth)
            default: throw X64InstructionDecoderError(kind: .invalidEncoding("FF group extension /\(groupExtension) is not in this IR slice"))
            }
        }

        throw X64InstructionDecoderError(kind: .unsupportedOpcode(map: instruction.opcodeMap, opcode: opcode))
    }
}
