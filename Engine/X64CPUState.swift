import Foundation

/// The operand width of an x86-64 integer register access.
enum X64OperandWidth: Int, CaseIterable, Sendable {
    case byte = 8
    case word = 16
    case dword = 32
    case qword = 64

    var bitCount: Int { rawValue }

    var mask: UInt64 {
        switch self {
        case .byte: return 0xFF
        case .word: return 0xFFFF
        case .dword: return 0xFFFF_FFFF
        case .qword: return .max
        }
    }

    var signBit: UInt64 {
        UInt64(1) << (bitCount - 1)
    }
}

/// Register numbering follows the ModRM / REX encoding order.
enum X64GeneralRegister: Int, CaseIterable, Sendable, Identifiable {
    case rax = 0
    case rcx = 1
    case rdx = 2
    case rbx = 3
    case rsp = 4
    case rbp = 5
    case rsi = 6
    case rdi = 7
    case r8 = 8
    case r9 = 9
    case r10 = 10
    case r11 = 11
    case r12 = 12
    case r13 = 13
    case r14 = 14
    case r15 = 15

    var id: Int { rawValue }

    var name: String {
        switch self {
        case .rax: return "RAX"
        case .rcx: return "RCX"
        case .rdx: return "RDX"
        case .rbx: return "RBX"
        case .rsp: return "RSP"
        case .rbp: return "RBP"
        case .rsi: return "RSI"
        case .rdi: return "RDI"
        case .r8: return "R8"
        case .r9: return "R9"
        case .r10: return "R10"
        case .r11: return "R11"
        case .r12: return "R12"
        case .r13: return "R13"
        case .r14: return "R14"
        case .r15: return "R15"
        }
    }
}

/// The six arithmetic status flags updated by integer ADD/SUB operations,
/// plus common architectural control/status flags retained in RFLAGS.
enum X64Flag: UInt64, CaseIterable, Sendable {
    case carry = 1
    case parity = 4
    case auxiliaryCarry = 16
    case zero = 64
    case sign = 128
    case trap = 256
    case interruptEnable = 512
    case direction = 1024
    case overflow = 2048

    var mask: UInt64 { rawValue }
}

struct X64CPUStateError: LocalizedError {
    let message: String

    var errorDescription: String? { message }

    static func invalidRegisterIndex(_ index: UInt8) -> Self {
        Self(message: "Invalid x86-64 register index \(index); expected 0...15.")
    }

    static func invalidHighByteRegister(_ index: UInt8, width: X64OperandWidth) -> Self {
        Self(message: "High-byte register encoding is invalid for index \(index) and width \(width.bitCount).")
    }
}

/// A decoded view of a general-purpose register.
///
/// `highByte` is true only for AH/CH/DH/BH. In the absence of a REX prefix,
/// byte-register encodings 4...7 select those high-byte registers. With any
/// REX prefix, the same encodings select SPL/BPL/SIL/DIL instead.
struct X64RegisterOperand: Sendable, Equatable {
    let register: X64GeneralRegister
    let width: X64OperandWidth
    let highByte: Bool

    init(encodedIndex: UInt8, width: X64OperandWidth, rexPresent: Bool) throws {
        guard encodedIndex < 16,
              (encodedIndex < 8 || rexPresent),
              let decodedRegister = X64GeneralRegister(rawValue: Int(encodedIndex)) else {
            throw X64CPUStateError.invalidRegisterIndex(encodedIndex)
        }

        if width == .byte && !rexPresent && (4...7).contains(encodedIndex) {
            guard let legacyRegister = X64GeneralRegister(rawValue: Int(encodedIndex - 4)) else {
                throw X64CPUStateError.invalidHighByteRegister(encodedIndex, width: width)
            }
            register = legacyRegister
            self.width = width
            highByte = true
        } else {
            register = decodedRegister
            self.width = width
            highByte = false
        }
    }

    init(register: X64GeneralRegister, width: X64OperandWidth, highByte: Bool = false) throws {
        guard !highByte || width == .byte,
              !highByte || register.rawValue <= X64GeneralRegister.rbx.rawValue else {
            throw X64CPUStateError.invalidHighByteRegister(UInt8(register.rawValue), width: width)
        }
        self.register = register
        self.width = width
        self.highByte = highByte
    }
}

/// Architectural state for one x86-64 guest thread.
///
/// This is guest state only. The values are not host ARM64 registers, and guest
/// pointers stored here must never be directly dereferenced as host pointers.
struct X64CPUState: Sendable {
    private(set) var generalRegisters: [UInt64]
    var rip: UInt64
    private(set) var rflags: UInt64

    private static let reservedRFLAGSBit1: UInt64 = 1 << 1
    private static let arithmeticFlagMask: UInt64 =
        X64Flag.carry.mask |
        X64Flag.parity.mask |
        X64Flag.auxiliaryCarry.mask |
        X64Flag.zero.mask |
        X64Flag.sign.mask |
        X64Flag.overflow.mask

    init(rip: UInt64 = 0, rflags: UInt64 = 0x2) {
        generalRegisters = Array(repeating: 0, count: 16)
        self.rip = rip
        self.rflags = rflags | Self.reservedRFLAGSBit1
    }

    func registerValue(_ register: X64GeneralRegister) -> UInt64 {
        generalRegisters[register.rawValue]
    }

    func read(_ operand: X64RegisterOperand) -> UInt64 {
        let value = generalRegisters[operand.register.rawValue]
        if operand.highByte {
            return (value >> 8) & 0xFF
        }
        return value & operand.width.mask
    }

    mutating func write(_ value: UInt64, to operand: X64RegisterOperand) {
        let index = operand.register.rawValue
        let oldValue = generalRegisters[index]

        if operand.highByte {
            let byteMask: UInt64 = 0xFF << 8
            generalRegisters[index] = (oldValue & ~byteMask) | ((value & 0xFF) << 8)
            return
        }

        switch operand.width {
        case .byte:
            generalRegisters[index] = (oldValue & ~UInt64(0xFF)) | (value & 0xFF)
        case .word:
            generalRegisters[index] = (oldValue & ~UInt64(0xFFFF)) | (value & 0xFFFF)
        case .dword:
            // In 64-bit mode, writing a 32-bit GPR clears its upper 32 bits.
            generalRegisters[index] = value & 0xFFFF_FFFF
        case .qword:
            generalRegisters[index] = value
        }
    }

    mutating func writeRegister(
        _ register: X64GeneralRegister,
        value: UInt64,
        width: X64OperandWidth,
        highByte: Bool = false
    ) throws {
        let operand = try X64RegisterOperand(register: register, width: width, highByte: highByte)
        write(value, to: operand)
    }

    func readRegister(
        _ register: X64GeneralRegister,
        width: X64OperandWidth,
        highByte: Bool = false
    ) throws -> UInt64 {
        let operand = try X64RegisterOperand(register: register, width: width, highByte: highByte)
        return read(operand)
    }

    func flagIsSet(_ flag: X64Flag) -> Bool {
        (rflags & flag.mask) != 0
    }

    mutating func setFlag(_ flag: X64Flag, to enabled: Bool) {
        if enabled {
            rflags |= flag.mask
        } else {
            rflags &= ~flag.mask
        }
        rflags |= Self.reservedRFLAGSBit1
    }

    /// Executes the architectural flag calculation for an integer ADD/ADC.
    /// Returns the width-truncated result and updates CF, PF, AF, ZF, SF, OF.
    @discardableResult
    mutating func add(
        _ lhs: UInt64,
        _ rhs: UInt64,
        width: X64OperandWidth,
        carryIn: Bool = false
    ) -> UInt64 {
        let a = lhs & width.mask
        let b = rhs & width.mask
        let carry = carryIn ? UInt64(1) : UInt64(0)

        let (partial, firstOverflow) = a.addingReportingOverflow(b)
        let (sum, secondOverflow) = partial.addingReportingOverflow(carry)
        let result = sum & width.mask
        let carryOut: Bool
        if width == .qword {
            carryOut = firstOverflow || secondOverflow
        } else {
            carryOut = sum > width.mask
        }

        let overflow = ((~(a ^ b) & (a ^ result)) & width.signBit) != 0
        let auxiliaryCarry = ((a ^ b ^ result) & 0x10) != 0
        updateArithmeticFlags(
            result: result,
            width: width,
            carry: carryOut,
            parity: hasEvenParity(in: result),
            auxiliaryCarry: auxiliaryCarry,
            overflow: overflow
        )
        return result
    }

    /// Executes the architectural flag calculation for integer SUB/SBB.
    /// Returns the width-truncated result and updates CF, PF, AF, ZF, SF, OF.
    @discardableResult
    mutating func subtract(
        _ lhs: UInt64,
        _ rhs: UInt64,
        width: X64OperandWidth,
        borrowIn: Bool = false
    ) -> UInt64 {
        let a = lhs & width.mask
        let b = rhs & width.mask
        let borrow = borrowIn ? UInt64(1) : UInt64(0)

        let (partial, firstBorrow) = a.subtractingReportingOverflow(b)
        let (difference, secondBorrow) = partial.subtractingReportingOverflow(borrow)
        let result = difference & width.mask
        let borrowOut: Bool
        if width == .qword {
            borrowOut = firstBorrow || secondBorrow
        } else {
            borrowOut = a < (b + borrow)
        }

        let overflow = (((a ^ b) & (a ^ result)) & width.signBit) != 0
        let auxiliaryBorrow = ((a ^ b ^ result) & 0x10) != 0
        updateArithmeticFlags(
            result: result,
            width: width,
            carry: borrowOut,
            parity: hasEvenParity(in: result),
            auxiliaryCarry: auxiliaryBorrow,
            overflow: overflow
        )
        return result
    }

    private mutating func updateArithmeticFlags(
        result: UInt64,
        width: X64OperandWidth,
        carry: Bool,
        parity: Bool,
        auxiliaryCarry: Bool,
        overflow: Bool
    ) {
        rflags &= ~Self.arithmeticFlagMask
        if carry { rflags |= X64Flag.carry.mask }
        if parity { rflags |= X64Flag.parity.mask }
        if auxiliaryCarry { rflags |= X64Flag.auxiliaryCarry.mask }
        if result == 0 { rflags |= X64Flag.zero.mask }
        if (result & width.signBit) != 0 { rflags |= X64Flag.sign.mask }
        if overflow { rflags |= X64Flag.overflow.mask }
        rflags |= Self.reservedRFLAGSBit1
    }

    private func hasEvenParity(in value: UInt64) -> Bool {
        UInt8(truncatingIfNeeded: value).nonzeroBitCount.isMultiple(of: 2)
    }
}

extension X64CPUState {
    /// Restores a serialized architectural RFLAGS value. Reserved bit 1 is
    /// always forced to one, matching the invariant used by the interpreter.
    mutating func restoreRFLAGS(_ value: UInt64) {
        rflags = value | 0x2
    }
}
