import Foundation

/// First executable slice of Kestrel's x86_64 -> AArch64 dynamic translator.
/// This deliberately supports a tiny, explicit instruction subset. It is not
/// a general x86_64 decoder and must not be used to load arbitrary Mach-O apps.
enum X64BasicBlockTranslator {
    enum TranslationError: LocalizedError {
        case emptyBlock
        case truncatedInstruction(offset: Int)
        case unsupportedOpcode(opcode: UInt8, offset: Int)
        case missingReturn
        case trailingBytes(offset: Int)

        var errorDescription: String? {
            switch self {
            case .emptyBlock:
                return "The x86_64 block is empty."
            case .truncatedInstruction(let offset):
                return String(format: "Truncated x86_64 instruction at byte offset 0x%X.", offset)
            case .unsupportedOpcode(let opcode, let offset):
                return String(format: "Unsupported x86_64 opcode 0x%02X at byte offset 0x%X.", opcode, offset)
            case .missingReturn:
                return "The block must end with RET (0xC3)."
            case .trailingBytes(let offset):
                return String(format: "Unexpected bytes after RET at byte offset 0x%X.", offset)
            }
        }
    }

    /// Supported instructions:
    ///   B8 id              MOV EAX, imm32
    ///   05                 ADD EAX, imm32
    ///   90                 NOP
    ///   C3                 RET
    ///
    /// The output is one AArch64 function using the platform C calling
    /// convention. EAX maps to W0. Arithmetic wraps at 32 bits, as x86 does.
    static func translate(_ x86: [UInt8]) throws -> [UInt32] {
        guard !x86.isEmpty else { throw TranslationError.emptyBlock }

        var arm: [UInt32] = []
        var cursor = 0
        var sawReturn = false

        while cursor < x86.count {
            let instructionOffset = cursor
            let opcode = x86[cursor]
            cursor += 1

            switch opcode {
            case 0x90: // NOP
                arm.append(0xD503_201F)

            case 0xB8: // MOV EAX, imm32
                let immediate = try readImmediate32(x86, cursor: &cursor, instructionOffset: instructionOffset)
                emitLoad32(immediate, into: 0, output: &arm)

            case 0x05: // ADD EAX, imm32
                let immediate = try readImmediate32(x86, cursor: &cursor, instructionOffset: instructionOffset)
                emitLoad32(immediate, into: 1, output: &arm)
                // ADD W0, W0, W1
                arm.append(0x0B01_0000)

            case 0xC3: // RET
                arm.append(0xD65F_03C0)
                sawReturn = true
                if cursor != x86.count {
                    throw TranslationError.trailingBytes(offset: cursor)
                }
                break

            default:
                throw TranslationError.unsupportedOpcode(opcode: opcode, offset: instructionOffset)
            }

            if sawReturn { break }
        }

        guard sawReturn else { throw TranslationError.missingReturn }
        return arm
    }

    private static func readImmediate32(_ bytes: [UInt8], cursor: inout Int, instructionOffset: Int) throws -> UInt32 {
        guard cursor + 4 <= bytes.count else {
            throw TranslationError.truncatedInstruction(offset: instructionOffset)
        }
        let value = UInt32(bytes[cursor])
            | (UInt32(bytes[cursor + 1]) << 8)
            | (UInt32(bytes[cursor + 2]) << 16)
            | (UInt32(bytes[cursor + 3]) << 24)
        cursor += 4
        return value
    }

    private static func emitLoad32(_ value: UInt32, into register: UInt32, output: inout [UInt32]) {
        let low = value & 0xFFFF
        let high = (value >> 16) & 0xFFFF
        // MOVZ Wd, #low
        output.append(0x5280_0000 | (low << 5) | register)
        // MOVK Wd, #high, LSL #16
        output.append(0x72A0_0000 | (high << 5) | register)
    }
}
