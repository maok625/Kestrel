import Foundation

/// Swift boundary for the C MAP_JIT executor.
enum JITExecutor {
    static func executeReturningUInt32(_ words: [UInt32]) throws -> UInt32 {
        var result: UInt32 = 0
        let status = words.withUnsafeBufferPointer { buffer in
            kestrel_jit_execute(buffer.baseAddress, buffer.count, &result)
        }
        guard status == 0 else {
            throw JITError.executionFailed(code: status)
        }
        return result
    }

    enum JITError: LocalizedError {
        case executionFailed(code: Int32)
        var errorDescription: String? {
            switch self {
            case .executionFailed(let code):
                return "MAP_JIT execution failed with error code \(code)."
            }
        }
    }
}

enum KestrelRuntime {
    static func runSelfTest() throws -> (result: UInt32, arm64Words: [UInt32]) {
        // x86_64: mov eax, 42 ; add eax, 8 ; ret
        let sample: [UInt8] = [
            0xB8, 0x2A, 0x00, 0x00, 0x00,
            0x05, 0x08, 0x00, 0x00, 0x00,
            0xC3
        ]

        let arm64 = try X64BasicBlockTranslator.translate(sample)
        let result = try JITExecutor.executeReturningUInt32(arm64)
        guard result == 50 else {
            throw SelfTestError.wrongResult(expected: 50, actual: result)
        }
        return (result, arm64)
    }

    enum SelfTestError: LocalizedError {
        case wrongResult(expected: UInt32, actual: UInt32)
        var errorDescription: String? {
            switch self {
            case .wrongResult(let expected, let actual):
                return "Translation self-test failed: expected \(expected), got \(actual)."
            }
        }
    }
}
