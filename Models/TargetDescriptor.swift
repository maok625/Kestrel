import Foundation

enum BinaryArchitecture: String, CaseIterable {
    case arm64 = "arm64"
    case x86_64 = "x86_64"
    case unknown = "Unknown"
}

struct TargetDescriptor {
    let selectedURL: URL
    let executableURL: URL
    let isApplicationBundle: Bool
    let architectures: Set<BinaryArchitecture>

    var architectureSummary: String {
        architectures.map(\.rawValue).sorted().joined(separator: " + ")
    }

    var canRunNativelyOnAppleSilicon: Bool {
        architectures.contains(.arm64)
    }
}

enum TargetInspectionError: LocalizedError {
    case missingExecutable
    case unreadableBinary
    case unsupportedMachO

    var errorDescription: String? {
        switch self {
        case .missingExecutable: return "The application bundle does not contain a readable executable."
        case .unreadableBinary: return "The selected executable could not be read."
        case .unsupportedMachO: return "The selected file is not a supported 64-bit Mach-O executable."
        }
    }
}

enum TargetInspector {
    static func inspect(_ selectedURL: URL) throws -> TargetDescriptor {
        let isBundle = selectedURL.pathExtension.lowercased() == "app"
        let executableURL: URL

        if isBundle {
            guard let bundle = Bundle(url: selectedURL),
                  let resolved = bundle.executableURL,
                  FileManager.default.isReadableFile(atPath: resolved.path) else {
                throw TargetInspectionError.missingExecutable
            }
            executableURL = resolved
        } else {
            executableURL = selectedURL
        }

        let architectures = try MachOArchitectureReader.read(from: executableURL)
        return TargetDescriptor(
            selectedURL: selectedURL,
            executableURL: executableURL,
            isApplicationBundle: isBundle,
            architectures: architectures
        )
    }
}

private enum MachOArchitectureReader {
    private static let cpuTypeX86_64: UInt32 = 0x0100_0007
    private static let cpuTypeARM64: UInt32 = 0x0100_000C
    private static let mhMagic64: UInt32 = 0xFEED_FACF
    private static let fatMagic: UInt32 = 0xCAFE_BABE
    private static let fatMagic64: UInt32 = 0xCAFE_BABF
    private static let fatCigam: UInt32 = 0xBEBA_FECA
    private static let fatCigam64: UInt32 = 0xBFBA_FECA

    static func read(from url: URL) throws -> Set<BinaryArchitecture> {
        guard let handle = try? FileHandle(forReadingFrom: url) else {
            throw TargetInspectionError.unreadableBinary
        }
        defer { try? handle.close() }
        guard let data = try? handle.read(upToCount: 4096), data.count >= 8 else {
            throw TargetInspectionError.unreadableBinary
        }

        let magic = be32(data, 0)
        if magic == fatMagic || magic == fatMagic64 {
            return readFat(data, is64: magic == fatMagic64, swapped: false)
        }
        if magic == fatCigam || magic == fatCigam64 {
            return readFat(data, is64: magic == fatCigam64, swapped: true)
        }

        // Thin Mach-O headers are little-endian on macOS.
        let littleMagic = le32(data, 0)
        guard littleMagic == mhMagic64 else { throw TargetInspectionError.unsupportedMachO }
        return architectureSet(for: le32(data, 4))
    }

    private static func readFat(_ data: Data, is64: Bool, swapped: Bool) -> Set<BinaryArchitecture> {
        guard data.count >= 8 else { return [.unknown] }
        let count = Int(readFatWord(data, 4, swapped: swapped))
        let entrySize = is64 ? 32 : 20
        guard count > 0, count <= 64, data.count >= 8 + count * entrySize else { return [.unknown] }

        var result = Set<BinaryArchitecture>()
        for index in 0..<count {
            let offset = 8 + index * entrySize
            result.formUnion(architectureSet(for: readFatWord(data, offset, swapped: swapped)))
        }
        return result.isEmpty ? [.unknown] : result
    }

    private static func readFatWord(_ data: Data, _ offset: Int, swapped: Bool) -> UInt32 {
        let value = be32(data, offset)
        return swapped ? value.byteSwapped : value
    }

    private static func architectureSet(for cpuType: UInt32) -> Set<BinaryArchitecture> {
        switch cpuType {
        case cpuTypeARM64: return [.arm64]
        case cpuTypeX86_64: return [.x86_64]
        default: return [.unknown]
        }
    }

    private static func le32(_ data: Data, _ offset: Int) -> UInt32 {
        guard offset + 4 <= data.count else { return 0 }
        return UInt32(data[offset])
            | (UInt32(data[offset + 1]) << 8)
            | (UInt32(data[offset + 2]) << 16)
            | (UInt32(data[offset + 3]) << 24)
    }

    private static func be32(_ data: Data, _ offset: Int) -> UInt32 {
        guard offset + 4 <= data.count else { return 0 }
        return (UInt32(data[offset]) << 24)
            | (UInt32(data[offset + 1]) << 16)
            | (UInt32(data[offset + 2]) << 8)
            | UInt32(data[offset + 3])
    }
}
