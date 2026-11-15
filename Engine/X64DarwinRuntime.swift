import Foundation

// MARK: - Initial guest process state

struct X64GuestProcessStartupState: Sendable, Equatable {
    /// The executable's LC_MAIN address. dyld reaches this only after it has
    /// loaded dependencies, applied fixups, initialized runtime state, etc.
    let entryPoint: UInt64
    /// Address of the mapped main executable mach_header in guest memory.
    let mainMachHeaderAddress: UInt64
    /// Initial kernel stack pointer: the first word is mainMachHeaderAddress,
    /// followed by argc, argv[], envp[], and the apple parameter vector.
    let stackPointer: UInt64
    let argumentCount: Int
    let argvPointer: UInt64
    let envpPointer: UInt64
    let applePointer: UInt64
    let stackReservation: X64GuestVirtualRegionInfo
    let usableStackBase: UInt64
    let usableStackSize: UInt64
}

enum X64GuestProcessStartupError: LocalizedError {
    case tooManyArguments
    case tooManyEnvironmentEntries
    case valueTooLarge
    case stackOverflow

    var errorDescription: String? {
        switch self {
        case .tooManyArguments: return "Guest startup has more than 4096 arguments."
        case .tooManyEnvironmentEntries: return "Guest startup has more than 4096 environment entries."
        case .valueTooLarge: return "A guest startup string exceeds the 1 MiB safety limit."
        case .stackOverflow: return "The initial guest process data does not fit in the reserved stack."
        }
    }
}

/// Builds the kernel-provided x86_64 Darwin KernelArgs stack shape:
/// mach_header*, argc, argv[], NULL, envp[], NULL, apple[], NULL, strings.
/// It does not synthesize the rest of dyld's runtime state. In particular,
/// Kestrel must load/initialize a compatible dyld before transferring control
/// to an actual __dyld_start entry point.
enum X64GuestProcessStackBuilder {
    static let defaultUsableStackSize: UInt64 = 8 * 1024 * 1024
    private static let minimumAddress: UInt64 = 0x0000_7FFF_0000_0000
    private static let maximumAddress: UInt64 = 0x0000_8000_0000_0000
    private static let maximumStringBytes = 1024 * 1024

    static func build(
        entryPoint: UInt64,
        mainMachHeaderAddress: UInt64,
        executablePath: String,
        arguments: [String],
        environment: [String: String],
        into memory: inout X64GuestVirtualMemory,
        usableStackSize: UInt64 = defaultUsableStackSize
    ) throws -> X64GuestProcessStartupState {
        guard arguments.count <= 4_096 else { throw X64GuestProcessStartupError.tooManyArguments }
        guard environment.count <= 4_096 else { throw X64GuestProcessStartupError.tooManyEnvironmentEntries }
        guard usableStackSize > 0, usableStackSize % memory.pageSize == 0 else {
            throw X64GuestProcessStartupError.stackOverflow
        }

        let pageSize = memory.pageSize
        let twoGuards = pageSize.multipliedReportingOverflow(by: 2)
        let reservationSize = usableStackSize.addingReportingOverflow(twoGuards.partialValue)
        guard !twoGuards.overflow, !reservationSize.overflow else { throw X64GuestProcessStartupError.stackOverflow }

        let reservation = try memory.reserveAnywhere(
            byteCount: reservationSize.partialValue,
            alignment: pageSize,
            minimumAddress: minimumAddress,
            maximumAddress: maximumAddress,
            kind: .stack
        )
        let usableBase = reservation.baseAddress + pageSize
        do {
            try memory.commit(at: usableBase, byteCount: usableStackSize, permissions: .readWrite)

            let argv = [executablePath] + arguments
            let envp = environment.keys.sorted().map { "\($0)=\(environment[$0] ?? "")" }
            // This is intentionally a minimal apple vector, not the complete
            // set of kernel parameters consumed by every dyld version.
            let apple = ["executable_path=\(executablePath)", "platform=MACOS"]
            var cursor = usableBase + usableStackSize

            func pushString(_ value: String, cursor: inout UInt64, memory: inout X64GuestVirtualMemory) throws -> UInt64 {
                let encoded = Array(value.utf8)
                guard encoded.count < maximumStringBytes else { throw X64GuestProcessStartupError.valueTooLarge }
                let byteCount = UInt64(encoded.count + 1)
                guard cursor >= usableBase, byteCount <= cursor - usableBase else {
                    throw X64GuestProcessStartupError.stackOverflow
                }
                cursor -= byteCount
                try memory.writeBytes(encoded + [0], at: cursor)
                return cursor
            }

            var argvPointers = [UInt64]()
            argvPointers.reserveCapacity(argv.count)
            for value in argv.reversed() {
                argvPointers.append(try pushString(value, cursor: &cursor, memory: &memory))
            }
            argvPointers.reverse()

            var envPointers = [UInt64]()
            envPointers.reserveCapacity(envp.count)
            for value in envp.reversed() {
                envPointers.append(try pushString(value, cursor: &cursor, memory: &memory))
            }
            envPointers.reverse()

            var applePointers = [UInt64]()
            applePointers.reserveCapacity(apple.count)
            for value in apple.reversed() {
                applePointers.append(try pushString(value, cursor: &cursor, memory: &memory))
            }
            applePointers.reverse()

            // Darwin dyld's KernelArgs view begins with the main executable's
            // mach_header pointer and argc. The dyld entry shim receives this
            // whole vector through its original stack pointer.
            var words = [mainMachHeaderAddress, UInt64(argv.count)]
            let argvPointerOffset = words.count * 8
            words.append(contentsOf: argvPointers)
            words.append(0)
            let envpPointerOffset = words.count * 8
            words.append(contentsOf: envPointers)
            words.append(0)
            let applePointerOffset = words.count * 8
            words.append(contentsOf: applePointers)
            words.append(0)

            let tableBytes = UInt64(words.count * 8)
            guard cursor >= usableBase, tableBytes <= cursor - usableBase else {
                throw X64GuestProcessStartupError.stackOverflow
            }
            let stackPointer = (cursor - tableBytes) & ~UInt64(0xF)
            guard stackPointer >= usableBase else { throw X64GuestProcessStartupError.stackOverflow }

            var encodedWords = [UInt8]()
            encodedWords.reserveCapacity(words.count * 8)
            for word in words {
                for shift in stride(from: 0, to: 64, by: 8) {
                    encodedWords.append(UInt8(truncatingIfNeeded: word >> shift))
                }
            }
            try memory.writeBytes(encodedWords, at: stackPointer)

            return X64GuestProcessStartupState(
                entryPoint: entryPoint,
                mainMachHeaderAddress: mainMachHeaderAddress,
                stackPointer: stackPointer,
                argumentCount: argv.count,
                argvPointer: stackPointer + UInt64(argvPointerOffset),
                envpPointer: stackPointer + UInt64(envpPointerOffset),
                applePointer: stackPointer + UInt64(applePointerOffset),
                stackReservation: reservation,
                usableStackBase: usableBase,
                usableStackSize: usableStackSize
            )
        } catch {
            try? memory.release(at: reservation.baseAddress)
            throw error
        }
    }
}

extension X64GuestProcessStartupState {
    /// Installs the kernel-to-dyld entry state. The dyld startup shim itself
    /// moves the original RSP into RDI before calling dyld::start(KernelArgs*).
    /// This method requires a real guest __dyld_start address; LC_MAIN is not
    /// substituted because it is reached only after dyld initialization.
    func installDyldEntry(
        dyldEntryPoint: UInt64,
        into state: inout X64CPUState
    ) throws {
        state.rip = dyldEntryPoint
        try state.writeRegister(.rsp, value: stackPointer, width: .qword)
        try state.writeRegister(.rbp, value: 0, width: .qword)
    }
}

// MARK: - Darwin x86_64 syscall ABI subset

protocol X64DarwinSyscallHost {
    var processIdentifier: UInt32 { get }
    func read(fileDescriptor: Int32, maximumCount: Int) throws -> [UInt8]
    func write(fileDescriptor: Int32, bytes: [UInt8]) throws -> Int
}

struct X64DarwinSyscallHostError: Error, Sendable {
    let errno: Int32
}

struct X64ConsoleDarwinSyscallHost: X64DarwinSyscallHost {
    var processIdentifier: UInt32 { UInt32(ProcessInfo.processInfo.processIdentifier) }

    func read(fileDescriptor: Int32, maximumCount: Int) throws -> [UInt8] {
        guard fileDescriptor == 0 else { throw X64DarwinSyscallHostError(errno: 9) }
        do {
            return Array(try FileHandle.standardInput.read(upToCount: maximumCount) ?? Data())
        } catch {
            throw X64DarwinSyscallHostError(errno: 5)
        }
    }

    func write(fileDescriptor: Int32, bytes: [UInt8]) throws -> Int {
        let handle: FileHandle
        switch fileDescriptor {
        case 1: handle = .standardOutput
        case 2: handle = .standardError
        default: throw X64DarwinSyscallHostError(errno: 9)
        }
        do {
            try handle.write(contentsOf: Data(bytes))
            return bytes.count
        } catch {
            throw X64DarwinSyscallHostError(errno: 5)
        }
    }
}

enum X64DarwinSyscallDisposition: Sendable, Equatable {
    case continueExecution
    case processExit(status: Int32)
}

enum X64DarwinSyscallDispatcher {
    private static let unixClass: UInt64 = 0x0200_0000
    private static let syscallClassMask: UInt64 = 0xFF00_0000
    private static let syscallNumberMask: UInt64 = 0x00FF_FFFF
    private static let maximumIOBytes = 1 * 1024 * 1024

    // Darwin x86_64 BSD syscall numbers within SYSCALL_CLASS_UNIX.
    private enum Number: UInt64 {
        case exit = 1
        case read = 3
        case write = 4
        case getpid = 20
    }

    /// Dispatches a syscall after the translated SYSCALL instruction has
    /// exited to the Swift block dispatcher. RAX contains the Darwin syscall
    /// number; RDI, RSI and RDX contain its first three arguments.
    static func dispatch(
        state: inout X64CPUState,
        memory: inout X64GuestVirtualMemory,
        host: any X64DarwinSyscallHost
    ) throws -> X64DarwinSyscallDisposition {
        let encodedNumber = state.registerValue(.rax)
        guard encodedNumber & syscallClassMask == unixClass else {
            returnFailure(errno: 78, state: &state) // ENOSYS
            return .continueExecution
        }
        let number = encodedNumber & syscallNumberMask
        guard let syscall = Number(rawValue: number) else {
            returnFailure(errno: 78, state: &state)
            return .continueExecution
        }

        switch syscall {
        case .exit:
            let status = Int32(truncatingIfNeeded: state.registerValue(.rdi))
            return .processExit(status: status)

        case .getpid:
            returnSuccess(UInt64(host.processIdentifier), state: &state)

        case .write:
            let fd = Int32(truncatingIfNeeded: state.registerValue(.rdi))
            let address = state.registerValue(.rsi)
            let count = state.registerValue(.rdx)
            guard count <= UInt64(maximumIOBytes) else {
                returnFailure(errno: 22, state: &state) // EINVAL
                return .continueExecution
            }
            do {
                try materializeDemandZeroPages(at: address, count: Int(count), access: .read, memory: &memory)
                let bytes = try memory.readBytes(at: address, count: Int(count))
                let written = try host.write(fileDescriptor: fd, bytes: bytes)
                guard written >= 0, written <= bytes.count else {
                    returnFailure(errno: 5, state: &state)
                    return .continueExecution
                }
                returnSuccess(UInt64(written), state: &state)
            } catch let error as X64DarwinSyscallHostError {
                returnFailure(errno: error.errno, state: &state)
            } catch {
                returnFailure(errno: 14, state: &state) // EFAULT
            }

        case .read:
            let fd = Int32(truncatingIfNeeded: state.registerValue(.rdi))
            let address = state.registerValue(.rsi)
            let count = state.registerValue(.rdx)
            guard count <= UInt64(maximumIOBytes) else {
                returnFailure(errno: 22, state: &state)
                return .continueExecution
            }
            do {
                let bytes = try host.read(fileDescriptor: fd, maximumCount: Int(count))
                try materializeDemandZeroPages(at: address, count: bytes.count, access: .write, memory: &memory)
                try memory.writeBytes(bytes, at: address)
                returnSuccess(UInt64(bytes.count), state: &state)
            } catch let error as X64DarwinSyscallHostError {
                returnFailure(errno: error.errno, state: &state)
            } catch {
                returnFailure(errno: 14, state: &state)
            }
        }

        return .continueExecution
    }

    private static func materializeDemandZeroPages(
        at address: UInt64,
        count: Int,
        access: X64GuestMemoryAccess,
        memory: inout X64GuestVirtualMemory
    ) throws {
        guard count > 0 else { return }
        let pageSize = memory.pageSize
        let end = address.addingReportingOverflow(UInt64(count))
        guard !end.overflow, end.partialValue > address else {
            throw X64GuestVirtualMemoryFault(address: address, byteCount: count, access: access, reason: "I/O range overflows guest address space")
        }
        var page = address & ~(pageSize - 1)
        let finalPage = (end.partialValue - 1) & ~(pageSize - 1)
        while page <= finalPage {
            _ = try memory.resolveDemandZeroPage(at: page, access: access)
            if page == finalPage { break }
            let next = page.addingReportingOverflow(pageSize)
            guard !next.overflow else {
                throw X64GuestVirtualMemoryFault(address: page, byteCount: 1, access: access, reason: "I/O page walk overflows")
            }
            page = next.partialValue
        }
    }

    private static func returnSuccess(_ value: UInt64, state: inout X64CPUState) {
        try? state.writeRegister(.rax, value: value, width: .qword)
        state.setFlag(.carry, to: false)
    }

    private static func returnFailure(errno: Int32, state: inout X64CPUState) {
        try? state.writeRegister(.rax, value: UInt64(errno), width: .qword)
        state.setFlag(.carry, to: true)
    }
}

// MARK: - Guest/host function ABI descriptors

enum X64DarwinABIArgumentSource: String, Sendable, Equatable {
    case rdi, rsi, rdx, rcx, r8, r9
    case guestStack
}

struct X64DarwinABIThunkDescriptor: Sendable, Equatable {
    let symbolName: String
    let argumentSources: [X64DarwinABIArgumentSource]
    let returnsIntegerInRAX: Bool
    let requiresGuestPointerTranslation: Bool
}

/// Registry of explicit guest-to-host thunk contracts. It intentionally does
/// not treat an ARM64 host function pointer as a guest address. A generated
/// trampoline and call dispatcher must consume these descriptors before any
/// imported function can be invoked safely.
struct X64DarwinABIThunkRegistry: Sendable {
    private(set) var descriptors: [String: X64DarwinABIThunkDescriptor] = [:]

    mutating func register(_ descriptor: X64DarwinABIThunkDescriptor) {
        descriptors[descriptor.symbolName] = descriptor
    }

    func descriptor(for symbolName: String) -> X64DarwinABIThunkDescriptor? {
        descriptors[symbolName]
    }

    static var initialCBridge: X64DarwinABIThunkRegistry {
        var registry = X64DarwinABIThunkRegistry()
        registry.register(.init(symbolName: "_read", argumentSources: [.rdi, .rsi, .rdx], returnsIntegerInRAX: true, requiresGuestPointerTranslation: true))
        registry.register(.init(symbolName: "_write", argumentSources: [.rdi, .rsi, .rdx], returnsIntegerInRAX: true, requiresGuestPointerTranslation: true))
        registry.register(.init(symbolName: "_getpid", argumentSources: [], returnsIntegerInRAX: true, requiresGuestPointerTranslation: false))
        registry.register(.init(symbolName: "_exit", argumentSources: [.rdi], returnsIntegerInRAX: false, requiresGuestPointerTranslation: false))
        return registry
    }
}
