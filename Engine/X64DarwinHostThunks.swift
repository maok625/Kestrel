import Foundation

/// Guest addresses for a deliberately small set of synchronous Darwin C
/// thunks. Each stub is an INT3 byte in an RX guest page; the dispatcher
/// recognizes the exact stub RIP before instruction fetch and invokes its
/// registered host implementation. These are not host function pointers.
struct X64DarwinHostThunkTable: Sendable {
    let baseAddress: UInt64
    let byteCount: UInt64
    private let symbolsByAddress: [UInt64: String]
    private let addressesBySymbol: [String: UInt64]

    var supportedSymbols: [String] { addressesBySymbol.keys.sorted() }

    func address(for symbol: String) -> UInt64? { addressesBySymbol[symbol] }
    func symbol(at guestAddress: UInt64) -> String? { symbolsByAddress[guestAddress] }

    static func install(
        into memory: inout X64GuestVirtualMemory,
        baseAddress: UInt64 = 0x0000_6FFF_FFFF_0000
    ) throws -> (table: X64DarwinHostThunkTable, resolver: X64MachOSymbolResolver) {
        let pageSize = memory.pageSize
        let names = X64DarwinABIThunkRegistry.initialCBridge.descriptors.keys.sorted()
        let requiredBytes = UInt64(names.count) * 16
        guard !names.isEmpty, requiredBytes <= pageSize else {
            throw X64MachOFormatError(message: "The initial Darwin thunk table does not fit in one guest page.")
        }
        try memory.reserve(at: baseAddress, byteCount: pageSize, kind: .shared)
        do {
            try memory.commit(at: baseAddress, byteCount: pageSize, permissions: .readWrite)
            var byAddress: [UInt64: String] = [:]
            var bySymbol: [String: UInt64] = [:]
            var resolver = X64MachOSymbolResolver()
            for (index, name) in names.enumerated() {
                let address = baseAddress + UInt64(index) * 16
                try memory.writeBytes([0xCC], at: address) // INT3; dispatch intercepts exact registered RIPs.
                byAddress[address] = name
                bySymbol[name] = address
                resolver.register(symbol: name, address: address)
            }
            try memory.protect(at: baseAddress, byteCount: pageSize, permissions: .readExecute)
            return (
                X64DarwinHostThunkTable(
                    baseAddress: baseAddress,
                    byteCount: pageSize,
                    symbolsByAddress: byAddress,
                    addressesBySymbol: bySymbol
                ),
                resolver
            )
        } catch {
            try? memory.release(at: baseAddress)
            throw error
        }
    }
}

enum X64DarwinHostThunkDisposition: Sendable, Equatable {
    case returned(symbol: String)
    case processExit(status: Int32)
}

enum X64DarwinHostThunkDispatcher {
    private static let maximumIOBytes = 1 * 1024 * 1024

    static func invoke(
        symbol: String,
        state: inout X64CPUState,
        memory: inout X64GuestVirtualMemory,
        host: any X64DarwinSyscallHost
    ) throws -> X64DarwinHostThunkDisposition {
        switch symbol {
        case "_exit":
            let status = Int32(truncatingIfNeeded: state.registerValue(.rdi))
            return .processExit(status: status)

        case "_getpid":
            try returnInteger(UInt64(host.processIdentifier), state: &state)

        case "_write":
            let fd = Int32(truncatingIfNeeded: state.registerValue(.rdi))
            let address = state.registerValue(.rsi)
            let count = state.registerValue(.rdx)
            guard count <= UInt64(maximumIOBytes), count <= UInt64(Int.max) else {
                try returnInteger(UInt64.max, state: &state)
                return try finish(symbol, state: &state, memory: &memory)
            }
            do {
                try materializePages(at: address, count: Int(count), access: .read, memory: &memory)
                let bytes = try memory.readBytes(at: address, count: Int(count))
                let written = try host.write(fileDescriptor: fd, bytes: bytes)
                try returnInteger(UInt64(max(0, written)), state: &state)
            } catch {
                // POSIX C functions return -1 on failure. Thread-local errno
                // storage is not implemented yet, so the failure code is
                // preserved but errno consumers are not yet compatible.
                try returnInteger(UInt64.max, state: &state)
            }

        case "_read":
            let fd = Int32(truncatingIfNeeded: state.registerValue(.rdi))
            let address = state.registerValue(.rsi)
            let count = state.registerValue(.rdx)
            guard count <= UInt64(maximumIOBytes), count <= UInt64(Int.max) else {
                try returnInteger(UInt64.max, state: &state)
                return try finish(symbol, state: &state, memory: &memory)
            }
            do {
                let bytes = try host.read(fileDescriptor: fd, maximumCount: Int(count))
                try materializePages(at: address, count: bytes.count, access: .write, memory: &memory)
                try memory.writeBytes(bytes, at: address)
                try returnInteger(UInt64(bytes.count), state: &state)
            } catch {
                try returnInteger(UInt64.max, state: &state)
            }

        default:
            throw X64MachOFormatError(message: "No host implementation is registered for Darwin thunk \(symbol).")
        }
        return try finish(symbol, state: &state, memory: &memory)
    }

    private static func finish(
        _ symbol: String,
        state: inout X64CPUState,
        memory: inout X64GuestVirtualMemory
    ) throws -> X64DarwinHostThunkDisposition {
        let stack = state.registerValue(.rsp)
        let returnAddress = try memory.readUnsigned(at: stack, byteCount: 8)
        let (updatedStack, overflow) = stack.addingReportingOverflow(8)
        guard !overflow else {
            throw X64GuestVirtualMemoryFault(address: stack, byteCount: 8, access: .read, reason: "guest stack pointer overflows while returning from a host thunk")
        }
        try state.writeRegister(.rsp, value: updatedStack, width: .qword)
        state.rip = returnAddress
        return .returned(symbol: symbol)
    }

    private static func returnInteger(_ value: UInt64, state: inout X64CPUState) throws {
        try state.writeRegister(.rax, value: value, width: .qword)
    }

    private static func materializePages(
        at address: UInt64,
        count: Int,
        access: X64GuestMemoryAccess,
        memory: inout X64GuestVirtualMemory
    ) throws {
        guard count > 0 else { return }
        let (end, overflow) = address.addingReportingOverflow(UInt64(count))
        guard !overflow, end > address else {
            throw X64GuestVirtualMemoryFault(address: address, byteCount: count, access: access, reason: "host thunk I/O range overflows guest address space")
        }
        let pageSize = memory.pageSize
        var page = address & ~(pageSize - 1)
        let lastPage = (end - 1) & ~(pageSize - 1)
        while true {
            _ = try memory.resolveDemandZeroPage(at: page, access: access)
            if page == lastPage { return }
            let (next, nextOverflow) = page.addingReportingOverflow(pageSize)
            guard !nextOverflow else {
                throw X64GuestVirtualMemoryFault(address: page, byteCount: 1, access: access, reason: "host thunk page walk overflows")
            }
            page = next
        }
    }
}
