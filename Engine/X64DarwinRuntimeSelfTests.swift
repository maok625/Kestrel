import Foundation

enum X64DarwinRuntimeSelfTests {
    private final class MockHost: X64DarwinSyscallHost {
        let processIdentifier: UInt32 = 4242
        var input: [UInt8] = [0x41, 0x42, 0x43]
        var output: [UInt8] = []

        func read(fileDescriptor: Int32, maximumCount: Int) throws -> [UInt8] {
            guard fileDescriptor == 0 else { throw X64DarwinSyscallHostError(errno: 9) }
            let count = min(maximumCount, input.count)
            let result = Array(input.prefix(count))
            input.removeFirst(count)
            return result
        }

        func write(fileDescriptor: Int32, bytes: [UInt8]) throws -> Int {
            guard fileDescriptor == 1 || fileDescriptor == 2 else {
                throw X64DarwinSyscallHostError(errno: 9)
            }
            output.append(contentsOf: bytes)
            return bytes.count
        }
    }

    static func run() throws -> [String] {
        var passed: [String] = []

        do {
            var memory = try X64GuestVirtualMemory()
            let startup = try X64GuestProcessStackBuilder.build(
                entryPoint: 0x1_0000_1000,
                mainMachHeaderAddress: 0x1_0000_0000,
                executablePath: "/Applications/Kyty.app/Contents/MacOS/kyty_emulator",
                arguments: ["--headless", "two words"],
                environment: ["ZETA": "last", "ALPHA": "first"],
                into: &memory,
                dyldPath: "/usr/lib/dyld",
                usableStackSize: 64 * 1024
            )
            try expect(startup.stackPointer % 16 == 0, "kernel KernelArgs stack alignment")
            try expect(try memory.readUnsigned(at: startup.stackPointer, byteCount: 8) == startup.mainMachHeaderAddress, "main executable mach_header pointer")
            try expect(try memory.readUnsigned(at: startup.stackPointer + 8, byteCount: 8) == 3, "argc")
            let argv0 = try memory.readUnsigned(at: startup.argvPointer, byteCount: 8)
            let argv1 = try memory.readUnsigned(at: startup.argvPointer + 8, byteCount: 8)
            let argv2 = try memory.readUnsigned(at: startup.argvPointer + 16, byteCount: 8)
            try expect(try readCString(argv0, memory: memory) == "/Applications/Kyty.app/Contents/MacOS/kyty_emulator", "argv[0]")
            try expect(try readCString(argv1, memory: memory) == "--headless", "argv[1]")
            try expect(try readCString(argv2, memory: memory) == "two words", "argv[2]")
            let env0 = try memory.readUnsigned(at: startup.envpPointer, byteCount: 8)
            let env1 = try memory.readUnsigned(at: startup.envpPointer + 8, byteCount: 8)
            try expect(try readCString(env0, memory: memory) == "ALPHA=first", "sorted envp[0]")
            try expect(try readCString(env1, memory: memory) == "ZETA=last", "sorted envp[1]")
            let apple0 = try memory.readUnsigned(at: startup.applePointer, byteCount: 8)
            let apple1 = try memory.readUnsigned(at: startup.applePointer + 8, byteCount: 8)
            let apple2 = try memory.readUnsigned(at: startup.applePointer + 16, byteCount: 8)
            try expect(try readCString(apple0, memory: memory) == "executable_path=/Applications/Kyty.app/Contents/MacOS/kyty_emulator", "apple executable_path")
            try expect(try readCString(apple1, memory: memory) == "dyld_path=/usr/lib/dyld", "apple dyld_path")
            try expect(try readCString(apple2, memory: memory) == "platform=MACOS", "apple platform follows dyld_path")
            try expect(startup.dyldPath == "/usr/lib/dyld", "startup retains dyld path")
            try expect(memory.permissions(at: startup.stackReservation.baseAddress) == nil, "low stack guard")
            try expect(memory.permissions(at: startup.stackReservation.endAddress - 1) == nil, "high stack guard")
            var initialState = X64CPUState()
            let dyldEntry: UInt64 = 0x6_FFFF_F000
            try startup.installDyldEntry(dyldEntryPoint: dyldEntry, into: &initialState)
            try expect(initialState.rip == dyldEntry, "dyld entrypoint installed into RIP")
            try expect(initialState.registerValue(.rsp) == startup.stackPointer, "kernel RSP points at KernelArgs")
            try expect(initialState.registerValue(.rbp) == 0, "frame pointer chain starts terminated")
            try expect(startup.entryPoint == 0x1_0000_1000, "LC_MAIN retained as post-dyld executable entry")
            passed.append("Darwin kernel-style startup stack builds mach_header/argc/argv/envp/apple vectors and guard pages; dyld entry is separate from LC_MAIN")
        }

        do {
            var memory = try X64GuestVirtualMemory()
            _ = try memory.reserve(at: 0x2_0000_0000, byteCount: 0x2_000, kind: .anonymous)
            try memory.commit(at: 0x2_0000_0000, byteCount: 0x2_000, permissions: .readWrite)
            try memory.writeBytes(Array("hello".utf8), at: 0x2_0000_0100)
            let host = MockHost()
            var state = X64CPUState()
            try state.writeRegister(.rax, value: 0x0200_0004, width: .qword) // write
            try state.writeRegister(.rdi, value: 1, width: .qword)
            try state.writeRegister(.rsi, value: 0x2_0000_0100, width: .qword)
            try state.writeRegister(.rdx, value: 5, width: .qword)
            let disposition = try X64DarwinSyscallDispatcher.dispatch(state: &state, memory: &memory, host: host)
            try expect(disposition == .continueExecution, "write disposition")
            try expect(host.output == Array("hello".utf8), "write output")
            try expect(state.registerValue(.rax) == 5 && !state.flagIsSet(.carry), "write success ABI")
            passed.append("Darwin x86_64 write syscall marshals guest buffer bytes and returns RAX with CF clear")
        }

        do {
            var memory = try X64GuestVirtualMemory()
            _ = try memory.reserve(at: 0x2_1000_0000, byteCount: 0x1_000, kind: .anonymous)
            try memory.commit(at: 0x2_1000_0000, byteCount: 0x1_000, permissions: .readWrite)
            let host = MockHost()
            var state = X64CPUState()
            try state.writeRegister(.rax, value: 0x0200_0003, width: .qword) // read
            try state.writeRegister(.rdi, value: 0, width: .qword)
            try state.writeRegister(.rsi, value: 0x2_1000_0020, width: .qword)
            try state.writeRegister(.rdx, value: 3, width: .qword)
            _ = try X64DarwinSyscallDispatcher.dispatch(state: &state, memory: &memory, host: host)
            try expect(state.registerValue(.rax) == 3 && !state.flagIsSet(.carry), "read return")
            try expect(try memory.readBytes(at: 0x2_1000_0020, count: 3) == [0x41, 0x42, 0x43], "read bytes")
            passed.append("Darwin x86_64 read syscall copies host input into guest memory and preserves guest write permissions")
        }

        do {
            var memory = try X64GuestVirtualMemory()
            let lazyAddress: UInt64 = 0x2_1800_0000
            try memory.reserve(at: lazyAddress, byteCount: 0x1000, kind: .anonymous)
            try memory.registerDemandZeroRange(at: lazyAddress, byteCount: 0x1000, permissions: .readWrite)
            let host = MockHost()
            var state = X64CPUState()
            try state.writeRegister(.rax, value: 0x0200_0004, width: .qword) // write
            try state.writeRegister(.rdi, value: 1, width: .qword)
            try state.writeRegister(.rsi, value: lazyAddress + 8, width: .qword)
            try state.writeRegister(.rdx, value: 3, width: .qword)
            _ = try X64DarwinSyscallDispatcher.dispatch(state: &state, memory: &memory, host: host)
            try expect(memory.isCommitted(address: lazyAddress), "write did not materialize demand-zero source page")
            try expect(host.output == [0, 0, 0], "demand-zero write did not return zero-filled bytes")
            try expect(state.registerValue(.rax) == 3 && !state.flagIsSet(.carry), "demand-zero write return")
            passed.append("Darwin write syscall materializes demand-zero source pages and writes their zero-filled contents")
        }

        do {
            var memory = try X64GuestVirtualMemory()
            let lazyAddress: UInt64 = 0x2_2000_0000
            try memory.reserve(at: lazyAddress, byteCount: 0x1000, kind: .anonymous)
            try memory.registerDemandZeroRange(at: lazyAddress, byteCount: 0x1000, permissions: .readWrite)
            let host = MockHost()
            var state = X64CPUState()
            try state.writeRegister(.rax, value: 0x0200_0003, width: .qword) // read
            try state.writeRegister(.rdi, value: 0, width: .qword)
            try state.writeRegister(.rsi, value: lazyAddress + 8, width: .qword)
            try state.writeRegister(.rdx, value: 3, width: .qword)
            _ = try X64DarwinSyscallDispatcher.dispatch(state: &state, memory: &memory, host: host)
            try expect(memory.isCommitted(address: lazyAddress), "read did not materialize demand-zero target page")
            try expect(try memory.readBytes(at: lazyAddress + 8, count: 3) == [0x41, 0x42, 0x43], "demand-zero read bytes")
            passed.append("Darwin read syscall materializes demand-zero guest pages before copying host input")
        }

        do {
            var memory = try X64GuestVirtualMemory()
            let host = MockHost()
            var state = X64CPUState()
            try state.writeRegister(.rax, value: 0x0200_0014, width: .qword) // getpid
            _ = try X64DarwinSyscallDispatcher.dispatch(state: &state, memory: &memory, host: host)
            try expect(state.registerValue(.rax) == 4242 && !state.flagIsSet(.carry), "getpid return")
            try state.writeRegister(.rax, value: 0x0200_FFFF, width: .qword)
            _ = try X64DarwinSyscallDispatcher.dispatch(state: &state, memory: &memory, host: host)
            try expect(state.registerValue(.rax) == 78 && state.flagIsSet(.carry), "ENOSYS convention")
            passed.append("Darwin syscall return convention reports getpid, ENOSYS in RAX, and the error indicator in RFLAGS.CF")
        }

        do {
            let registry = X64DarwinABIThunkRegistry.initialCBridge
            try expect(registry.descriptor(for: "_read")?.argumentSources == [.rdi, .rsi, .rdx], "read ABI descriptor")
            try expect(registry.descriptor(for: "_write")?.requiresGuestPointerTranslation == true, "write pointer translation")
            try expect(registry.descriptor(for: "_getpid")?.argumentSources.isEmpty == true, "getpid ABI descriptor")
            passed.append("Explicit Darwin C ABI thunk descriptors define argument registers and guest-pointer translation requirements")
        }

        do {
            var memory = try X64GuestVirtualMemory()
            let startup = try X64GuestProcessStackBuilder.build(
                entryPoint: 0x1_0000_1000,
                mainMachHeaderAddress: 0x1_0000_0000,
                executablePath: "/tmp/freestanding",
                arguments: ["--mode", "two words"],
                environment: ["MODE": "test"],
                into: &memory,
                usableStackSize: 64 * 1024
            )
            var state = X64CPUState()
            try startup.installDirectMainEntry(into: &state, memory: &memory)
            try expect(state.rip == startup.entryPoint, "direct-main RIP")
            try expect(state.registerValue(.rdi) == 3, "main argc includes argv[0]")
            try expect(state.registerValue(.rsi) == startup.argvPointer, "main argv register")
            try expect(state.registerValue(.rdx) == startup.envpPointer, "main envp register")
            try expect(state.registerValue(.rsp) % 16 == 8, "SysV callee-entry stack alignment")
            try expect(
                try memory.readUnsigned(at: state.registerValue(.rsp), byteCount: 8) == startup.stackReservation.baseAddress,
                "direct-main return sentinel"
            )
            passed.append("Direct LC_MAIN handoff installs the x86_64 main(argc, argv, envp) registers and CALL-compatible stack frame")
        }

        do {
            let image = try X64MachOParser.parse(data: X64MachOLoaderSelfTests.makeFreestandingMainExecutable(
                code: [0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3] // mov eax, 42; ret
            ))
            var memory = try X64GuestVirtualMemory()
            let loaded = try X64MachOLoader.load(image, into: &memory)
            let startup = try X64GuestProcessStackBuilder.build(
                entryPoint: loaded.entryAddress,
                mainMachHeaderAddress: loaded.preferredLoadAddress,
                executablePath: image.sourceName,
                arguments: [],
                environment: [:],
                into: &memory,
                usableStackSize: 64 * 1024
            )
            let result = try X64GuestDirectMainLauncher.launch(
                image: image,
                loadedImage: loaded,
                startup: startup,
                memory: &memory,
                maximumInstructions: 100,
                maximumBlocks: 100
            )
            try expect(result.report.exit == .halted, "direct-main returns through its sentinel")
            try expect(result.returnedFromMain && result.exitStatus == 42, "main return value becomes process status")
            try expect(result.report.instructionsExecuted == 2, "two guest instructions executed natively")
            passed.append("Freestanding x86_64 Mach-O loads, enters LC_MAIN through native AArch64 blocks, returns, and reports the C main status")
        }

        do {
            // mov eax, SYS_write; mov edi, 1; lea rsi, [rip+13]; mov edx, 2;
            // syscall; mov eax, 0; ret; "OK".
            let code: [UInt8] = [
                0xB8, 0x04, 0x00, 0x00, 0x02,
                0xBF, 0x01, 0x00, 0x00, 0x00,
                0x48, 0x8D, 0x35, 0x0D, 0x00, 0x00, 0x00,
                0xBA, 0x02, 0x00, 0x00, 0x00,
                0x0F, 0x05,
                0xB8, 0x00, 0x00, 0x00, 0x00,
                0xC3,
                0x4F, 0x4B
            ]
            let image = try X64MachOParser.parse(data: X64MachOLoaderSelfTests.makeFreestandingMainExecutable(code: code))
            var memory = try X64GuestVirtualMemory()
            let loaded = try X64MachOLoader.load(image, into: &memory)
            let startup = try X64GuestProcessStackBuilder.build(
                entryPoint: loaded.entryAddress,
                mainMachHeaderAddress: loaded.preferredLoadAddress,
                executablePath: image.sourceName,
                arguments: [],
                environment: [:],
                into: &memory,
                usableStackSize: 64 * 1024
            )
            let host = MockHost()
            let result = try X64GuestDirectMainLauncher.launch(
                image: image,
                loadedImage: loaded,
                startup: startup,
                memory: &memory,
                syscallHost: host,
                maximumInstructions: 100,
                maximumBlocks: 100
            )
            try expect(host.output == [0x4F, 0x4B], "guest write syscall reaches host stdout")
            try expect(result.report.exit == .halted && result.exitStatus == 0, "guest main returns after host write")
            passed.append("Launched x86_64 guest code executes Darwin SYS_write through the host bridge and returns normally")
        }

        do {
            let image = try X64MachOParser.parse(data: X64MachOLoaderSelfTests.makeFreestandingMainExecutable(
                code: [0xC3] // LC_MAIN is the handoff boundary; do not execute it in this test.
            ))
            var memory = try X64GuestVirtualMemory()
            let loaded = try X64MachOLoader.load(image, into: &memory)
            let dyldAddress: UInt64 = 0x6_F000_0000
            try memory.reserve(at: dyldAddress, byteCount: 0x1000, kind: .shared)
            try memory.commit(at: dyldAddress, byteCount: 0x1000, permissions: .readExecute)
            var dyldCode: [UInt8] = [0x48, 0xB8] // movabs rax, <LC_MAIN>
            for shift in stride(from: 0, to: 64, by: 8) {
                dyldCode.append(UInt8(truncatingIfNeeded: loaded.entryAddress >> shift))
            }
            dyldCode.append(contentsOf: [0xFF, 0xE0]) // jmp rax
            try memory.writeBytes(dyldCode, at: dyldAddress)
            let dyld = X64DyldSharedCacheDylinkerEntry(
                installName: "/usr/lib/dyld",
                machHeaderAddress: dyldAddress,
                entryPoint: dyldAddress,
                executableSegments: [dyldAddress..<(dyldAddress + 0x1000)]
            )
            let startup = try X64GuestProcessStackBuilder.build(
                entryPoint: loaded.entryAddress,
                mainMachHeaderAddress: loaded.preferredLoadAddress + loaded.slide,
                executablePath: image.sourceName,
                arguments: [],
                environment: [:],
                into: &memory,
                dyldPath: dyld.installName,
                usableStackSize: 64 * 1024
            )
            let result = try X64GuestDyldLauncher.launch(
                dyld: dyld,
                loadedImage: loaded,
                startup: startup,
                memory: &memory,
                maximumInstructions: 100,
                maximumBlocks: 100
            )
            try expect(result.reachedMainEntry, "dyld execution stops at the main LC_MAIN handoff")
            try expect(result.finalState.rip == loaded.entryAddress, "guest RIP is the real main executable entrypoint")
            try expect(result.finalState.registerValue(.rsp) == startup.stackPointer, "kernel startup RSP survives the minimal dyld handoff")
            passed.append("Cache-backed dyld entry executes under native AArch64 translation and hands off at the main executable LC_MAIN boundary")
        }

        do {
            let image = try X64MachOParser.parse(data: X64MachOLoaderSelfTests.makeBoundThinExecutable())
            var memory = try X64GuestVirtualMemory()
            let loaded = try X64MachOLoader.load(image, into: &memory)
            let startup = try X64GuestProcessStackBuilder.build(
                entryPoint: loaded.entryAddress,
                mainMachHeaderAddress: loaded.preferredLoadAddress,
                executablePath: image.sourceName,
                arguments: [],
                environment: [:],
                into: &memory,
                usableStackSize: 64 * 1024
            )
            var blocked = false
            do {
                _ = try X64GuestDirectMainLauncher.launch(
                    image: image,
                    loadedImage: loaded,
                    startup: startup,
                    memory: &memory,
                    maximumInstructions: 100,
                    maximumBlocks: 100
                )
            } catch {
                blocked = error.localizedDescription.contains("bypasses dyld")
            }
            try expect(blocked, "normal dylib-dependent image is rejected before guest execution")
            passed.append("Direct-main mode fails closed for an executable with LC_LOAD_DYLIB dependencies instead of pretending dyld ran")
        }

        return passed
    }

    private static func readCString(_ address: UInt64, memory: X64GuestVirtualMemory) throws -> String {
        var bytes: [UInt8] = []
        for offset in 0..<4096 {
            let value = try memory.readBytes(at: address + UInt64(offset), count: 1)[0]
            if value == 0 { return String(decoding: bytes, as: UTF8.self) }
            bytes.append(value)
        }
        throw X64MachOFormatError(message: "Runtime test string was not NUL terminated.")
    }

    private static func expect(_ condition: @autoclosure () throws -> Bool, _ label: String) throws {
        guard try condition() else {
            throw X64MachOFormatError(message: "Darwin runtime self-test failed: \(label).")
        }
    }
}
