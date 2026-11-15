import SwiftUI

@MainActor
struct ContentView: View {
    @StateObject private var model = LauncherViewModel()

    private static let versionLabel: String = {
        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String
        return "RUNTIME \(version ?? "dev")"
    }()

    private let testColumns = [GridItem(.adaptive(minimum: 250), spacing: 8, alignment: .leading)]
    private let pipelineColumns = [GridItem(.adaptive(minimum: 300), spacing: 8, alignment: .leading)]

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            header

            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    applicationBox
                    launchOptionsRow
                    nativeLaunchBox
                    testsBox
                    pipelineBox
                }
                .padding(.trailing, 4)
            }
            .frame(minHeight: 200)

            logBox
        }
        .padding(20)
    }

    // MARK: Sections

    private var header: some View {
        HStack(alignment: .center, spacing: 14) {
            Image(systemName: "arrow.left.arrow.right.circle.fill")
                .font(.system(size: 34))
                .foregroundStyle(.tint)
            VStack(alignment: .leading, spacing: 3) {
                Text("Kestrel")
                    .font(.largeTitle.bold())
                Text("Native ARM64 launcher · experimental x86_64 translator")
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Text(Self.versionLabel)
                .font(.caption2.weight(.bold))
                .padding(.horizontal, 9)
                .padding(.vertical, 5)
                .background(.quaternary, in: Capsule())
        }
    }

    private var applicationBox: some View {
        GroupBox("Application") {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Text(model.targetPath.isEmpty ? "No application selected" : model.targetPath)
                        .font(.system(.body, design: .monospaced))
                        .lineLimit(2)
                        .textSelection(.enabled)
                    Spacer()
                    Button("Browse…", action: model.chooseTarget)
                        .disabled(model.isBusy)
                }
                HStack(spacing: 8) {
                    Text("Detected architecture")
                        .foregroundStyle(.secondary)
                    Text(model.architectureLabel)
                        .fontWeight(.semibold)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.vertical, 4)
        }
    }

    private var launchOptionsRow: some View {
        HStack(alignment: .top, spacing: 14) {
            GroupBox("Arguments") {
                VStack(alignment: .leading, spacing: 6) {
                    Text("One argument per line; spaces are preserved.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    TextEditor(text: $model.argumentsText)
                        .font(.system(.body, design: .monospaced))
                        .frame(minHeight: 90)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }

            GroupBox("Environment") {
                VStack(alignment: .leading, spacing: 6) {
                    Text("One KEY=VALUE pair per line.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    TextEditor(text: $model.environmentText)
                        .font(.system(.body, design: .monospaced))
                        .frame(minHeight: 90)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }

    private var nativeLaunchBox: some View {
        GroupBox("Native launch") {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Button {
                        model.launchSelectedTarget()
                    } label: {
                        Label("Launch native ARM64 app", systemImage: "play.fill")
                    }
                    .disabled(model.isBusy)

                    Button {
                        model.stopRunningProcess()
                    } label: {
                        Label("Stop", systemImage: "stop.fill")
                    }
                    .disabled(!model.hasRunningProcess)
                }
                Text("Intel-only applications are deliberately not sent to Rosetta; they can only be inspected and mapped by the experimental translator below.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.vertical, 3)
        }
    }

    private var testsBox: some View {
        GroupBox("Translator self-tests") {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Button {
                        model.runAllSelfTests()
                    } label: {
                        Label("Run all tests", systemImage: "checkmark.seal")
                    }
                    .disabled(model.isBusy)

                    Button {
                        model.runTranslationSelfTest()
                    } label: {
                        Label("x86 → ARM64 smoke test", systemImage: "cpu")
                    }
                    .disabled(model.isBusy)
                }
                LazyVGrid(columns: testColumns, alignment: .leading, spacing: 8) {
                    ForEach(SelfTestSuite.all) { suite in
                        Button {
                            model.runSelfTestSuite(suite)
                        } label: {
                            Label(suite.buttonTitle, systemImage: suite.systemImage)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        .disabled(model.isBusy)
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.vertical, 3)
        }
    }

    private var pipelineBox: some View {
        GroupBox("x86_64 guest pipeline (experimental)") {
            VStack(alignment: .leading, spacing: 10) {
                LazyVGrid(columns: pipelineColumns, alignment: .leading, spacing: 8) {
                    pipelineButton("1. Load selected x86_64 Mach-O image", "shippingbox",
                                   enabled: model.canLoadX86MachOImage, action: model.loadSelectedX64MachOImage)
                    pipelineButton("2. Inspect x86_64 dyld shared cache", "externaldrive",
                                   enabled: model.canPrepareGuestProcessStartup, action: model.inspectX64DyldSharedCache)
                    pipelineButton("3. Analyze cached dependency segments", "list.bullet.rectangle",
                                   enabled: model.canPrepareGuestProcessStartup, action: model.planX64DyldSharedCacheMappings)
                    pipelineButton("4. Materialize cached dependency pages", "square.stack.3d.up",
                                   enabled: model.canMaterializeCachedDependencies, action: model.materializeX64DyldSharedCacheDependencies)
                    pipelineButton("5. Resolve imports from cached dylibs", "link",
                                   enabled: model.canResolveCachedImports, action: model.resolveX64MachOImportsFromCache)
                    pipelineButton("6. Prepare Darwin KernelArgs stack", "rectangle.stack",
                                   enabled: model.canPrepareGuestProcessStartup, action: model.prepareGuestProcessStartup)
                }
                Text("Kestrel parses regular, weak and lazy dyld bind streams, indexes export tries and dependencies, discovers LC_RPATH candidates, and applies guest-address bindings. It installs a small guest C thunk set (_read, _write, _getpid, _exit), dispatches a narrow BSD SYSCALL subset, and prepares a kernel-shaped KernelArgs stack. It can inspect the x86_64 dyld shared cache, validate slide-info v2 chains, copy selected dependency pages into guest-owned memory, apply cache pointer fixups, and resolve supported two-level imports from cached export tries. This is still not a process launcher: recursive dependency initialization, all dyld symbol forms, main-image chained fixups, TLS/errno, broad syscalls and macOS framework ABI bridges remain incomplete, and LC_MAIN is not executed.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text("Steps 2–6 stay disabled until the selected x86_64 Mach-O image has loaded successfully; a failed load is rolled back and cannot be used to prepare guest process state. Step 4 needs a successful step 3, and step 5 needs step 4.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.vertical, 3)
        }
    }

    private var logBox: some View {
        GroupBox {
            ScrollViewReader { proxy in
                ScrollView {
                    VStack(alignment: .leading, spacing: 0) {
                        Text(model.output)
                            .font(.system(.callout, design: .monospaced))
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(8)
                        Color.clear.frame(height: 1).id(Self.logBottomID)
                    }
                }
                .onChange(of: model.output) { _ in
                    proxy.scrollTo(Self.logBottomID, anchor: .bottom)
                }
            }
            .frame(minHeight: 160, maxHeight: .infinity)
        } label: {
            HStack {
                Text("Runtime log")
                Spacer()
                Button("Copy", action: model.copyLogToPasteboard)
                Button("Clear", action: model.clearLog)
            }
        }
    }

    private static let logBottomID = "kestrel-log-bottom"

    private func pipelineButton(
        _ title: String,
        _ systemImage: String,
        enabled: Bool,
        action: @escaping () -> Void
    ) -> some View {
        Button(action: action) {
            Label(title, systemImage: systemImage)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .disabled(model.isBusy || !enabled)
    }
}
