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
                Text("Native ARM64 launcher · experimental x86_64 guest runner")
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
                    pipelineButton("Run x86_64 guest via dyld", "play.circle",
                                   enabled: model.canLaunchX64GuestViaDyld, action: model.launchSelectedX64GuestViaDyld)
                    pipelineButton("Continue into x86_64 program", "gamecontroller",
                                   enabled: model.canContinueX64GuestAfterDyld, action: model.continueSelectedX64GuestAfterDyld)
                    pipelineButton("Run x86_64 guest (direct main)", "play.fill",
                                   enabled: model.canLaunchX64Guest, action: model.launchSelectedX64Guest)
                    pipelineButton("1. Load selected x86_64 Mach-O image", "shippingbox",
                                   enabled: model.canLoadX86MachOImage, action: model.loadSelectedX64MachOImage)
                    pipelineButton("2. Inspect x86_64 dyld shared cache", "externaldrive",
                                   enabled: model.canPrepareGuestProcessStartup, action: model.inspectX64DyldSharedCache)
                    pipelineButton("3. Analyze recursive dylib dependency closure", "list.bullet.rectangle",
                                   enabled: model.canPrepareGuestProcessStartup, action: model.planX64DyldSharedCacheMappings)
                    pipelineButton("4. Materialize recursive dependency pages", "square.stack.3d.up",
                                   enabled: model.canMaterializeCachedDependencies, action: model.materializeX64DyldSharedCacheDependencies)
                    pipelineButton("5. Resolve imports from cached dylibs", "link",
                                   enabled: model.canResolveCachedImports, action: model.resolveX64MachOImportsFromCache)
                    pipelineButton("6. Prepare Darwin KernelArgs stack", "rectangle.stack",
                                   enabled: model.canPrepareGuestProcessStartup, action: model.prepareGuestProcessStartup)
                }
                Text("The dyld path now locates the x86_64 MH_DYLINKER in the Rosetta cache, maps its executable pages with the recursive dependency closure, supplies dyld_path in KernelArgs and attempts the real __dyld_start entry. It stops at the main executable's LC_MAIN handoff so you can inspect whether dyld initialized successfully, then offers a separate bounded continuation into the actual program. The direct-main button remains only for freestanding test executables. KytyPS5 will still need missing syscalls, instructions, uncached/@rpath images and framework ABI support as the first real run exposes them.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text("For the normal launch path: load the executable, inspect the Rosetta cache, analyze and materialize the recursive closure (including /usr/lib/dyld), then prepare KernelArgs. Import resolution remains available as a diagnostic/prebinding step; dyld is intended to perform the executable’s own fixups when it starts.")
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
                    LazyVStack(alignment: .leading, spacing: 0) {
                        ForEach(model.displayedLogLines.indices, id: \.self) { index in
                            Text(model.displayedLogLines[index])
                                .font(.system(.callout, design: .monospaced))
                                .textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .fixedSize(horizontal: false, vertical: true)
                                .padding(.horizontal, 8)
                        }
                        Color.clear.frame(height: 1).id(Self.logBottomID)
                    }
                    .padding(.vertical, 8)
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
