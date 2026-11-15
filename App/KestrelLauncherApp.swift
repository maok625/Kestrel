import Foundation
import SwiftUI

@main
struct KestrelLauncherApp: App {
    init() {
        // `Kestrel.app/Contents/MacOS/Kestrel --run-self-tests` runs every
        // self-test suite without opening a window and exits 0 on success.
        if CommandLine.arguments.contains("--run-self-tests") {
            exit(SelfTestRunner.runAllHeadless())
        }
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                .frame(minWidth: 760, minHeight: 620)
        }
        .defaultSize(width: 900, height: 860)
        .windowResizability(.contentMinSize)
    }
}
