import SwiftUI

/// Both native serializers return fixed-schema metadata, never the result plist.
enum DeviceAuthSnapshot {
    private static func read(_ pointer: UnsafeMutablePointer<CChar>?) -> [String: Any] {
        guard let pointer else { return [:] }
        defer { free(pointer) }
        guard let data = String(cString: pointer).data(using: .utf8),
              let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return [:] }
        return value
    }
    static func state() -> [String: Any] { read(hv_share_auth_state()) }
    static func backend() -> [String: Any] { read(HengeAuthBridgeDiagnosticsJSON()) }
}

@MainActor
struct DeviceAuthExperimentSection: View {
    @State private var mode = "public_token"
    @State private var state: [String: Any] = [:]
    @State private var helper = HelperHealthSnapshot.unavailable
    @State private var actionError: String?

    private var enabled: Bool { state["enabled"] as? Bool == true }
    private var progress: DeviceAuthProgress { DeviceAuthProgress.read(state: state, helper: helper) }

    var body: some View {
        Section("ChatGPT authentication · Test9") {
            Text(progress.title).font(.headline)
            Text(progress.detail).font(.footnote).foregroundStyle(.secondary)
            Picker("Path", selection: $mode) {
                Text("iPad DeviceCheck token").tag("public_token")
                Text("deb BAA signing path").tag("baa")
            }.disabled(enabled)
            if enabled {
                Button("Stop authentication test", role: .destructive) {
                    hv_device_auth_disable()
                    Diagnostics.recordAuthControl(.stopCompleted, mode: mode)
                    actionError = nil
                    state = DeviceAuthSnapshot.state()
                }
            } else {
                Button("Quit and start ChatGPT with iPad authentication") {
                    Diagnostics.recordAuthControl(.startRequested, mode: mode)
                    HostServices.shared.refreshForAuthenticationStart()
                    let selected = mode == "baa" ? HV_DEVICE_AUTH_MODE_BAA : HV_DEVICE_AUTH_MODE_PUBLIC_TOKEN
                    let result = hv_device_auth_enable(selected, UUID().uuidString.lowercased())
                    Diagnostics.recordAuthControl(.startCompleted, mode: mode, resultCode: Int(result.rawValue))
                    actionError = result == HV_DEVICE_AUTH_OK ? nil : String(cString: hv_device_auth_error_name(result))
                    state = DeviceAuthSnapshot.state()
                    helper = Sharing.helperHealth
                }.buttonStyle(.borderedProminent)
            }
            if let actionError { Text("Could not start: \(actionError)").font(.caption).foregroundStyle(.red) }
            LabeledContent("Mac helper", value: helper.helperVersion > 0 ? "\(helper.helperVersion) · \(helper.connectionTitle)" : "Version unconfirmed · \(helper.connectionTitle)")
                .font(.caption)
            if helper.requiresAuthColdStartUpdate {
                Text("Update the Mac helper with Install / Repair below. This test needs Helper 9's normal quit and cold-start capability.")
                    .font(.caption).foregroundStyle(.orange)
            }
            if progress.adapterReadiness == "confirmed" {
                LabeledContent("Adapter handshake", value: enabled ? "Confirmed for this attempt" : "Previously confirmed; permission stopped")
                    .font(.caption)
            }
            if progress.processObservation != "not_recorded" {
                LabeledContent("ChatGPT at preflight", value: progress.processObservation == "running" ? "Running app observed" : "No running app observed")
                    .font(.caption)
            }
            if progress.stage != "none" { LabeledContent("Result stage", value: progress.stage).font(.caption.monospaced()) }
            Text("Save your work in ChatGPT first. This button asks ChatGPT to quit normally, waits for its process to exit, then starts the original app once with a temporary adapter. Check the Mac for any save or quit prompt. The helper does not force-quit the app. macOS decides whether the adapter can load; signed policy information is a prediction, not a launch result.")
                .font(.footnote).foregroundStyle(.secondary)
            Text("The BAA path uses a separate iPad signing process. Both paths return real Apple results; a generated result does not establish that Chat accepts it. Backgrounding Henge or ending the Mac session stops permission. No VM recreation is needed.")
                .font(.footnote).foregroundStyle(.secondary)
            Text("Debug stages, timing, byte counts and numeric errors are saved automatically in Latest-Henge-diagnostics.txt. Tokens, signing payloads and signatures are excluded.")
                .font(.footnote).foregroundStyle(.secondary)
        }
        .task {
            Diagnostics.recordAuthControl(.presented, mode: mode)
            while !Task.isCancelled {
                state = DeviceAuthSnapshot.state()
                helper = Sharing.helperHealth
                if enabled, let current = state["mode"] as? String { mode = current }
                try? await Task.sleep(nanoseconds: 500_000_000)
            }
        }
    }
}
