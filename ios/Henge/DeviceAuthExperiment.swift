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
    @State private var actionError: String?

    private var enabled: Bool { state["enabled"] as? Bool == true }
    private var available: Bool {
        state["running"] as? Bool == true && state["foreground"] as? Bool == true && state["fresh"] as? Bool == true
    }
    private var latest: [String: Any] { (state["events"] as? [[String: Any]])?.last ?? [:] }
    private var stage: String { latest["stage"] as? String ?? "idle" }
    private var status: String {
        switch stage {
        case "target_not_found": return "ChatGPT.app was not found in Applications."
        case "target_identity_mismatch", "target_signature_invalid": return "The installed app's identity or signature did not match."
        case "signature_policy_blocked": return "The app's signature does not permit this adapter."
        case "already_running": return "Quit ChatGPT normally, stop this test, then start a new test."
        case "adapter_not_loaded", "launch_timeout": return "The adapter did not report a successful load."
        case "adapter_abi_mismatch": return "The installed authentication method has an incompatible interface."
        case "adapter_ready": return "Adapter ready. Try opening Chat in the Mac app."
        case "token_result", "baa_data_result", "baa_dictionary_result", "host_request_completed":
            return "An authentication operation returned. Its result is in the combined report; Chat acceptance is not verified."
        case "session_inactive", "host_bridge_disabled": return "Test stopped. Quit and reopen ChatGPT normally to remove the adapter."
        case "host_bridge_enabled", "launch_requested": return "Waiting for Helper 7 to launch the test. Quit ChatGPT first."
        case "transport_failed", "response_invalid", "host_request_failed": return "The test recorded a failure. The combined report includes its stage and numeric error."
        default: return enabled ? "Test active. Keep Henge in the foreground." : "Test is off."
        }
    }

    var body: some View {
        Section("Chat authentication experiment · Test7") {
            Picker("Path", selection: $mode) {
                Text("iPad DeviceCheck token").tag("public_token")
                Text("deb BAA signing path").tag("baa")
            }.disabled(enabled)
            Text("Update the Mac helper once with Install / Repair above. Quit ChatGPT normally, then start a test. Helper 7 launches the original app with a temporary adapter if its signature allows it.")
                .font(.footnote).foregroundStyle(.secondary)
            if enabled {
                Button("Stop authentication test", role: .destructive) {
                    hv_device_auth_disable()
                    actionError = nil
                    state = DeviceAuthSnapshot.state()
                }
            } else {
                Button("Start authentication test") {
                    let selected = mode == "baa" ? HV_DEVICE_AUTH_MODE_BAA : HV_DEVICE_AUTH_MODE_PUBLIC_TOKEN
                    let result = hv_device_auth_enable(selected, UUID().uuidString.lowercased())
                    actionError = result == HV_DEVICE_AUTH_OK ? nil : String(cString: hv_device_auth_error_name(result))
                    state = DeviceAuthSnapshot.state()
                }.disabled(!available)
            }
            Text(status).font(.footnote)
            if let actionError { Text("Could not start: \(actionError)").font(.caption).foregroundStyle(.red) }
            if stage != "idle" { LabeledContent("Last stage", value: stage).font(.caption.monospaced()) }
            Text("The BAA path uses a separate iPad signing process. Both paths return real Apple results; a generated result does not establish that Chat accepts it. Backgrounding Henge or ending the Mac session stops permission. No VM recreation is needed.")
                .font(.footnote).foregroundStyle(.secondary)
            Text("Debug stages, timing, byte counts and numeric errors are saved automatically in Latest-Henge-diagnostics.txt. Tokens, signing payloads and signatures are excluded.")
                .font(.footnote).foregroundStyle(.secondary)
        }
        .task {
            while !Task.isCancelled {
                state = DeviceAuthSnapshot.state()
                if enabled, let current = state["mode"] as? String { mode = current }
                try? await Task.sleep(nanoseconds: 500_000_000)
            }
        }
    }
}
