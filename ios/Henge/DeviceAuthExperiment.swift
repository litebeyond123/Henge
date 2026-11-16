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
    @State private var captureStatus = "Starts with the next authentication test"

    private var enabled: Bool { state["enabled"] as? Bool == true }
    private var progress: DeviceAuthProgress { DeviceAuthProgress.read(state: state, helper: helper) }

    private func start(_ action: DeviceAuthLaunchAction) {
        Diagnostics.recordAuthControl(.startRequested, mode: mode, launchAction: action.rawValue)
        let current = DeviceAuthSnapshot.state()
        helper = Sharing.helperHealth
        guard helper.permitsVerifiedExit(forSession: current["session"] as? String ?? "") else {
            actionError = "This startup needs Helper 11 with a current connection to this Mac. Use Install / Repair below and wait for its connection."
            Diagnostics.recordAuthControl(.startBlockedHelper, mode: mode, launchAction: action.rawValue)
            state = current
            return // Do not revoke an earlier authorized attempt when capability is unknown.
        }
        if action == .forceQuit {
            NetworkCapture.stop(HV_NET_CAPTURE_STOP_USER)
            hv_device_auth_disable()
            if current["enabled"] as? Bool == true {
                Diagnostics.recordAuthControl(.stopCompleted, mode: mode,
                    launchAction: current["launch_action"] as? String ?? "normal_quit")
            }
        }
        HostServices.shared.refreshForAuthenticationStart()
        let selected = mode == "baa" ? HV_DEVICE_AUTH_MODE_BAA : HV_DEVICE_AUTH_MODE_PUBLIC_TOKEN
        let nativeAction = action == .forceQuit ? HV_DEVICE_AUTH_ACTION_FORCE_QUIT : HV_DEVICE_AUTH_ACTION_NORMAL_QUIT
        let launchID = UUID().uuidString.lowercased()
        let result = hv_device_auth_enable_with_action(selected, nativeAction, launchID)
        Diagnostics.recordAuthControl(.startCompleted, mode: mode, resultCode: Int(result.rawValue), launchAction: action.rawValue)
        actionError = result == HV_DEVICE_AUTH_OK ? nil : String(cString: hv_device_auth_error_name(result))
        state = DeviceAuthSnapshot.state()
        if result == HV_DEVICE_AUTH_OK {
            let captureResult = NetworkCapture.start(session: state["session"] as? String ?? "", launchID: launchID)
            captureStatus = captureResult == 0 ? NetworkCapture.status : "Could not start capture (\(captureResult))"
        }
    }

    var body: some View {
        Section("ChatGPT authentication · Test11") {
            Text(progress.title).font(.headline)
            Text(progress.detail).font(.footnote).foregroundStyle(.secondary)
            Picker("Path", selection: $mode) {
                Text("iPad DeviceCheck token").tag("public_token")
                Text("deb BAA signing path").tag("baa")
            }.disabled(enabled)
            if enabled {
                Button("Stop authentication test", role: .destructive) {
                    NetworkCapture.stop(HV_NET_CAPTURE_STOP_USER)
                    hv_device_auth_disable()
                    Diagnostics.recordAuthControl(.stopCompleted, mode: mode, launchAction: progress.launchAction)
                    actionError = nil
                    state = DeviceAuthSnapshot.state()
                }
            } else {
                Button("Quit and start ChatGPT with iPad authentication") {
                    start(.normalQuit)
                }.buttonStyle(.borderedProminent)
            }
            Button("Force quit ChatGPT and retry", role: .destructive) { start(.forceQuit) }
                .buttonStyle(.bordered)
            Text("Force quit may discard unsent input. It applies only to the attempt started with this separate button; a normal quit never escalates automatically.")
                .font(.footnote).foregroundStyle(.secondary)
            if let actionError { Text("Could not start: \(actionError)").font(.caption).foregroundStyle(.red) }
            LabeledContent("Mac helper", value: helper.helperVersion > 0 ? "\(helper.helperVersion) · \(helper.connectionTitle)" : "Version unconfirmed · \(helper.connectionTitle)")
                .font(.caption)
            LabeledContent("Startup action", value: progress.launchAction == "force_quit" ? "Explicit force quit" :
                progress.launchAction == "normal_quit" ? "Normal quit" : "Unconfirmed").font(.caption)
            LabeledContent("Network capture", value: captureStatus).font(.caption)
            Text("Each test records up to two minutes of Mac network headers. The same diagnostic report includes the capture. Message contents, HTTP bodies and authentication values are excluded; encrypted HTTPS responses remain unreadable.")
                .font(.footnote).foregroundStyle(.secondary)
            if helper.requiresVerifiedExitUpdate {
                Text("Update the Mac helper with Install / Repair below. This test needs Helper 11's current startup capability.")
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
            Text("Save your work in ChatGPT first. The normal startup button asks ChatGPT to quit, waits for its process to exit, then starts the original app once with a temporary adapter. Check the Mac for any save or quit prompt. Only the separate Force quit button authorizes forced termination of the verified main process. macOS decides whether the adapter can load; signed policy information is a prediction, not a launch result.")
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
                captureStatus = NetworkCapture.status
                if enabled, let current = state["mode"] as? String { mode = current }
                try? await Task.sleep(nanoseconds: 500_000_000)
            }
        }
    }
}
