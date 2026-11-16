import Foundation
import CoreFoundation

/// A diagnosis of the current launch only. Helper installation, an Apple operation,
/// and acceptance by Chat are separate observations.
struct DeviceAuthProgress {
    let classification: String
    let title: String
    let detail: String
    let stage: String
    let permissionEnabled: Bool
    let processObservation: String
    let signingPolicy: [String: Bool]
    let signingPrediction: String
    let adapterReadiness: String
    let launchAction: String
    let targetPID: Int
    let observedPID: Int

    private enum Readiness { case confirmed, failed, unconfirmed }
    private static func readiness(_ event: [String: Any]) -> Readiness {
        guard let code = event["errorCode"] as? NSNumber, CFGetTypeID(code) != CFBooleanGetTypeID(),
              code.doubleValue.isFinite, code.doubleValue.rounded(.towardZero) == code.doubleValue else { return .unconfirmed }
        if code.doubleValue != 0 { return .failed }
        guard let domain = event["errorDomain"] as? String else { return .unconfirmed }
        return domain.isEmpty ? .confirmed : .failed
    }

    private static func currentEvents(_ state: [String: Any], launch: String) -> [[String: Any]] {
        guard !launch.isEmpty else { return [] }
        func sequence(_ event: [String: Any]) -> UInt64? {
            guard let value = event["sequence"] as? NSNumber, CFGetTypeID(value) != CFBooleanGetTypeID(),
                  value.doubleValue.isFinite, value.doubleValue.rounded(.towardZero) == value.doubleValue,
                  value.compare(NSNumber(value: 1)) != .orderedAscending,
                  value.compare(NSNumber(value: UInt64.max)) != .orderedDescending else { return nil }
            return value.uint64Value
        }
        let saved = Array((state["startup_events"] as? [[String: Any]] ?? []).prefix(48))
        let recent = Array((state["events"] as? [[String: Any]] ?? []).prefix(32))
        var merged: [(event: [String: Any], sequence: UInt64?, order: Int)] = []
        var indexBySequence: [UInt64: Int] = [:]
        for event in saved + recent {
            guard let value = event["launch_id"] as? String,
                  value.caseInsensitiveCompare(launch) == .orderedSame else { continue }
            let valueSequence = sequence(event)
            if let valueSequence, let index = indexBySequence[valueSequence] {
                merged[index].event = event // The same service event appears in both views.
            } else {
                if let valueSequence { indexBySequence[valueSequence] = merged.count }
                merged.append((event, valueSequence, merged.count))
            }
        }
        return merged.sorted {
            if let lhs = $0.sequence, let rhs = $1.sequence { return lhs < rhs }
            if ($0.sequence != nil) != ($1.sequence != nil) { return $0.sequence != nil }
            return $0.order < $1.order
        }.map { $0.event }
    }

    static func read(state: [String: Any], helper: HelperHealthSnapshot) -> DeviceAuthProgress {
        let launch = state["launch_id"] as? String ?? ""
        let enabled = state["enabled"] as? Bool == true
        let launchAction = state["launch_action"] == nil ? "normal_quit" :
            (state["launch_action"] as? String).flatMap(DeviceAuthLaunchAction.init(rawValue:))?.rawValue ?? "unknown"
        let current = currentEvents(state, launch: launch)
        func lastPID(_ key: String) -> Int {
            for event in current.reversed() {
                guard let value = event[key] as? NSNumber, CFGetTypeID(value) != CFBooleanGetTypeID(),
                      value.doubleValue.isFinite, value.doubleValue.rounded(.towardZero) == value.doubleValue,
                      value.doubleValue > 0, value.doubleValue <= Double(Int32.max) else { continue }
                return value.intValue
            }
            return 0
        }
        let targetPID = lastPID("targetPid"), observedPID = lastPID("observedPid")
        let stages = current.compactMap { $0["stage"] as? String }
        let process = stages.reversed().first { ["target_process_running", "target_process_not_running"].contains($0) }
        let processObservation = process == "target_process_running" ? "running" : process == "target_process_not_running" ? "not_running" : "not_recorded"
        let prediction = stages.reversed().first { ["policy_predicts_restriction", "policy_predicts_permission"].contains($0) }
        let signingPrediction = prediction == "policy_predicts_restriction" ? "restriction_predicted" :
            prediction == "policy_predicts_permission" ? "permission_predicted" : "not_recorded"
        let readyEvents = current.filter { $0["stage"] as? String == "adapter_ready" }
        let readyFailed = readyEvents.contains { readiness($0) == .failed }
        let readyConfirmed = readyEvents.contains { readiness($0) == .confirmed }
        let adapterReadiness = readyFailed ? "failed" : readyConfirmed ? "confirmed" :
            readyEvents.isEmpty ? "not_recorded" : "unconfirmed"
        var policy: [String: Bool] = [:]
        for (key, yes, no) in [
            ("hardened_runtime", "policy_runtime_on", "policy_runtime_off"),
            ("library_validation_flag", "policy_library_flag_on", "policy_library_flag_off"),
            ("dyld_environment_allowed", "policy_dyld_env_allowed", "policy_dyld_env_not_allowed"),
            ("library_validation_exception", "policy_library_exception_on", "policy_library_exception_off")
        ] {
            if let value = stages.reversed().first(where: { $0 == yes || $0 == no }) { policy[key] = value == yes }
        }
        if stages.contains("policy_flags_unavailable") { policy["flags_readable"] = false }
        else if policy["hardened_runtime"] != nil { policy["flags_readable"] = true }
        func result(_ code: String, _ title: String, _ detail: String, _ stage: String = "none") -> Self {
            Self(classification: code, title: title, detail: detail, stage: stage,
                 permissionEnabled: enabled, processObservation: processObservation, signingPolicy: policy,
                 signingPrediction: signingPrediction, adapterReadiness: adapterReadiness,
                 launchAction: launchAction, targetPID: targetPID, observedPID: observedPID)
        }
        guard state["protocol"] as? Int == 1 else {
            return result("state_unavailable", "Authentication status unavailable", "Tap Start to record a fresh startup attempt.")
        }
        // Independent HTTP event deliveries can arrive out of order. Preserve a concrete
        // launch failure even after a late launch_requested event or permission revocation.
        let failurePriority = ["target_identity_mismatch", "target_signature_invalid", "adapter_target_rejected",
            "target_not_found", "process_identity_unavailable", "target_process_changed", "target_reappeared",
            "force_quit_refused", "force_quit_timeout", "quit_refused", "quit_timeout", "adapter_abi_mismatch", "adapter_initialization_failed",
            "target_exited_before_adapter", "signature_policy_blocked", "already_running", "launch_failed",
            "launch_timeout", "adapter_not_loaded"]
        let failure = failurePriority.first {
            stages.contains($0) || ($0 == "adapter_initialization_failed" && readyFailed)
        }
        let lastError = state["last_enable_error"] as? String ?? "not_attempted"
        if !enabled && failure == nil {
            if ((state["enable_attempts"] as? NSNumber)?.uint64Value ?? 0) > 0,
               lastError != "ok", lastError != "not_attempted" {
                return result("start_rejected", "Authentication did not start", "The startup return code is saved in the report. Keep the Mac running and Henge in the foreground, then tap Start again.")
            }
            if launch.isEmpty {
                return result("not_started", "Authentication test has not started", "Save your work in ChatGPT, then tap Quit and start below. The helper will request a normal quit before starting a new process.")
            }
            return result("stopped", "Authentication test stopped", "Tap Quit and start for a new test. Leaving Henge or ending the Mac session stops permission.")
        }
        let progressStages = stages.filter { !$0.hasPrefix("policy_") && !$0.hasPrefix("target_process_") }
        let activityStages: Set<String> = ["probe_requested", "probe_result", "token_requested", "token_result",
            "baa_data_requested", "baa_data_result", "baa_dictionary_requested", "baa_dictionary_result",
            "host_request_queued", "host_request_started", "host_request_completed", "transport_failed",
            "response_invalid", "host_request_failed", "host_request_cancelled", "session_inactive", "request_declined"]
        var last = failure ?? "host_bridge_enabled"
        if failure == nil {
            if !readyEvents.isEmpty && !readyConfirmed {
                return result("adapter_readiness_unconfirmed", "Adapter readiness is unconfirmed", "A readiness event arrived without a complete success result. The report preserves this uncertainty.", "adapter_ready")
            }
            if stages.contains("adapter_loaded") && !readyConfirmed {
                return result("adapter_loaded_waiting_for_ready", "Adapter loaded; waiting for initialization", "The library was observed in ChatGPT. A successful adapter handshake has not arrived yet.", "adapter_loaded")
            }
            if readyConfirmed {
                // The constructor must probe before it can report ready, and
                // keeps probing afterwards. Those capability observations must
                // not hide the moment when the person can try Chat.
                let routineProbeStages: Set<String> = ["probe_requested", "probe_result",
                    "host_request_queued", "host_request_started", "host_request_completed"]
                last = progressStages.last(where: { activityStages.contains($0) && !routineProbeStages.contains($0) }) ?? "adapter_ready"
            }
            else if let activity = progressStages.last(where: { activityStages.contains($0) }) { last = activity }
            else {
                // These phases only move forward for one launch. A late quit or
                // launch_requested delivery must not undo a later spawn observation.
                last = ["launch_started", "force_quit_completed", "quit_completed", "force_quit_requested", "quit_requested", "launch_requested", "host_bridge_enabled"]
                    .first { progressStages.contains($0) } ?? "host_bridge_enabled"
            }
        }
        // Before any launcher event, a heartbeat can explain what we are waiting for.
        // It must not hide a concrete launch failure already received from the guest.
        if last == "host_bridge_enabled" || last == "none" {
            if !helper.isConnected {
                return result("waiting_for_helper", "Waiting for the Mac helper", "The test is enabled. Keep Henge in the foreground; check the Sharing section for the helper connection.")
            }
            if state["launch_action"] != nil && !helper.permitsVerifiedExit(forSession: state["session"] as? String ?? "") {
                if helper.requiresVerifiedExitUpdate {
                    return result("helper_update_required", "Update the Mac helper for this test", "Run Install / Repair once for Helper 10, then start a new test. Both startup actions need its verified process-exit support.")
                }
                return result("helper_capability_unconfirmed", "Helper startup capability unconfirmed", "A current Helper 10 connection to this Mac has not been confirmed. Check Sharing below and wait for the connection.")
            }
            if helper.requiresAuthColdStartUpdate {
                return result("helper_update_required", "Update the Mac helper for this test", "This helper reports the earlier startup capability. Run Install / Repair once for Helper 10, then Stop and start a new test.")
            }
            if !helper.supportsAuthColdStart {
                return result("helper_capability_unconfirmed", "Helper authentication capability unconfirmed", "Run Install / Repair once to update the Mac helper. Its actual version and authentication capability will appear here.")
            }
        }
        switch last {
        case "target_not_found":
            return result("target_not_found", "ChatGPT.app was not found", "Install the original ChatGPT.app in the Mac's Applications folder, then stop and start a new test.", last)
        case "target_identity_mismatch", "target_signature_invalid", "adapter_target_rejected":
            return result("target_verification_failed", "ChatGPT verification failed", "The installed app's identity or signature did not match. The report records the verification stage.", last)
        case "signature_policy_blocked":
            return result(last, "Earlier helper stopped at signing preflight", "This is the earlier helper's static prediction, before an actual adapter launch. Update to Helper 10 and start a new test to let macOS decide. No protection setting is changed.", last)
        case "already_running":
            return result(last, "A running ChatGPT process prevented startup", "The helper did not launch another copy. Check ChatGPT in the Mac, then Stop and start a new test.", last)
        case "process_identity_unavailable":
            return result(last, "ChatGPT process identity could not be confirmed", "The helper stopped without guessing which process to terminate. The fixed process observations are saved in the report.", last)
        case "target_process_changed":
            return result(last, "The verified ChatGPT process changed", "The process identity changed during the quit attempt. The helper stopped instead of terminating a different instance.", last)
        case "target_reappeared":
            return result(last, "Another ChatGPT process appeared", "Another matching main process was observed before launch. The helper stopped and will not repeatedly terminate new instances.", last)
        case "force_quit_requested":
            return result("waiting_for_force_quit", "Waiting for the requested force quit", "This attempt was explicitly started with Force quit. The helper is checking that the verified main process has ended before one new launch.", last)
        case "force_quit_completed":
            return result("waiting_for_adapter", "Force quit confirmed; preparing a new launch", "The verified main process has ended. The helper will start the original app once with the temporary adapter.", last)
        case "force_quit_refused", "force_quit_timeout":
            return result(last, last == "force_quit_refused" ? "The force-quit request was not accepted" : "Force quit was not confirmed in time", "The requested attempt stopped before a replacement launch. It will not retry termination automatically.", last)
        case "quit_requested":
            return result("waiting_for_quit", "Waiting for ChatGPT to quit normally", "Check the Mac for a save or quit prompt. The helper waits for the process to exit and does not force-quit it.", last)
        case "quit_completed":
            return result("waiting_for_adapter", "ChatGPT quit; preparing a new launch", "The prior process has exited. The helper will start the original app once with the temporary adapter.", last)
        case "quit_refused", "quit_timeout":
            return result(last, last == "quit_refused" ? "ChatGPT did not accept the quit request" : "ChatGPT did not quit in time", "Save any unfinished input in ChatGPT. You can then choose Force quit ChatGPT and retry below; that separate action may discard unsent input. This normal attempt did not force-quit the app or start a replacement.", last)
        case "target_exited_before_adapter":
            return result(last, "ChatGPT exited before the adapter was ready", "The newly started process exited before a successful handshake. This observation alone does not identify why it exited; the report preserves the exact stage.", last)
        case "adapter_initialization_failed":
            return result(last, readyFailed ? "Adapter initialization failed" : "Adapter readiness was not confirmed",
                readyFailed ? "The adapter reported an error instead of a successful handshake. The report preserves its error domain and code; Chat acceptance is not verified." :
                    "The attempt ended without confirming a successful readiness handshake. A missing receipt alone does not identify an initialization error or a macOS signature refusal.",
                readyFailed && !stages.contains(last) ? "adapter_ready" : last)
        case "adapter_not_loaded":
            return result("adapter_handshake_not_observed", "Adapter handshake was not observed", "The launch attempt did not confirm the adapter within its deadline. This does not establish that macOS rejected its signature.", last)
        case "launch_timeout", "launch_failed", "adapter_abi_mismatch":
            return result("adapter_start_failed", "Authentication adapter did not start", "The report records the exact launch or interface failure. Stop the test before trying another launch.", last)
        case "transport_failed", "response_invalid", "host_request_failed", "host_request_cancelled", "session_inactive", "request_declined":
            return result("authentication_request_failed", "An authentication request failed", "The stage, numeric error and any Apple response are saved automatically. Chat acceptance is not verified.", last)
        case "adapter_ready":
            return result(last, "Adapter ready", "Return to the Mac and try Chat once. The report will include the resulting authentication calls.", last)
        case "host_bridge_enabled", "launch_requested", "launch_started":
            return result("waiting_for_adapter", "Starting ChatGPT with the adapter", "Keep Henge in the foreground. macOS decides whether the original app can load the adapter; a successful launch alone is not a handshake.", last)
        case "probe_requested", "probe_result", "token_requested", "token_result", "baa_data_requested", "baa_data_result",
             "baa_dictionary_requested", "baa_dictionary_result", "host_request_queued", "host_request_started", "host_request_completed":
            return result("authentication_activity_recorded", "Authentication activity recorded", "The report contains the Apple operation's result. An operation returning does not establish that Chat accepted it.", last)
        default:
            return result("waiting_for_adapter", "Waiting for authentication progress", "The test is enabled. Keep Henge in the foreground while the Mac helper starts ChatGPT.")
        }
    }

    var diagnostics: [String: Any] {
        ["classification": classification, "diagnostic_stage": stage, "permission_enabled": permissionEnabled,
         "target_process_at_preflight": processObservation, "signing_policy_observed": signingPolicy,
         "signing_policy_prediction": signingPrediction, "adapter_readiness": adapterReadiness,
         "launch_action": launchAction, "target_pid": targetPID, "observed_pid": observedPID,
         "server_acceptance_verified": false]
    }
}

enum DeviceAuthControlAction: String {
    case presented = "controls_presented"
    case startRequested = "start_requested"
    case startCompleted = "start_completed"
    case stopCompleted = "stop_completed"
    case startBlockedHelper = "start_blocked_helper"
}

enum DeviceAuthLaunchAction: String {
    case normalQuit = "normal_quit"
    case forceQuit = "force_quit"
}
