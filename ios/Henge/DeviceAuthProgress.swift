import Foundation

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

    static func read(state: [String: Any], helper: HelperHealthSnapshot) -> DeviceAuthProgress {
        let launch = state["launch_id"] as? String ?? ""
        let enabled = state["enabled"] as? Bool == true
        let current = (state["events"] as? [[String: Any]] ?? []).filter {
            guard let value = $0["launch_id"] as? String else { return false }
            return !launch.isEmpty && value.caseInsensitiveCompare(launch) == .orderedSame
        }
        let stages = current.compactMap { $0["stage"] as? String }
        let process = stages.reversed().first { ["target_process_running", "target_process_not_running"].contains($0) }
        let processObservation = process == "target_process_running" ? "running" : process == "target_process_not_running" ? "not_running" : "not_recorded"
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
                 permissionEnabled: enabled, processObservation: processObservation, signingPolicy: policy)
        }
        guard state["protocol"] as? Int == 1 else {
            return result("state_unavailable", "Authentication status unavailable", "Tap Start to record a fresh startup attempt.")
        }
        // Independent HTTP event deliveries can arrive out of order. Preserve a concrete
        // launch failure even after a late launch_requested event or permission revocation.
        let failurePriority = ["target_identity_mismatch", "target_signature_invalid", "adapter_target_rejected",
            "signature_policy_blocked", "adapter_abi_mismatch", "target_not_found", "already_running",
            "launch_failed", "launch_timeout", "adapter_not_loaded"]
        let failure = failurePriority.first { stages.contains($0) }
        let lastError = state["last_enable_error"] as? String ?? "not_attempted"
        if !enabled && failure == nil {
            if ((state["enable_attempts"] as? NSNumber)?.uint64Value ?? 0) > 0,
               lastError != "ok", lastError != "not_attempted" {
                return result("start_rejected", "Authentication did not start", "The startup return code is saved in the report. Keep the Mac running and Henge in the foreground, then tap Start again.")
            }
            if launch.isEmpty {
                return result("not_started", "Authentication test has not started", "Installing the helper does not start this test. Quit ChatGPT normally in the Mac, then tap Start below.")
            }
            return result("stopped", "Authentication test stopped", "Quit ChatGPT normally, then tap Start for a new test. Leaving Henge or ending the Mac session stops permission.")
        }
        let progressStages = stages.filter { !$0.hasPrefix("policy_") && !$0.hasPrefix("target_process_") }
        var last = failure ?? progressStages.last ?? "host_bridge_enabled"
        if failure == nil, ["host_bridge_enabled", "launch_requested", "launch_started"].contains(last), stages.contains("adapter_ready") {
            last = "adapter_ready"
        }
        // Before any launcher event, a heartbeat can explain what we are waiting for.
        // It must not hide a concrete launch failure already received from the guest.
        if last == "host_bridge_enabled" || last == "none" {
            if !helper.isConnected {
                return result("waiting_for_helper", "Waiting for the Mac helper", "The test is enabled. Keep Henge in the foreground; check the Sharing section for the helper connection.")
            }
            if !helper.supportsAuthExperiment {
                return result("helper_capability_unconfirmed", "Helper authentication capability unconfirmed", "Run Install / Repair once to update the Mac helper. Its actual version and authentication capability will appear here.")
            }
        }
        switch last {
        case "target_not_found":
            return result("target_not_found", "ChatGPT.app was not found", "Install the original ChatGPT.app in the Mac's Applications folder, then stop and start a new test.", last)
        case "target_identity_mismatch", "target_signature_invalid", "adapter_target_rejected":
            return result("target_verification_failed", "ChatGPT verification failed", "The installed app's identity or signature did not match. The report records the verification stage.", last)
        case "signature_policy_blocked":
            return result(last, "Signing-policy preflight blocked the adapter", "The installed app does not pass this launch method's signing-policy check. This is a Henge preflight result, before an Apple token request. Quitting ChatGPT does not change its signed policy.", last)
        case "already_running":
            return result(last, "ChatGPT is already running", "Quit ChatGPT normally in the Mac, tap Stop, then tap Start again so the helper can launch it with the adapter.", last)
        case "adapter_not_loaded", "launch_timeout", "launch_failed", "adapter_abi_mismatch":
            return result("adapter_start_failed", "Authentication adapter did not start", "The report records the exact launch or interface failure. Stop the test before trying another launch.", last)
        case "transport_failed", "response_invalid", "host_request_failed", "host_request_cancelled", "session_inactive":
            return result("authentication_request_failed", "An authentication request failed", "The stage, numeric error and any Apple response are saved automatically. Chat acceptance is not verified.", last)
        case "adapter_ready":
            return result(last, "Adapter ready", "Return to the Mac and try Chat once. The report will include the resulting authentication calls.", last)
        case "host_bridge_enabled", "launch_requested", "launch_started":
            return result("waiting_for_adapter", "Starting ChatGPT with the adapter", "Keep Henge in the foreground. The helper will report whether the original app permits the adapter.", last)
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
         "server_acceptance_verified": false]
    }
}

enum DeviceAuthControlAction: String {
    case presented = "controls_presented"
    case startRequested = "start_requested"
    case startCompleted = "start_completed"
    case stopCompleted = "stop_completed"
}
