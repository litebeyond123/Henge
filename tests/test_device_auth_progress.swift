import Foundation

@main struct DeviceAuthProgressTests {
    static func check(_ value: Bool, _ message: String, file: StaticString = #file, line: UInt = #line) {
        precondition(value, message, file: file, line: line)
    }

    static func main() throws {
        var health: [String: Any] = ["protocol": 1, "session": "3B956C9F-D048-4CD8-9503-61362B49A942",
            "helper_protocol": 4, "helper_pid": 983, "agent_seen_s": 9, "probe_seen_s": -1,
            "install_seen_s": 112, "startup_stage": "ready", "install_stage": "confirmed",
            "install_error": "none", "install_exit_code": 0]
        func helper() throws -> HelperHealthSnapshot {
            HelperHealthSnapshot.decode(try JSONSerialization.data(withJSONObject: health))
        }
        // Regression: the 4008 report had a confirmed helper and active service,
        // but no authorization. Neither observation is a token-generation attempt.
        var state: [String: Any] = ["protocol": 1, "enabled": false, "active": true,
            "running": true, "foreground": true, "fresh": true, "launch_id": "", "mode": "none",
            "accepted_requests": 0, "events": []]
        check(try DeviceAuthProgress.read(state: state, helper: helper()).classification == "not_started", "4008 is not an Apple rejection")
        check(try helper().isConnected && !helper().supportsAuthExperiment, "wire protocol 4 does not prove auth capability")
        state["enable_attempts"] = 1; state["last_enable_error"] = "host_inactive"
        check(try DeviceAuthProgress.read(state: state, helper: helper()).classification == "start_rejected", "startup rejection survives a later fresh snapshot")
        let launch = "D5F14A6D-E793-4180-BB36-884B8F7C367C"
        func event(_ stage: String, code: Int = 0, domain: String = "", sequence: Int? = nil) -> [String: Any] {
            var value: [String: Any] = ["launch_id": launch, "stage": stage, "errorCode": code, "errorDomain": domain]
            if let sequence { value["sequence"] = sequence }
            return value
        }
        state["launch_id"] = launch; state["enabled"] = true; state["last_enable_error"] = "ok"
        check(DeviceAuthProgress.read(state: state, helper: .unavailable).classification == "waiting_for_helper", "wait for connection")
        check(try DeviceAuthProgress.read(state: state, helper: helper()).classification == "helper_capability_unconfirmed", "missing version is unknown")
        health["helper_version"] = 8; health["auth_experiment_protocol"] = 1
        check(try helper().supportsAuthExperiment && !helper().supportsAuthColdStart, "earlier capability is recognized separately")
        check(try DeviceAuthProgress.read(state: state, helper: helper()).classification == "helper_update_required", "old capability needs cold-start update")
        health["helper_version"] = 9; health["auth_experiment_protocol"] = 2
        check(try helper().supportsAuthColdStart, "new runtime explicitly advertises cold-start capability")
        check(try DeviceAuthProgress.read(state: state, helper: helper()).classification == "waiting_for_adapter", "wait for actual launcher")
        state["events"] = [["launch_id": "11111111-1111-1111-1111-111111111111", "stage": "adapter_ready"]]
        check(try DeviceAuthProgress.read(state: state, helper: helper()).classification == "waiting_for_adapter", "ignore another launch")
        state["events"] = [["launch_id": launch.lowercased(), "stage": "signature_policy_blocked"]]
        check(DeviceAuthProgress.read(state: state, helper: .unavailable).classification == "signature_policy_blocked", "stale heartbeat must not hide a recorded failure")
        state["events"] = [["launch_id": launch, "stage": "signature_policy_blocked"],
                           ["launch_id": launch, "stage": "launch_requested"]]
        check(try DeviceAuthProgress.read(state: state, helper: helper()).classification == "signature_policy_blocked", "late initial event must not hide terminal failure")
        state["enabled"] = false
        check(try DeviceAuthProgress.read(state: state, helper: helper()).classification == "signature_policy_blocked", "4008 follow-up: stopping must preserve the recorded reason")
        state["enabled"] = true
        state["events"] = [["launch_id": launch, "stage": "adapter_target_rejected"],
                           ["launch_id": launch, "stage": "adapter_not_loaded"]]
        check(try DeviceAuthProgress.read(state: state, helper: helper()).classification == "target_verification_failed", "specific constructor failure survives generic launcher result")
        state["events"] = ["target_process_running", "policy_runtime_on", "policy_library_flag_off",
                           "policy_dyld_env_not_allowed", "policy_library_exception_on", "signature_policy_blocked"]
            .map { ["launch_id": launch, "stage": $0] }
        let preflight = try DeviceAuthProgress.read(state: state, helper: helper())
        check(preflight.processObservation == "running", "running is independent of the policy failure")
        check(preflight.signingPolicy["hardened_runtime"] == true && preflight.signingPolicy["library_validation_flag"] == false,
              "do not conflate explicit LV bit with hardened runtime")
        check(preflight.signingPolicy["dyld_environment_allowed"] == false && preflight.signingPolicy["library_validation_exception"] == true,
              "DYLD and library exceptions are independent")
        state["events"] = [["launch_id": launch, "stage": "policy_flags_unavailable"]]
        let unknownPolicy = try DeviceAuthProgress.read(state: state, helper: helper())
        check(unknownPolicy.signingPolicy["flags_readable"] == false && unknownPolicy.signingPolicy["hardened_runtime"] == nil,
              "unknown flags are never shown as off")
        state["events"] = [event("adapter_ready"), event("policy_runtime_on"), event("target_process_not_running")]
        check(try DeviceAuthProgress.read(state: state, helper: helper()).classification == "adapter_ready", "late preflight facts must not regress ready state")
        state["events"] = [event("policy_predicts_restriction"), event("quit_completed"), event("launch_started"),
                           event("adapter_loaded"), event("adapter_ready"), event("quit_requested"), event("launch_requested")]
        let actualReady = try DeviceAuthProgress.read(state: state, helper: helper())
        check(actualReady.classification == "adapter_ready" && actualReady.adapterReadiness == "confirmed",
              "successful handshake wins over restrictive prediction and late startup deliveries")
        check(actualReady.signingPrediction == "restriction_predicted", "prediction remains a separate observation")
        state["events"] = [event("adapter_loaded", sequence: 1), event("probe_requested", sequence: 2),
            event("host_request_queued", sequence: 3), event("host_request_started", sequence: 4),
            event("host_request_completed", sequence: 5), event("probe_result", sequence: 6), event("adapter_ready", sequence: 7)]
        check(try DeviceAuthProgress.read(state: state, helper: helper()).classification == "adapter_ready",
              "the real constructor's required probe must not hide ready")
        state["events"] = (state["events"] as! [[String: Any]]) + [event("probe_requested", sequence: 8),
            event("probe_result", sequence: 9), event("host_request_completed", sequence: 10)]
        check(try DeviceAuthProgress.read(state: state, helper: helper()).classification == "adapter_ready",
              "late or periodic probe completions must not hide ready")
        state["events"] = (state["events"] as! [[String: Any]]) + [event("token_requested", sequence: 11)]
        check(try DeviceAuthProgress.read(state: state, helper: helper()).classification == "authentication_activity_recorded",
              "an actual token operation can move the title past ready while preserving handshake proof")
        state["events"] = [event("adapter_loaded"), event("launch_requested")]
        check(try DeviceAuthProgress.read(state: state, helper: helper()).classification == "adapter_loaded_waiting_for_ready", "loaded is not ready")
        state["events"] = [event("adapter_ready", code: 1002, domain: "HengeAuthBridge"), event("launch_requested")]
        check(try DeviceAuthProgress.read(state: state, helper: helper()).classification == "adapter_initialization_failed", "nonzero ready result is a failure")
        check(try DeviceAuthProgress.read(state: state, helper: helper()).title == "Adapter initialization failed", "an explicit error receipt can identify a failed handshake")
        state["enabled"] = false
        check(try DeviceAuthProgress.read(state: state, helper: helper()).classification == "adapter_initialization_failed", "failed handshake survives Stop")
        state["enabled"] = true
        var incomplete = event("adapter_ready"); incomplete.removeValue(forKey: "errorDomain")
        state["events"] = [incomplete]
        check(try DeviceAuthProgress.read(state: state, helper: helper()).classification == "adapter_readiness_unconfirmed", "missing domain is not a complete success receipt")
        incomplete["errorCode"] = 1002; state["events"] = [incomplete]
        check(try DeviceAuthProgress.read(state: state, helper: helper()).classification == "adapter_initialization_failed", "explicit nonzero error cannot become unknown or ready")
        for bad in [true, "0", NSNull(), 0.5] as [Any] {
            var malformed = event("adapter_ready"); malformed["errorCode"] = bad
            state["events"] = [malformed]
            check(try DeviceAuthProgress.read(state: state, helper: helper()).classification == "adapter_readiness_unconfirmed", "malformed success code is not ready")
        }
        state["events"] = [event("adapter_ready", domain: "HengeAuthBridge")]
        check(try DeviceAuthProgress.read(state: state, helper: helper()).classification == "adapter_initialization_failed", "nonempty error domain is not a successful handshake")
        state["events"] = [event("quit_requested")]
        check(try DeviceAuthProgress.read(state: state, helper: helper()).classification == "waiting_for_quit", "normal quit has a distinct waiting state")
        state["events"] = [event("launch_started"), event("quit_requested")]
        check(try DeviceAuthProgress.read(state: state, helper: helper()).stage == "launch_started", "late quit request cannot regress a spawn observation")
        for failure in ["quit_refused", "quit_timeout", "target_exited_before_adapter", "adapter_initialization_failed"] {
            state["events"] = [event(failure, code: 1021, domain: "HengeAuthBridge"), event("launch_requested")]
            check(DeviceAuthProgress.read(state: state, helper: .unavailable).classification == failure, "concrete cold-start failure survives heartbeat loss and reordering")
            state["enabled"] = false
            check(try DeviceAuthProgress.read(state: state, helper: helper()).classification == failure, "cold-start failure survives Stop")
            state["enabled"] = true
        }
        state["events"] = [event("adapter_loaded"), event("adapter_initialization_failed", code: 1022, domain: "HengeAuthBridge")]
        let unconfirmedInitialization = try DeviceAuthProgress.read(state: state, helper: helper())
        check(unconfirmedInitialization.classification == "adapter_initialization_failed" &&
              unconfirmedInitialization.title == "Adapter readiness was not confirmed",
              "a best-effort local receipt can be absent without proving the initialization code failed")
        state["events"] = [event("adapter_not_loaded")]
        let notObserved = try DeviceAuthProgress.read(state: state, helper: helper())
        check(notObserved.classification == "adapter_handshake_not_observed", "absence of a handshake is not an OS refusal")
        state["startup_events"] = [event("quit_completed", sequence: 2), event("adapter_loaded", sequence: 4),
                                   event("adapter_ready", sequence: 5), event("policy_predicts_restriction", sequence: 1)]
        state["events"] = [event("adapter_ready", sequence: 5), event("probe_result", sequence: 72)]
        let cached = try DeviceAuthProgress.read(state: state, helper: helper())
        check(cached.adapterReadiness == "confirmed" && cached.signingPrediction == "restriction_predicted",
              "startup summary survives probe ring wrap and a duplicate service event")
        check(cached.classification == "adapter_ready", "a cached handshake remains visible through routine probe activity")
        state["startup_events"] = [event("quit_refused", code: 1021, domain: "HengeAuthBridge", sequence: 7)]
        state["events"] = [event("probe_result", sequence: 72)]
        state["enabled"] = false
        check(try DeviceAuthProgress.read(state: state, helper: helper()).classification == "quit_refused", "cached terminal reason survives Stop and request churn")
        state["enabled"] = true; state["launch_id"] = "11111111-1111-1111-1111-111111111111"
        check(try DeviceAuthProgress.read(state: state, helper: helper()).classification == "waiting_for_adapter", "new launch cannot inherit cached failure")
        state["launch_id"] = launch; state.removeValue(forKey: "startup_events")
        state["events"] = [["launch_id": launch, "stage": "token_result"]]
        let operation = try DeviceAuthProgress.read(state: state, helper: helper())
        check(operation.classification == "authentication_activity_recorded", "a returned operation is not server acceptance")
        check(operation.diagnostics["server_acceptance_verified"] as? Bool == false, "never claim server acceptance")
        state["enabled"] = false
        check(try DeviceAuthProgress.read(state: state, helper: helper()).classification == "stopped", "revocation is different from never started")
        state["enabled"] = true; state["events"] = [["launch_id": launch, "stage": "PRIVATE-TOKEN-FIXTURE"]]
        let safe = try DeviceAuthProgress.read(state: state, helper: helper()).diagnostics
        check(!String(decoding: try JSONSerialization.data(withJSONObject: safe), as: UTF8.self).contains("PRIVATE-TOKEN-FIXTURE"), "summary has fixed categories only")

        // Test11 binds the action to this launch. Both buttons use the same verified-exit
        // capability gate; a Helper9 cold-start heartbeat remains valid historical evidence.
        state["events"] = []; state["session"] = health["session"]
        check(try DeviceAuthProgress.read(state: state, helper: helper()).launchAction == "normal_quit", "missing legacy action defaults to normal")
        state["launch_action"] = "normal_quit"
        check(try DeviceAuthProgress.read(state: state, helper: helper()).classification == "helper_update_required", "Helper9 cannot start a Test11 normal attempt")
        state["launch_action"] = "force_quit"
        check(try DeviceAuthProgress.read(state: state, helper: helper()).classification == "helper_update_required", "Helper9 cannot start a force attempt")
        health["helper_version"] = 11; health["auth_experiment_protocol"] = 4
        check(try DeviceAuthProgress.read(state: state, helper: helper()).classification == "waiting_for_adapter", "new capable helper waits for real evidence")
        state["session"] = UUID().uuidString
        check(try DeviceAuthProgress.read(state: state, helper: helper()).classification == "helper_capability_unconfirmed", "another VM helper cannot explain this launch")
        state["session"] = (health["session"] as! String).lowercased()
        check(try DeviceAuthProgress.read(state: state, helper: helper()).classification == "waiting_for_adapter", "session UUID matching is case insensitive")
        state["events"] = [event("force_quit_requested")]
        check(try DeviceAuthProgress.read(state: state, helper: helper()).classification == "waiting_for_force_quit", "force quit is separate from normal quit")
        state["events"] = [event("force_quit_completed"), event("force_quit_requested")]
        check(try DeviceAuthProgress.read(state: state, helper: helper()).stage == "force_quit_completed", "late request cannot undo verified exit")
        state["events"] = [event("launch_started"), event("force_quit_completed")]
        check(try DeviceAuthProgress.read(state: state, helper: helper()).stage == "launch_started", "late exit cannot undo spawn")
        for stage in ["quit_operation_returned", "process_exit_pending", "post_exit_signature_started",
                      "post_exit_signature_completed", "post_exit_census_started", "post_exit_census_completed"] {
            state["events"] = [event(stage), event("quit_requested")]
            check(try DeviceAuthProgress.read(state: state, helper: helper()).stage == stage, "observed phase survives late quit intent")
            state["events"] = [event(stage), event("process_identity_unavailable")]
            check(try DeviceAuthProgress.read(state: state, helper: helper()).classification == "process_identity_unavailable", "terminal process failure takes precedence over observed phase")
        }
        for failure in ["force_quit_refused", "force_quit_timeout", "process_identity_unavailable", "target_process_changed", "target_reappeared"] {
            var observation = event(failure, code: 1023, domain: "HengeAuthBridge", sequence: 44)
            observation["targetPid"] = 321; observation["observedPid"] = 654
            state["startup_events"] = [observation]
            state["events"] = [event("launch_requested", sequence: 45), event("probe_result", sequence: 77)]
            let failed = DeviceAuthProgress.read(state: state, helper: .unavailable)
            check(failed.classification == failure && failed.launchAction == "force_quit", "fixed force/process failure survives reordered events and heartbeat loss")
            check(failed.targetPID == 321 && failed.observedPID == 654, "PID observations survive ring churn")
            state["enabled"] = false
            check(try DeviceAuthProgress.read(state: state, helper: helper()).classification == failure, "force/process failure survives Stop")
            state["enabled"] = true
        }
        state.removeValue(forKey: "startup_events")
        var reappeared = event("target_reappeared"); reappeared["observedPid"] = 654
        state["events"] = [reappeared]
        let newProcess = try DeviceAuthProgress.read(state: state, helper: helper())
        check(newProcess.targetPID == 0 && newProcess.observedPID == 654, "a new process can appear without a previous one")
        check(!newProcess.detail.contains("original process ended"), "do not invent a prior quit")
        for malformed in [true, -1, Int64(Int32.max) + 1, 1.5, "123", NSNull()] as [Any] {
            var invalid = event("force_quit_requested"); invalid["targetPid"] = malformed; invalid["observedPid"] = malformed
            state["events"] = [invalid]
            let bounded = try DeviceAuthProgress.read(state: state, helper: helper())
            check(bounded.targetPID == 0 && bounded.observedPID == 0, "malformed PID metadata is not displayed")
        }
        var maximum = event("force_quit_completed", sequence: 2)
        maximum["targetPid"] = Int32.max; maximum["observedPid"] = 0
        var otherLaunch = event("target_reappeared", sequence: 3)
        otherLaunch["launch_id"] = UUID().uuidString; otherLaunch["targetPid"] = 888; otherLaunch["observedPid"] = 999
        state["events"] = [maximum, otherLaunch]
        let bounded = try DeviceAuthProgress.read(state: state, helper: helper())
        check(bounded.targetPID == Int(Int32.max) && bounded.observedPID == 0, "positive int32 bounds and launch isolation")
        check(bounded.diagnostics["target_pid"] as? Int == Int(Int32.max), "PID fields remain ordinary fixed metadata")
        state["launch_action"] = "PRIVATE-TOKEN-FIXTURE"
        check(try DeviceAuthProgress.read(state: state, helper: helper()).launchAction == "unknown", "unknown actions do not leak arbitrary text")
        state["launch_action"] = "normal_quit"
        check(try DeviceAuthProgress.read(state: state, helper: helper()).launchAction == "normal_quit", "normal action never escalates from a prior observation")
        check(DeviceAuthControlAction.startBlockedHelper.rawValue == "start_blocked_helper", "rejected local attempts have a fixed diagnostic category")
        for bad in [true, -1, 65536, 1.5, "8", NSNull()] as [Any] {
            health["helper_version"] = bad
            check(try !helper().valid, "invalid version is rejected")
        }
        health["helper_version"] = 9
        for bad in [true, -1, 65536, 1.5, "1", NSNull()] as [Any] {
            health["auth_experiment_protocol"] = bad
            check(try !helper().valid, "invalid capability protocol is rejected")
        }
        print("PASS: current-launch authentication progress, disabled-start regression, runtime capability bounds and fixed diagnostics")
    }
}
