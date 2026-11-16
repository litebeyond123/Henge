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
        state["launch_id"] = launch; state["enabled"] = true; state["last_enable_error"] = "ok"
        check(DeviceAuthProgress.read(state: state, helper: .unavailable).classification == "waiting_for_helper", "wait for connection")
        check(try DeviceAuthProgress.read(state: state, helper: helper()).classification == "helper_capability_unconfirmed", "missing version is unknown")
        health["helper_version"] = 8; health["auth_experiment_protocol"] = 1
        check(try helper().supportsAuthExperiment, "new runtime explicitly advertises capability")
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
        state["events"] = [["launch_id": launch, "stage": "adapter_ready"],
                           ["launch_id": launch, "stage": "policy_runtime_on"],
                           ["launch_id": launch, "stage": "target_process_not_running"]]
        check(try DeviceAuthProgress.read(state: state, helper: helper()).classification == "adapter_ready", "late preflight facts must not regress ready state")
        state["events"] = [["launch_id": launch, "stage": "token_result"]]
        let operation = try DeviceAuthProgress.read(state: state, helper: helper())
        check(operation.classification == "authentication_activity_recorded", "a returned operation is not server acceptance")
        check(operation.diagnostics["server_acceptance_verified"] as? Bool == false, "never claim server acceptance")
        state["enabled"] = false
        check(try DeviceAuthProgress.read(state: state, helper: helper()).classification == "stopped", "revocation is different from never started")
        state["enabled"] = true; state["events"] = [["launch_id": launch, "stage": "PRIVATE-TOKEN-FIXTURE"]]
        let safe = try DeviceAuthProgress.read(state: state, helper: helper()).diagnostics
        check(!String(decoding: try JSONSerialization.data(withJSONObject: safe), as: UTF8.self).contains("PRIVATE-TOKEN-FIXTURE"), "summary has fixed categories only")
        for bad in [true, -1, 65536, 1.5, "8", NSNull()] as [Any] {
            health["helper_version"] = bad
            check(try !helper().valid, "invalid version is rejected")
        }
        health["helper_version"] = 8
        for bad in [true, -1, 65536, 1.5, "1", NSNull()] as [Any] {
            health["auth_experiment_protocol"] = bad
            check(try !helper().valid, "invalid capability protocol is rejected")
        }
        print("PASS: current-launch authentication progress, disabled-start regression, runtime capability bounds and fixed diagnostics")
    }
}
