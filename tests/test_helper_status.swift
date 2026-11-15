import Foundation

// Foundation-only: compile with ios/Henge/Sharing.swift. UIKit/C bridge is excluded.
@main struct HelperStatusTests {
    static func check(_ condition: Bool, file: StaticString = #file, line: UInt = #line) {
        precondition(condition, "helper-state assertion failed", file: file, line: line)
    }
    static func main() throws {
        var value: [String: Any] = [
            "protocol": 1, "session": "6B0449C3-B96E-4EB3-B938-A585DD766D12",
            "helper_protocol": 4, "helper_pid": 1234,
            "agent_seen_s": 2, "probe_seen_s": 3, "install_seen_s": 4,
            "startup_stage": "ready", "install_stage": "confirmed", "install_error": "none", "install_exit_code": 0
        ]
        func decode(_ raw: [String: Any]) throws -> HelperHealthSnapshot {
            HelperHealthSnapshot.decode(try JSONSerialization.data(withJSONObject: raw))
        }
        let connected = try decode(value)
        check(connected.valid && connected.isConnected && connected.install == .confirmed)
        value["agent_seen_s"] = 30
        let disconnected = try decode(value)
        check(!disconnected.isConnected && disconnected.install == .confirmed)
        check(disconnected.installationTitle == connected.installationTitle)
        check(disconnected.connectionTitle == "Connection interrupted")
        value["agent_seen_s"] = -1; value["install_stage"] = "not_started"
        let neverSeen = try decode(value)
        check(!neverSeen.isConnected && neverSeen.connectionTitle == "Waiting for connection")
        check(!neverSeen.connectionTitle.lowercased().contains("installed"))
        value["install_stage"] = "awaiting_connection"
        let awaiting = try decode(value)
        check(awaiting.valid && !awaiting.isConnected && awaiting.install == .awaiting_connection)
        check(awaiting.installationTitle.contains("waiting for connection"))
        check(awaiting.detail.contains("not confirmed") && awaiting.detail.contains("do not repeat"))
        check(awaiting.diagnostics["install_stage"] as? String == "awaiting_connection")
        value["install_stage"] = "confirmed"; value["agent_seen_s"] = 0
        check(try decode(value).isConnected) // An asynchronous app receipt can finish the pending installation.
        value["agent_seen_s"] = 29; value["startup_stage"] = "clipboard_unavailable"
        check(try decode(value).isConnected) // Clipboard denial does not imply the agent is absent.
        value["install_stage"] = "failed"; value["install_error"] = "bootstrap_failed"; value["install_exit_code"] = 5
        let failed = try decode(value)
        check(failed.isConnected && failed.install == .failed && failed.installExitCode == 5)
        check(failed.detail.contains("macOS did not start"))
        value["session"] = ""
        check(try !decode(value).isConnected)
        value["session"] = UUID().uuidString
        value["private_error_message"] = "PRIVATE-TOKEN-FIXTURE"
        let safe = try decode(value)
        check(!String(decoding: try JSONSerialization.data(withJSONObject: safe.diagnostics), as: UTF8.self).contains("PRIVATE-TOKEN-FIXTURE"))
        value["startup_stage"] = "PRIVATE-TOKEN-FIXTURE"
        check(try !decode(value).valid)
        value["startup_stage"] = "ready"; value["helper_protocol"] = true
        check(try !decode(value).valid)
        value["helper_protocol"] = 4; value["agent_seen_s"] = -2
        check(try !decode(value).valid)
        check(!HelperHealthSnapshot.decode(Data(repeating: 32, count: 8193)).valid)
        print("PASS: helper connection is independent of installation/clipboard; receipt bounds and allowlisted diagnostics")
    }
}
