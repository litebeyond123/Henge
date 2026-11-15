import Foundation

@main struct GuestChatTests {
    static func encoded(_ value: [String: Any]) -> Data { try! JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]) }
    static func main() throws {
        let now = ISO8601DateFormatter().date(from: "2026-11-15T14:00:00Z")!
        let request = GuestChatDiagnosticsSchema.Request(sessionID: UUID(), now: now)
        let probe = GuestChatDiagnosticsSchema.Request(sessionID: request.sessionID, now: now, collect: false)
        precondition(probe.sessionID == request.sessionID && probe.expires < now)
        precondition(request.expires > now && probe.requestID != request.requestID)
        let guestClockNinetySecondsBehind = now.addingTimeInterval(-90)
        precondition(!probe.collect && probe.dictionary["collect"] as? Bool == false)
        precondition(probe.expires < guestClockNinetySecondsBehind)
        precondition(request.collect && request.dictionary["collect"] as? Bool == true)
        var report: [String: Any] = [
            "schema_version": 1, "collector_version": 1, "vm_session_id": request.sessionID.uuidString,
            "request_id": request.requestID.uuidString, "request_created_utc": GuestChatDiagnosticsSchema.utc(request.created),
            "request_expires_utc": GuestChatDiagnosticsSchema.utc(request.expires), "collected_utc": GuestChatDiagnosticsSchema.utc(now),
            "collection_status": "complete", "log_status": "complete", "classification": "devicecheck_unavailable_observed",
            "client_found": true, "client_signature_kind": "signed", "client_signature_check": "valid_main_bundle",
            "architecture": "arm64", "log_window_seconds": 900, "collection_elapsed_ms": 50,
            "log_event_count": 3, "matched_event_count": 1, "client_version": "26.1111.21308",
            "client_bundle_id": "com.openai.chat", "os_version": "15.6.1", "hardware_model": "VirtualMac2,1"
        ]
        report["source_scope"] = "mixed_chatgpt_device_services"
        report["chatgpt_matched_event_count"] = 1
        report["system_devicecheck_matched_event_count"] = 0
        report["unknown_source_matched_event_count"] = 0
        for key in GuestChatDiagnosticsSchema.countKeys { report[key] = 0 }
        report["error_devicecheck_unsupported_count"] = 1
        let valid = GuestChatDiagnosticsSchema.canonicalReport(encoded(report), request: request, now: now)
        precondition(valid?["client_version"] as? String == "26.1111.21308")
        precondition(valid?["error_devicecheck_unsupported_count"] as? Int == 1)
        // Even if a time supplied to the validator makes a probe appear fresh,
        // its explicit collect:false can never authorize a collected result.
        var probeReport = report
        probeReport["request_id"] = probe.requestID.uuidString
        probeReport["request_created_utc"] = GuestChatDiagnosticsSchema.utc(probe.created)
        probeReport["request_expires_utc"] = GuestChatDiagnosticsSchema.utc(probe.expires)
        probeReport["collected_utc"] = GuestChatDiagnosticsSchema.utc(probe.created)
        precondition(GuestChatDiagnosticsSchema.canonicalReport(encoded(probeReport), request: probe, now: probe.created) == nil)
        var bad = report; bad["request_id"] = UUID().uuidString
        precondition(GuestChatDiagnosticsSchema.canonicalReport(encoded(bad), request: request, now: now) == nil)
        bad = report; bad["vm_session_id"] = UUID().uuidString
        precondition(GuestChatDiagnosticsSchema.canonicalReport(encoded(bad), request: request, now: now) == nil)
        precondition(GuestChatDiagnosticsSchema.canonicalReport(encoded(report), request: request, now: now.addingTimeInterval(61)) == nil)
        bad = report; bad["request_created_utc"] = "2026-11-14T14:00:00Z"
        precondition(GuestChatDiagnosticsSchema.canonicalReport(encoded(bad), request: request, now: now) == nil)
        bad = report; bad["error_devicecheck_unsupported_count"] = true
        precondition(GuestChatDiagnosticsSchema.canonicalReport(encoded(bad), request: request, now: now) == nil)
        bad = report; bad["error_devicecheck_unsupported_count"] = 2
        precondition(GuestChatDiagnosticsSchema.canonicalReport(encoded(bad), request: request, now: now) == nil)
        bad = report; bad["client_found"] = 1
        precondition(GuestChatDiagnosticsSchema.canonicalReport(encoded(bad), request: request, now: now) == nil)
        bad = report; bad["log_status"] = "timed_out"
        precondition(GuestChatDiagnosticsSchema.canonicalReport(encoded(bad), request: request, now: now) == nil)
        let secret = "PRIVATE_CHAT_COOKIE_TOKEN_EMAIL"
        bad = report; bad["messages"] = [["content": secret]]; bad["env"] = ["TOKEN": secret]
        bad["client_build"] = secret; bad["client_team_identifier"] = "user@example.invalid"
        let safe = GuestChatDiagnosticsSchema.canonicalReport(encoded(bad), request: request, now: now)!
        precondition(!String(data: encoded(safe), encoding: .utf8)!.contains(secret))
        precondition(safe["messages"] == nil && safe["env"] == nil && safe["client_build"] == nil && safe["client_team_identifier"] == nil)
        precondition(GuestChatDiagnosticsSchema.canonicalReport(Data(repeating: 32, count: 16385), request: request, now: now) == nil)
        let heartbeat: [String: Any] = ["schema_version": 1, "collector_version": 1,
            "vm_session_id": request.sessionID.uuidString, "seen_utc": GuestChatDiagnosticsSchema.utc(now)]
        precondition(GuestChatDiagnosticsSchema.ready(encoded(heartbeat), session: request.sessionID, now: now))
        precondition(!GuestChatDiagnosticsSchema.ready(encoded(heartbeat), session: UUID(), now: now))
        precondition(!GuestChatDiagnosticsSchema.ready(encoded(heartbeat), session: request.sessionID, now: now.addingTimeInterval(46)))
        precondition(GuestChatDiagnosticsSchema.readiness(nil, session: request.sessionID, now: now).state == .missing_or_unreadable)
        precondition(GuestChatDiagnosticsSchema.readiness(encoded(heartbeat), session: UUID(), now: now).state == .other_session)
        precondition(GuestChatDiagnosticsSchema.readiness(encoded(heartbeat), session: request.sessionID, now: now.addingTimeInterval(46)).state == .stale)
        precondition(GuestChatDiagnosticsSchema.readiness(encoded(heartbeat), session: request.sessionID, now: now.addingTimeInterval(-31)).state == .clock_ahead)
        var newer = heartbeat; newer["collector_version"] = 2
        precondition(GuestChatDiagnosticsSchema.readiness(encoded(newer), session: request.sessionID, now: now).state == .version_mismatch)

        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("henge-chat-test-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: folder) }
        precondition(GuestChatDiagnosticsFiles.write(encoded(report), directory: folder, name: "report.json"))
        precondition(GuestChatDiagnosticsFiles.read(directory: folder, name: "report.json", limit: 16384) == encoded(report))
        precondition(GuestChatDiagnosticsFiles.read(directory: folder, name: "report.json", limit: 2) == nil)
        try FileManager.default.createSymbolicLink(atPath: folder.appendingPathComponent("link.json").path,
                                                 withDestinationPath: folder.appendingPathComponent("report.json").path)
        precondition(GuestChatDiagnosticsFiles.read(directory: folder, name: "link.json", limit: 16384) == nil)
        precondition(GuestChatDiagnosticsFiles.read(directory: folder, name: "missing.json", limit: 16384) == nil)
        print("PASS: host guest-schema allowlist, IDs, expiry, heartbeat, atomic file I/O, cap and symlinks")
    }
}
