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
        precondition(request.collectionMode == .automatic && request.dictionary["collection_mode"] as? String == "automatic")
        let manualRequest = GuestChatDiagnosticsSchema.Request(sessionID: request.sessionID, now: now, collectionMode: .manual)
        precondition(manualRequest.dictionary["collection_mode"] as? String == "manual")
        precondition(manualRequest.expires.timeIntervalSince(manualRequest.created) == 60)
        precondition(GuestChatDiagnosticsSchema.maximumManualWait == 45)
        let manualProbe = GuestChatDiagnosticsSchema.Request(sessionID: request.sessionID, now: now, collect: false, collectionMode: .manual)
        precondition(!manualProbe.collect && manualProbe.collectionMode == .automatic)
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
        precondition(valid?["log_counts_status"] as? String == "complete")
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

        // A complete event read before a timeout is evidence, even though its
        // counter is only a lower bound for the requested 15-minute window.
        var partial = report
        partial["collection_status"] = "partial"
        partial["log_status"] = "timed_out"
        partial["log_counts_status"] = "partial"
        partial["log_command_status"] = "timed_out"
        partial["log_command_started"] = true
        partial["log_command_elapsed_ms"] = 8000
        partial["log_command_termination_signal"] = 9
        partial["collection_elapsed_ms"] = 9000
        partial["metadata_status"] = "complete"
        partial["metadata_elapsed_ms"] = 10
        partial["signature_display_status"] = "complete"
        partial["signature_display_elapsed_ms"] = 25
        partial["signature_verify_status"] = "timed_out"
        partial["signature_verify_elapsed_ms"] = 750
        partial["client_signature_check"] = "timed_out"
        partial["client_executable"] = "Codex"
        let acceptedPartial = GuestChatDiagnosticsSchema.canonicalReport(encoded(partial), request: request, now: now)!
        precondition(acceptedPartial["classification"] as? String == "devicecheck_unavailable_observed")
        precondition(acceptedPartial["log_command_termination_signal"] as? Int == 9)
        precondition(acceptedPartial["client_executable"] as? String == "Codex")
        precondition(GuestChatDiagnosticsSchema.collectionMessage(acceptedPartial).contains("Partial Mac error summary"))
        let receipt = GuestChatDiagnosticsSchema.collectionReceipt(acceptedPartial)
        precondition(receipt.contains("result=partial") && receipt.contains("error_devicecheck_unsupported_count=1"))
        precondition(receipt.contains("system_devicecheck_matched_event_count=0"))
        for (key, value) in [("log_counts_status", "complete" as Any), ("log_counts_status", "bogus"),
                             ("log_counts_status", true), ("classification", "no_known_error_observed"),
                             ("log_command_status", "not_run_budget"), ("log_command_started", 1),
                             ("log_command_started", false), ("log_command_elapsed_ms", true),
                             ("log_command_elapsed_ms", 30001), ("log_command_elapsed_ms", -1),
                             ("log_command_elapsed_ms", 1.5), ("log_command_exit_code", 0),
                             ("log_command_termination_signal", 0), ("log_command_termination_signal", 32),
                             ("metadata_status", "arbitrary text"), ("signature_verify_status", "not_verified")] {
            bad = partial; bad[key] = value
            precondition(GuestChatDiagnosticsSchema.canonicalReport(encoded(bad), request: request, now: now) == nil,
                         "accepted inconsistent field: \(key)=\(value)")
        }
        // A parser error after valid events also preserves only partial evidence,
        // even when the child command itself completed successfully.
        var damaged = partial
        damaged["log_status"] = "unavailable"
        damaged["log_command_status"] = "complete"
        damaged["log_command_termination_signal"] = nil
        damaged["log_command_exit_code"] = 0
        precondition(GuestChatDiagnosticsSchema.canonicalReport(encoded(damaged), request: request, now: now) != nil)
        bad = damaged; bad["log_command_exit_code"] = 7
        precondition(GuestChatDiagnosticsSchema.canonicalReport(encoded(bad), request: request, now: now) == nil)
        bad = damaged; bad["log_command_exit_code"] = nil; bad["log_command_termination_signal"] = 9
        precondition(GuestChatDiagnosticsSchema.canonicalReport(encoded(bad), request: request, now: now) == nil)

        var noMatches = partial
        noMatches["matched_event_count"] = 0
        noMatches["chatgpt_matched_event_count"] = 0
        noMatches["classification"] = "logs_unavailable"
        for key in GuestChatDiagnosticsSchema.countKeys { noMatches[key] = 0 }
        let acceptedNoMatches = GuestChatDiagnosticsSchema.canonicalReport(encoded(noMatches), request: request, now: now)!
        precondition(GuestChatDiagnosticsSchema.collectionMessage(acceptedNoMatches).contains("incomplete result"))
        bad = noMatches; bad["classification"] = "no_known_error_observed"
        precondition(GuestChatDiagnosticsSchema.canonicalReport(encoded(bad), request: request, now: now) == nil)
        bad = noMatches; bad["log_event_count"] = 0
        precondition(GuestChatDiagnosticsSchema.canonicalReport(encoded(bad), request: request, now: now) == nil)

        // Reproduce the old helper's timed-out/default-zero summary without
        // allowing it to become a complete or healthy result.
        var legacyTimeout = report
        legacyTimeout["collection_status"] = "partial"
        legacyTimeout["log_status"] = "timed_out"
        legacyTimeout["classification"] = "logs_unavailable"
        legacyTimeout["log_event_count"] = 0
        legacyTimeout["matched_event_count"] = 0
        legacyTimeout["chatgpt_matched_event_count"] = 0
        for key in GuestChatDiagnosticsSchema.countKeys { legacyTimeout[key] = 0 }
        let acceptedLegacy = GuestChatDiagnosticsSchema.canonicalReport(encoded(legacyTimeout), request: request, now: now)!
        precondition(acceptedLegacy["log_counts_status"] as? String == "unavailable")
        precondition(acceptedLegacy["log_command_elapsed_ms"] == nil)
        precondition(GuestChatDiagnosticsSchema.collectionMessage(acceptedLegacy).contains("could not be determined"))
        var notRun = legacyTimeout
        notRun["log_counts_status"] = "unavailable"
        notRun["log_status"] = "not_run_budget"
        notRun["log_command_status"] = "not_run_budget"
        notRun["log_command_started"] = false
        notRun["log_command_elapsed_ms"] = 0
        precondition(GuestChatDiagnosticsSchema.canonicalReport(encoded(notRun), request: request, now: now) != nil)
        bad = notRun; bad["log_command_started"] = true
        precondition(GuestChatDiagnosticsSchema.canonicalReport(encoded(bad), request: request, now: now) == nil)
        var emptyComplete = legacyTimeout
        emptyComplete["collection_status"] = "complete"
        emptyComplete["log_status"] = "complete"
        emptyComplete["classification"] = "no_known_error_observed"
        let acceptedEmpty = GuestChatDiagnosticsSchema.canonicalReport(encoded(emptyComplete), request: request, now: now)!
        precondition(GuestChatDiagnosticsSchema.collectionMessage(acceptedEmpty).contains("still needs verification"))
        var completeWithSignatureTimeout = report
        completeWithSignatureTimeout["metadata_status"] = "partial"
        completeWithSignatureTimeout["signature_verify_status"] = "timed_out"
        completeWithSignatureTimeout["signature_verify_elapsed_ms"] = 750
        completeWithSignatureTimeout["client_signature_check"] = "timed_out"
        let acceptedSignatureTimeout = GuestChatDiagnosticsSchema.canonicalReport(encoded(completeWithSignatureTimeout), request: request, now: now)!
        precondition(acceptedSignatureTimeout["log_counts_status"] as? String == "complete")
        precondition(acceptedSignatureTimeout["classification"] as? String == "devicecheck_unavailable_observed")
        bad = report; bad["classification"] = "network_error_observed"
        precondition(GuestChatDiagnosticsSchema.canonicalReport(encoded(bad), request: request, now: now) == nil)

        let secret = "PRIVATE_CHAT_COOKIE_TOKEN_EMAIL"
        bad = report; bad["messages"] = [["content": secret]]; bad["env"] = ["TOKEN": secret]
        bad["client_build"] = secret; bad["client_team_identifier"] = "user@example.invalid"
        let safe = GuestChatDiagnosticsSchema.canonicalReport(encoded(bad), request: request, now: now)!
        precondition(!String(data: encoded(safe), encoding: .utf8)!.contains(secret))
        precondition(safe["messages"] == nil && safe["env"] == nil && safe["client_build"] == nil && safe["client_team_identifier"] == nil)
        precondition(!GuestChatDiagnosticsSchema.collectionReceipt(bad).contains(secret))

        // The manual profile accepts a completed 35-second collection inside the
        // unchanged 60-second request lifetime, with explicit phase budgets/statuses.
        var manual = report
        manual["request_id"] = manualRequest.requestID.uuidString
        manual["request_created_utc"] = GuestChatDiagnosticsSchema.utc(manualRequest.created)
        manual["request_expires_utc"] = GuestChatDiagnosticsSchema.utc(manualRequest.expires)
        manual["collected_utc"] = GuestChatDiagnosticsSchema.utc(now.addingTimeInterval(35))
        manual["collection_mode"] = "manual"
        manual["collection_elapsed_ms"] = 35_000
        manual["collection_budget_ms"] = 35_000
        manual["collection_effective_budget_ms"] = 35_000
        manual["log_command_budget_ms"] = 30_000
        manual["log_command_effective_budget_ms"] = 30_000
        manual["log_command_elapsed_ms"] = 30_000
        manual["log_command_status"] = "complete"
        manual["log_command_started"] = true
        manual["log_command_exit_code"] = 0
        manual["signature_display_budget_ms"] = 3_000
        manual["signature_display_effective_budget_ms"] = 3_000
        manual["signature_display_status"] = "complete"
        manual["signature_display_elapsed_ms"] = 500
        manual["signature_verify_budget_ms"] = 0
        manual["signature_verify_status"] = "not_requested"
        manual["signature_verify_elapsed_ms"] = 0
        manual["client_signature_check"] = "not_verified"
        manual["electron_framework_metadata_status"] = "complete"
        manual["electron_framework_version"] = "42.0.0-beta.2"
        let afterCollection = now.addingTimeInterval(36)
        precondition(manual.count <= 96 && encoded(manual).count <= 16_384)
        let extended = GuestChatDiagnosticsSchema.canonicalReport(encoded(manual), request: manualRequest, now: afterCollection)!
        precondition(extended["collection_elapsed_ms"] as? Int == 35_000 && extended["collection_budget_ms"] as? Int == 35_000)
        precondition(extended["client_signature_check"] as? String == "not_verified")
        precondition(extended["electron_framework_version"] as? String == "42.0.0-beta.2")
        let manualReceipt = GuestChatDiagnosticsSchema.collectionReceipt(extended)
        precondition(manualReceipt.contains("collection_mode=manual") && manualReceipt.contains("log_command_budget_ms=30000"))
        precondition(manualReceipt.contains("signature_verify_status=not_requested") && manualReceipt.contains("electron_framework_version=42.0.0-beta.2"))
        precondition(GuestChatDiagnosticsSchema.canonicalReport(encoded(manual), request: manualRequest, now: now.addingTimeInterval(61)) == nil)
        for (key, invalid) in [("collection_mode", "automatic" as Any), ("collection_mode", true),
                              ("collection_budget_ms", 35_001), ("collection_effective_budget_ms", 35_001),
                              ("log_command_budget_ms", 8_000), ("log_command_effective_budget_ms", 30_001),
                              ("signature_display_budget_ms", 3_001), ("signature_display_effective_budget_ms", 3_001),
                              ("signature_verify_budget_ms", 1), ("signature_verify_elapsed_ms", 1),
                              ("collection_elapsed_ms", 60_001), ("log_command_elapsed_ms", true),
                              ("client_signature_check", "valid_main_bundle"), ("signature_verify_status", "complete"),
                              ("electron_framework_metadata_status", "not_found"), ("electron_framework_version", secret)] {
            bad = manual; bad[key] = invalid
            precondition(GuestChatDiagnosticsSchema.canonicalReport(encoded(bad), request: manualRequest, now: afterCollection) == nil,
                         "accepted invalid manual/metadata field: \(key)")
        }
        bad = manual; bad["log_command_effective_budget_ms"] = nil
        precondition(GuestChatDiagnosticsSchema.canonicalReport(encoded(bad), request: manualRequest, now: afterCollection) == nil)
        bad = manual; bad["electron_framework_version"] = nil
        precondition(GuestChatDiagnosticsSchema.canonicalReport(encoded(bad), request: manualRequest, now: afterCollection) == nil)
        bad = manual; bad["electron_framework_metadata_status"] = "not_found"; bad["electron_framework_version"] = nil
        precondition(GuestChatDiagnosticsSchema.canonicalReport(encoded(bad), request: manualRequest, now: afterCollection) != nil)
        bad = manual; bad["collection_effective_budget_ms"] = 2_000; bad["log_command_effective_budget_ms"] = 2_000
        bad["signature_display_effective_budget_ms"] = 0
        precondition(GuestChatDiagnosticsSchema.canonicalReport(encoded(bad), request: manualRequest, now: afterCollection) != nil)
        // A new helper must not label a zero-event timeout as a healthy empty query.
        var manualTimeout = manual
        for key in GuestChatDiagnosticsSchema.countKeys { manualTimeout[key] = 0 }
        for key in ["log_event_count", "matched_event_count", "chatgpt_matched_event_count",
                    "system_devicecheck_matched_event_count", "unknown_source_matched_event_count"] { manualTimeout[key] = 0 }
        manualTimeout["collection_status"] = "partial"; manualTimeout["log_status"] = "timed_out"
        manualTimeout["log_counts_status"] = "unavailable"; manualTimeout["log_command_status"] = "timed_out"
        manualTimeout["classification"] = "logs_unavailable"; manualTimeout["log_command_exit_code"] = nil
        manualTimeout["log_command_termination_signal"] = 9
        let missingManual = GuestChatDiagnosticsSchema.canonicalReport(encoded(manualTimeout), request: manualRequest, now: afterCollection)!
        precondition(GuestChatDiagnosticsSchema.collectionMessage(missingManual).contains("could not be determined"))
        manualTimeout["classification"] = "no_known_error_observed"
        precondition(GuestChatDiagnosticsSchema.canonicalReport(encoded(manualTimeout), request: manualRequest, now: afterCollection) == nil)
        bad = manual; bad["electron_framework_version"] = secret; bad["collection_mode"] = secret
        precondition(!GuestChatDiagnosticsSchema.collectionReceipt(bad).contains(secret))
        precondition(GuestChatDiagnosticsSchema.canonicalReport(Data(repeating: 32, count: 16385), request: request, now: now) == nil)
        let heartbeat: [String: Any] = ["schema_version": 1, "collector_version": 1,
            "vm_session_id": request.sessionID.uuidString, "seen_utc": GuestChatDiagnosticsSchema.utc(now)]
        precondition(GuestChatDiagnosticsSchema.ready(encoded(heartbeat), session: request.sessionID, now: now))
        precondition(GuestChatDiagnosticsSchema.ready(encoded(heartbeat), session: request.sessionID, now: now.addingTimeInterval(35)))
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
