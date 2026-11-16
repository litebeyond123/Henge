import Foundation
import CoreFoundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

extension Notification.Name {
    static let hengeGuestChatDiagnosticsDidUpdate = Notification.Name("HengeGuestChatDiagnosticsUpdated")
}

struct GuestChatReadiness: Equatable {
    enum State: String { case ready, missing_or_unreadable, invalid, version_mismatch, other_session, stale, clock_ahead }
    let state: State
    let ageSeconds: Int?
    var explanation: String {
        switch state {
        case .ready: return "The diagnostic heartbeat is current."
        case .missing_or_unreadable: return "No diagnostic heartbeat has been received."
        case .invalid: return "The diagnostic heartbeat could not be validated."
        case .version_mismatch: return "The diagnostic protocol version differs."
        case .other_session: return "The diagnostic heartbeat belongs to a different Mac session."
        case .stale: return "The diagnostic heartbeat has expired."
        case .clock_ahead: return "The Mac heartbeat time is ahead of the iPad clock."
        }
    }
}

/// The guest can submit only a small, typed summary. Shared files are untrusted input.
enum GuestChatDiagnosticsSchema {
    enum CollectionMode: String {
        case automatic, manual
        var budgets: (collection: Int, log: Int, display: Int) {
            self == .manual ? (35_000, 30_000, 3_000) : (10_000, 8_000, 1_500)
        }
    }
    static let maximumManualWait: TimeInterval = 45
    static let electronVersionPattern = "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,6}(-(alpha|beta|rc|nightly)\\.[0-9]{1,12})?"
    struct Request {
        let sessionID: UUID
        let requestID: UUID
        let created: Date
        let expires: Date
        let collect: Bool
        let collectionMode: CollectionMode
        init(sessionID: UUID, now: Date = Date(), collect: Bool = true, collectionMode: CollectionMode = .automatic) {
            self.sessionID = sessionID
            requestID = UUID()
            self.collect = collect
            self.collectionMode = collect ? collectionMode : .automatic
            // New helpers use the explicit Bool; the old timestamp also keeps
            // an older helper from collecting under ordinary clock drift.
            let start = collect ? now : now.addingTimeInterval(-86_400)
            created = Date(timeIntervalSince1970: floor(start.timeIntervalSince1970))
            expires = created.addingTimeInterval(60)
        }
        var dictionary: [String: Any] {
            ["schema_version": 1, "task": "chat_error_summary", "vm_session_id": sessionID.uuidString,
             "request_id": requestID.uuidString, "created_utc": utc(created), "expires_utc": utc(expires), "collect": collect,
             "collection_mode": collectionMode.rawValue]
        }
    }

    static let countKeys = [
        "error_devicecheck_unsupported_count", "error_devicecheck_token_unavailable_count",
        "error_devicecheck_other_count", "error_network_timeout_count", "error_network_offline_count",
        "error_network_connection_lost_count", "error_network_tls_count", "error_http_401_count",
        "error_http_403_count", "error_http_429_count", "error_http_5xx_count", "error_request_failed_count"
    ]
    static func utc(_ date: Date) -> String { ISO8601DateFormatter().string(from: date) }
    static func date(_ value: Any?) -> Date? {
        guard let value = value as? String, value.utf8.count <= 40 else { return nil }
        let formatter = ISO8601DateFormatter()
        if let date = formatter.date(from: value) { return date }
        formatter.formatOptions.insert(.withFractionalSeconds)
        return formatter.date(from: value)
    }
    static func integer(_ value: Any?, maximum: Int) -> Int? {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
              number.doubleValue.isFinite, number.doubleValue >= 0, number.doubleValue <= Double(maximum),
              number.doubleValue.rounded(.towardZero) == number.doubleValue else { return nil }
        return number.intValue
    }
    static func string(_ value: Any?, pattern: String, limit: Int) -> String? {
        guard let value = value as? String, value.utf8.count <= limit,
              let range = value.range(of: "\\A(?:" + pattern + ")\\z", options: .regularExpression),
              range == value.startIndex..<value.endIndex else { return nil }
        return value
    }
    static func choice(_ value: Any?, _ choices: [String]) -> String? {
        guard let value = value as? String, choices.contains(value) else { return nil }
        return value
    }
    static let commandStatuses = ["complete", "timed_out", "output_limit", "not_run_budget", "launch_failed", "exit_nonzero", "read_failed"]

    /// Rebuild rather than redact the input. No guest-provided free text is retained.
    static func canonicalReport(_ data: Data, request: Request, now: Date = Date()) -> [String: Any]? {
        guard request.collect, data.count <= 16_384, now <= request.expires,
              let raw = try? JSONSerialization.jsonObject(with: data) as? [String: Any], raw.count <= 96,
              integer(raw["schema_version"], maximum: 1) == 1,
              integer(raw["collector_version"], maximum: 1) == 1,
              (raw["request_id"] as? String).flatMap(UUID.init(uuidString:)) == request.requestID,
              (raw["vm_session_id"] as? String).flatMap(UUID.init(uuidString:)) == request.sessionID,
              date(raw["request_created_utc"]) == request.created,
              date(raw["request_expires_utc"]) == request.expires,
              let collected = date(raw["collected_utc"]), collected >= request.created.addingTimeInterval(-2),
              collected <= request.expires, collected <= now.addingTimeInterval(30),
              let status = choice(raw["collection_status"], ["complete", "partial"]),
              let logStatus = choice(raw["log_status"], ["complete", "unavailable", "timed_out", "output_limit", "not_run_budget"]),
              let classification = choice(raw["classification"], ["devicecheck_unavailable_observed", "devicecheck_error_observed",
                  "network_error_observed", "http_error_observed", "request_error_observed", "no_known_error_observed", "logs_unavailable"]),
              let signatureKind = choice(raw["client_signature_kind"], ["unavailable", "signed", "adhoc"]),
              let signatureCheck = choice(raw["client_signature_check"], ["not_found", "valid_main_bundle", "timed_out", "not_verified"]),
              let architecture = choice(raw["architecture"], ["arm64", "arm64e", "x86_64", "unknown"]),
              let found = raw["client_found"] as? NSNumber, CFGetTypeID(found) == CFBooleanGetTypeID(),
              integer(raw["log_window_seconds"], maximum: 900) == 900,
              let elapsed = integer(raw["collection_elapsed_ms"], maximum: raw["collection_mode"] as? String == "manual" ? 60_000 : 30_000),
              let events = integer(raw["log_event_count"], maximum: 50_000),
              let matched = integer(raw["matched_event_count"], maximum: events),
              raw["source_scope"] as? String == "mixed_chatgpt_device_services",
              let chatMatches = integer(raw["chatgpt_matched_event_count"], maximum: matched),
              let systemMatches = integer(raw["system_devicecheck_matched_event_count"], maximum: matched),
              let unknownMatches = integer(raw["unknown_source_matched_event_count"], maximum: matched),
              chatMatches + systemMatches + unknownMatches == matched,
              (status == "complete") == (logStatus == "complete") else { return nil }
        // Older v1 helpers discarded all log output on timeout. Normalize their
        // default zero counters to unavailable, while accepting the newer v1
        // extension that preserves complete events from an interrupted query.
        let countsStatus: String
        if let rawCounts = raw["log_counts_status"] {
            guard let value = choice(rawCounts, ["complete", "partial", "unavailable"]) else { return nil }
            countsStatus = value
        } else {
            countsStatus = logStatus == "complete" ? "complete" : "unavailable"
        }
        switch countsStatus {
        case "complete":
            guard logStatus == "complete" else { return nil }
        case "partial":
            guard logStatus != "complete", events > 0 else { return nil }
        default:
            guard logStatus != "complete", events == 0, matched == 0 else { return nil }
        }
        var result: [String: Any] = [
            "schema_version": 1, "collector_version": 1, "request_id": request.requestID.uuidString,
            "vm_session_id": request.sessionID.uuidString, "request_created_utc": utc(request.created),
            "request_expires_utc": utc(request.expires), "collected_utc": utc(collected), "host_received_utc": utc(now),
            "host_collection_status": "complete", "data_freshness": "completed_request_snapshot",
            "collection_status": status, "log_status": logStatus, "log_counts_status": countsStatus, "classification": classification,
            "log_window_seconds": 900, "log_event_count": events, "matched_event_count": matched,
            "collection_elapsed_ms": elapsed, "privacy_mode": "error_categories_only", "client_found": found.boolValue,
            "architecture": architecture, "client_signature_kind": signatureKind, "client_signature_check": signatureCheck
        ]
        result["source_scope"] = "mixed_chatgpt_device_services"
        result["chatgpt_matched_event_count"] = chatMatches
        result["system_devicecheck_matched_event_count"] = systemMatches
        result["unknown_source_matched_event_count"] = unknownMatches
        for key in countKeys {
            guard let count = integer(raw[key], maximum: matched) else { return nil }
            result[key] = count
        }
        let counts = countKeys.map { result[$0] as! Int }
        guard counts.reduce(0, +) >= matched else { return nil }
        let expectedClassification: String
        if counts[0] > 0 || counts[1] > 0 { expectedClassification = "devicecheck_unavailable_observed" }
        else if counts[2] > 0 { expectedClassification = "devicecheck_error_observed" }
        else if counts[3...6].contains(where: { $0 > 0 }) { expectedClassification = "network_error_observed" }
        else if counts[7...10].contains(where: { $0 > 0 }) { expectedClassification = "http_error_observed" }
        else if counts[11] > 0 { expectedClassification = "request_error_observed" }
        else { expectedClassification = countsStatus == "complete" ? "no_known_error_observed" : "logs_unavailable" }
        guard classification == expectedClassification else { return nil }

        // Optional bounded phase fields preserve compatibility with the prior
        // helper. Unknown/free-text fields are never copied into the report.
        let phaseChoices: [(String, [String])] = [
            ("log_command_status", commandStatuses), ("metadata_status", ["complete", "partial"]),
            ("signature_display_status", commandStatuses + ["not_found"]),
            ("signature_verify_status", commandStatuses + ["not_found", "not_requested"])
        ]
        for (key, choices) in phaseChoices {
            if let rawValue = raw[key] {
                guard let value = choice(rawValue, choices) else { return nil }
                result[key] = value
            }
        }
        for key in ["log_command_elapsed_ms", "metadata_elapsed_ms", "signature_display_elapsed_ms", "signature_verify_elapsed_ms"] {
            if let rawValue = raw[key] {
                guard let value = integer(rawValue, maximum: raw["collection_mode"] as? String == "manual" ? 60_000 : 30_000) else { return nil }
                result[key] = value
            }
        }
        let budgetKeys = ["collection_budget_ms", "collection_effective_budget_ms", "log_command_budget_ms",
                          "log_command_effective_budget_ms", "signature_display_budget_ms",
                          "signature_display_effective_budget_ms", "signature_verify_budget_ms"]
        if raw["collection_mode"] != nil || budgetKeys.contains(where: { raw[$0] != nil }) {
            guard let mode = (raw["collection_mode"] as? String).flatMap(CollectionMode.init(rawValue:)),
                  mode == request.collectionMode else { return nil }
            let budgets = mode.budgets
            let expected = ["collection_budget_ms": budgets.collection, "log_command_budget_ms": budgets.log,
                            "signature_display_budget_ms": budgets.display, "signature_verify_budget_ms": 0]
            for (key, maximum) in expected {
                guard integer(raw[key], maximum: maximum) == maximum else { return nil }
                result[key] = maximum
            }
            guard let effective = integer(raw["collection_effective_budget_ms"], maximum: budgets.collection),
                  let log = integer(raw["log_command_effective_budget_ms"], maximum: min(budgets.log, effective)),
                  let display = integer(raw["signature_display_effective_budget_ms"], maximum: min(budgets.display, effective)) else { return nil }
            result["collection_mode"] = mode.rawValue
            result["collection_effective_budget_ms"] = effective
            result["log_command_effective_budget_ms"] = log
            result["signature_display_effective_budget_ms"] = display
            // Test11 does not duplicate the launcher's validation in the collector.
            // Metadata display must never be promoted to a verified signature.
            guard signatureCheck == (found.boolValue ? "not_verified" : "not_found"),
                  result["signature_verify_status"] as? String == (found.boolValue ? "not_requested" : "not_found"),
                  result["signature_verify_elapsed_ms"] as? Int == 0 else { return nil }
        }
        if let rawStatus = raw["electron_framework_metadata_status"] {
            guard let metadataStatus = choice(rawStatus, ["complete", "not_found", "unavailable", "invalid"]) else { return nil }
            result["electron_framework_metadata_status"] = metadataStatus
            if metadataStatus == "complete" {
                guard let version = string(raw["electron_framework_version"], pattern: electronVersionPattern, limit: 48) else { return nil }
                result["electron_framework_version"] = version
            } else if raw["electron_framework_version"] != nil { return nil }
        } else if raw["electron_framework_version"] != nil { return nil }
        if let started = raw["log_command_started"] {
            guard let value = started as? NSNumber, CFGetTypeID(value) == CFBooleanGetTypeID() else { return nil }
            result["log_command_started"] = value.boolValue
        }
        for (key, maximum) in [("log_command_exit_code", 255), ("log_command_termination_signal", 31)] {
            if let rawValue = raw[key] {
                guard let value = integer(rawValue, maximum: maximum),
                      key != "log_command_termination_signal" || value > 0 else { return nil }
                result[key] = value
            }
        }
        guard result["log_command_exit_code"] == nil || result["log_command_termination_signal"] == nil else { return nil }
        if let command = result["log_command_status"] as? String {
            let expectedLogStatus = ["timed_out", "output_limit", "not_run_budget"].contains(command) ? command : "unavailable"
            guard command == "complete" ? ["complete", "unavailable"].contains(logStatus) : logStatus == expectedLogStatus else { return nil }
            if command == "complete" {
                guard result["log_command_termination_signal"] == nil,
                      result["log_command_exit_code"] == nil || result["log_command_exit_code"] as? Int == 0 else { return nil }
            }
            if let started = result["log_command_started"] as? Bool {
                guard started == !["not_run_budget", "launch_failed"].contains(command) else { return nil }
            }
            if command == "not_run_budget" || command == "launch_failed" {
                guard events == 0, result["log_command_exit_code"] == nil, result["log_command_termination_signal"] == nil else { return nil }
            }
        }
        let fields: [(String, String, Int)] = [
            ("os_version", "[0-9]{1,3}(\\.[0-9]{1,6}){0,5}", 40),
            ("os_build", "[0-9]{1,3}[A-Z][0-9]{1,8}[a-z]?", 20),
            ("hardware_model", "[A-Za-z]{1,32}[0-9]{1,3},[0-9]{1,3}", 40),
            ("client_bundle_id", "[A-Za-z][A-Za-z0-9-]{0,40}(\\.[A-Za-z0-9-]{1,40}){1,5}", 128),
            ("client_executable", "[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}", 64),
            ("client_version", "[0-9]{1,12}(\\.[0-9]{1,12}){0,5}([a-z][0-9]{0,4})?", 64),
            ("client_build", "[0-9]{1,12}(\\.[0-9]{1,12}){0,5}([a-z][0-9]{0,4})?", 64),
            ("client_team_identifier", "[A-Z0-9]{10}", 10)
        ]
        for (key, pattern, limit) in fields {
            if let value = string(raw[key], pattern: pattern, limit: limit) { result[key] = value }
        }
        for key in ["first_match_utc", "last_match_utc"] {
            if let date = date(raw[key]), date >= collected.addingTimeInterval(-930), date <= collected.addingTimeInterval(1) {
                result[key] = utc(date)
            }
        }
        return result
    }

    /// Collection completeness is separate from the outcome of native Chat.
    static func collectionMessage(_ report: [String: Any]?) -> String {
        let status = report?["log_counts_status"] as? String
        let matched = integer(report?["matched_event_count"], maximum: 50_000) ?? 0
        if status == "complete" {
            return matched > 0
                ? "Mac error summary included. No raw messages or credentials are included."
                : "The Mac log query completed without a recognized error in its window. Chat functionality still needs verification."
        }
        if status == "partial" {
            return matched > 0
                ? "Partial Mac error summary included. Errors read before the query stopped were preserved; counts cover only the collected events."
                : "Only part of the Mac logs was collected. Chat status could not be determined from that incomplete result."
        }
        return "Mac metadata included; usable log results were unavailable. Error counts and Chat status could not be determined."
    }

    /// One fixed receipt per accepted request preserves earlier observations in
    /// the combined run log even when a later snapshot is incomplete.
    static func collectionReceipt(_ report: [String: Any]) -> String {
        let request = (report["request_id"] as? String).flatMap(UUID.init(uuidString:))?.uuidString.prefix(8) ?? "unknown"
        let collected = date(report["collected_utc"]).map(utc) ?? "unavailable"
        let status = choice(report["collection_status"], ["complete", "partial"]) ?? "unavailable"
        let availability = choice(report["log_counts_status"], ["complete", "partial", "unavailable"]) ?? "unavailable"
        let classification = choice(report["classification"], ["devicecheck_unavailable_observed", "devicecheck_error_observed",
            "network_error_observed", "http_error_observed", "request_error_observed", "no_known_error_observed", "logs_unavailable"]) ?? "logs_unavailable"
        let command = choice(report["log_command_status"], commandStatuses) ?? "legacy_unreported"
        var fields = ["result=\(status)", "request=\(request)", "collected_utc=\(collected)",
                      "log_counts_status=\(availability)", "classification=\(classification)", "log_command_status=\(command)"]
        if let mode = choice(report["collection_mode"], ["automatic", "manual"]) { fields.append("collection_mode=\(mode)") }
        for (key, choices) in [("metadata_status", ["complete", "partial"]),
                              ("signature_display_status", commandStatuses + ["not_found"]),
                              ("signature_verify_status", commandStatuses + ["not_found", "not_requested"]),
                              ("electron_framework_metadata_status", ["complete", "not_found", "unavailable", "invalid"])] {
            if let value = choice(report[key], choices) { fields.append("\(key)=\(value)") }
        }
        if let version = string(report["electron_framework_version"], pattern: electronVersionPattern, limit: 48) {
            fields.append("electron_framework_version=\(version)")
        }
        for key in ["collection_elapsed_ms", "log_command_elapsed_ms", "log_event_count", "matched_event_count",
                    "metadata_elapsed_ms", "signature_display_elapsed_ms", "signature_verify_elapsed_ms",
                    "collection_budget_ms", "collection_effective_budget_ms", "log_command_budget_ms", "log_command_effective_budget_ms",
                    "signature_display_budget_ms", "signature_display_effective_budget_ms", "signature_verify_budget_ms",
                    "chatgpt_matched_event_count", "system_devicecheck_matched_event_count", "unknown_source_matched_event_count"] + countKeys {
            if let value = integer(report[key], maximum: 60_000) { fields.append("\(key)=\(value)") }
        }
        return fields.joined(separator: " ")
    }

    static func ready(_ data: Data, session: UUID, now: Date = Date()) -> Bool {
        readiness(data, session: session, now: now).state == .ready
    }

    static func readiness(_ data: Data?, session: UUID, now: Date = Date()) -> GuestChatReadiness {
        guard let data else { return .init(state: .missing_or_unreadable, ageSeconds: nil) }
        guard data.count <= 4096, let raw = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let schema = integer(raw["schema_version"], maximum: 65535),
              let collector = integer(raw["collector_version"], maximum: 65535),
              let identifier = (raw["vm_session_id"] as? String).flatMap(UUID.init(uuidString:)),
              let seen = date(raw["seen_utc"]) else { return .init(state: .invalid, ageSeconds: nil) }
        guard schema == 1 && collector == 1 else { return .init(state: .version_mismatch, ageSeconds: nil) }
        guard identifier == session else { return .init(state: .other_session, ageSeconds: nil) }
        let age = now.timeIntervalSince(seen)
        let boundedAge = Int(min(max(age, -2_147_483_648), 2_147_483_647))
        if age < -30 { return .init(state: .clock_ahead, ageSeconds: boundedAge) }
        if age > 45 { return .init(state: .stale, ageSeconds: boundedAge) }
        return .init(state: .ready, ageSeconds: boundedAge)
    }
}

/// O_NOFOLLOW + bounded reads protect against a shared file being replaced or grown after stat.
enum GuestChatDiagnosticsFiles {
    @discardableResult static func remove(directory: URL, name: String) -> Bool {
        let fd = open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        return unlinkat(fd, name, 0) == 0 || errno == ENOENT
    }
    static func read(directory: URL, name: String, limit: Int) -> Data? {
        let directoryFD = open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directoryFD >= 0 else { return nil }
        defer { close(directoryFD) }
        let fd = openat(directoryFD, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG, info.st_size >= 0, info.st_size <= limit else { return nil }
        var data = Data(), bytes = [UInt8](repeating: 0, count: 4096)
        while true {
            let count = bytes.withUnsafeMutableBytes { buffer in
                #if canImport(Darwin)
                return Darwin.read(fd, buffer.baseAddress, min(buffer.count, limit + 1 - data.count))
                #else
                return Glibc.read(fd, buffer.baseAddress, min(buffer.count, limit + 1 - data.count))
                #endif
            }
            if count < 0 && errno == EINTR { continue }
            if count < 0 { return nil }
            if count == 0 { return data }
            data.append(contentsOf: bytes.prefix(count))
            if data.count > limit { return nil }
        }
    }
    @discardableResult static func write(_ data: Data, directory: URL, name: String, executable: Bool = false) -> Bool {
        let directoryFD = open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directoryFD >= 0 else { return false }
        defer { close(directoryFD) }
        let temporary = ".henge-chat-" + UUID().uuidString
        let fd = openat(directoryFD, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, executable ? 0o755 : 0o600)
        guard fd >= 0 else { return false }
        defer { close(fd); unlinkat(directoryFD, temporary, 0) }
        let success = data.withUnsafeBytes { buffer -> Bool in
            var written = 0
            while written < buffer.count {
                #if canImport(Darwin)
                let count = Darwin.write(fd, buffer.baseAddress!.advanced(by: written), buffer.count - written)
                #else
                let count = Glibc.write(fd, buffer.baseAddress!.advanced(by: written), buffer.count - written)
                #endif
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { return false }
                written += count
            }
            return true
        }
        return success && fsync(fd) == 0 && renameat(directoryFD, temporary, directoryFD, name) == 0
    }
}

/// Readable from the diagnostic writer's queue without crossing the UI actor.
enum GuestChatDiagnosticsPersistence {
    private static let lock = NSLock()
    private static var value = "not_updated"
    static var status: String { lock.lock(); defer { lock.unlock() }; return value }
    @discardableResult static func set(_ next: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        let changed = value != next; value = next; return changed
    }
}

#if canImport(UIKit)
import UIKit

@MainActor enum GuestChatDiagnostics {
    private static let fileManager = FileManager.default
    private static var session: UUID?
    private static var request: GuestChatDiagnosticsSchema.Request?
    private static var imported: UUID?
    private static var lastSafeReport: [String: Any]?
    private static var monitor: Task<Void, Never>?
    private static var refreshing = false
    private static var requestedAfterReady = false
    private static var nextAutomaticRequest: TimeInterval = 0
    private static var memoryPauseUntil: TimeInterval = 0
    private static var loggedAutomaticPause: String?
    private static var folder: URL { Sharing.folder.appendingPathComponent("Henge-Chat-Diagnostics", isDirectory: true) }
    private static var inputFolder: URL {
        fileManager.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("HengeDiagnostics/Inputs", isDirectory: true)
    }

    /// Each VM start rotates the identifier. Old requests/results cannot enter this session's report.
    static func prepare() {
        monitor?.cancel()
        session = UUID(); request = nil; imported = nil; lastSafeReport = nil; requestedAfterReady = false
        loggedAutomaticPause = nil
        nextAutomaticRequest = ProcessInfo.processInfo.systemUptime + 120
        try? fileManager.createDirectory(at: folder, withIntermediateDirectories: true)
        try? fileManager.createDirectory(at: inputFolder, withIntermediateDirectories: true)
        if let url = Bundle.main.url(forResource: "guest-chat-diagnostics", withExtension: "command"),
           let data = try? Data(contentsOf: url) {
            GuestChatDiagnosticsFiles.write(data, directory: folder, name: "Enable Chat Diagnostics.command", executable: true)
        }
        let webloc = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict><key>URL</key><string>https://chatgpt.com/</string></dict></plist>\n"
        GuestChatDiagnosticsFiles.write(Data(webloc.utf8), directory: folder, name: "ChatGPT in Browser.webloc")
        let help = "Details > Sharing shows the helper connection and the latest installer receipt separately. An absent heartbeat does not determine whether the helper is installed.\nTo install, update or repair: focus Terminal in the Mac, then tap Details > Sharing > Type Install / Repair Command. Return to Terminal, wait until the entire command has finished typing, then press Return. The result appears in Henge automatically. Allow local networking if macOS asks. No VM rebuild is needed.\nUse Collect Chat diagnostics in Henge for a fresh combined report. Background guest checks wait until startup settles and pause during heat or recent memory pressure.\nEnable Chat Diagnostics.command is an optional installer; WebDAV volumes may prevent double-click execution. The Terminal procedure above is available in that case.\nNo conversation databases, cookies, tokens, keychain, full environment or raw log messages are exported.\nSystem DeviceCheck messages are counted separately and do not prove that ChatGPT requested them. This summary does not generate a DeviceCheck token.\nThe browser shortcut opens https://chatgpt.com/ as an alternative; it does not repair the native app.\n"
        GuestChatDiagnosticsFiles.write(Data(help.utf8), directory: folder, name: "Read Me.txt")
        // collect:false explicitly prohibits executing the session/heartbeat
        // probe, independent of the guest clock. The old expiry aids old helpers.
        _ = makeRequest(collect: false)
        writeState("waiting_for_helper")
        let thisSession = session
        monitor = Task { @MainActor in
            var sawRunning = false
            let startupDeadline = ProcessInfo.processInfo.systemUptime + 120
            while !Task.isCancelled && session == thisSession {
                let state = henge_vm_state()
                if state == 1 || state == 3 { sawRunning = true }
                if (sawRunning && state != 1 && state != 3) || ProcessInfo.processInfo.systemUptime > startupDeadline && !sawRunning {
                    // The request must not run after this VM ends. Keep the already captured summary labelled stale.
                    invalidateRequest()
                    break
                }
                if !requestedAfterReady && isReady() {
                    requestedAfterReady = true
                    if lastSafeReport == nil {
                        writeState((request?.expires.timeIntervalSinceNow ?? 0) > 0 ? "pending" : "connected")
                    }
                }
                _ = importAvailable()
                let pause = automaticPauseReason()
                if pause != loggedAutomaticPause {
                    loggedAutomaticPause = pause
                    HengeLog.log("guest-diagnostics", "automatic_collection=\(pause == nil ? "available" : "paused") reason=\(pause ?? "none")")
                }
                if state == 1 && UIApplication.shared.applicationState == .active && !refreshing && isReady(),
                   pause == nil,
                   ProcessInfo.processInfo.systemUptime >= nextAutomaticRequest,
                   request == nil || imported == request!.requestID || request!.expires <= Date() {
                    if makeRequest() { writeState("pending") }
                    nextAutomaticRequest = ProcessInfo.processInfo.systemUptime + 120
                }
                try? await Task.sleep(nanoseconds: 500_000_000)
            }
        }
    }

    private static func makeRequest(collect: Bool = true, collectionMode: GuestChatDiagnosticsSchema.CollectionMode = .automatic) -> Bool {
        guard let session else { return false }
        let next = GuestChatDiagnosticsSchema.Request(sessionID: session, collect: collect, collectionMode: collectionMode)
        guard let data = try? JSONSerialization.data(withJSONObject: next.dictionary, options: [.sortedKeys]),
              GuestChatDiagnosticsFiles.write(data, directory: folder, name: "request.json") else { return false }
        request = next; imported = nil
        HengeLog.log("guest-diagnostics", "request=\(collect ? "collection" : "heartbeat_only") collection_mode=\(next.collectionMode.rawValue)")
        return true
    }

    private static func invalidateRequest() {
        request = nil
        GuestChatDiagnosticsFiles.write(Data("{}\n".utf8), directory: folder, name: "request.json")
        writeState("stale")
    }

    private static func isReady() -> Bool {
        readiness().state == .ready
    }

    private static func readiness() -> GuestChatReadiness {
        guard let session else { return .init(state: .missing_or_unreadable, ageSeconds: nil) }
        let data = GuestChatDiagnosticsFiles.read(directory: folder, name: "agent-status.json", limit: 4096)
        return GuestChatDiagnosticsSchema.readiness(data, session: session)
    }

    static func pauseAutomaticCollectionAfterMemoryWarning() {
        memoryPauseUntil = ProcessInfo.processInfo.systemUptime + 120
    }

    private static func automaticPauseReason() -> String? {
        if ProcessInfo.processInfo.systemUptime < memoryPauseUntil { return "recent_memory_warning" }
        if ProcessInfo.processInfo.thermalState.rawValue >= ProcessInfo.ThermalState.serious.rawValue { return "thermal" }
        return nil
    }

    @discardableResult private static func save(_ value: [String: Any]) -> Bool {
        let data = try? JSONSerialization.data(withJSONObject: value, options: [.prettyPrinted, .sortedKeys])
        if let data, data.count <= 16_384,
           GuestChatDiagnosticsFiles.write(data, directory: inputFolder, name: "guest-chat.json") {
            GuestChatDiagnosticsPersistence.set("updated")
            return true
        }
        let code = errno == 0 ? EIO : errno
        let removed = GuestChatDiagnosticsFiles.remove(directory: inputFolder, name: "guest-chat.json")
        let status = "summary_write_failed errno=\(code) previous_summary_\(removed ? "removed" : "not_updated")"
        if GuestChatDiagnosticsPersistence.set(status) {
            HengeLog.log("guest-diagnostics", status)
            NotificationCenter.default.post(name: .hengeGuestChatDiagnosticsDidUpdate, object: nil)
        }
        return false
    }
    private static func writeState(_ state: String) {
        var value = lastSafeReport ?? ["schema_version": 1, "collector_version": 1, "privacy_mode": "error_categories_only"]
        value["host_collection_status"] = state
        value["data_freshness"] = lastSafeReport == nil ? "no_guest_snapshot" : "stale"
        value["host_status_utc"] = GuestChatDiagnosticsSchema.utc(Date())
        if let session { value["active_vm_session_id"] = session.uuidString }
        if let request {
            value["active_request_id"] = request.requestID.uuidString
            value["active_collection_mode"] = request.collectionMode.rawValue
            value["active_collection_budget_ms"] = request.collectionMode.budgets.collection
            value["active_log_budget_ms"] = request.collectionMode.budgets.log
        }
        let heartbeat = readiness(), health = Sharing.helperHealth
        value["diagnostic_heartbeat_state"] = heartbeat.state.rawValue
        if let age = heartbeat.ageSeconds { value["diagnostic_heartbeat_age_seconds"] = age }
        value["helper_connected"] = health.isConnected
        value["helper_install_stage"] = health.install.rawValue
        value["helper_install_error"] = health.installError.rawValue
        value["automatic_collection_pause"] = automaticPauseReason() ?? "none"
        _ = save(value)
    }

    @discardableResult private static func importAvailable() -> Bool {
        guard let request, request.sessionID == session, imported != request.requestID,
              let data = GuestChatDiagnosticsFiles.read(directory: folder, name: "report.json", limit: 16_384),
              let value = GuestChatDiagnosticsSchema.canonicalReport(data, request: request), save(value) else { return false }
        lastSafeReport = value; imported = request.requestID
        HengeLog.log("guest-diagnostics", GuestChatDiagnosticsSchema.collectionReceipt(value))
        NotificationCenter.default.post(name: .hengeGuestChatDiagnosticsDidUpdate, object: nil)
        return true
    }

    /// Main actor stays responsive. The single pending task has a fixed deadline, not arbitrary guest commands.
    static func refresh(timeout: TimeInterval = 45) async -> String {
        guard let activeSession = session, henge_vm_state() == 1 else {
            try? fileManager.createDirectory(at: inputFolder, withIntermediateDirectories: true)
            writeState("not_running")
            return "Mac diagnostics unavailable: start this Mac first. Host diagnostics are ready."
        }
        guard !refreshing else { return "Mac diagnostics is already being collected; host diagnostics are ready." }
        refreshing = true
        defer { refreshing = false }
        let end = ProcessInfo.processInfo.systemUptime + (timeout.isFinite ? min(max(timeout, 0), GuestChatDiagnosticsSchema.maximumManualWait) : 0)
        let reconnectUntil = min(end, ProcessInfo.processInfo.systemUptime + 3)
        if !isReady() { writeState("connecting") }
        while !isReady() && ProcessInfo.processInfo.systemUptime < reconnectUntil && !Task.isCancelled {
            guard session == activeSession, henge_vm_state() == 1 else { return "The Mac session changed while connecting. Host diagnostics are ready." }
            try? await Task.sleep(nanoseconds: 200_000_000)
        }
        guard session == activeSession, henge_vm_state() == 1, !Task.isCancelled else {
            return "The Mac session changed while connecting. Host diagnostics are ready."
        }
        guard isReady() else {
            writeState("helper_unreachable")
            let health = Sharing.helperHealth
            if health.install == .failed || health.install == .rolled_back {
                return "Host diagnostics include the installer failure. Details > Sharing shows its result; collection did not start."
            }
            return health.isConnected
                ? "The helper is connected. \(readiness().explanation) Host diagnostics include this state; guest collection did not start."
                : "The helper has not reconnected yet. Host diagnostics include its connection and installation receipt; guest collection did not start."
        }
        guard makeRequest(collectionMode: .manual), let requested = request else {
            writeState("unavailable")
            return "The Mac diagnostic request could not be saved. Host diagnostics are ready."
        }
        nextAutomaticRequest = ProcessInfo.processInfo.systemUptime + 120
        writeState("pending")
        if GuestChatDiagnosticsPersistence.status.hasPrefix("summary_write_failed") {
            return "Host diagnostics are ready. The Mac summary could not be saved; its previous file was not treated as a new result."
        }
        while ProcessInfo.processInfo.systemUptime < end && !Task.isCancelled {
            guard request?.requestID == requested.requestID, henge_vm_state() == 1 else {
                return "The Mac session changed while collecting. Host diagnostics are ready."
            }
            _ = importAvailable()
            if imported == requested.requestID {
                return GuestChatDiagnosticsSchema.collectionMessage(lastSafeReport)
            }
            try? await Task.sleep(nanoseconds: 200_000_000)
        }
        guard request?.requestID == requested.requestID else {
            return "The Mac session changed while collecting. Host diagnostics are ready."
        }
        writeState("timed_out")
        return "Host diagnostics are ready. The Mac summary is still pending; a late result updates the automatic report."
    }
}
#endif
