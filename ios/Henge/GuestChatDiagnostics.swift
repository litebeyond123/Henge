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

/// The guest can submit only a small, typed summary. Shared files are untrusted input.
enum GuestChatDiagnosticsSchema {
    struct Request {
        let sessionID: UUID
        let requestID: UUID
        let created: Date
        let expires: Date
        init(sessionID: UUID, now: Date = Date()) {
            self.sessionID = sessionID
            requestID = UUID()
            created = Date(timeIntervalSince1970: floor(now.timeIntervalSince1970))
            expires = created.addingTimeInterval(60)
        }
        var dictionary: [String: Any] {
            ["schema_version": 1, "task": "chat_error_summary", "vm_session_id": sessionID.uuidString,
             "request_id": requestID.uuidString, "created_utc": utc(created), "expires_utc": utc(expires)]
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

    /// Rebuild rather than redact the input. No guest-provided free text is retained.
    static func canonicalReport(_ data: Data, request: Request, now: Date = Date()) -> [String: Any]? {
        guard data.count <= 16_384, now <= request.expires,
              let raw = try? JSONSerialization.jsonObject(with: data) as? [String: Any], raw.count <= 64,
              integer(raw["schema_version"], maximum: 1) == 1,
              integer(raw["collector_version"], maximum: 1) == 1,
              (raw["request_id"] as? String).flatMap(UUID.init(uuidString:)) == request.requestID,
              (raw["vm_session_id"] as? String).flatMap(UUID.init(uuidString:)) == request.sessionID,
              date(raw["request_created_utc"]) == request.created,
              date(raw["request_expires_utc"]) == request.expires,
              let collected = date(raw["collected_utc"]), collected >= request.created.addingTimeInterval(-2),
              collected <= request.expires, collected <= now.addingTimeInterval(30),
              let status = choice(raw["collection_status"], ["complete", "partial"]),
              let logStatus = choice(raw["log_status"], ["complete", "unavailable", "timed_out", "output_limit"]),
              let classification = choice(raw["classification"], ["devicecheck_unavailable_observed", "devicecheck_error_observed",
                  "network_error_observed", "http_error_observed", "request_error_observed", "no_known_error_observed", "logs_unavailable"]),
              let signatureKind = choice(raw["client_signature_kind"], ["unavailable", "signed", "adhoc"]),
              let signatureCheck = choice(raw["client_signature_check"], ["not_found", "valid_main_bundle", "timed_out", "not_verified"]),
              let architecture = choice(raw["architecture"], ["arm64", "arm64e", "x86_64", "unknown"]),
              let found = raw["client_found"] as? NSNumber, CFGetTypeID(found) == CFBooleanGetTypeID(),
              integer(raw["log_window_seconds"], maximum: 900) == 900,
              let elapsed = integer(raw["collection_elapsed_ms"], maximum: 30_000),
              let events = integer(raw["log_event_count"], maximum: 50_000),
              let matched = integer(raw["matched_event_count"], maximum: events),
              raw["source_scope"] as? String == "mixed_chatgpt_device_services",
              let chatMatches = integer(raw["chatgpt_matched_event_count"], maximum: matched),
              let systemMatches = integer(raw["system_devicecheck_matched_event_count"], maximum: matched),
              let unknownMatches = integer(raw["unknown_source_matched_event_count"], maximum: matched),
              chatMatches + systemMatches + unknownMatches == matched,
              (logStatus == "complete") == (classification != "logs_unavailable"),
              (status == "complete") == (logStatus == "complete") else { return nil }
        var result: [String: Any] = [
            "schema_version": 1, "collector_version": 1, "request_id": request.requestID.uuidString,
            "vm_session_id": request.sessionID.uuidString, "request_created_utc": utc(request.created),
            "request_expires_utc": utc(request.expires), "collected_utc": utc(collected), "host_received_utc": utc(now),
            "host_collection_status": "complete", "data_freshness": "completed_request_snapshot",
            "collection_status": status, "log_status": logStatus, "classification": classification,
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
        let fields: [(String, String, Int)] = [
            ("os_version", "[0-9]{1,3}(\\.[0-9]{1,6}){0,5}", 40),
            ("os_build", "[0-9]{1,3}[A-Z][0-9]{1,8}[a-z]?", 20),
            ("hardware_model", "[A-Za-z]{1,32}[0-9]{1,3},[0-9]{1,3}", 40),
            ("client_bundle_id", "[A-Za-z][A-Za-z0-9-]{0,40}(\\.[A-Za-z0-9-]{1,40}){1,5}", 128),
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

    static func ready(_ data: Data, session: UUID, now: Date = Date()) -> Bool {
        guard data.count <= 4096, let raw = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              integer(raw["schema_version"], maximum: 1) == 1,
              integer(raw["collector_version"], maximum: 1) == 1,
              (raw["vm_session_id"] as? String).flatMap(UUID.init(uuidString:)) == session,
              let seen = date(raw["seen_utc"]) else { return false }
        return seen.timeIntervalSince(now) <= 30 && now.timeIntervalSince(seen) <= 45
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
    private static var folder: URL { Sharing.folder.appendingPathComponent("Henge-Chat-Diagnostics", isDirectory: true) }
    private static var inputFolder: URL {
        fileManager.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("HengeDiagnostics/Inputs", isDirectory: true)
    }

    /// Each VM start rotates the identifier. Old requests/results cannot enter this session's report.
    static func prepare() {
        monitor?.cancel()
        session = UUID(); imported = nil; lastSafeReport = nil; requestedAfterReady = false
        nextAutomaticRequest = ProcessInfo.processInfo.systemUptime + 120
        try? fileManager.createDirectory(at: folder, withIntermediateDirectories: true)
        try? fileManager.createDirectory(at: inputFolder, withIntermediateDirectories: true)
        if let url = Bundle.main.url(forResource: "guest-chat-diagnostics", withExtension: "command"),
           let data = try? Data(contentsOf: url) {
            GuestChatDiagnosticsFiles.write(data, directory: folder, name: "Enable Chat Diagnostics.command", executable: true)
        }
        let webloc = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict><key>URL</key><string>https://chatgpt.com/</string></dict></plist>\n"
        GuestChatDiagnosticsFiles.write(Data(webloc.utf8), directory: folder, name: "ChatGPT in Browser.webloc")
        let help = "Once for this existing Mac: open Terminal in the Mac, then Henge > running Mac > Details > Sharing > Type the Update Helper Command (or Type the Set Up Command). Return to the focused Terminal and press Return. Choose Allow if macOS asks about local networks. No VM rebuild is needed.\nThen use Collect Chat diagnostics in Henge. The Mac contributes fixed error categories, versions and signature status automatically.\nEnable Chat Diagnostics.command is an optional installer for locations that allow executable scripts; WebDAV volumes may prevent double-click execution. Use the Terminal/setup-button procedure above in that case.\nNo conversation databases, cookies, tokens, keychain, full environment or raw log messages are exported.\nSystem DeviceCheck messages are counted separately and do not prove that ChatGPT requested them. This is a log summary, not a live DeviceCheck capability/token probe.\nThe browser shortcut opens https://chatgpt.com/ as an alternative; it does not repair the native app.\n"
        GuestChatDiagnosticsFiles.write(Data(help.utf8), directory: folder, name: "Read Me.txt")
        _ = makeRequest()
        writeState("not_enabled")
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
                    if request == nil || request!.expires.timeIntervalSinceNow < 20 { _ = makeRequest() }
                    nextAutomaticRequest = ProcessInfo.processInfo.systemUptime + 120
                    writeState("pending")
                }
                _ = importAvailable()
                if state == 1 && UIApplication.shared.applicationState == .active && !refreshing && isReady(),
                   ProcessInfo.processInfo.systemUptime >= nextAutomaticRequest,
                   request == nil || imported == request!.requestID || request!.expires <= Date() {
                    if makeRequest() { writeState("pending") }
                    nextAutomaticRequest = ProcessInfo.processInfo.systemUptime + 120
                }
                try? await Task.sleep(nanoseconds: 500_000_000)
            }
        }
    }

    private static func makeRequest() -> Bool {
        guard let session else { return false }
        let next = GuestChatDiagnosticsSchema.Request(sessionID: session)
        guard let data = try? JSONSerialization.data(withJSONObject: next.dictionary, options: [.sortedKeys]),
              GuestChatDiagnosticsFiles.write(data, directory: folder, name: "request.json") else { return false }
        request = next; imported = nil
        return true
    }

    private static func invalidateRequest() {
        request = nil
        GuestChatDiagnosticsFiles.write(Data("{}\n".utf8), directory: folder, name: "request.json")
        writeState("stale")
    }

    private static func isReady() -> Bool {
        guard let session, let data = GuestChatDiagnosticsFiles.read(directory: folder, name: "agent-status.json", limit: 4096) else { return false }
        return GuestChatDiagnosticsSchema.ready(data, session: session)
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
        if let request { value["active_request_id"] = request.requestID.uuidString }
        _ = save(value)
    }

    @discardableResult private static func importAvailable() -> Bool {
        guard let request, imported != request.requestID,
              let data = GuestChatDiagnosticsFiles.read(directory: folder, name: "report.json", limit: 16_384),
              let value = GuestChatDiagnosticsSchema.canonicalReport(data, request: request), save(value) else { return false }
        lastSafeReport = value; imported = request.requestID
        NotificationCenter.default.post(name: .hengeGuestChatDiagnosticsDidUpdate, object: nil)
        return true
    }

    /// Main actor stays responsive. The single pending task has a fixed deadline, not arbitrary guest commands.
    static func refresh(timeout: TimeInterval = 15) async -> String {
        guard session != nil, henge_vm_state() == 1 else {
            try? fileManager.createDirectory(at: inputFolder, withIntermediateDirectories: true)
            writeState("not_running")
            return "Mac diagnostics unavailable: start this Mac first. Host diagnostics are ready."
        }
        guard isReady() else {
            writeState("not_enabled")
            return "Host diagnostics are ready. Once: focus Terminal in the Mac, tap Details > Sharing > Type the Update Helper Command (or Set Up Command), then press Return in Terminal."
        }
        guard !refreshing else { return "Mac diagnostics is already being collected; host diagnostics are ready." }
        refreshing = true
        defer { refreshing = false }
        guard makeRequest(), let requested = request else {
            writeState("unavailable")
            return "The Mac diagnostic request could not be saved. Host diagnostics are ready."
        }
        nextAutomaticRequest = ProcessInfo.processInfo.systemUptime + 120
        writeState("pending")
        if GuestChatDiagnosticsPersistence.status.hasPrefix("summary_write_failed") {
            return "Host diagnostics are ready. The Mac summary could not be saved; its previous file was not treated as a new result."
        }
        let end = ProcessInfo.processInfo.systemUptime + min(max(timeout, 0), 15)
        while ProcessInfo.processInfo.systemUptime < end && !Task.isCancelled {
            guard request?.requestID == requested.requestID, henge_vm_state() == 1 else {
                return "The Mac session changed while collecting. Host diagnostics are ready."
            }
            _ = importAvailable()
            if imported == requested.requestID {
                return lastSafeReport?["log_status"] as? String == "complete"
                    ? "Mac error summary included. No raw messages or credentials are included."
                    : "Mac metadata included; its unified log query was unavailable or reached its limit."
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
