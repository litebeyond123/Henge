// SPDX-License-Identifier: GPL-2.0-or-later
import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// Export filtering is deliberately separate from capture: the on-device logs
/// remain intact. It removes recognizable secrets, not every possible piece of
/// application content. In particular, this is not a promise of anonymity.
struct DiagnosticLogFilter {
    private let privateRoots: [String]
    private var suppressRemainder = false
    private var inPrivateKey = false
    private(set) var redactedFragments = 0

    init(privateRoots: [String] = []) { self.privateRoots = privateRoots }

    private static let rules: [(NSRegularExpression, String)] = [
        (#"(?i)(\b(?:authorization|proxy-authorization|cookie|set-cookie|access[_-]?token|refresh[_-]?token|id[_-]?token|token|password|passwd|passphrase|client[_-]?secret|pairing[_-]?record|anisette|X-Apple-I-MD(?:-M|-RINFO|-LU)?)\b[\"']?\s*[:=]\s*).*"#, "$1<redacted>"),
        (#"(?i)(\b(?:clipboard|pasteboard|typed[ _-]?text|input[ _-]?text|insertText|setMarkedText|prompt|chat[ _-]?(?:message|content)|message[ _-]?body)\b[\"']?\s*[:=(]\s*).*"#, "$1<content omitted>"),
        (#"(?i)\b[a-z][a-z0-9+.-]{1,24}://[^\s<>\"']*"#, "<url omitted>"),
        (#"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"#, "<email omitted>"),
        (#"(?i)(\b(?:ECID|UDID|serialNumber|serial_number)\s*[:=]?\s+)[A-Z0-9-]+"#, "$1<identifier omitted>"),
        (#"/(?:private/)?var/mobile/Containers/(?:Data|Bundle)/Application/[A-Fa-f0-9-]+"#, "<app-container>"),
        (#"/Users/[^/\s]+"#, "/Users/<user>"),
        (#"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"#, "<JWT omitted>"),
        (#"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{16,}\b"#, "<API key omitted>"),
    ].map { (try! NSRegularExpression(pattern: $0.0), $0.1) }

    private static let tuning = try! NSRegularExpression(pattern: #"(\[tuning\]\s+)([^=\s]+)=(.*)"#)
    private static let numericTuning: Set<String> = [
        "HV_HZ", "HV_WFI_SPIN", "HV_FLUSH", "HV_STATS", "HV_SUPERBLOCKS",
    ]

    /// Large lines are processed in bounded fragments. Once a secret has been
    /// found, suppress that line's remaining fragments too, including long keys.
    mutating func filter(_ raw: String, endsLine: Bool) -> String {
        defer { if endsLine { suppressRemainder = false } }
        let upper = raw.uppercased()
        if upper.contains("-----BEGIN"), upper.contains("PRIVATE KEY-----") { inPrivateKey = true }
        if inPrivateKey {
            if upper.contains("-----END"), upper.contains("PRIVATE KEY-----") { inPrivateKey = false }
            redactedFragments += 1
            return "<private key omitted>" + (raw.hasSuffix("\n") ? "\n" : "")
        }
        if suppressRemainder {
            redactedFragments += 1
            return "<sensitive line continuation omitted>" + (raw.hasSuffix("\n") ? "\n" : "")
        }
        var text = raw
        for root in privateRoots where !root.isEmpty {
            text = text.replacingOccurrences(of: root, with: "<app-container>")
        }
        // User-supplied environment overrides may contain arbitrary values.
        // Keep known numeric tuning; the metadata records the effective values.
        if let match = Self.tuning.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)),
           let keyRange = Range(match.range(at: 2), in: text),
           let valueRange = Range(match.range(at: 3), in: text) {
            let key = String(text[keyRange]), value = String(text[valueRange])
            if !Self.numericTuning.contains(key) || Int(value) == nil {
                text.replaceSubrange(valueRange, with: "<custom environment value omitted>")
            }
        }
        var hasSensitivePayload = false
        for (index, entry) in Self.rules.enumerated() {
            let (rule, replacement) = entry
            if (index < 3 || index >= 7), rule.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)) != nil {
                hasSensitivePayload = true
            }
            text = rule.stringByReplacingMatches(in: text, range: NSRange(text.startIndex..., in: text), withTemplate: replacement)
        }
        if text != raw {
            redactedFragments += 1
            // The next chunk may be the remainder of a long credential/URL.
            if !endsLine && hasSensitivePayload { suppressRemainder = true }
        }
        return text
    }
}

/// A single, readable attachment. Snapshot lengths are fixed before copying, so
/// an actively growing native log cannot make export run forever. No whole-log
/// Data/String allocation and no "last N lines" truncation.
enum DiagnosticReportWriter {
    private static func scopedTemporaryObjects<T>(_ operation: () throws -> T) rethrows -> T {
        #if canImport(ObjectiveC)
        return try autoreleasepool(invoking: operation)
        #else
        return try operation()
        #endif
    }

    struct Source {
        let name: String
        let url: URL
    }

    private struct Snapshot {
        let source: Source
        let file: FileHandle?
        let length: UInt64
        let unavailable: String?
    }

    static func write(to destination: URL, sources: [Source], privateRoots: [String] = [], context: String = "") throws {
        let fm = FileManager.default
        let snapshots: [Snapshot] = sources.map { source in
            var opened: FileHandle?
            do {
                guard source.url.standardizedFileURL != destination.standardizedFileURL else {
                    return Snapshot(source: source, file: nil, length: 0, unavailable: "report output is not a log source")
                }
                let attributes = try fm.attributesOfItem(atPath: source.url.path)
                guard attributes[.type] as? FileAttributeType == .typeRegular else {
                    return Snapshot(source: source, file: nil, length: 0, unavailable: "not a regular file")
                }
                let file = try FileHandle(forReadingFrom: source.url)
                opened = file
                let length = try file.seekToEnd()
                try file.seek(toOffset: 0)
                return Snapshot(source: source, file: file, length: length, unavailable: nil)
            } catch {
                try? opened?.close()
                return Snapshot(source: source, file: nil, length: 0, unavailable: "missing or unreadable")
            }
        }
        defer { for item in snapshots { try? item.file?.close() } }
        guard fm.createFile(atPath: destination.path, contents: nil) else {
            throw CocoaError(.fileWriteUnknown)
        }
        let output = try FileHandle(forWritingTo: destination)
        defer { try? output.close() }
        func append(_ text: String) throws { try output.write(contentsOf: Data(text.utf8)) }
        try append("""
        Henge diagnostics — format 2
        Exported UTC: \(ISO8601DateFormatter().string(from: Date()))
        \(context)
        Each source covers all bytes available at its snapshot boundary. Live logs may end mid-line.
        Current and previous mean app launches, not individual Mac boots. Missing files are listed explicitly.
        Native stderr is mirrored into henge.log; matching native/app lines describe the same event, not two events.
        Recognizable secrets, input payloads, URLs, email addresses and private paths are filtered.
        Filtering is not complete anonymization: existing application logs can still contain personal information.
        This export does not read the Mac disk, account/keychain stores, clipboard, typed text or screenshots.
        Memory headroom is os_proc_available_memory(), not free physical RAM or a guaranteed kill threshold.
        A sudden log ending does not establish jetsam. A SIGKILL cannot be captured by an app signal handler.
        For a system kill/crash, retain the matching iPadOS Analytics .ips report separately.

        """)
        for item in snapshots {
            try append("\n===== BEGIN \(item.source.name) | snapshot bytes: \(item.length) =====\n")
            guard let input = item.file else {
                try append("[unavailable: \(item.unavailable ?? "unknown")]\n===== END \(item.source.name) =====\n")
                continue
            }
            var remaining = item.length
            var pending = Data()
            var filter = DiagnosticLogFilter(privateRoots: privateRoots)
            var bytesRead: UInt64 = 0
            var fragments = 0
            let chunkLimit = 64 * 1024
            while remaining > 0 {
                guard let chunk = try input.read(upToCount: Int(min(remaining, 32 * 1024))), !chunk.isEmpty else { break }
                remaining -= UInt64(chunk.count)
                bytesRead += UInt64(chunk.count)
                pending.append(chunk)
                while !pending.isEmpty {
                    let newline = pending.firstIndex(of: 10)
                    let lineSize = newline.map { pending.distance(from: pending.startIndex, to: $0) + 1 }
                    guard lineSize != nil || pending.count >= chunkLimit else { break }
                    var count = min(lineSize ?? chunkLimit, chunkLimit)
                    let complete = lineSize == count
                    // Keep a credential field name together when a very long
                    // line happens to cross the chunk boundary mid-word.
                    if !complete {
                        let floor = max(1, count - 512)
                        for offset in stride(from: count - 1, through: floor, by: -1) {
                            let byte = pending[pending.index(pending.startIndex, offsetBy: offset)]
                            if byte == 32 || byte == 9 || byte == 13 || byte == 123 || byte == 44 {
                                count = offset + 1
                                break
                            }
                        }
                    }
                    // Avoid corrupting a multibyte UTF-8 character at a chunk
                    // boundary; invalid bytes already in a log remain visible
                    // as replacement characters rather than aborting export.
                    if !complete {
                        var start = count - 1
                        while start > max(0, count - 4), pending[pending.index(pending.startIndex, offsetBy: start)] & 0xc0 == 0x80 {
                            start -= 1
                        }
                        let lead = pending[pending.index(pending.startIndex, offsetBy: start)]
                        let needed = (0xc2...0xdf).contains(lead) ? 2 : (0xe0...0xef).contains(lead) ? 3 : (0xf0...0xf4).contains(lead) ? 4 : 1
                        if count - start < needed { count = start }
                    }
                    let part = pending.prefix(count)
                    try scopedTemporaryObjects {
                        try append(filter.filter(String(decoding: part, as: UTF8.self), endsLine: complete))
                    }
                    pending.removeFirst(count)
                    fragments += 1
                }
            }
            if !pending.isEmpty {
                try scopedTemporaryObjects {
                    try append(filter.filter(String(decoding: pending, as: UTF8.self), endsLine: true))
                }
                fragments += 1
            }
            try append("\n[read \(bytesRead)/\(item.length) source bytes; processed \(fragments) fragments; privacy-filtered \(filter.redactedFragments) fragments]")
            if bytesRead != item.length { try append("\n[source ended before its snapshot boundary]") }
            try append("\n===== END \(item.source.name) =====\n")
        }
        try output.synchronize()
    }
}

/// Stable identity for one app launch. Snapshot time lives in the report; the
/// archive filename remains stable so a long run does not fill storage with
/// copies of the same growing logs.
struct DiagnosticRunIdentity {
    let runID: String
    let startedUTC: String
    let version: String
    let build: String
    let pid: Int

    init?(metadata: [String: Any]) {
        guard let runID = metadata["run_id"] as? String, !runID.isEmpty,
              let started = metadata["started_utc"] as? String,
              let pid = metadata["pid"] as? NSNumber else { return nil }
        self.runID = runID
        self.startedUTC = started
        self.version = metadata["app_version"] as? String ?? "unknown"
        self.build = metadata["app_build"] as? String ?? "unknown"
        self.pid = pid.intValue
    }

    private static func filenamePart(_ value: String) -> String {
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.")
        return String(String.UnicodeScalarView(value.unicodeScalars.filter { allowed.contains($0) }.prefix(64)))
    }

    var filename: String {
        "Henge-diagnostics-\(Self.filenamePart(startedUTC))-v\(Self.filenamePart(version))-b\(Self.filenamePart(build))-pid\(pid)-\(Self.filenamePart(String(runID.prefix(8)))).txt"
    }

    var summary: String {
        "Run started UTC: \(Self.filenamePart(startedUTC)) | Henge \(Self.filenamePart(version)) (\(Self.filenamePart(build))) | PID \(pid) | run \(Self.filenamePart(runID))"
    }
}

struct DiagnosticReportPublication {
    let archiveURL: URL
    let latestURL: URL
    let bytes: UInt64
}

/// Only this type publishes reports. The writer streams to an unpublished
/// sibling, then rename replaces each visible file atomically. Hard links keep
/// Latest and a share attachment immutable without loading/copying a whole log.
/// A crash mid-write leaves the last complete report available.
struct DiagnosticReportStore {
    static let latestFilename = "Latest-Henge-diagnostics.txt"
    let directory: URL
    var historyLimit = 8

    var latestURL: URL { directory.appendingPathComponent(Self.latestFilename) }

    private func replace(_ temporary: URL, withName destination: URL) throws {
        if rename(temporary.path, destination.path) != 0 {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
    }

    private func linkedCopy(from source: URL, to destination: URL) throws {
        do { try FileManager.default.linkItem(at: source, to: destination) }
        catch { try FileManager.default.copyItem(at: source, to: destination) }
    }

    func publish(identity: DiagnosticRunIdentity, sources: [DiagnosticReportWriter.Source],
                 privateRoots: [String] = [], context: String = "") throws -> DiagnosticReportPublication {
        // Input summaries have their own explicit subdirectory. Report files
        // must never become sources, including through a future broad glob.
        let root = directory.standardizedFileURL.path + "/"
        let inputs = directory.appendingPathComponent("Inputs", isDirectory: true).standardizedFileURL.path + "/"
        for source in sources {
            let path = source.url.standardizedFileURL.path
            if path.hasPrefix(root) && !path.hasPrefix(inputs) {
                throw NSError(domain: "HengeDiagnostics", code: 1,
                              userInfo: [NSLocalizedDescriptionKey: "A report cannot include another report."])
            }
        }
        return try publish(identity: identity) { temporary in
            try DiagnosticReportWriter.write(to: temporary, sources: sources, privateRoots: privateRoots,
                                             context: identity.summary + "\n" + context)
        }
    }

    /// The closure boundary also lets tests inject a failed partial write and
    /// verify that neither a visible archive nor Latest was damaged.
    func publish(identity: DiagnosticRunIdentity, writeBody: (URL) throws -> Void) throws -> DiagnosticReportPublication {
        let fm = FileManager.default
        try fm.createDirectory(at: directory, withIntermediateDirectories: true)
        let temporary = directory.appendingPathComponent(".pending-\(UUID().uuidString).txt")
        let latestTemporary = directory.appendingPathComponent(".latest-\(UUID().uuidString).txt")
        defer {
            try? fm.removeItem(at: temporary)
            try? fm.removeItem(at: latestTemporary)
        }
        try writeBody(temporary)
        let attributes = try fm.attributesOfItem(atPath: temporary.path)
        guard attributes[.type] as? FileAttributeType == .typeRegular,
              let size = attributes[.size] as? NSNumber, size.uint64Value > 0 else {
            throw CocoaError(.fileWriteUnknown)
        }
        // Make both names ready before touching the last visible report.
        try linkedCopy(from: temporary, to: latestTemporary)
        let archive = directory.appendingPathComponent(identity.filename)
        try replace(temporary, withName: archive)
        try replace(latestTemporary, withName: latestURL)
        try pruneHistory(keeping: archive)
        return DiagnosticReportPublication(archiveURL: archive, latestURL: latestURL, bytes: size.uint64Value)
    }

    func attachment(from publication: DiagnosticReportPublication, in folder: URL) throws -> URL {
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        let name = publication.archiveURL.deletingPathExtension().lastPathComponent
        let output = folder.appendingPathComponent("\(name)-\(UUID().uuidString.prefix(8)).txt")
        try linkedCopy(from: publication.archiveURL, to: output)
        return output
    }

    func removeAbandonedWrites() throws {
        let fm = FileManager.default
        guard fm.fileExists(atPath: directory.path) else { return }
        for url in try fm.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil) {
            if url.lastPathComponent.hasPrefix(".pending-") || url.lastPathComponent.hasPrefix(".latest-") {
                try fm.removeItem(at: url)
            }
        }
    }

    private func pruneHistory(keeping current: URL) throws {
        let fm = FileManager.default
        let files = try fm.contentsOfDirectory(at: directory.resolvingSymlinksInPath(), includingPropertiesForKeys: [.contentModificationDateKey, .isRegularFileKey])
        var archives: [(URL, Date)] = []
        for url in files where url.lastPathComponent.hasPrefix("Henge-diagnostics-") && url.pathExtension == "txt" {
            let values = try url.resourceValues(forKeys: [.contentModificationDateKey, .isRegularFileKey])
            if values.isRegularFile == true { archives.append((url, values.contentModificationDate ?? .distantPast)) }
        }
        // Every candidate came from this one directory. Darwin may enumerate
        // /var/... as /private/var/... (and URL base representations can also
        // differ), so URL equality cannot identify the entry we just wrote.
        let currentName = current.lastPathComponent
        archives.sort { lhs, rhs in
            if lhs.0.lastPathComponent == currentName { return rhs.0.lastPathComponent != currentName }
            if rhs.0.lastPathComponent == currentName { return false }
            if lhs.1 != rhs.1 { return lhs.1 > rhs.1 }
            return lhs.0.lastPathComponent > rhs.0.lastPathComponent
        }
        for (url, _) in archives.dropFirst(max(1, historyLimit)) { try fm.removeItem(at: url) }
    }
}

/// One streaming write at a time. Automatic triggers never build a work queue
/// under memory pressure; manual requests are coalesced by the iOS coordinator.
struct DiagnosticReportThrottle {
    private(set) var writing = false
    private(set) var lastAutomaticAttempt: TimeInterval?

    mutating func begin(now: TimeInterval, automatic: Bool, minimumInterval: TimeInterval = 120) -> Bool {
        guard !writing else { return false }
        if automatic, let last = lastAutomaticAttempt, now - last < minimumInterval { return false }
        writing = true
        lastAutomaticAttempt = now
        return true
    }

    mutating func finish() { writing = false }
}

#if canImport(UIKit)
import UIKit
import SwiftUI
import GameController

@MainActor
private final class DiagnosticReportStatus: ObservableObject {
    static let shared = DiagnosticReportStatus()
    @Published var savedAt: Date?
    @Published var failure: String?
}

@MainActor
private final class DiagnosticBackgroundTime {
    private var identifier: UIBackgroundTaskIdentifier = .invalid

    init() {
        identifier = UIApplication.shared.beginBackgroundTask(withName: "Save Henge diagnostics") { [weak self] in
            Task { @MainActor in self?.finish() }
        }
    }

    func finish() {
        guard identifier != .invalid else { return }
        UIApplication.shared.endBackgroundTask(identifier)
        identifier = .invalid
    }
}

/// Small, explicit metadata only. Never serialize UserDefaults, environment,
/// VirtualMac, a pairing record or a guest response wholesale.
enum Diagnostics {
    private static let queue = DispatchQueue(label: "com.henge.diagnostics", qos: .utility)
    private static let exportQueue = DispatchQueue(label: "com.henge.diagnostics.export", qos: .utility)
    private static var timer: DispatchSourceTimer?
    private static var observers: [NSObjectProtocol] = []
    private static var run: [String: Any] = [:] // accessed on queue only
    private static let launched = ProcessInfo.processInfo.systemUptime
    private static var peakFootprint: UInt64 = 0
    private static var lowestHeadroom: UInt64 = .max
    private static var sampleCount = 0
    private static var memoryWarnings = 0
    private static var canWriteRunMetadata = true
    private static var reportThrottle = DiagnosticReportThrottle()
    private static var manualWaiters: [(Result<URL, Error>) -> Void] = []
    private static var backgroundWaiters: [() -> Void] = []
    private static var firstReport = true
    private static var deferredReport: DispatchWorkItem?
    private static let attachmentFolder = FileManager.default.temporaryDirectory
        .appendingPathComponent("HengeDiagnosticsExports", isDirectory: true)
        .appendingPathComponent("\(getpid())-\(UUID().uuidString)", isDirectory: true)

    static var reportDirectory: URL {
        HengeLog.logFileURL.deletingLastPathComponent().appendingPathComponent("HengeDiagnostics", isDirectory: true)
    }

    /// Only the separately filtered, fixed-schema guest summary is imported.
    /// Do not put raw guest logs, tokens or a conversation in this directory.
    static var guestSummaryURL: URL {
        reportDirectory.appendingPathComponent("Inputs", isDirectory: true).appendingPathComponent("guest-chat.json")
    }

    private static var currentURL: URL {
        HengeLog.logFileURL.deletingLastPathComponent().appendingPathComponent("henge-diagnostics.json")
    }
    private static var previousURL: URL {
        currentURL.deletingLastPathComponent().appendingPathComponent("henge-diagnostics-prev.json")
    }

    /// Called once on the main thread, after HengeLog rotated both log pairs.
    static func start() {
        canWriteRunMetadata = HengeLog.rotate(currentURL, to: previousURL)
        let info = Bundle.main.infoDictionary ?? [:]
        let initial: [String: Any] = [
            "format": 1, "run_id": UUID().uuidString,
            "started_utc": ISO8601DateFormatter().string(from: Date()), "pid": getpid(),
            "app_version": info["CFBundleShortVersionString"] as? String ?? "unknown",
            "app_build": info["CFBundleVersion"] as? String ?? "unknown",
            "source_commit": info["HengeBuildCommit"] as? String ?? "unstamped",
            "build_date": info["HengeBuildDate"] as? String ?? "unknown",
            "test_build_name": info["HengeTestBuildName"] as? String ?? "unspecified",
            "base_commit": info["HengeBaseCommit"] as? String ?? "unstamped",
            "metadata_rotation_succeeded": canWriteRunMetadata,
            "device_model": HengeLog.deviceModel, "system_version": UIDevice.current.systemVersion,
            "physical_memory_bytes": ProcessInfo.processInfo.physicalMemory,
            "host_processor_count": ProcessInfo.processInfo.processorCount,
            "increased_memory_entitlement": Entitlements.increasedMemory,
            "extended_addressing_entitlement": Entitlements.extendedAddressing,
            "allocation_headroom_at_launch_bytes": UInt64(Entitlements.memoryLimitAtLaunch),
            "memory_note": "Allocation headroom is not free physical RAM or a guaranteed termination threshold.",
            "termination_note": "An absent termination notification does not identify the cause. SIGKILL cannot be caught.",
            "host_devicecheck": HostDeviceCheckProbe.snapshot(),
        ]
        queue.async {
            run = initial
            if !canWriteRunMetadata { HengeLog.log("diagnostics", "metadata rotation failed; preserving existing files") }
            sample("launch")
            requestReport(reason: "launch", automatic: true)
        }
        let center = NotificationCenter.default
        for (notification, event) in [
            (UIApplication.didReceiveMemoryWarningNotification, "memory_warning"),
            (UIApplication.didEnterBackgroundNotification, "entered_background"),
            (UIApplication.willEnterForegroundNotification, "entering_foreground"),
            (UIApplication.willTerminateNotification, "termination_notification"),
        ] {
            observers.append(center.addObserver(forName: notification, object: nil, queue: .main) { _ in
                Task { @MainActor in
                    let backgroundTime = event == "entered_background" ? DiagnosticBackgroundTime() : nil
                    queue.async {
                        if event == "memory_warning" { memoryWarnings += 1 }
                        sample(event)
                        if event == "entered_background" {
                            requestReport(reason: event, automatic: true, minimumInterval: 30, finished: {
                                DispatchQueue.main.async { backgroundTime?.finish() }
                            })
                        } else if event == "termination_notification" {
                            requestReport(reason: event, automatic: true, minimumInterval: 30)
                        }
                    }
                }
            })
        }
        observers.append(center.addObserver(forName: .hengeGuestChatDiagnosticsDidUpdate, object: nil, queue: nil) { _ in
            queue.async { scheduleReport(reason: "guest_summary_updated") }
        })
        let source = DispatchSource.makeTimerSource(queue: queue)
        source.schedule(deadline: .now() + 30, repeating: 30, leeway: .seconds(2))
        source.setEventHandler {
            sample("periodic")
            requestReport(reason: "periodic", automatic: true)
        }
        timer = source
        source.resume()
    }

    static func recordSession(ramMB: UInt64, requestedRAMMB: Int, cpus: Int, width: Int, height: Int, retina: Bool) {
        var environment: [String: Int] = [:]
        for key in ["HV_HZ", "HV_FLUSH", "HV_WFI_SPIN", "HV_STATS", "HV_SUPERBLOCKS"] {
            if let raw = getenv(key), let value = Int(String(cString: raw)) { environment[key] = value }
        }
        let session: [String: Any] = [
            "ram_mib": ramMB, "requested_ram_mib": requestedRAMMB, "cpus": cpus,
            "width_pixels": width, "height_pixels": height, "retina": retina,
            "jit_region_bytes": JITBootstrap.jitBytes,
            "code_cache_setting_mib": UserDefaults.standard.object(forKey: JITBootstrap.codeCacheKey) as? Int ?? JITBootstrap.defaultCodeCacheMB,
            "numeric_engine_settings": environment,
        ]
        queue.async { run["last_session"] = session; sample("session_start") }
    }

    static func markInputIssue(softwareKeyboardVisible: Bool, externalDisplay: Bool, zoomed: Bool, helperRunning: Bool) {
        let input: [String: Any] = [
            "software_keyboard_requested": softwareKeyboardVisible,
            "hardware_keyboard_connected": GCKeyboard.coalesced != nil,
            "external_display": externalDisplay, "zoomed": zoomed,
            "guest_helper_recently_seen": helperRunning,
        ]
        queue.async {
            run["input_issue_context"] = input
            sample("user_marked_missing_candidates")
        }
    }

    /// No process-exit inference: this is a timestamped observation only.
    private static func sample(_ event: String) {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<integer_t>.size)
        let capacity = Int(count)
        let result = withUnsafeMutablePointer(to: &info) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: capacity) {
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
            }
        }
        let headroom = UInt64(henge_available_memory())
        lowestHeadroom = min(lowestHeadroom, headroom)
        sampleCount += 1
        let elapsed = ProcessInfo.processInfo.systemUptime - launched
        var observation: [String: Any] = [
            "event": event, "elapsed_seconds": elapsed,
            "observed_utc": ISO8601DateFormatter().string(from: Date()),
            "allocation_headroom_bytes": headroom,
            "thermal_state": ProcessInfo.processInfo.thermalState.rawValue,
            "vm_state": henge_vm_state(),
            "task_info_status": result,
        ]
        if result == KERN_SUCCESS {
            observation["physical_footprint_bytes"] = info.phys_footprint
            observation["resident_bytes"] = info.resident_size
            peakFootprint = max(peakFootprint, info.phys_footprint)
        }
        run["latest_observation"] = observation
        run["sample_count"] = sampleCount
        run["peak_observed_footprint_bytes"] = peakFootprint
        run["lowest_observed_allocation_headroom_bytes"] = lowestHeadroom
        run["memory_warning_count"] = memoryWarnings
        let footprint = result == KERN_SUCCESS ? String(info.phys_footprint) : "unavailable"
        let resident = result == KERN_SUCCESS ? String(info.resident_size) : "unavailable"
        HengeLog.log("diagnostics", "event=\(event) elapsed_s=\(Int(elapsed)) phys_bytes=\(footprint) resident_bytes=\(resident) allocation_headroom_bytes=\(headroom) thermal=\(ProcessInfo.processInfo.thermalState.rawValue) memory_warnings=\(memoryWarnings)")
        writeRunMetadata()
        HengeLog.flushNow()
    }

    private static func writeRunMetadata() {
        if canWriteRunMetadata {
            do {
                let data = try JSONSerialization.data(withJSONObject: run, options: [.prettyPrinted, .sortedKeys])
                try data.write(to: currentURL, options: .atomic)
            } catch {
                HengeLog.log("diagnostics", "metadata write failed (\((error as NSError).code))")
            }
        }
    }

    /// A manual request always waits for a fresh snapshot. Requests arriving
    /// during an automatic write coalesce into one subsequent manual write.
    static func export() async throws -> URL {
        try await withCheckedThrowingContinuation { continuation in
            queue.async {
                sample("export_requested")
                manualWaiters.append { continuation.resume(with: $0) }
                requestReport(reason: "manual", automatic: false)
            }
        }
    }

    /// Event names and numeric errors only. Never log the chosen destination,
    /// activity payload or the URLs returned by the document picker.
    static func recordPresentation(_ event: String, error: Error? = nil) {
        queue.async {
            var observation: [String: Any] = ["event": event, "observed_utc": ISO8601DateFormatter().string(from: Date())]
            let suffix: String
            if let error = error {
                observation["error_code"] = (error as NSError).code
                suffix = " error_code=\((error as NSError).code)"
            } else { suffix = "" }
            run["last_export_interaction"] = observation
            HengeLog.log("diagnostics", "event=\(event)\(suffix)")
            writeRunMetadata()
            HengeLog.flushNow()
            if event.hasSuffix("completed") || event.hasSuffix("cancelled") || event.hasSuffix("failed") {
                scheduleReport(reason: "export_interaction")
            }
        }
    }

    /// Only an activity/picker completion releases its immutable attachment.
    /// Automatic publication/pruning never removes an attachment in use.
    static func releaseAttachment(_ url: URL) {
        guard url.deletingLastPathComponent().standardizedFileURL == attachmentFolder.standardizedFileURL,
              url.lastPathComponent.hasPrefix("Henge-diagnostics-"), url.pathExtension == "txt" else { return }
        exportQueue.async {
            do { try FileManager.default.removeItem(at: url) }
            catch {
                HengeLog.log("diagnostics", "event=attachment_cleanup_failed error_code=\((error as NSError).code)")
            }
        }
    }

    /// A late guest response or share result should reach Latest without a
    /// rapid series of complete log copies. There is only one deferred trigger.
    private static func scheduleReport(reason: String) {
        guard deferredReport == nil else { return }
        let delay = max(reportThrottle.writing ? 10 : 1, 30 - (ProcessInfo.processInfo.systemUptime - (reportThrottle.lastAutomaticAttempt ?? 0)))
        let work = DispatchWorkItem {
            deferredReport = nil
            if reportThrottle.writing {
                scheduleReport(reason: reason)
            } else {
                requestReport(reason: reason, automatic: true, minimumInterval: 30)
            }
        }
        deferredReport = work
        queue.asyncAfter(deadline: .now() + delay, execute: work)
    }

    private static func requestReport(reason: String, automatic: Bool, minimumInterval: TimeInterval = 120,
                                      finished: (() -> Void)? = nil) {
        guard reportThrottle.begin(now: ProcessInfo.processInfo.systemUptime, automatic: automatic, minimumInterval: minimumInterval) else {
            if let finished = finished {
                if reportThrottle.writing { backgroundWaiters.append(finished) }
                else { finished() }
            }
            return
        }
        if let finished = finished { backgroundWaiters.append(finished) }
        let completions = automatic ? [] : manualWaiters
        if !automatic { manualWaiters.removeAll() }
        let recoverPrevious = firstReport
        firstReport = false
        let started = ProcessInfo.processInfo.systemUptime
        HengeLog.log("diagnostics", "event=export_started mode=\(automatic ? "automatic" : "manual") reason=\(reason)")
        HengeLog.flushNow()
        do {
            guard let identity = DiagnosticRunIdentity(metadata: run) else { throw CocoaError(.fileWriteUnknown) }
            var exportMetadata = run
            exportMetadata["guest_summary_storage_status"] = GuestChatDiagnosticsPersistence.status
            let metadata = try JSONSerialization.data(withJSONObject: exportMetadata, options: [.prettyPrinted, .sortedKeys])
            exportQueue.async {
                do {
                    let store = DiagnosticReportStore(directory: reportDirectory)
                    if recoverPrevious {
                        try store.removeAbandonedWrites()
                        // No active share can belong to another process launch.
                        let oldAttachments = attachmentFolder.deletingLastPathComponent()
                        if FileManager.default.fileExists(atPath: oldAttachments.path) {
                            for old in try FileManager.default.contentsOfDirectory(at: oldAttachments, includingPropertiesForKeys: nil) where old != attachmentFolder {
                                try FileManager.default.removeItem(at: old)
                            }
                        }
                        recoverPreviousReport(in: store)
                    }
                    try FileManager.default.createDirectory(at: attachmentFolder, withIntermediateDirectories: true)
                    let currentSnapshot = attachmentFolder.appendingPathComponent("metadata-\(UUID().uuidString).json")
                    defer { try? FileManager.default.removeItem(at: currentSnapshot) }
                    try metadata.write(to: currentSnapshot, options: .atomic)
                    let guestStorage = GuestChatDiagnosticsPersistence.status
                    var files: [DiagnosticReportWriter.Source] = [
                        .init(name: "current-run.json", url: currentSnapshot),
                        .init(name: "previous-run.json", url: previousURL),
                        .init(name: "henge.log", url: HengeLog.logFileURL),
                        .init(name: "henge-prev.log", url: HengeLog.previousLogURL),
                        .init(name: "henge-native.log", url: HengeLog.nativeLogURL),
                        .init(name: "henge-native-prev.log", url: HengeLog.previousNativeLogURL),
                    ]
                    // An unsuccessful overwrite must never make an older
                    // guest file appear to be this session's refreshed result.
                    if !guestStorage.hasPrefix("summary_write_failed") {
                        files.insert(.init(name: "guest-chat-summary.json", url: guestSummaryURL), at: 2)
                    }
                    let publication = try store.publish(identity: identity, sources: files, privateRoots: [NSHomeDirectory()],
                                                        context: "Capture reason: \(reason). Guest summary storage: \(guestStorage). A not_updated summary is from an earlier run; a failed summary is omitted. Guest checks are a timestamped summary, not an attestation token.")
                    let attachment = automatic ? nil : try store.attachment(from: publication, in: attachmentFolder)
                    queue.async {
                        reportFinished(result: .success((publication, attachment)), automatic: automatic,
                                       started: started, completions: completions)
                    }
                } catch {
                    queue.async { reportFinished(result: .failure(error), automatic: automatic, started: started, completions: completions) }
                }
            }
        } catch {
            reportFinished(result: .failure(error), automatic: automatic, started: started, completions: completions)
        }
    }

    /// Preserve an existing prior archive, including its guest summary. For an
    /// older build with no durable report, recover one from rotated raw files.
    /// The new combined report always also includes the complete previous raw
    /// files, including a fatal tail written after the last automatic snapshot.
    private static func recoverPreviousReport(in store: DiagnosticReportStore) {
        guard canWriteRunMetadata else {
            HengeLog.log("diagnostics", "event=previous_report_recovery_skipped reason=metadata_rotation_failed")
            return
        }
        guard let file = try? FileHandle(forReadingFrom: previousURL) else { return }
        defer { try? file.close() }
        do {
            guard let bytes = try file.read(upToCount: 256 * 1024), bytes.count < 256 * 1024,
                  let metadata = try JSONSerialization.jsonObject(with: bytes) as? [String: Any],
                  let identity = DiagnosticRunIdentity(metadata: metadata) else {
                HengeLog.log("diagnostics", "event=previous_report_recovery_unavailable")
                return
            }
            if FileManager.default.fileExists(atPath: store.directory.appendingPathComponent(identity.filename).path) {
                HengeLog.log("diagnostics", "event=previous_report_preserved pid=\(identity.pid)")
                return
            }
            _ = try store.publish(identity: identity, sources: [
                .init(name: "recovered-run.json", url: previousURL),
                .init(name: "henge-prev.log (this archived run)", url: HengeLog.previousLogURL),
                .init(name: "henge-native-prev.log (this archived run)", url: HengeLog.previousNativeLogURL),
            ], privateRoots: [NSHomeDirectory()], context: "Recovered after the next app launch; this is the prior run, not the current process.")
            HengeLog.log("diagnostics", "event=previous_report_recovered pid=\(identity.pid)")
        } catch {
            // The current combined report still includes the raw previous
            // files. Failure here must not prevent a usable current report.
            HengeLog.log("diagnostics", "event=previous_report_recovery_failed error_code=\((error as NSError).code)")
        }
    }

    private static func reportFinished(result: Result<(DiagnosticReportPublication, URL?), Error>, automatic: Bool,
                                       started: TimeInterval, completions: [(Result<URL, Error>) -> Void]) {
        reportThrottle.finish()
        let now = Date()
        switch result {
        case .success(let (publication, attachment)):
            HengeLog.log("diagnostics", "event=export_succeeded mode=\(automatic ? "automatic" : "manual") bytes=\(publication.bytes) duration_ms=\(Int((ProcessInfo.processInfo.systemUptime - started) * 1000))")
            run["last_report"] = ["status": "saved", "saved_utc": ISO8601DateFormatter().string(from: now), "bytes": publication.bytes,
                                  "filename": DiagnosticReportStore.latestFilename]
            DispatchQueue.main.async {
                DiagnosticReportStatus.shared.savedAt = now
                DiagnosticReportStatus.shared.failure = nil
            }
            for completion in completions { completion(.success(attachment ?? publication.latestURL)) }
        case .failure(let error):
            let code = (error as NSError).code
            HengeLog.log("diagnostics", "event=export_failed mode=\(automatic ? "automatic" : "manual") error_code=\(code)")
            run["last_report"] = ["status": "failed", "observed_utc": ISO8601DateFormatter().string(from: now), "error_code": code]
            DispatchQueue.main.async {
                DiagnosticReportStatus.shared.failure = "The automatic report could not be updated (\(code)). Check free storage, then collect diagnostics again."
            }
            for completion in completions { completion(.failure(error)) }
        }
        writeRunMetadata()
        HengeLog.flushNow()
        let background = backgroundWaiters
        backgroundWaiters.removeAll()
        for finish in background { finish() }
        if !manualWaiters.isEmpty { requestReport(reason: "manual", automatic: false) }
    }
}

private enum DiagnosticExportAction { case share, files }

private struct DiagnosticExportPresentation: Identifiable {
    let id = UUID()
    let url: URL
    let action: DiagnosticExportAction
}

private enum DiagnosticPresentationOutcome {
    case completed, cancelled
    case failed(Error)
}

/// An anchor in the existing SwiftUI view, including the Session Details sheet.
/// UIKit owns exactly one activity/picker presentation; no second SwiftUI sheet
/// competes with it. The actual on-screen view anchors the iPad popover.
@MainActor
private final class DiagnosticPresentationController: UIViewController, UIDocumentPickerDelegate, UIPopoverPresentationControllerDelegate {
    var requested: DiagnosticExportPresentation?
    var completion: ((UUID, DiagnosticPresentationOutcome) -> Void)?
    private var active: DiagnosticExportPresentation?
    private var handledID: UUID?
    private weak var activity: UIViewController?

    override func loadView() {
        view = UIView()
        view.backgroundColor = .clear
        view.isUserInteractionEnabled = false
    }

    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        presentIfNeeded()
    }

    func update(_ request: DiagnosticExportPresentation?) {
        if let request = request, request.id == handledID { return }
        requested = request
        // SwiftUI must finish its view update before presenting or changing
        // state through the completion callback.
        DispatchQueue.main.async { [weak self] in self?.presentIfNeeded() }
    }

    private func presentIfNeeded() {
        guard active == nil, let request = requested, request.id != handledID else { return }
        handledID = request.id
        active = request
        requested = nil
        let event = request.action == .share ? "share" : "files_save"
        Diagnostics.recordPresentation("\(event)_requested")
        guard isViewLoaded, view.window != nil else {
            finish(.failed(NSError(domain: "HengeDiagnosticsPresentation", code: 1)))
            return
        }
        var ancestor: UIViewController? = self
        while let controller = ancestor {
            if controller.presentedViewController != nil || controller.isBeingDismissed {
                finish(.failed(NSError(domain: "HengeDiagnosticsPresentation", code: 2)))
                return
            }
            ancestor = controller.parent
        }
        guard FileManager.default.isReadableFile(atPath: request.url.path) else {
            finish(.failed(CocoaError(.fileReadNoSuchFile)))
            return
        }
        let controller: UIViewController
        if request.action == .share {
            let share = UIActivityViewController(activityItems: [request.url], applicationActivities: nil)
            share.completionWithItemsHandler = { [weak self] _, completed, _, error in
                DispatchQueue.main.async {
                    if let error = error { self?.finish(.failed(error)) }
                    else { self?.finish(completed ? .completed : .cancelled) }
                }
            }
            if let popover = share.popoverPresentationController {
                popover.sourceView = view
                popover.sourceRect = CGRect(x: view.bounds.midX, y: view.bounds.midY, width: 1, height: 1)
                popover.permittedArrowDirections = []
                popover.delegate = self
            }
            controller = share
        } else {
            let picker = UIDocumentPickerViewController(forExporting: [request.url], asCopy: true)
            picker.delegate = self
            picker.shouldShowFileExtensions = true
            controller = picker
        }
        activity = controller
        controller.presentationController?.delegate = self
        present(controller, animated: true) { [weak self, weak controller] in
            guard let self = self, self.active?.id == request.id else { return }
            guard let controller = controller, controller.presentingViewController != nil else {
                self.finish(.failed(NSError(domain: "HengeDiagnosticsPresentation", code: 3)))
                return
            }
            controller.presentationController?.delegate = self
            Diagnostics.recordPresentation("\(event)_presented")
        }
        // UIKit can reject a conflicting presentation without calling its
        // completion. Report that explicitly rather than leaving a dead button.
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) { [weak self, weak controller] in
            guard let self = self, self.active?.id == request.id else { return }
            if controller?.presentingViewController == nil && controller?.isBeingPresented != true {
                self.finish(.failed(NSError(domain: "HengeDiagnosticsPresentation", code: 3)))
            }
        }
    }

    func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
        finish(urls.isEmpty ? .failed(CocoaError(.fileWriteUnknown)) : .completed)
    }

    func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) { finish(.cancelled) }

    func presentationControllerDidDismiss(_ presentationController: UIPresentationController) { finish(.cancelled) }

    private func finish(_ outcome: DiagnosticPresentationOutcome) {
        guard let request = active else { return }
        active = nil
        activity = nil
        let event = request.action == .share ? "share" : "files_save"
        switch outcome {
        case .completed: Diagnostics.recordPresentation("\(event)_completed")
        case .cancelled: Diagnostics.recordPresentation("\(event)_cancelled")
        case .failed(let error): Diagnostics.recordPresentation("\(event)_failed", error: error)
        }
        let completed = completion
        DispatchQueue.main.async { completed?(request.id, outcome) }
    }
}

@MainActor
private struct DiagnosticPresentationAnchor: UIViewControllerRepresentable {
    let request: DiagnosticExportPresentation?
    let completion: (UUID, DiagnosticPresentationOutcome) -> Void

    func makeUIViewController(context: Context) -> DiagnosticPresentationController { DiagnosticPresentationController() }

    func updateUIViewController(_ controller: DiagnosticPresentationController, context: Context) {
        controller.completion = completion
        controller.update(request)
    }
}

@MainActor
struct DiagnosticsExportButton: View {
    @ObservedObject private var archive = DiagnosticReportStatus.shared
    @State private var preparing = false
    @State private var progress = ""
    @State private var presentation: DiagnosticExportPresentation?
    @State private var failure: String?
    @State private var outcome: String?
    @State private var guestStatus: String?

    private var busy: Bool { preparing || presentation != nil }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Button { collect(for: .share) } label: {
                if preparing { HStack { ProgressView(); Text(progress) } }
                else { Label("Collect Chat diagnostics", systemImage: "square.and.arrow.up") }
            }
            .buttonStyle(.borderless)
            .disabled(busy)
            Button { collect(for: .files) } label: {
                Label("Save diagnostics to Files", systemImage: "folder")
            }
            .buttonStyle(.borderless)
            .disabled(busy)
            if let guestStatus = guestStatus { Text(guestStatus).font(.footnote).foregroundStyle(.secondary) }
            if let outcome = outcome { Text(outcome).font(.footnote).foregroundStyle(.secondary) }
            if let failure = archive.failure {
                Text(failure).font(.footnote).foregroundStyle(.red)
            } else if let saved = archive.savedAt {
                Text("Report saved at \(saved.formatted(date: .omitted, time: .standard)).")
                    .font(.footnote).foregroundStyle(.secondary)
            }
            Text("Automatic copy: Files → On My iPad → Henge → HengeDiagnostics → Latest-Henge-diagnostics.txt")
                .font(.footnote).foregroundStyle(.secondary).textSelection(.enabled)
            Text("Send that one file. It combines this run, the previous run and available Mac checks. Reports update automatically; the latest 8 runs are retained. Nothing is uploaded automatically.")
                .font(.footnote).foregroundStyle(.secondary)
        }
        .background(DiagnosticPresentationAnchor(request: presentation, completion: presentationFinished))
        .alert("Diagnostics could not be shared or saved", isPresented: Binding(get: { failure != nil }, set: { if !$0 { failure = nil } })) {
            Button("OK") { failure = nil }
        } message: { Text(failure ?? "") }
    }

    private func collect(for action: DiagnosticExportAction) {
        guard !busy else { return }
        preparing = true
        failure = nil
        outcome = nil
        progress = "Checking Mac diagnostics (up to 15 seconds)…"
        Diagnostics.recordPresentation("collection_started")
        Task { @MainActor in
            guestStatus = await GuestChatDiagnostics.refresh(timeout: 15)
            progress = "Saving the combined report…"
            do {
                let url = try await Diagnostics.export()
                presentation = DiagnosticExportPresentation(url: url, action: action)
                outcome = "The report is also saved in HengeDiagnostics."
            } catch {
                failure = "Could not create the report. Check free storage and try again. (\((error as NSError).code))"
            }
            preparing = false
        }
    }

    private func presentationFinished(id: UUID, result: DiagnosticPresentationOutcome) {
        guard let request = presentation, request.id == id else { return }
        presentation = nil
        Diagnostics.releaseAttachment(request.url)
        switch result {
        case .completed:
            outcome = request.action == .files ? "Saved to the location you chose." : "The sharing action completed."
        case .cancelled:
            outcome = "Cancelled. The automatic copy is still available in HengeDiagnostics."
        case .failed(let error):
            outcome = "The automatic copy is still available in HengeDiagnostics."
            failure = "The system could not open or complete this action (\((error as NSError).code)). Close any other dialog and try Save diagnostics to Files, or open the automatic copy shown below."
        }
    }
}
#endif
