// SPDX-License-Identifier: GPL-2.0-or-later
import Foundation

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

    static func write(to destination: URL, sources: [Source], privateRoots: [String] = []) throws {
        let fm = FileManager.default
        let snapshots: [Snapshot] = sources.map { source in
            var opened: FileHandle?
            do {
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
        Henge diagnostics — format 1
        Exported UTC: \(ISO8601DateFormatter().string(from: Date()))
        Each source covers all bytes available at its snapshot boundary. Live logs may end mid-line.
        Current and previous mean app launches, not individual Mac boots. Missing files are listed explicitly.
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

#if canImport(UIKit)
import UIKit
import SwiftUI
import GameController
import Darwin

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
        ]
        queue.async {
            run = initial
            if !canWriteRunMetadata { HengeLog.log("diagnostics", "metadata rotation failed; preserving existing files") }
            sample("launch")
        }
        let center = NotificationCenter.default
        for (notification, event) in [
            (UIApplication.didReceiveMemoryWarningNotification, "memory_warning"),
            (UIApplication.didEnterBackgroundNotification, "entered_background"),
            (UIApplication.willEnterForegroundNotification, "entering_foreground"),
            (UIApplication.willTerminateNotification, "termination_notification"),
        ] {
            observers.append(center.addObserver(forName: notification, object: nil, queue: .main) { _ in
                queue.async {
                    if event == "memory_warning" { memoryWarnings += 1 }
                    sample(event)
                }
            })
        }
        let source = DispatchSource.makeTimerSource(queue: queue)
        source.schedule(deadline: .now() + 30, repeating: 30, leeway: .seconds(2))
        source.setEventHandler { sample("periodic") }
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
        if canWriteRunMetadata {
            do {
                let data = try JSONSerialization.data(withJSONObject: run, options: [.prettyPrinted, .sortedKeys])
                try data.write(to: currentURL, options: .atomic)
            } catch {
                HengeLog.log("diagnostics", "metadata write failed (\((error as NSError).code))")
            }
        }
        HengeLog.flushNow()
    }

    static func export() async throws -> URL {
        try await withCheckedThrowingContinuation { continuation in
            queue.async {
                do {
                    sample("export_requested")
                    let folder = FileManager.default.temporaryDirectory.appendingPathComponent("HengeDiagnostics", isDirectory: true)
                    try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
                    // Old share-sheet attachments need not accumulate indefinitely.
                    let cutoff = Date().addingTimeInterval(-7 * 24 * 60 * 60)
                    for url in (try? FileManager.default.contentsOfDirectory(at: folder, includingPropertiesForKeys: [.contentModificationDateKey])) ?? [] {
                        if let date = try? url.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate, date < cutoff {
                            try? FileManager.default.removeItem(at: url)
                        }
                    }
                    let output = folder.appendingPathComponent("Henge-diagnostics-\(Int(Date().timeIntervalSince1970))-\(UUID().uuidString.prefix(8)).txt")
                    // Also works when metadata rotation/writing failed: never
                    // mislabel a retained old JSON file as the current run.
                    let currentSnapshot = output.deletingPathExtension().appendingPathExtension("json")
                    try JSONSerialization.data(withJSONObject: run, options: [.prettyPrinted, .sortedKeys]).write(to: currentSnapshot)
                    let files: [DiagnosticReportWriter.Source] = [
                        .init(name: "current-run.json", url: currentSnapshot),
                        .init(name: "previous-run.json", url: previousURL),
                        .init(name: "henge.log", url: HengeLog.logFileURL),
                        .init(name: "henge-prev.log", url: HengeLog.previousLogURL),
                        .init(name: "henge-native.log", url: HengeLog.nativeLogURL),
                        .init(name: "henge-native-prev.log", url: HengeLog.previousNativeLogURL),
                    ]
                    // Keep periodic observations running during a large export.
                    exportQueue.async {
                        defer { try? FileManager.default.removeItem(at: currentSnapshot) }
                        do {
                            try DiagnosticReportWriter.write(to: output, sources: files, privateRoots: [NSHomeDirectory()])
                            continuation.resume(returning: output)
                        } catch {
                            try? FileManager.default.removeItem(at: output)
                            continuation.resume(throwing: error)
                        }
                    }
                } catch { continuation.resume(throwing: error) }
            }
        }
    }
}

struct DiagnosticsExportButton: View {
    @State private var preparing = false
    @State private var reportURL: URL?
    @State private var failure: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Button {
                preparing = true
                Task {
                    do { reportURL = try await Diagnostics.export() }
                    catch { failure = "Could not create the report. Check free storage and try again. (\((error as NSError).code))" }
                    preparing = false
                }
            } label: {
                if preparing { HStack { ProgressView(); Text("Preparing diagnostics…") } }
                else { Label(reportURL == nil ? "Export diagnostics" : "Refresh diagnostics", systemImage: "doc.text") }
            }
            .buttonStyle(.borderless)
            .disabled(preparing)
            if let url = reportURL {
                // Use the platform's existing ShareLink presentation, including
                // its iPad popover anchor, rather than a custom activity sheet.
                ShareLink(item: url) { Label("Share diagnostics", systemImage: "square.and.arrow.up") }
                    .buttonStyle(.borderless)
                    .disabled(preparing)
            }
        }
        .alert("Diagnostics export failed", isPresented: Binding(get: { failure != nil }, set: { if !$0 { failure = nil } })) {
            Button("OK") { failure = nil }
        } message: { Text(failure ?? "") }
    }
}
#endif
