// SPDX-License-Identifier: GPL-2.0-or-later
import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// Foundation-only: swiftc ios/Henge/Diagnostics.swift tests/test_diagnostics.swift -o /tmp/test_diagnostics
// On macOS, UIKit-dependent collection and UI are excluded from this test build.
@main
struct DiagnosticsTests {
    static var failures = 0
    static func check(_ condition: Bool, _ message: String, details: @autoclosure () -> String = "") {
        print("\(condition ? "ok  " : "FAIL") \(message)")
        if !condition {
            failures += 1
            let detail = details()
            if !detail.isEmpty { print("     \(detail)") }
        }
        // CI pipes stdout through tee. A failed top-level Swift throw traps
        // without flushing libc's fully buffered stdout on Darwin.
        fflush(stdout)
    }

    static func main() {
        do { try runChecks() }
        catch {
            print("diagnostics: test run failed: \(error)")
            fflush(stdout)
            fflush(stderr)
            exit(EXIT_FAILURE)
        }
    }

    static func runChecks() throws {
        let fm = FileManager.default
        let folder = fm.temporaryDirectory.appendingPathComponent("henge-diagnostics-test-\(UUID().uuidString)")
        try fm.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: folder) }

        var filter = DiagnosticLogFilter(privateRoots: ["/example/private-container"])
        let sensitive = [
            "Authorization: Bearer fixture-secret\n",
            "{\"refresh_token\":\"fixture-secret\"}\n",
            "{\"input_text\":\"fixture-secret\"}\n",
            "clipboard: fixture-secret\n",
            "visit https://example.invalid/path?code=fixture-secret\n",
            "email fixture-secret@example.invalid\n",
            "[tuning] CUSTOM_OPTION=fixture-secret\n",
        ]
        for (index, line) in sensitive.enumerated() {
            check(!filter.filter(line, endsLine: true).contains("fixture-secret"), "recognized sensitive field \(index) is filtered")
        }
        let fatal = "*** FATAL SIGNAL 11 -- process is dying ***\n"
        let metal = "-[AGXCommandBuffer waitUntilCompleted]: error 3 at 0x12345678\n"
        let stack = "0   Henge  0x0000000100001234 henge_vm_boot + 44\n"
        for line in [fatal, metal, stack, "[diagnostics] allocation_headroom_bytes=2147483648\n"] {
            check(filter.filter(line, endsLine: true) == line, "fatal, Metal, stack and memory evidence is preserved")
        }
        check(!filter.filter("/example/private-container/Documents/henge.log\n", endsLine: true).contains("/example/private-container"), "private container root is removed")
        _ = filter.filter("-----BEGIN PRIVATE KEY-----\n", endsLine: true)
        check(!filter.filter("fixture-private-key-data\n", endsLine: true).contains("fixture-private-key-data"), "multiline private key is filtered")
        _ = filter.filter("-----END PRIVATE KEY-----\n", endsLine: true)
        check(filter.filter(fatal, endsLine: true) == fatal, "normal evidence resumes after a private key")

        let current = folder.appendingPathComponent("current.log")
        let previous = folder.appendingPathComponent("previous.log")
        let output = folder.appendingPathComponent("report.txt")
        let longLine = "metal-diagnostic: " + String(repeating: "unicode-诊断-", count: 30_000) + " LONG-LINE-END\n"
        let longSecret = "Authorization: " + String(repeating: "fixture-secret", count: 25_000) + "\n"
        let boundarySecret = String(repeating: " ", count: 65_530) + "Authorization: fixture-secret\n"
        let currentText = "CURRENT-FIRST\n" + String(repeating: "engine observation\n", count: 20_000) + longLine + longSecret + boundarySecret + fatal + metal + stack + "CURRENT-LAST-without-newline"
        let previousText = "PREVIOUS-FIRST\nprevious engine state\nPREVIOUS-LAST\n"
        try Data(currentText.utf8).write(to: current)
        try Data(previousText.utf8).write(to: previous)
        let link = folder.appendingPathComponent("unexpected-link.log")
        try fm.createSymbolicLink(at: link, withDestinationURL: previous)
        try DiagnosticReportWriter.write(to: output, sources: [
            .init(name: "current", url: current), .init(name: "previous", url: previous),
            .init(name: "missing", url: folder.appendingPathComponent("absent.log")),
            .init(name: "symlink", url: link),
        ])
        let report = try String(contentsOf: output, encoding: .utf8)
        for marker in ["CURRENT-FIRST", "CURRENT-LAST-without-newline", "PREVIOUS-FIRST", "PREVIOUS-LAST"] {
            check(report.contains(marker), "full current/previous time range: \(marker)")
        }
        check(report.contains(longLine), "large UTF-8 diagnostic line survives bounded streaming without truncation")
        check(!report.contains("fixture-secret"), "large credential line remains filtered across chunks")
        check(report.contains(fatal + metal + stack), "crash evidence after a large sensitive line is preserved")
        check(report.contains("[unavailable: missing or unreadable]"), "missing previous source is explicit")
        check(report.contains("[unavailable: not a regular file]"), "export does not follow a substituted symlink")
        check(report.contains("read \(currentText.utf8.count)/\(currentText.utf8.count) source bytes"), "report accounts for the complete source byte range")
        check(try Data(contentsOf: current) == Data(currentText.utf8), "export leaves the original log unchanged")
        // In particular, a two-read buffer of exactly 64 KiB can end with just
        // the leading byte of a scalar. Keep that byte for the next read.
        for boundary in [32_768, 65_536, 131_072] {
            for scalar in ["é", "诊", "🧪"] {
                let crossing = String(repeating: "x", count: boundary - 1) + scalar + String(repeating: "y", count: 10_000) + "\n"
                try Data(crossing.utf8).write(to: current)
                try DiagnosticReportWriter.write(to: output, sources: [.init(name: "unicode", url: current)])
                let exported = try String(contentsOf: output, encoding: .utf8)
                check(exported.contains(crossing), "UTF-8 scalar (\(scalar.utf8.count) bytes) survives boundary \(boundary)")
            }
        }
        try checkArchive(in: folder)
        checkThrottle()
        print(failures == 0 ? "diagnostics: all checks passed" : "diagnostics: \(failures) failure(s)")
        if failures > 0 { throw NSError(domain: "DiagnosticsTests", code: failures) }
    }

    static func checkArchive(in folder: URL) throws {
        let fm = FileManager.default
        let directory = folder.appendingPathComponent("HengeDiagnostics", isDirectory: true)
        var store = DiagnosticReportStore(directory: directory)
        check(store.historyLimit == 8, "automatic retention defaults to eight app runs")
        store.historyLimit = 3
        func identity(_ index: Int) -> DiagnosticRunIdentity {
            DiagnosticRunIdentity(metadata: [
                "run_id": "fixture\(index)-run", "started_utc": "2026-11-15T14:00:0\(index)Z",
                "app_version": "0.4.0", "app_build": "4003", "pid": NSNumber(value: 100 + index),
            ])!
        }
        check(DiagnosticRunIdentity(metadata: ["run_id": "old", "started_utc": "unknown"]) == nil,
              "missing previous-run identity cannot be mislabelled as current")
        let source = folder.appendingPathComponent("archive-source.log")
        let inputs = directory.appendingPathComponent("Inputs", isDirectory: true)
        try fm.createDirectory(at: inputs, withIntermediateDirectories: true)
        let guest = inputs.appendingPathComponent("guest-chat.json")
        try Data("{\"collection_status\":\"complete\",\"token\":\"fixture-secret\"}\n".utf8).write(to: guest)
        try Data("FIRST-SNAPSHOT\n".utf8).write(to: source)
        let sources: [DiagnosticReportWriter.Source] = [.init(name: "current", url: source), .init(name: "guest-summary", url: guest)]
        let first = try store.publish(identity: identity(0), sources: sources)
        let firstBytes = try Data(contentsOf: first.latestURL)
        check(first.latestURL.lastPathComponent == "Latest-Henge-diagnostics.txt", "one predictable Files entry identifies the combined report")
        check(first.archiveURL.lastPathComponent.contains("2026-11-15T140000Z-v0.4.0-b4003-pid100"),
              "history name identifies run time, version, build and PID")
        check(first.bytes == firstBytes.count, "successful publication reports the actual byte count")
        check(firstBytes == (try Data(contentsOf: first.archiveURL)), "Latest and the run archive contain the complete same snapshot")
        let firstText = String(decoding: firstBytes, as: UTF8.self)
        check(firstText.contains("PID 100") && firstText.contains("guest-summary") && !firstText.contains("fixture-secret"),
              "automatic publication includes identity and applies filtering to explicit guest input")

        let attachment = try store.attachment(from: first, in: folder.appendingPathComponent("attachments", isDirectory: true))
        try Data("SECOND-SNAPSHOT\n".utf8).write(to: source)
        let second = try store.publish(identity: identity(0), sources: sources)
        check(first.archiveURL == second.archiveURL, "periodic updates replace the same run archive")
        check(try Data(contentsOf: attachment) == firstBytes, "a presented attachment remains unchanged when automatic saving replaces Latest")
        let secondBytes = try Data(contentsOf: second.latestURL)
        check(String(decoding: secondBytes, as: UTF8.self).contains("SECOND-SNAPSHOT"), "Latest advances to the new complete report")
        do {
            _ = try store.publish(identity: identity(0)) { temporary in
                try Data("PARTIAL-FAILED-WRITE".utf8).write(to: temporary)
                throw CocoaError(.fileWriteOutOfSpace)
            }
            check(false, "a partial write must fail")
        } catch {
            check(try Data(contentsOf: second.latestURL) == secondBytes, "failed partial write leaves Latest intact")
            check(try Data(contentsOf: second.archiveURL) == secondBytes, "failed partial write leaves the run archive intact")
        }
        do {
            _ = try store.publish(identity: identity(0), sources: [.init(name: "accidental-recursion", url: store.latestURL)])
            check(false, "including a generated report must fail")
        } catch {
            check(try Data(contentsOf: store.latestURL) == secondBytes, "generated reports cannot recursively become report sources")
        }
        for run in 1...5 { _ = try store.publish(identity: identity(run), sources: sources) }
        let history = try fm.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
            .filter { $0.lastPathComponent.hasPrefix("Henge-diagnostics-") && $0.pathExtension == "txt" }
        check(history.count == 3, "retention bounds app-run history, not the number of automatic snapshots",
              details: "count=\(history.count), files=\(history.map(\.lastPathComponent))")
        let expected = directory.appendingPathComponent(identity(5).filename)
        check(history.contains(expected), "retention never removes the just-published run",
              details: "expected=\(expected.absoluteString), base=\(String(describing: expected.baseURL)); actual=\(history.map { "\($0.absoluteString) base=\(String(describing: $0.baseURL))" }); exists=\(fm.fileExists(atPath: expected.path))")
        check(fm.fileExists(atPath: guest.path), "retention does not delete explicit guest inputs")
        check(try Data(contentsOf: attachment) == firstBytes, "history pruning cannot delete or change a share attachment")
        let orphan = directory.appendingPathComponent(".pending-abandoned.txt")
        try Data("unfinished".utf8).write(to: orphan)
        try store.removeAbandonedWrites()
        check(!fm.fileExists(atPath: orphan.path) && fm.fileExists(atPath: store.latestURL.path), "next launch removes abandoned temporary writes and keeps the complete report")
        let pending = try fm.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
            .filter { $0.lastPathComponent.hasPrefix(".pending-") || $0.lastPathComponent.hasPrefix(".latest-") }
        check(pending.isEmpty, "success and failure leave no unpublished report fragments")
    }

    static func checkThrottle() {
        var throttle = DiagnosticReportThrottle()
        check(throttle.begin(now: 0, automatic: true), "launch can save the first report immediately")
        check(!throttle.begin(now: 200, automatic: true) && !throttle.begin(now: 200, automatic: false),
              "automatic and manual writes never overlap")
        throttle.finish()
        check(!throttle.begin(now: 100, automatic: true), "automatic snapshots are rate limited")
        check(throttle.begin(now: 100, automatic: false), "manual collection bypasses the periodic interval")
        throttle.finish()
        check(!throttle.begin(now: 110, automatic: true), "manual collection also prevents an immediate redundant automatic copy")
        check(throttle.begin(now: 220, automatic: true), "periodic capture resumes after two minutes")
        throttle.finish()
        check(!throttle.begin(now: 241, automatic: true, minimumInterval: 30), "rapid background transitions do not repeatedly copy logs")
        check(throttle.begin(now: 250, automatic: true, minimumInterval: 30), "a background snapshot is eligible after the shorter interval")
        throttle.finish()
    }
}
