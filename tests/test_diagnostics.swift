// SPDX-License-Identifier: GPL-2.0-or-later
import Foundation

// Foundation-only: swiftc ios/Henge/Diagnostics.swift tests/test_diagnostics.swift -o /tmp/test_diagnostics
// On macOS, UIKit-dependent collection and UI are excluded from this test build.
@main
struct DiagnosticsTests {
    static var failures = 0
    static func check(_ condition: Bool, _ message: String) {
        print("\(condition ? "ok  " : "FAIL") \(message)")
        if !condition { failures += 1 }
    }

    static func main() throws {
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
        print(failures == 0 ? "diagnostics: all checks passed" : "diagnostics: \(failures) failure(s)")
        if failures > 0 { throw NSError(domain: "DiagnosticsTests", code: failures) }
    }
}
