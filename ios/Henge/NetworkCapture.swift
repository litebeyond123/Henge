// SPDX-License-Identifier: GPL-2.0-or-later
#if os(iOS)
import Foundation
import CryptoKit

/// Native capture stores verified protocol headers in a bounded memory buffer.
/// Snapshot/file work is performed by the diagnostics export queue, never by
/// the VM packet callback. Raw HTTP/TLS/application bytes are not captured.
enum NetworkCapture {
    static func start(session: String, launchID: String) -> Int {
        let result = Int(hv_net_capture_start(session, launchID))
        HengeLog.log("network-capture", "action=start launch=\(launchID) result_code=\(result)")
        return result
    }

    static func stop(_ reason: HvNetCaptureStopReason) {
        hv_net_capture_stop(reason)
    }

    static var status: String {
        guard let raw = hv_net_capture_metadata_json() else { return "Unavailable" }
        defer { free(raw) }
        guard let data = String(cString: raw).data(using: .utf8),
              let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return "Unavailable" }
        if value["active"] as? Bool == true { return "Recording network headers" }
        if value["status"] as? String == "not_started" { return "Starts with the next authentication test" }
        return "Capture retained for diagnostics"
    }

    static func reportSources(in temporaryDirectory: URL, persistentDirectory: URL) -> [DiagnosticReportWriter.Source] {
        var rawMetadata: UnsafeMutablePointer<CChar>?
        var rawPackets: UnsafeMutablePointer<UInt8>?
        var packetLength = 0
        let result = hv_net_capture_snapshot(&rawMetadata, &rawPackets, &packetLength)
        defer { free(rawMetadata); free(rawPackets) }
        let prefix = "network-\(UUID().uuidString)"
        let metadataURL = temporaryDirectory.appendingPathComponent(prefix + ".json")
        let packetURL = temporaryDirectory.appendingPathComponent(prefix + ".pcap")
        var metadata: [String: Any] = ["protocol": 1, "status": "snapshot_failed", "error_code": Int(result)]
        var packets: Data?
        if result == 0, let rawMetadata,
           let data = String(cString: rawMetadata).data(using: .utf8), data.count <= 128 * 1024,
           let parsed = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            metadata = parsed
            if let rawPackets, packetLength >= 24, packetLength <= 2 * 1024 * 1024 {
                packets = Data(bytes: rawPackets, count: packetLength)
            } else if rawPackets != nil || packetLength != 0 {
                metadata["export_status"] = "invalid_packet_snapshot_size"
            }
        }
        metadata["pcap_encoding_in_report"] = "base64"
        metadata["exported_pcap_bytes"] = packets?.count ?? 0
        if let packets {
            metadata["pcap_sha256"] = SHA256.hash(data: packets).map { String(format: "%02x", $0) }.joined()
        }
        let folder = persistentDirectory.appendingPathComponent("Inputs/Network", isDirectory: true)
        let standaloneURL = folder.appendingPathComponent("Latest-Henge-network-headers.pcap")
        func removeStaleStandalone() {
            guard FileManager.default.fileExists(atPath: standaloneURL.path) else { return }
            do { try FileManager.default.removeItem(at: standaloneURL) }
            catch {
                metadata["standalone_cleanup_error_code"] = (error as NSError).code
                metadata["standalone_pcap_status"] = "stale_file_removal_failed"
            }
        }
        do {
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
            if let packets {
                try packets.write(to: standaloneURL, options: .atomic)
                metadata["standalone_pcap_status"] = "saved"
            } else {
                metadata["standalone_pcap_status"] = "no_current_capture"
                removeStaleStandalone()
            }
        } catch {
            metadata["standalone_pcap_status"] = "write_failed"
            metadata["standalone_pcap_error_code"] = (error as NSError).code
            removeStaleStandalone()
        }
        // The fixed standalone name has a current companion receipt even when
        // no capture exists. Combined reports use the paired native snapshot.
        do {
            let receipt = try JSONSerialization.data(withJSONObject: metadata, options: [.prettyPrinted, .sortedKeys])
            try receipt.write(to: folder.appendingPathComponent("Latest-Henge-network-capture.json"), options: .atomic)
        } catch {
            metadata["standalone_metadata_error_code"] = (error as NSError).code
        }
        var sources: [DiagnosticReportWriter.Source] = []
        do {
            if let packets {
                try packets.write(to: packetURL, options: .atomic)
                sources.append(.init(name: "network-headers.pcap", url: packetURL, packetHeadersBase64: true))
            }
            let data = try JSONSerialization.data(withJSONObject: metadata, options: [.prettyPrinted, .sortedKeys])
            try data.write(to: metadataURL, options: .atomic)
            sources.insert(.init(name: "network-capture-summary.json", url: metadataURL), at: 0)
            return sources
        } catch {
            HengeLog.log("network-capture", "action=snapshot_write_failed error_code=\((error as NSError).code)")
            try? FileManager.default.removeItem(at: metadataURL)
            try? FileManager.default.removeItem(at: packetURL)
            return [.init(name: "network-capture-summary.json", url: metadataURL)]
        }
    }
}
#endif
