import Foundation
import CoreFoundation

/// A connection observation and an installer receipt are different facts.
/// Missing/stale heartbeats never establish whether a helper is installed.
struct HelperHealthSnapshot: Equatable {
    enum Startup: String { case unseen, network_ready, clipboard_starting, ready, clipboard_unavailable }
    enum Install: String { case not_started, script_started, downloaded, verified, replacing, launch_requested, confirmed, failed, rolled_back }
    enum InstallError: String {
        case none, download_failed, gzip_invalid, signature_invalid, version_invalid, replace_failed, plist_invalid
        case bootout_failed, bootstrap_failed, connection_failed, health_unconfirmed, rollback_failed
    }
    let valid: Bool
    let session: String
    let helperProtocol: Int
    let helperPID: Int
    let agentSeenSeconds: Int
    let probeSeenSeconds: Int
    let installSeenSeconds: Int
    let startup: Startup
    let install: Install
    let installError: InstallError
    let installExitCode: Int

    static let unavailable = HelperHealthSnapshot(valid: false, session: "", helperProtocol: 0, helperPID: 0,
        agentSeenSeconds: -1, probeSeenSeconds: -1, installSeenSeconds: -1,
        startup: .unseen, install: .not_started, installError: .none, installExitCode: 0)

    static func decode(_ data: Data) -> HelperHealthSnapshot {
        func integer(_ value: Any?, _ range: ClosedRange<Int>) -> Int? {
            guard let value = value as? NSNumber, CFGetTypeID(value) != CFBooleanGetTypeID(),
                  value.doubleValue.isFinite, value.doubleValue.rounded(.towardZero) == value.doubleValue,
                  value.doubleValue >= Double(range.lowerBound), value.doubleValue <= Double(range.upperBound) else { return nil }
            return value.intValue
        }
        guard data.count <= 8192, let raw = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              integer(raw["protocol"], 1...1) == 1,
              let session = raw["session"] as? String, session.isEmpty || UUID(uuidString: session) != nil,
              let helperProtocol = integer(raw["helper_protocol"], 0...65535),
              let pid = integer(raw["helper_pid"], 0...Int(Int32.max)),
              let seen = integer(raw["agent_seen_s"], -1...Int(Int32.max)),
              let probe = integer(raw["probe_seen_s"], -1...Int(Int32.max)),
              let installed = integer(raw["install_seen_s"], -1...Int(Int32.max)),
              let startup = (raw["startup_stage"] as? String).flatMap(Startup.init(rawValue:)),
              let install = (raw["install_stage"] as? String).flatMap(Install.init(rawValue:)),
              let error = (raw["install_error"] as? String).flatMap(InstallError.init(rawValue:)),
              let exit = integer(raw["install_exit_code"], 0...255) else { return .unavailable }
        return HelperHealthSnapshot(valid: true, session: session, helperProtocol: helperProtocol, helperPID: pid,
            agentSeenSeconds: seen, probeSeenSeconds: probe, installSeenSeconds: installed,
            startup: startup, install: install, installError: error, installExitCode: exit)
    }

    var isConnected: Bool { valid && !session.isEmpty && helperProtocol == 4 && agentSeenSeconds >= 0 && agentSeenSeconds < 30 }
    var connectionTitle: String {
        if !valid { return "Status unavailable" }
        if session.isEmpty { return "Mac is not running" }
        if isConnected { return "Connected" }
        if agentSeenSeconds >= 0 && agentSeenSeconds < 30 && helperProtocol != 4 { return "Helper version differs" }
        return agentSeenSeconds < 0 ? "Waiting for connection" : "Connection interrupted"
    }
    var installationTitle: String {
        switch install {
        case .not_started: return "No installer receipt"
        case .script_started, .downloaded, .verified, .replacing: return "Installing…"
        case .launch_requested: return "Waiting for helper startup"
        case .confirmed: return "Installation confirmed"
        case .failed: return "Installation failed"
        case .rolled_back: return "Previous helper restored"
        }
    }
    var detail: String {
        if !valid { return "Helper status could not be read. The diagnostic report records this state." }
        if install == .failed || install == .rolled_back {
            let reason: String
            switch installError {
            case .none: reason = "The installer did not confirm success."
            case .download_failed: reason = "The helper download failed."
            case .gzip_invalid: reason = "The downloaded helper was incomplete or invalid."
            case .signature_invalid: reason = "The helper signature check failed."
            case .version_invalid: reason = "The downloaded helper did not report the expected version."
            case .replace_failed: reason = "The helper file could not be replaced."
            case .plist_invalid: reason = "The startup configuration was invalid."
            case .bootout_failed: reason = "The previous helper could not be stopped."
            case .bootstrap_failed: reason = "macOS did not start the replacement helper."
            case .connection_failed: reason = "The helper could not reach Henge."
            case .health_unconfirmed: reason = "The installer did not receive the startup heartbeat."
            case .rollback_failed: reason = "The installer could not restore the previous helper."
            }
            return "\(reason) Exit code \(installExitCode). The result is included in diagnostics."
        }
        if isConnected && startup == .clipboard_unavailable { return "The helper is connected. Clipboard access is unavailable; its health connection continues independently." }
        if isConnected && startup == .clipboard_starting { return "The helper is connected. Clipboard initialization is still pending." }
        if isConnected { return "The helper has a recent connection. Installation is not needed each time you open Details." }
        if install == .confirmed { return "Installation was confirmed, but there is no recent connection. Henge is waiting for the helper to reconnect." }
        return "Henge is waiting for a connection. This status does not determine whether the helper is installed."
    }
    var diagnostics: [String: Any] {
        ["status_available": valid, "session": session, "helper_protocol": helperProtocol, "helper_pid": helperPID,
         "connected": isConnected, "agent_seen_seconds": agentSeenSeconds, "probe_seen_seconds": probeSeenSeconds,
         "install_seen_seconds": installSeenSeconds, "startup_stage": startup.rawValue, "install_stage": install.rawValue,
         "install_error": installError.rawValue, "install_exit_code": installExitCode]
    }
}

#if canImport(UIKit)
import SwiftUI
import UIKit

/// What a running Mac shares with this device: the Shared folder in Files, and the clipboard. The Mac mounts
/// the folder and follows the clipboard through a small helper (host/share.c, tools/henge-agent.m).
enum Sharing {
    static var folder: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0].appendingPathComponent("Shared", isDirectory: true)
    }

    static let setUpCommand = #"henge_installer=$(mktemp -t henge-install) && { curl --fail --show-error --connect-timeout 3 --max-time 20 http://10.0.2.4/.henge/install -o "$henge_installer" && sh "$henge_installer"; henge_result=$?; rm -f "$henge_installer"; (exit "$henge_result"); }"#
    /// Less background work and drawing in macOS (host/share.c, lighten_script), and back.
    static let lightenCommand = "curl -s http://10.0.2.4/.henge/lighten | sh"
    static let unlightenCommand = "curl -s http://10.0.2.4/.henge/unlighten | sh"

    /// Before a Mac starts.
    @MainActor static func prepare() {
        try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        // A Unix socket's path can't be long, so the short temporary folder.
        let socket = (NSTemporaryDirectory() as NSString).appendingPathComponent("s.sock")
        henge_vm_share(folder.path, socket, Bundle.main.path(forResource: "henge-agent", ofType: "gz"))
        HostServices.shared.begin()
        GuestChatDiagnostics.prepare()
    }

    /// The helper asks the server for news at most 25 s apart.
    /// This is clipboard liveness, not an installation detector.
    static var helperRunning: Bool {
        let seen = henge_share_agent_seen()
        return seen >= 0 && seen < 40
    }

    /// The dedicated heartbeat is independent of NSPasteboard and is safe to
    /// sample from the diagnostic writer's utility queue as well as the UI.
    static var helperHealth: HelperHealthSnapshot {
        guard let json = henge_share_helper_health() else { return .unavailable }
        defer { free(json) }
        let count = strnlen(json, 8193)
        guard count <= 8192 else { return .unavailable }
        return HelperHealthSnapshot.decode(Data(bytes: json, count: count))
    }

    /// What is copied on the Mac is copied here too. The other way needs the system's paste button: iOS
    /// asks for permission whenever an app reads the clipboard on its own.
    @MainActor static func followMacClipboard() async {
        defer { HostServices.shared.end() }
        while !Task.isCancelled {
            HostServices.shared.poll()
            if let text = henge_share_take_clipboard() {
                UIPasteboard.general.string = String(cString: text)
                free(text)
            }
            try? await Task.sleep(nanoseconds: 500_000_000)
        }
    }

    /// Text from this device, pasted at the Mac's cursor. Without the helper it is typed, as far as the keyboard can.
    static func paste(_ text: String) {
        Task { @MainActor in
            if helperRunning {
                henge_share_set_clipboard(text)
                try? await Task.sleep(nanoseconds: 800_000_000) // for the helper to put it on the Mac's clipboard
                Keys.chord(Keys.command, "v")
            } else {
                await Keys.typeSlowly(text)
            }
        }
    }

    /// Types the set up command at the Mac's cursor, and stops there: the person using the Mac presses Return.
    /// Henge can't see what has the keyboard, so it must not submit anything by itself. Opening Terminal for them
    /// through Spotlight was tried: when Spotlight was slow the text went to a web search, and it could as easily
    /// have gone to a chat.
    static func typeSetUpCommand() async {
        HengeLog.log("sharing", "event=command_typing_started")
        await Keys.typeSlowly(setUpCommand)
        HengeLog.log("sharing", "event=command_typing_finished")
    }
}
#endif
