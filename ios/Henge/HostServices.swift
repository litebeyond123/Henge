import SwiftUI
import UIKit
import AVFAudio

/// A small, explicit host-service bridge. All UIKit work happens on the main actor; the HTTP workers only
/// see snapshots and bounded requests. This does not forward account credentials or expose private radios.
@MainActor
final class HostServices: ObservableObject {
    static let shared = HostServices()

    @Published private(set) var available = false
    @Published private(set) var allowsBrightnessControl = false
    @Published private(set) var brightness = 0.0
    @Published private(set) var outputVolume = 0.0

    private var session: String?
    private var originalBrightness: CGFloat?
    private var lastAppliedBrightness: CGFloat?
    private var activityObservers: [NSObjectProtocol] = []

    private init() {
        HengeAuthInstallBridge()
        for name in [UIApplication.willResignActiveNotification, UIApplication.didEnterBackgroundNotification,
                     UIApplication.didBecomeActiveNotification] {
            activityObservers.append(NotificationCenter.default.addObserver(forName: name, object: nil, queue: .main) { [weak self] note in
                // The notification is delivered on the main queue. No UI event loop or dispatch_sync is used
                // by the C callback; publishing here also revokes pending requests as the app becomes inactive.
                MainActor.assumeIsolated {
                    if note.name == UIApplication.didBecomeActiveNotification { self?.publish() }
                    else { self?.publish(forceInactive: true) }
                }
            })
        }
    }

    func begin() {
        end()
        session = UUID().uuidString.lowercased()
        henge_host_services_begin(session!)
        publish()
    }

    func end() {
        henge_host_services_end()
        restoreBrightnessIfUnchanged()
        session = nil
        available = false
        allowsBrightnessControl = false
    }

    func setBrightnessControl(_ enabled: Bool) {
        guard session != nil, henge_vm_state() == 1 else { return }
        if enabled && !allowsBrightnessControl { originalBrightness = UIScreen.main.brightness }
        allowsBrightnessControl = enabled
        publish() // revoke before restoring, so a queued request cannot undo the restore
        if !enabled { restoreBrightnessIfUnchanged() }
        publish()
    }

    /// Sharing's session task calls this every half second and ends the service when that task is cancelled.
    func poll() {
        guard session != nil else { return }
        let state = henge_vm_state()
        if state == 0 || state == 2 { end(); return }
        publish()
        let processed = henge_host_services_process_brightness { value in
            MainActor.assumeIsolated {
                // A lifecycle notification may be queued behind this tick. Check UIKit again immediately
                // before the side effect. Never call any C service while its process callback holds the lock.
                guard UIApplication.shared.applicationState == .active else { return -1 }
                UIScreen.main.brightness = CGFloat(value)
                return Double(UIScreen.main.brightness)
            }
        }
        if processed > 0 {
            lastAppliedBrightness = UIScreen.main.brightness
            publish()
        }
    }

    /// Refresh the existing session immediately before an explicit authentication start.
    /// This never creates a session or substitutes a foreground/running value.
    func refreshForAuthenticationStart() { publish() }

    private func publish(forceInactive: Bool = false) {
        guard session != nil else { return }
        let running = henge_vm_state() == 1
        let foreground = !forceInactive && UIApplication.shared.applicationState == .active
        available = running && foreground
        brightness = Double(UIScreen.main.brightness)
        outputVolume = Double(AVAudioSession.sharedInstance().outputVolume)
        henge_host_services_publish(running ? 1 : 0, foreground ? 1 : 0, allowsBrightnessControl ? 1 : 0,
                                    brightness, outputVolume)
    }

    private func restoreBrightnessIfUnchanged() {
        // Preserve a subsequent change the person made in Control Center. UIKit otherwise keeps an app's
        // brightness change until lock; restore only the value that this session last applied.
        if let originalBrightness, let lastAppliedBrightness,
           abs(UIScreen.main.brightness - lastAppliedBrightness) < 0.005 {
            UIScreen.main.brightness = originalBrightness
        }
        originalBrightness = nil
        lastAppliedBrightness = nil
    }
}

/// Inserted in the running Mac's Details list. Opt-in is per session and is never persisted in UserDefaults.
struct HostServicesSection: View {
    @ObservedObject private var services = HostServices.shared

    var body: some View {
        Section("iPad services") {
            LabeledContent("Connection", value: services.available ? "Available" : "Mac or app inactive")
            LabeledContent("iPad screen brightness", value: "\(Int(services.brightness * 100))%")
            LabeledContent("iPad output volume", value: "\(Int(services.outputVolume * 100))% (read only)")
            Toggle("Allow Mac to change iPad brightness", isOn: Binding(
                get: { services.allowsBrightnessControl },
                set: { services.setBrightnessControl($0) }
            ))
            .disabled(!services.available)
            Text("The Mac can change the iPad's main screen only while Henge is active. Permission ends with this Mac session. If the screen still has the value set by the Mac, Henge restores its previous brightness.")
                .font(.footnote).foregroundStyle(.secondary)
            Text("Update the helper using the Sharing setup command. In the Mac's Terminal, run the following command to read the host state; use --host-brightness 0.6 to set 60% after enabling the switch above.")
                .font(.footnote).foregroundStyle(.secondary)
            Text("\"$HOME/Library/Application Support/Henge/henge-agent\" --host-state")
                .font(.caption.monospaced()).textSelection(.enabled)
        }
    }
}
