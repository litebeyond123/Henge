import Foundation

/// A reversible test configuration. It does not resize guest RAM or change a
/// Mac's saved configuration. JIT memory is fixed for the process lifetime, so
/// both limits use the selection captured when Henge starts.
enum ResourcePolicy {
    static let reducedLoadKey = "henge.perf.reducedLoad"

    static func defaultEnabled(deviceModel: String, physicalMemory: UInt64) -> Bool {
        deviceModel.hasPrefix("iPad") && physicalMemory > 0 && physicalMemory <= UInt64(8) << 30
    }

    static func selected(defaults: UserDefaults, deviceModel: String, physicalMemory: UInt64) -> Bool {
        if let saved = defaults.object(forKey: reducedLoadKey) as? Bool { return saved }
        return defaultEnabled(deviceModel: deviceModel, physicalMemory: physicalMemory)
    }

    static func codeCacheMB(requested: Int, fallback: Int, reducedLoad: Bool) -> Int {
        let valid = [512, 1024, 1536].contains(requested) ? requested : fallback
        return reducedLoad ? min(valid, 512) : valid
    }

    /// Apply after the optional environment file too: an enabled profile must
    /// have the effective limit shown in Settings. Turning it off restores the
    /// user's saved refresh rate and advanced environment-file override.
    static func applyRefreshLimit(to environment: inout [String: String], reducedLoad: Bool) {
        if reducedLoad { environment["HV_HZ"] = "30" }
    }
}

#if canImport(UIKit)
extension ResourcePolicy {
    static let defaultReducedLoad = defaultEnabled(deviceModel: HengeLog.deviceModel,
                                                   physicalMemory: ProcessInfo.processInfo.physicalMemory)
    static let reducedLoadAtLaunch = selected(defaults: .standard, deviceModel: HengeLog.deviceModel,
                                              physicalMemory: ProcessInfo.processInfo.physicalMemory)

    static func snapshot() -> [String: Any] {
        [
            "reduced_load_at_launch": reducedLoadAtLaunch,
            "reduced_load_selected": selected(defaults: .standard, deviceModel: HengeLog.deviceModel,
                                               physicalMemory: ProcessInfo.processInfo.physicalMemory),
            "jit_region_mb": JITBootstrap.jitBytes >> 20,
            "effective_refresh_hz": getenv("HV_HZ").map { String(cString: $0) } ?? "unknown",
            "guest_ram_changed_by_policy": false,
        ]
    }
}
#endif
