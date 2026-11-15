import Foundation

#if canImport(DeviceCheck)
import DeviceCheck
#endif

/// A capability observation in Henge's host process, not a guest authentication service.
/// Deliberately never generates, stores, or forwards a DeviceCheck token.
enum HostDeviceCheckProbe {
    static func snapshot() -> [String: Any] {
        var result: [String: Any] = [
            "scope": "henge_host_process",
            "api": "DCDevice.current.isSupported",
            "token_generation_attempted": false,
            "guest_forwarding_implemented": false,
            "interpretation": "Host API support does not establish DeviceCheck support in the macOS guest or acceptance by Chat.",
        ]

        #if canImport(DeviceCheck)
        if #available(iOS 11.0, macOS 10.15, tvOS 11.0, watchOS 9.0, *) {
            result["framework_available"] = true
            result["is_supported"] = DCDevice.current.isSupported
        } else {
            result["framework_available"] = false
            result["is_supported"] = NSNull()
            result["unavailable_reason"] = "operating_system_api_unavailable"
        }
        #else
        result["framework_available"] = false
        result["is_supported"] = NSNull()
        result["unavailable_reason"] = "framework_not_in_build"
        #endif

        return result
    }
}
