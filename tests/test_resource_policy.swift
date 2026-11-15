import Foundation

@main
struct ResourcePolicyTests {
    static func main() {
        var failures = 0
        var assertions = 0
        func check(_ condition: @autoclosure () -> Bool, _ message: String) {
            assertions += 1
            if !condition() { failures += 1; print("FAIL: \(message)") }
        }
        let suite = "henge.resource-policy-tests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        let eightGB = UInt64(8) << 30
        check(ResourcePolicy.selected(defaults: defaults, deviceModel: "iPad13,16", physicalMemory: 8_020_672_512),
              "reported 8 GB iPad defaults to reduced load")
        check(ResourcePolicy.defaultEnabled(deviceModel: "iPad13,16", physicalMemory: eightGB), "8 GiB boundary included")
        check(!ResourcePolicy.defaultEnabled(deviceModel: "iPad16,6", physicalMemory: UInt64(16) << 30), "16 GB device retains normal defaults")
        check(!ResourcePolicy.defaultEnabled(deviceModel: "iPhone17,1", physicalMemory: eightGB), "iPhone defaults unchanged")
        check(!ResourcePolicy.defaultEnabled(deviceModel: "iPad13,16", physicalMemory: 0), "unknown physical memory does not imply pressure")
        defaults.set(false, forKey: ResourcePolicy.reducedLoadKey)
        check(!ResourcePolicy.selected(defaults: defaults, deviceModel: "iPad13,16", physicalMemory: eightGB), "explicit opt-out survives default")
        defaults.set(true, forKey: ResourcePolicy.reducedLoadKey)
        check(ResourcePolicy.selected(defaults: defaults, deviceModel: "iPad16,6", physicalMemory: UInt64(16) << 30), "explicit opt-in on larger device")
        defaults.set(1536, forKey: "henge.perf.codeCacheMB")
        check(ResourcePolicy.codeCacheMB(requested: defaults.integer(forKey: "henge.perf.codeCacheMB"), fallback: 1024, reducedLoad: true) == 512,
              "saved large allocation capped")
        check(defaults.integer(forKey: "henge.perf.codeCacheMB") == 1536, "saved setting preserved")
        check(ResourcePolicy.codeCacheMB(requested: 1536, fallback: 1024, reducedLoad: false) == 1536, "opt-out restores saved allocation")
        check(ResourcePolicy.codeCacheMB(requested: -1, fallback: 1024, reducedLoad: false) == 1024, "invalid saved value falls back")
        check(ResourcePolicy.codeCacheMB(requested: -1, fallback: 1536, reducedLoad: true) == 512, "invalid value still capped")
        check(ResourcePolicy.codeCacheMB(requested: 512, fallback: 1024, reducedLoad: false) == 512, "existing 512 MB choice preserved")
        var environment = ["HV_HZ": "120", "HV_STATS": "10"]
        ResourcePolicy.applyRefreshLimit(to: &environment, reducedLoad: true)
        check(environment["HV_HZ"] == "30", "profile overrides advanced refresh input")
        check(environment["HV_STATS"] == "10", "unrelated settings untouched")
        environment = ["HV_HZ": "120"]
        ResourcePolicy.applyRefreshLimit(to: &environment, reducedLoad: false)
        check(environment["HV_HZ"] == "120", "opt-out preserves advanced override")
        print("Resource policy: \(assertions) checks, \(failures) failures")
        exit(failures == 0 ? 0 : 1)
    }
}
