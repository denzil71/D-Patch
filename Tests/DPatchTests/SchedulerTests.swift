import Testing

@testable import DPatch

@Suite struct SchedulerTests {
    @Test func installedLocationsCanBeScheduled() {
        #expect(Scheduler.unsupportedLocation("/Applications/D-Patch.app/Contents/MacOS/DPatch") == nil)
        #expect(Scheduler.unsupportedLocation("/Users/me/Applications/D-Patch.app/Contents/MacOS/DPatch") == nil)
    }

    @Test func translocatedCopyCannotBeScheduled() {
        let path =
            "/private/var/folders/ab/xyz/T/AppTranslocation/1F2E3D4C-0000-1111-2222-333344445555/d/D-Patch.app/Contents/MacOS/DPatch"
        #expect(Scheduler.unsupportedLocation(path) != nil)
    }

    @Test func diskImageCopyCannotBeScheduled() {
        #expect(Scheduler.unsupportedLocation("/Volumes/D-Patch 0.6.2/D-Patch.app/Contents/MacOS/DPatch") != nil)
    }
}
