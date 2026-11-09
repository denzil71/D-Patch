import Testing

@testable import DPatch

@Suite struct VersionTests {
    @Test func comparesNumericPartsAsNumbers() throws {
        #expect(try #require(Version("1.2.10")) > #require(Version("1.2.9")))
        #expect(try #require(Version("10.0")) > #require(Version("9.99")))
    }

    @Test func missingPartsCountAsZero() throws {
        #expect(try #require(Version("1.2")) == #require(Version("1.2.0")))
    }

    @Test func preReleaseSortsBeforeRelease() throws {
        #expect(try #require(Version("1.0rc1")) < #require(Version("1.0")))
        #expect(try #require(Version("2.0-beta")) < #require(Version("2.0")))
    }

    @Test func ignoresPrefixesAndHomebrewSuffixes() throws {
        #expect(try #require(Version("v2.0")) == #require(Version("2.0")))
        // Homebrew revision "_N" and cask build ",N" aren't part of the upstream version.
        #expect(try #require(Version("3.5.1_1")) == #require(Version("3.5.1")))
        #expect(try #require(Version("4.95.0,242831")) == #require(Version("4.95.0")))
    }

    @Test func keepsTheOriginalText() throws {
        #expect(try #require(Version(" v1.2_3")).description == " v1.2_3")
    }

    @Test(arguments: ["", "abc", "beta1", "-"])
    func rejectsTextThatDoesNotStartWithANumber(_ text: String) {
        #expect(Version(text) == nil)
    }

    @Test func isLessSortsUnparseableFirst() {
        #expect(Version.isLess("1.0", "1.1"))
        #expect(!Version.isLess("1.1", "1.0"))
        #expect(Version.isLess("unknown", "1.0"))
        #expect(!Version.isLess("1.0", "unknown"))
    }

    @Test func findsTheFirstVersionInText() {
        #expect(Version.firstToken(in: "1.18.0 or later") == "1.18.0")
        #expect(Version.firstToken(in: "Fixed in version 3.2-rc1.") == "3.2-rc1")
        #expect(Version.firstToken(in: "no version here") == nil)
    }

    @Test func normalizesNames() {
        #expect(normalizeName("Visual Studio Code") == "visualstudiocode")
        #expect(normalizeName("visual_studio-code") == "visualstudiocode")
    }
}
