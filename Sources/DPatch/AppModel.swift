import Foundation
import SwiftUI

enum DayFilter: Hashable {
    case all
    case day(Date)
}

/// Fix sources the list can be filtered by.
enum FixKind: String, CaseIterable, Identifiable {
    case homebrew = "Homebrew"
    case appStore = "App Store"
    case apple = "Apple Software Update"

    var id: String { rawValue }

    init(_ method: FixMethod) {
        switch method {
        case .brewFormula, .brewCask, .brewCaskReplace: self = .homebrew
        case .appStore: self = .appStore
        case .softwareUpdate: self = .apple
        }
    }
}

struct DaySummary: Identifiable {
    var day: Date
    /// Distinct CVEs per severity published that day.
    var counts: [Severity: Int]
    var id: Date { day }
}

@MainActor
final class AppModel: ObservableObject {
    @Published var result: ScanResult?
    @Published var isScanning = false
    @Published var status = ""
    @Published var errorMessage: String?
    @Published var filter: DayFilter? = .all
    @Published var checked: Set<String> = []
    @Published var expanded: Set<String> = []
    @Published var search = ""
    /// List filters; an empty severity set shows every level.
    @Published var severityFilter: Set<Severity> = []
    @Published var fixFilter: FixKind?
    @Published var hideMajorUpgrades = false

    private var observer: NSObjectProtocol?

    init() {
        load()
        // A scheduled scan runs in a separate process; reload when it finishes.
        observer = DistributedNotificationCenter.default().addObserver(
            forName: Scanner.completedNotification, object: nil, queue: .main
        ) { [weak self] _ in
            Task { @MainActor in if self?.isScanning == false { self?.load() } }
        }
    }

    func load() {
        result = Storage.load(ScanResult.self, from: Storage.resultsURL)
        let ids = Set(result?.findings.map(\.id) ?? [])
        checked.formIntersection(ids)
    }

    func scan() {
        guard !isScanning else { return }
        isScanning = true
        errorMessage = nil
        status = "Starting scan…"
        Task.detached {
            do {
                let r = try await Scanner.run { msg in Task { @MainActor in self.status = msg } }
                await MainActor.run {
                    self.result = r
                    self.checked.formIntersection(Set(r.findings.map(\.id)))
                    self.status = ""
                    self.isScanning = false
                }
            } catch {
                await MainActor.run {
                    self.errorMessage = error.localizedDescription
                    self.status = ""
                    self.isScanning = false
                }
            }
        }
    }

    var findings: [Finding] { result?.findings ?? [] }

    var days: [DaySummary] {
        let cal = Calendar.current
        var byDay: [Date: [String: Severity]] = [:]
        for f in filtered { byDay[cal.startOfDay(for: f.cve.published), default: [:]][f.cve.id] = f.cve.severity }
        return byDay.map { day, cves in
            DaySummary(day: day, counts: Dictionary(grouping: cves.values, by: { $0 }).mapValues(\.count))
        }
        .sorted { $0.day > $1.day }
    }

    var filtersActive: Bool { !severityFilter.isEmpty || fixFilter != nil || hideMajorUpgrades }

    func clearFilters() {
        severityFilter = []
        fixFilter = nil
        hideMajorUpgrades = false
    }

    /// Severity levels present in the results, highest first.
    var severitiesFound: [Severity] { Set(findings.map(\.cve.severity)).sorted(by: >) }

    /// Findings that pass the severity, fix and major-upgrade filters (all dates).
    var filtered: [Finding] {
        findings.filter { f in
            (severityFilter.isEmpty || severityFilter.contains(f.cve.severity))
                && (fixFilter == nil || FixKind(f.fix.method) == fixFilter)
                && !(hideMajorUpgrades && f.isMajorUpgrade)
        }
    }

    var visible: [Finding] {
        var list = filtered
        if case .day(let d)? = filter {
            list = list.filter { Calendar.current.isDate($0.cve.published, inSameDayAs: d) }
        }
        let q = search.trimmingCharacters(in: .whitespaces)
        if !q.isEmpty {
            list = list.filter {
                $0.cve.id.localizedCaseInsensitiveContains(q) || $0.item.name.localizedCaseInsensitiveContains(q)
                    || $0.cve.summary.localizedCaseInsensitiveContains(q)
            }
        }
        return list
    }

    var checkedFindings: [Finding] { findings.filter { checked.contains($0.id) } }

    /// Ticked findings the current filters or date hide.
    var hiddenCheckedCount: Int { checked.subtracting(visible.map(\.id)).count }

    func toggleSeverityFilter(_ s: Severity) {
        if severityFilter.contains(s) { severityFilter.remove(s) } else { severityFilter.insert(s) }
    }

    func toggle(_ f: Finding) {
        if checked.contains(f.id) { checked.remove(f.id) } else { checked.insert(f.id) }
    }

    func toggleExpanded(_ f: Finding) {
        if expanded.contains(f.id) { expanded.remove(f.id) } else { expanded.insert(f.id) }
    }

    /// Ticks or unticks every finding currently shown.
    func setAllVisible(_ on: Bool) {
        let ids = visible.map(\.id)
        if on { checked.formUnion(ids) } else { checked.subtract(ids) }
    }
}
