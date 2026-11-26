import SwiftUI

struct SettingsView: View {
    var body: some View {
        TabView {
            GeneralSettings()
                .tabItem { Label("General", systemImage: "gearshape") }
            DatabaseSettings()
                .tabItem { Label("CVE Databases", systemImage: "square.stack.3d.up") }
        }
    }
}

/// Automatic scan, severity levels and update checks.
private struct GeneralSettings: View {
    @AppStorage("autoscanEnabled") private var autoscanEnabled = false
    @AppStorage("autoscanHour") private var hour = 9
    @AppStorage("autoscanMinute") private var minute = 0
    @AppStorage("notifyAfterAutoscan") private var notify = true
    @AppStorage("severities") private var severitiesRaw = "CRITICAL,HIGH"
    @AppStorage("showUnfixed") private var showUnfixed = true
    @AppStorage("checkForUpdates") private var checkForUpdates = true
    @ObservedObject private var updates = UpdateChecker.shared
    @State private var scheduleError: String?

    private var selectedSeverities: Set<Severity> {
        Set(severitiesRaw.split(separator: ",").compactMap { Severity(rawValue: String($0)) })
    }

    private func severityBinding(_ level: Severity) -> Binding<Bool> {
        Binding {
            selectedSeverities.contains(level)
        } set: { on in
            var set = selectedSeverities
            if on { set.insert(level) } else { set.remove(level) }
            guard !set.isEmpty else { return }
            severitiesRaw = set.sorted(by: >).map(\.rawValue).joined(separator: ",")
        }
    }

    private var time: Binding<Date> {
        Binding {
            Calendar.current.date(bySettingHour: hour, minute: minute, second: 0, of: Date()) ?? Date()
        } set: {
            let c = Calendar.current.dateComponents([.hour, .minute], from: $0)
            hour = c.hour ?? 9
            minute = c.minute ?? 0
        }
    }

    var body: some View {
        Form {
            Section("Automatic scan") {
                Toggle("Scan automatically every day", isOn: $autoscanEnabled)
                DatePicker("Scan at", selection: time, displayedComponents: .hourAndMinute)
                    .disabled(!autoscanEnabled)
                Toggle("Show a notification when the scan finishes", isOn: $notify)
                    .disabled(!autoscanEnabled)
                Text(
                    "Runs in the background even when D-Patch is closed. If the Mac is asleep at that time, the scan runs when it wakes."
                )
                .font(.caption)
                .foregroundStyle(.secondary)
                if let e = scheduleError {
                    Label(e, systemImage: "exclamationmark.triangle").foregroundStyle(.red).font(.caption)
                }
            }

            Section("Severity") {
                ForEach(Severity.scored.reversed(), id: \.self) { level in
                    Toggle(isOn: severityBinding(level)) {
                        HStack(spacing: 6) {
                            Circle().fill(level.color).frame(width: 8, height: 8)
                            Text(level.label)
                        }
                    }
                    // At least one level has to stay on.
                    .disabled(selectedSeverities == [level])
                }
                Text(
                    "Scans list CVEs at the ticked levels, and always CVEs that no one has scored yet. Every level is downloaded either way, so changing them applies from the next scan without downloading again."
                )
                .font(.caption)
                .foregroundStyle(.secondary)
            }

            Section("List") {
                Toggle("Show CVEs with no fix yet", isOn: $showUnfixed)
                Text(
                    "CVEs that affect this Mac but that no available update fixes yet. When this is off, they're left out of the list and the scan notification, and the list header says how many are hidden."
                )
                .font(.caption)
                .foregroundStyle(.secondary)
            }

            Section("Updates") {
                Toggle("Check for updates automatically", isOn: $checkForUpdates)
                HStack {
                    Text(updates.status ?? "You have D-Patch \(UpdateChecker.currentVersion ?? "(development build)").")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                    Spacer()
                    if updates.isChecking { ProgressView().controlSize(.small) }
                    Button("Check Now") { Task { await updates.check(userInitiated: true) } }
                        .disabled(updates.isChecking)
                }
                Text(
                    "Once a day, D-Patch asks GitHub for the latest release and, if it's newer, shows a notice with a link to it. Nothing is downloaded or installed for you. You can also choose D-Patch › Check for Updates… at any time."
                )
                .font(.caption)
                .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .frame(width: 480)
        .fixedSize(horizontal: false, vertical: true)
        .onChange(of: autoscanEnabled) { applySchedule() }
        .onChange(of: hour) { applySchedule() }
        .onChange(of: minute) { applySchedule() }
    }

    private func applySchedule() {
        do {
            try Scheduler.apply()
            scheduleError = nil
        } catch {
            scheduleError = error.localizedDescription
        }
    }
}

/// NVD (always used) and the optional databases found CVEs are cross-checked against.
private struct DatabaseSettings: View {
    @AppStorage("lookbackDays") private var lookbackDays = 90
    @AppStorage("nvdAPIKey") private var apiKey = ""
    @AppStorage("cveSources") private var sourcesRaw = CVESource.kev.rawValue

    private var enabled: Set<CVESource> {
        Set(sourcesRaw.split(separator: ",").compactMap { CVESource(rawValue: String($0)) })
    }

    private func binding(_ source: CVESource) -> Binding<Bool> {
        Binding {
            enabled.contains(source)
        } set: { on in
            var set = enabled
            if on { set.insert(source) } else { set.remove(source) }
            sourcesRaw = CVESource.optional.filter(set.contains).map(\.rawValue).joined(separator: ",")
        }
    }

    var body: some View {
        Form {
            Section("NIST National Vulnerability Database (NVD)") {
                Text(
                    "Always used: the NVD supplies the CVEs and the affected versions that D-Patch matches against this Mac."
                )
                .font(.caption)
                .foregroundStyle(.secondary)
                Picker("Check CVEs published in the last", selection: $lookbackDays) {
                    ForEach([30, 60, 90, 120, 180, 365], id: \.self) { Text("\($0) days").tag($0) }
                }
                SecureField("NVD API key (optional)", text: $apiKey)
                Text(
                    "Without a key the NVD limits downloads to 5 requests per 30 seconds, so the first scan takes a few minutes. [Request a free key](https://nvd.nist.gov/developers/request-an-api-key)"
                )
                .font(.caption)
                .foregroundStyle(.secondary)
            }

            Section {
                Toggle(isOn: binding(.kev)) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(CVESource.kev.fullName)
                        Text(
                            "Marks CVEs that are being exploited in the wild. D-Patch downloads CISA's public list, so nothing about this Mac is sent."
                        )
                        .font(.caption).foregroundStyle(.secondary)
                    }
                }
                Toggle(isOn: binding(.osv)) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(CVESource.osv.fullName)
                        Text(
                            "Google's open-source vulnerability database, which also links each CVE to its GitHub Advisory. Looks up each CVE found on this Mac."
                        )
                        .font(.caption).foregroundStyle(.secondary)
                    }
                }
                Toggle(isOn: binding(.euvd)) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(CVESource.euvd.fullName)
                        Text("The EU's vulnerability database. Looks up each CVE found on this Mac.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
            } header: {
                Text("Also check")
            } footer: {
                Text(
                    "Each CVE in the list shows the databases it appears in. OSV.dev and EUVD are sent the IDs of the CVEs found on this Mac (nothing else); their answers are kept for a day. Changes apply from the next scan."
                )
                .font(.caption)
                .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .frame(width: 480)
        .fixedSize(horizontal: false, vertical: true)
    }
}
