import SwiftUI

struct SettingsView: View {
    @AppStorage("autoscanEnabled") private var autoscanEnabled = false
    @AppStorage("autoscanHour") private var hour = 9
    @AppStorage("autoscanMinute") private var minute = 0
    @AppStorage("lookbackDays") private var lookbackDays = 90
    @AppStorage("nvdAPIKey") private var apiKey = ""
    @AppStorage("notifyAfterAutoscan") private var notify = true
    @AppStorage("severities") private var severitiesRaw = "CRITICAL,HIGH"
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
                Text("Runs in the background even when D-Patch is closed. If the Mac is asleep at that time, the scan runs when it wakes.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                if let e = scheduleError {
                    Label(e, systemImage: "exclamationmark.triangle").foregroundStyle(.red).font(.caption)
                }
            }

            Section("Severity") {
                ForEach(Severity.allCases.reversed(), id: \.self) { level in
                    Toggle(isOn: severityBinding(level)) {
                        HStack(spacing: 6) {
                            Circle().fill(level.color).frame(width: 8, height: 8)
                            Text(level.label)
                        }
                    }
                    // At least one level has to stay on.
                    .disabled(selectedSeverities == [level])
                }
                Text("Scans look for CVEs at the ticked levels. Medium and Low add many more CVEs, so the first scan after ticking them takes longer.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section("CVE database") {
                Picker("Check CVEs published in the last", selection: $lookbackDays) {
                    ForEach([30, 60, 90, 120, 180, 365], id: \.self) { Text("\($0) days").tag($0) }
                }
                SecureField("NVD API key (optional)", text: $apiKey)
                Text("Without a key the NVD limits downloads to 5 requests per 30 seconds, so the first scan takes a few minutes. [Request a free key](https://nvd.nist.gov/developers/request-an-api-key)")
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
