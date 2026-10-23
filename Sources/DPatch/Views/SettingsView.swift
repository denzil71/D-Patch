import SwiftUI

struct SettingsView: View {
    @AppStorage("autoscanEnabled") private var autoscanEnabled = false
    @AppStorage("autoscanHour") private var hour = 9
    @AppStorage("autoscanMinute") private var minute = 0
    @AppStorage("lookbackDays") private var lookbackDays = 90
    @AppStorage("nvdAPIKey") private var apiKey = ""
    @AppStorage("notifyAfterAutoscan") private var notify = true
    @State private var scheduleError: String?

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
