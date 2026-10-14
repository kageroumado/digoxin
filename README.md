# Digoxin

Digoxin counts Mac app usage and collects scrubbed crash reports with per-install Secure Enclave keys and Apple attestation. A Swift client enforces the user’s consent tier; one Go service separates counts by the evidence each install provides.

[Swift client](Package.swift) · [Service setup](REFERENCE.md#running-the-service)

## Highlights

- Separate install counts by attestation evidence rather than treating every client alike.
- Enforce consent in the Swift client, including deletion and key destruction when switched off.
- Scrub crash reports locally before sending them to the Go service.

<details>
<summary>Full feature list</summary>

### Consent and data

- **Off** is the default: no key or request. Turning it off after use queues a signed deletion request and destroys the key.
- **Counting** sends one heartbeat per active local day, with coarse device information and allowlisted app properties.
- **Crash reports** adds locally scrubbed crash files and diagnostic context.

Install IDs differ across apps. Attestation establishes an app/key relationship;
DeviceCheck is needed to distinguish reinstalls, and its bits are limited.
Deletion reaches backups when they rotate out, 30 days by default.
[Data fields, retention and attestation limits](REFERENCE.md).

### Integrating an app

```swift
import Digoxin

let telemetry = Digoxin(configuration: .init(
    app: "example",
    baseURL: URL(string: "https://telemetry.example.com/api/digoxin")!,
    storageDirectory: .applicationSupportDirectory.appending(path: "Example"),
    propertiesProvider: { ["isDefaultViewer": .bool(Viewer.isDefault)] },
))
await telemetry.setTier(settings.telemetryTier)   // whenever the person changes it
await telemetry.recordUse()                       // at launch and when the app becomes active
await telemetry.submitCrashReport(files: DiagnosticReports.reports(forProcess: "Example", after: lastLaunch))
```

`Digoxin` is an actor; every call is safe from the main actor. `status` answers what
settings should show (`off`, `deletionPending`, `secureEnclaveUnavailable`, `waiting`,
`registered(trust:)`, `failing(reason:)`), and `tier` the stored choice.
`Configuration.extraScrubRules` adds an app's own rewrites (`.replacing`, `.pattern`,
`.clearingField`), applied before the built-in ones.

Signing for App Attest: a Developer ID app needs the
`com.apple.developer.devicecheck.app-attest-opt-in` entitlement (`["CDhash"]`) beside
`com.apple.application-identifier` and `com.apple.developer.team-identifier`, with a
provisioning profile. Without it, debug and source builds still work and register as
`unverified`. App Attest also needs the Mac in Full Security with SIP on.

### Service

```sh
cd server
go build -o /usr/local/bin/digoxin ./cmd/digoxin
digoxin serve -config /etc/digoxin/apps.json -data /var/lib/digoxin \
  -addr 127.0.0.1:9130 -admin-addr 127.0.0.1:9131
```

[Configuration, reverse proxies and backups](REFERENCE.md#running-the-service) · [Admin API](REFERENCE.md#admin-endpoints)

</details>

## Notes

- Attestation needs a provisioned App Attest entitlement, Full Security, and SIP; source/debug builds can register as `unverified`.
- [Data fields and retention](REFERENCE.md) · [Service configuration](REFERENCE.md#running-the-service) · [Admin API](REFERENCE.md#admin-endpoints).
