# Digoxin

Anonymous, attested usage counting and crash reports for macOS apps: a Swift package
the apps link, and one Go service that serves any number of them.

Each install proves it runs on a real Mac with a Secure Enclave key that Apple's App
Attest vouches for, and signs everything it sends with that key. The person picks one
of three tiers in the app's settings; the library enforces it.

## What each tier sends

**Off** (the default). No key is created, no file is written, no request is made.
Choosing *off* after another tier signs one delete request with the install's key,
then destroys the key, its state and everything queued, on the spot. The signed
request is the one file kept, and it holds no key; it is sent until the server
confirms it, after which the server holds nothing from that install: the install,
every heartbeat and every crash report with its files are deleted.

**Counting.** One heartbeat per local calendar day on which the app is used:

| Field | Example |
|---|---|
| `appVersion`, `appBuild` | `0.34`, `41` |
| `os` | `27.0` (major.minor) |
| `arch` | `arm64` or `x86_64` (the process's, so Rosetta shows) |
| `chipFamily` | `M1` … `M5`, `Intel`, `unknown` |
| `memoryClassGB` | 8, 16, 24, 32, 36, 48, 64, 96, 128 (rounded down) |
| `language` | `fr` (two letters) |
| `day` | `2026-10-05`, the local date |
| `activeDays7` | days with use in the last 7, counted on the Mac |
| `properties` | the app's own flags, each on the server's allowlist for that app |

Registration, once per install, sends the public key, the app version, an App Attest
attestation (Apple's certificate that the key was made on this Mac for this app; it
states the macOS version and build) and a DeviceCheck token (which lets the server ask
Apple for the bit that tells a reinstall from a new Mac).

The server keeps: the install id (a hash of the key, random per app, so two apps on one
Mac have unrelated ids), the public key, the trust tier the evidence earned, what
Apple's certificate says about the key (environment, macOS version and build, the key's
signing policy), the day it registered and was last seen, and the heartbeats. It keeps
dates, never times of day. IP addresses are used in memory for rate limits and never
stored; log lines name no install and no report. Raw heartbeats are dropped after 400
days, leaving only daily counts; an install silent for 400 days is forgotten. Deleted
rows are overwritten on disk (`secure_delete`), but a deleted install remains in the
daily database backups until they rotate out, 30 days by default.

**Crash reports.** Counting, plus a report after a crash: the scrubbed crash files
(the `.ips` macOS wrote, and any log the app adds) and a context of the basic info
above, `installLocation` (`applications`, `translocated` or `other`), the version
before the last update, `consecutiveLaunchCrashes`, `secondsSinceLaunch`, and the
app's allowlisted fields. Reports are kept 180 days, stamped with the day they
arrived.

Scrubbing happens in the library before a file is queued, so nothing unscrubbed is
stored or sent:

- paths under any home folder become `~`; other volumes `/Volumes/<volume>`; per-user
  temporary folders `/var/folders/<tmp>`;
- the account's short and full name become `<user>`; the Mac's host, computer and
  Bonjour names `<host>`; e-mail addresses `<email>`;
- URLs keep only their scheme and host;
- `crashReporterKey`, `sleepWakeUUID`, `bootSessionUUID` and `deviceIdentifierForVendor`
  become the zero UUID, as does any UUID inside a longer string.

What a report still says: the stack, the loaded images and their UUIDs, register
values, the Mac's model code (`Mac13,1`), the macOS build, uptime, and the crash's
date with its time-zone offset. That is what symbolication and triage need. Every
number is the byte the system wrote: the scrubber rewrites only the text of JSON
strings, so the file is still a valid `.ips`.

## How an install proves itself

1. On the first tier above *off*, the library creates a P-256 key in the Secure Enclave,
   usable only on this Mac after its first unlock. The private key never leaves the
   Secure Enclave; what is stored is its wrapped blob, in the app's own folder, readable
   by the account only, and it loads on no other Mac. The install id is
   `base32(SHA-256(public key))`, cut to 26 characters.
2. Registration fetches a single-use challenge (HMAC-signed by the server, valid five
   minutes), asks DeviceCheck for a device token, then has App Attest attest a fresh key
   over `SHA-256(public key ‖ challenge ‖ SHA-256(device token))` (the token empty when
   there is none). It sends the public key, the attestation and the token, signed with the
   install key. The server checks the signature before it spends the challenge, checks
   the certificate chain up to Apple's App Attestation root, the nonce, the app id hash
   and the key binding, asks Apple about the token, and records a trust tier:
   - `attested`: App Attest verified, and, for an app with a `registered_bit`, Apple
     accepted the token the attestation covers;
   - `device`: Apple accepted the token, without App Attest;
   - `reregistered`: Apple accepted the token and the app's bit says this Mac registered
     an install of this app before;
   - `unverified`: neither, as for debug and source builds, or App Attest without the
     token an app with a `registered_bit` requires.
3. Every later request is signed with the Secure Enclave key and carries an envelope with
   the install id, a sequence number that must increase, and the time it was sent (within
   48 hours), so a captured request can be neither altered nor replayed.

What this proves: an `attested` install is a genuine copy of the app, signed by its team,
running on a real Mac in Full Security, and its key lives in that Mac's Secure Enclave.
What it does not prove: that two installs are two Macs. App Attest will attest any
number of keys on one Mac, so only the DeviceCheck bit tells a reinstall from a new Mac,
and only for an app that has one. A DeviceCheck token copied behind several keys is
caught for 24 hours (it counts for the first install only), but each call to DCDevice
yields a fresh token, so a Mac that registers many keys with fresh tokens in an app
without a bit is counted many times; the per-address limits are what bound that. The
key's blob is a file: any process running as the same account can read it and, as far
as is known, have that Mac's Secure Enclave sign with it, which lets local software
impersonate the install's telemetry but not move it to another Mac. (The data-protection
keychain would scope the key to the app, but needs an application-identifier entitlement
that debug and source builds do not carry.)

Stats count each trust tier separately; how much to believe `unverified` is the
reader's call.

## Integrating an app

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

## Running the service

```sh
cd server
go build -o /usr/local/bin/digoxin ./cmd/digoxin
digoxin serve -config /etc/digoxin/apps.json -data /var/lib/digoxin \
  -addr 127.0.0.1:9130 -admin-addr 127.0.0.1:9131
digoxin backup -data /var/lib/digoxin -dir /var/backups/digoxin   # daily, from a timer; keeps 30
```

The apps file names each app the service counts, and how the service sees clients
and disk:

```json
{"client_ip_header": "Digoxin-Client-IP",
 "trusted_proxies": ["127.0.0.1/32", "::1/128"],
 "crash_storage": {"daily_bytes": 536870912, "min_free_bytes": 2147483648, "concurrent_uploads": 4},
 "apps": {"example": {
  "app_attest_id": "TEAMID1234.com.example.app",
  "require_production_attest": true,
  "device_check": {"key_path": "/etc/digoxin/AuthKey_ABC123.p8", "key_id": "ABC123", "registered_bit": "bit1"},
  "properties": {"isDefaultViewer": "bool", "documentsOpened7d": "int"},
  "crash_context": {"plugins": "string"},
  "crash_reports": {"max_files": 4, "max_bytes": 2097152, "per_install_per_day": 5, "min_trust": "device"}
}}}
```

Unknown fields are refused, so a misspelling cannot fall back to a default.
`crash_storage` bounds every app together: bytes of crash files per UTC day, the free
space below which no report is taken, and reports arriving at once (the defaults are
shown). `min_trust` is the lowest tier whose crash reports an app takes (`unverified`
by default).

Property types are `bool`, `int`, `number` and `string` (64 characters at most); keys
not listed, or of another type, are dropped. DeviceCheck gives a team two bits per Mac
for all its apps, so `registered_bit` (`bit0` or `bit1`) can go to two apps at most,
and only if nothing else of the team's sets that bit. An app without one is still proven by its token
but does not tell reinstalls apart. The `.p8` key stays outside the repository; the
service refuses one readable by everyone (group-readable, for a service user in its
group, is fine).

### Client addresses

Rate limits count per client address: an IPv4 address, or an IPv6 address's /64. With
no `client_ip_header`, the peer is the client. Behind a reverse proxy, name the header it
writes the client's address into and list the proxy in `trusted_proxies`; the header is
believed only from those peers, and a list such as `X-Forwarded-For` is read from the
right, skipping trusted hops. The service warns at start when it listens on loopback with
no header, since every client would then share the proxy's address.

With Caddy on the same host, let Caddy decide who the client is and hand it over in a
header of its own, which it overwrites on every request:

```caddyfile
{
	servers {
		# Only when Cloudflare is in front: believe its header from its ranges.
		trusted_proxies static 173.245.48.0/20 103.21.244.0/22 …
		client_ip_headers CF-Connecting-IP
	}
}
example.com {
	handle_path /api/digoxin/* {
		reverse_proxy 127.0.0.1:9130 {
			header_up Digoxin-Client-IP {client_ip}
		}
	}
}
```

Forwarding `CF-Connecting-IP` itself (`"client_ip_header": "CF-Connecting-IP"` with
loopback as the trusted proxy) works too, but only while the origin accepts connections
from Cloudflare alone: anyone who reaches Caddy directly can write that header.

| Route | |
|---|---|
| `GET /v1/{app}/challenge` | a single-use registration challenge |
| `POST /v1/{app}/installs` | register a key with its evidence |
| `POST /v1/{app}/heartbeats` | signed batch of 1–8 heartbeats |
| `POST /v1/{app}/crash-reports` | signed multipart: an `envelope` part and `file` parts |
| `DELETE /v1/{app}/installs/{id}` | signed; deletes the install and everything it sent |

A new install takes one of five daily slots of its address per app before Apple is asked,
and gets it back when registration fails; an install may register again three times a
day. Requests the server cannot verify, including any for an install it does not know,
all answer `401` alike. A crash report is refused before any of its body is read when
its install is unknown, below `min_trust` or past its daily reports, or when the disk or
the day's budget is spent; the body is then streamed to disk within the limits and kept
only once its signature checks.

## Admin endpoints

On the loopback listener only (it refuses any other address), JSON, reached over ssh.
It answers only requests whose `Host` is `localhost`, `127.0.0.1` or `[::1]` and that
carry no `Origin`, so a web page cannot reach it by rebinding a name to 127.0.0.1.

| Endpoint | Answers |
|---|---|
| `GET /admin/apps` | each app's installs per trust tier, heartbeat and crash report counts |
| `GET /admin/{app}/stats?day=&trust=` | DAU, WAU, MAU per trust tier; spreads of version, OS, arch, chip, memory, language, `activeDays7`; property shares. `day` defaults to the newest day heartbeats carry; `trust` defaults to `attested,verified,device,unverified` |
| `GET /admin/{app}/history?days=90` | daily actives per trust tier, including rolled-up days |
| `GET /admin/{app}/installs/{id}` | one install's trust, attestation and counts |
| `GET /admin/{app}/crashes?limit=50` | crash reports, newest first, with context and file list |
| `GET /admin/{app}/crashes/{id}` | one report |
| `GET /admin/{app}/crashes/{id}/files/{name}` | one file, as stored |

Days are the client's local calendar days. `reregistered` installs (a reinstall on a
Mac already counted) are reported in their own column and left out of spreads by
default.

## Tests

```sh
swift test
(cd server && go test ./...)
Scripts/e2e.sh   # the Swift client against a local Go service, through this Mac's Secure Enclave
```

## Design decisions

- **Turning off signs the delete first.** The client signs the delete request, then
  destroys the key, and keeps only that signed request until the server confirms it, so
  a Mac that was offline can still delete its data later. The server accepts a delete
  sent up to 30 days ago; a replayed delete can only delete what its owner asked to.
- **No tombstones.** A deleted install's row goes too; a `deleted` flag would keep the
  id, the one thing left to forget.
- **Days, never times.** Heartbeats carry the client's local date and nothing records
  when they arrived, so no stored value says at what hour someone used an app. The admin
  stats default to the newest day heartbeats carry, since local days run ahead of UTC.
- **Scrubbed ids become the zero UUID** instead of disappearing, so tools that expect the
  field still parse the file; only the text of JSON strings is rewritten.
- **The client is an actor.** It owns the sequence numbers, queues and retry timer, and
  does file I/O, Secure Enclave signing and network, none of which belongs on the main
  actor.
