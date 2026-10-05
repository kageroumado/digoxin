import CryptoKit
import DeviceCheck
import Foundation
import Security

/// The key the server knows an install by.
///
/// The install id is derived from the public half, which lets the server
/// check a claimed id against the key that signed it; it names the key,
/// never the machine, and every app has its own.
protocol InstallKey: Sendable {
    /// The public key as SubjectPublicKeyInfo DER, which is what the server parses.
    var publicKeyDER: Data { get }
    /// An ECDSA P-256 signature over SHA-256 of `body`, DER-encoded.
    func sign(_ body: Data) throws -> Data
}

extension InstallKey {
    var installID: String {
        makeInstallID(publicKeyDER: publicKeyDER)
    }
}

/// `base32(SHA-256(DER))`, lowercase, the first 26 characters (130 bits).
func makeInstallID(publicKeyDER: Data) -> String {
    String(Base32.encode(Data(SHA256.hash(data: publicKeyDER))).prefix(26))
}

/// Where install keys come from: the Secure Enclave in apps, software keys in tests.
protocol InstallKeyStore: Sendable {
    var isAvailable: Bool { get }
    /// The stored key, or `nil` when there is none or it no longer opens.
    func load(from url: URL) -> (any InstallKey)?
    func create(at url: URL) throws -> any InstallKey
}

/// A P-256 key made inside the Secure Enclave. What is stored is its
/// ``SecureEnclave/P256/Signing/PrivateKey/dataRepresentation``: a blob only
/// this Mac's enclave can use, so a copied file signs nothing anywhere else.
struct SecureEnclaveKey: InstallKey {
    let key: SecureEnclave.P256.Signing.PrivateKey

    var publicKeyDER: Data {
        key.publicKey.derRepresentation
    }

    func sign(_ body: Data) throws -> Data {
        try key.signature(for: body).derRepresentation
    }
}

struct SecureEnclaveKeyStore: InstallKeyStore {
    var isAvailable: Bool {
        SecureEnclave.isAvailable
    }

    /// A blob restored onto another Mac is one the enclave refuses, which
    /// reads as no key.
    func load(from url: URL) -> (any InstallKey)? {
        guard let blob = try? Data(contentsOf: url),
              let key = try? SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob)
        else { return nil }
        return SecureEnclaveKey(key: key)
    }

    /// The key signs only on this Mac, after its first unlock since boot;
    /// its blob is written readable by the owner only. It stays a file: the
    /// data-protection keychain needs an application identifier
    /// entitlement, which debug and source builds do not carry.
    func create(at url: URL) throws -> any InstallKey {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, .privateKeyUsage, &error,
        ) else {
            throw error.map { $0.takeRetainedValue() as Error } ?? CocoaError(.featureUnsupported)
        }
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        try writePrivately(key.dataRepresentation, to: url)
        return SecureEnclaveKey(key: key)
    }
}

/// Writes `data` readable by the owner only.
func writePrivately(_ data: Data, to url: URL) throws {
    try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
    try data.write(to: url, options: .atomic)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
}

// MARK: - Apple's word that the key is on a real Mac

/// What registration carries besides the key: App Attest's certificate
/// chain binding an Apple-attested key to ours, and a DeviceCheck token the
/// server trades with Apple for this device's two bits. The server makes an
/// install `attested` on App Attest, `device` on DeviceCheck alone, and
/// `unverified` on neither. An attesting Mac sends the token too: its bit is
/// what tells a reinstall from a new Mac.
struct Evidence: Sendable, Equatable {
    var appAttestKeyID: String?
    var attestation: Data?
    var deviceToken: Data?

    /// The tier this evidence can earn, for the log.
    var tier: String {
        switch (attestation, deviceToken) {
        case (_?, _): "attested"
        case (nil, _?): "device"
        case (nil, nil): "unverified"
        }
    }
}

/// What App Attest signs at registration:
/// `SHA-256(publicKeyDER ‖ challenge ‖ SHA-256(deviceToken))`, the token empty
/// when there is none. It ties the attestation to this key, this
/// registration and the DeviceCheck token sent beside it; the server
/// computes the same (`identity.ClientDataHash`).
func clientDataHash(publicKeyDER: Data, challenge: Data, deviceToken: Data?) -> Data {
    let tokenHash = Data(SHA256.hash(data: deviceToken ?? Data()))
    return Data(SHA256.hash(data: publicKeyDER + challenge + tokenHash))
}

protocol Attestor: Sendable {
    /// Evidence for `key`, bound to this registration's `challenge`.
    func evidence(for key: any InstallKey, challenge: Data, log: @Sendable (String) -> Void) async -> Evidence
}

/// App Attest and DeviceCheck. Without the App Attest entitlement (debug
/// and source builds) both decline, and the install registers unverified.
struct AppleAttestor: Attestor {
    /// The DeviceCheck token comes first, because the attestation covers it.
    func evidence(for key: any InstallKey, challenge: Data, log: @Sendable (String) -> Void) async -> Evidence {
        var evidence = Evidence()
        if DCDevice.current.isSupported {
            do {
                evidence.deviceToken = try await DCDevice.current.generateToken()
            } catch {
                log("DeviceCheck declined: \(error.localizedDescription)")
            }
        }
        let service = DCAppAttestService.shared
        if service.isSupported {
            var step = "generateKey"
            do {
                let keyID = try await service.generateKey()
                step = "attestKey"
                let hash = clientDataHash(publicKeyDER: key.publicKeyDER, challenge: challenge, deviceToken: evidence.deviceToken)
                evidence.attestation = try await service.attestKey(keyID, clientDataHash: hash)
                evidence.appAttestKeyID = keyID
            } catch {
                let nsError = error as NSError
                if step == "attestKey", nsError.domain == DCError.errorDomain, nsError.code == DCError.invalidKey.rawValue {
                    // macOS binds App Attest keys to Full Security with SIP on; a Mac booted
                    // in Reduced or Permissive Security generates the key and cannot sign with it.
                    log("App Attest: this Mac cannot attest (App Attest needs Full Security and SIP); registering without it")
                } else {
                    log("App Attest declined at \(step): \(nsError.domain) \(nsError.code)")
                }
            }
        }
        return evidence
    }
}

/// RFC 4648 base32 without padding, lowercase.
enum Base32 {
    private static let alphabet = Array("abcdefghijklmnopqrstuvwxyz234567")

    static func encode(_ data: Data) -> String {
        var output = ""
        var buffer = 0
        var bits = 0
        for byte in data {
            buffer = (buffer << 8) | Int(byte)
            bits += 8
            while bits >= 5 {
                output.append(alphabet[(buffer >> (bits - 5)) & 31])
                bits -= 5
            }
        }
        if bits > 0 {
            output.append(alphabet[(buffer << (5 - bits)) & 31])
        }
        return output
    }
}
