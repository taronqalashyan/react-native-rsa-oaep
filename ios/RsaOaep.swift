//
//  RsaOaep.swift
//  react-native-rsa-oaep
//
//  RSA-OAEP (SHA-256) encryption/decryption for React Native.
//

import Foundation
import Security
#if canImport(React)
import React
#endif

@objc(RsaOaep)
class RsaOaep: NSObject {

  @objc
  static func requiresMainQueueSetup() -> Bool {
    return false
  }

  /// Strip PEM headers and decode base64 to raw DER bytes.
  /// Supports: PUBLIC KEY, RSA PUBLIC KEY, PRIVATE KEY, RSA PRIVATE KEY
  private func stripPem(_ pem: String) -> Data? {
    let cleaned = pem
      .replacingOccurrences(of: "-----BEGIN PUBLIC KEY-----", with: "")
      .replacingOccurrences(of: "-----END PUBLIC KEY-----", with: "")
      .replacingOccurrences(of: "-----BEGIN RSA PUBLIC KEY-----", with: "")
      .replacingOccurrences(of: "-----END RSA PUBLIC KEY-----", with: "")
      .replacingOccurrences(of: "-----BEGIN PRIVATE KEY-----", with: "")
      .replacingOccurrences(of: "-----END PRIVATE KEY-----", with: "")
      .replacingOccurrences(of: "-----BEGIN RSA PRIVATE KEY-----", with: "")
      .replacingOccurrences(of: "-----END RSA PRIVATE KEY-----", with: "")
      .replacingOccurrences(of: "\r", with: "")
      .replacingOccurrences(of: "\n", with: "")
      .replacingOccurrences(of: " ", with: "")
      .replacingOccurrences(of: "\t", with: "")
    return Data(base64Encoded: cleaned)
  }

  /// Create SecKey from raw DER bytes (PKCS#1 or SPKI for RSA).
  /// iOS SecKeyCreateWithData accepts both formats for RSA keys.
  private func makeKey(data: Data, isPublic: Bool) throws -> SecKey {
    let keyClass = isPublic ? kSecAttrKeyClassPublic : kSecAttrKeyClassPrivate
    let attrs: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
      kSecAttrKeyClass as String: keyClass,
      kSecAttrKeySizeInBits as String: NSNumber(value: 2048),
    ]
    var error: Unmanaged<CFError>?
    guard let key = SecKeyCreateWithData(data as CFData, attrs as CFDictionary, &error) else {
      throw error?.takeRetainedValue() as Error? ?? NSError(domain: "RsaOaep", code: -1, userInfo: [NSLocalizedDescriptionKey: "Failed to create key"])
    }
    return key
  }

  @objc
  func encryptOaep(_ message: String,
                   withKey publicKeyPem: String,
                   resolver resolve: @escaping RCTPromiseResolveBlock,
                   rejecter reject: @escaping RCTPromiseRejectBlock) {
    do {
      guard let der = stripPem(publicKeyPem), !der.isEmpty else {
        reject("KEY_ERR", "Invalid public key: could not decode PEM", nil)
        return
      }
      let key = try makeKey(data: der, isPublic: true)
      guard SecKeyIsAlgorithmSupported(key, .encrypt, .rsaEncryptionOAEPSHA256) else {
        reject("ALG_ERR", "RSA-OAEP SHA-256 not supported on this device", nil)
        return
      }
      guard let plainData = message.data(using: .utf8) else {
        reject("INPUT_ERR", "Invalid UTF-8 plaintext", nil)
        return
      }
      var error: Unmanaged<CFError>?
      guard let cipher = SecKeyCreateEncryptedData(key, .rsaEncryptionOAEPSHA256, plainData as CFData, &error) as Data? else {
        let err = error?.takeRetainedValue() as Error? ?? NSError(domain: "RsaOaep", code: -1, userInfo: [NSLocalizedDescriptionKey: "Encryption failed"])
        reject("ENCRYPT_ERROR", err.localizedDescription, err)
        return
      }
      resolve(cipher.base64EncodedString())
    } catch {
      reject("ENCRYPT_ERROR", error.localizedDescription, error)
    }
  }

  @objc
  func decryptOaep(_ cipherB64: String,
                   withKey privateKeyPem: String,
                   resolver resolve: @escaping RCTPromiseResolveBlock,
                   rejecter reject: @escaping RCTPromiseRejectBlock) {
    do {
      guard let der = stripPem(privateKeyPem), !der.isEmpty else {
        reject("KEY_ERR", "Invalid private key: could not decode PEM", nil)
        return
      }
      let key = try makeKey(data: der, isPublic: false)
      guard SecKeyIsAlgorithmSupported(key, .decrypt, .rsaEncryptionOAEPSHA256) else {
        reject("ALG_ERR", "RSA-OAEP SHA-256 not supported on this device", nil)
        return
      }
      guard let cipherData = Data(base64Encoded: cipherB64), !cipherData.isEmpty else {
        reject("DATA_ERR", "Invalid base64 ciphertext", nil)
        return
      }
      var error: Unmanaged<CFError>?
      guard let plain = SecKeyCreateDecryptedData(key, .rsaEncryptionOAEPSHA256, cipherData as CFData, &error) as Data? else {
        let err = error?.takeRetainedValue() as Error? ?? NSError(domain: "RsaOaep", code: -1, userInfo: [NSLocalizedDescriptionKey: "Decryption failed"])
        reject("DECRYPT_ERROR", err.localizedDescription, err)
        return
      }
      guard let plainText = String(data: plain, encoding: .utf8) else {
        reject("OUTPUT_ERR", "Decrypted data is not valid UTF-8", nil)
        return
      }
      resolve(plainText)
    } catch {
      reject("DECRYPT_ERROR", error.localizedDescription, error)
    }
  }
}
