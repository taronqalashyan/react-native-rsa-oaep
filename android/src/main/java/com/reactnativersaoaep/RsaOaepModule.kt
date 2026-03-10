package com.reactnativersaoaep

import android.util.Base64
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import java.io.StringReader
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.RSAPublicKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher

import org.spongycastle.asn1.pkcs.RSAPublicKey
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo
import org.spongycastle.cert.X509CertificateHolder
import org.spongycastle.openssl.PEMParser
import org.spongycastle.openssl.jcajce.JcaPEMKeyConverter

/**
 * React Native RSA-OAEP (SHA-256) module.
 * Supports PKCS#1 (RSA PUBLIC KEY) and PKCS#8/X.509 (PUBLIC KEY, PRIVATE KEY) PEM formats.
 */
class RsaOaepModule(reactContext: ReactApplicationContext) :
  ReactContextBaseJavaModule(reactContext) {

  override fun getName(): String = "RsaOaep"

  private fun pemToDer(pem: String): ByteArray {
    val cleaned = pem
      .replace("-----BEGIN PUBLIC KEY-----", "")
      .replace("-----END PUBLIC KEY-----", "")
      .replace("-----BEGIN RSA PUBLIC KEY-----", "")
      .replace("-----END RSA PUBLIC KEY-----", "")
      .replace("-----BEGIN PRIVATE KEY-----", "")
      .replace("-----END PRIVATE KEY-----", "")
      .replace("-----BEGIN RSA PRIVATE KEY-----", "")
      .replace("-----END RSA PRIVATE KEY-----", "")
      .replace(Regex("\\s"), "")
    return Base64.decode(cleaned, Base64.DEFAULT)
  }

  private fun loadPublicKey(pem: String): PublicKey {
    val der = pemToDer(pem)
    // 1) Try X.509 SPKI from raw DER (most PUBLIC KEY PEMs)
    try {
      val spec = X509EncodedKeySpec(der)
      return KeyFactory.getInstance("RSA").generatePublic(spec)
    } catch (_: Exception) {
      // fall through to PEMParser
    }
    // 2) Try parsing full PEM (handles CERTIFICATE, RSA PUBLIC KEY, etc.)
    val obj = PEMParser(StringReader(pem)).use { it.readObject() }
    val converter = JcaPEMKeyConverter() // no provider override
    return when (obj) {
      is RSAPublicKey -> {
        val spec = RSAPublicKeySpec(obj.modulus, obj.publicExponent)
        KeyFactory.getInstance("RSA").generatePublic(spec)
      }
      is SubjectPublicKeyInfo -> {
        converter.getPublicKey(obj)
      }
      is X509CertificateHolder -> {
        converter.getPublicKey(obj.subjectPublicKeyInfo)
      }
      else -> {
        throw IllegalArgumentException(
          "Unsupported public key format. Expected CERTIFICATE, RSA PUBLIC KEY or PUBLIC KEY."
        )
      }
    }
  }

  private fun loadPrivateKey(pem: String): PrivateKey {
    val der = pemToDer(pem)
    return try {
      val spec = PKCS8EncodedKeySpec(der)
      KeyFactory.getInstance("RSA").generatePrivate(spec)
    } catch (_: Exception) {
      val obj = PEMParser(StringReader(pem)).use { it.readObject() }
      when (obj) {
        is org.spongycastle.openssl.PEMKeyPair -> {
          JcaPEMKeyConverter().getKeyPair(obj).private
        }
        else -> throw IllegalArgumentException("Unsupported private key format. Use PKCS#1 (RSA PRIVATE KEY) or PKCS#8 (PRIVATE KEY).")
      }
    }
  }

  @ReactMethod
  fun encryptOaep(message: String, publicKeyPem: String, promise: Promise) {
    try {
      val key = loadPublicKey(publicKeyPem)
      val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
      cipher.init(Cipher.ENCRYPT_MODE, key)
      val cipherBytes = cipher.doFinal(message.toByteArray(StandardCharsets.UTF_8))
      val b64 = Base64.encodeToString(cipherBytes, Base64.NO_WRAP)
      promise.resolve(b64)
    } catch (e: Exception) {
      promise.reject("ENCRYPT_ERROR", e.message ?: "Encryption failed", e)
    }
  }

  @ReactMethod
  fun decryptOaep(cipherB64: String, privateKeyPem: String, promise: Promise) {
    try {
      val key = loadPrivateKey(privateKeyPem)
      val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
      cipher.init(Cipher.DECRYPT_MODE, key)
      val cipherBytes = Base64.decode(cipherB64, Base64.DEFAULT)
      val plain = cipher.doFinal(cipherBytes)
      promise.resolve(String(plain, StandardCharsets.UTF_8))
    } catch (e: Exception) {
      promise.reject("DECRYPT_ERROR", e.message ?: "Decryption failed", e)
    }
  }
}