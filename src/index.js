/**
 * react-native-rsa-oaep
 * RSA-OAEP (SHA-256) encryption/decryption for React Native iOS and Android.
 * Compatible with Node.js crypto.privateDecrypt (RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256').
 */

import { NativeModules } from 'react-native';

const LINKING_ERROR =
  'react-native-rsa-oaep: The native RsaOaep module is not linked. ' +
  'Make sure you have run `pod install` (iOS) and rebuilt the app.';

const RsaOaep = NativeModules.RsaOaep;

function getNativeModule() {
  if (RsaOaep == null) {
    throw new Error(LINKING_ERROR);
  }
  return RsaOaep;
}

/**
 * Encrypt plaintext with an RSA public key using OAEP with SHA-256.
 * @param {string} plainText - UTF-8 string to encrypt
 * @param {string} publicKeyPem - PEM-encoded public key
 * @returns {Promise<string>} Base64-encoded ciphertext
 */
export function encryptOaep(plainText, publicKeyPem) {
  if (typeof plainText !== 'string') {
    return Promise.reject(new TypeError('encryptOaep: plainText must be a string'));
  }
  if (typeof publicKeyPem !== 'string') {
    return Promise.reject(new TypeError('encryptOaep: publicKeyPem must be a string'));
  }
  if (!publicKeyPem.includes('-----BEGIN')) {
    return Promise.reject(new Error('encryptOaep: publicKeyPem must be PEM format'));
  }
  const native = getNativeModule();
  return native.encryptOaep(plainText, publicKeyPem);
}

/**
 * Decrypt base64 ciphertext with an RSA private key using OAEP with SHA-256.
 * @param {string} cipherB64 - Base64-encoded ciphertext
 * @param {string} privateKeyPem - PEM-encoded private key
 * @returns {Promise<string>} Decrypted UTF-8 plaintext
 */
export function decryptOaep(cipherB64, privateKeyPem) {
  if (typeof cipherB64 !== 'string') {
    return Promise.reject(new TypeError('decryptOaep: cipherB64 must be a string'));
  }
  if (typeof privateKeyPem !== 'string') {
    return Promise.reject(new TypeError('decryptOaep: privateKeyPem must be a string'));
  }
  if (!privateKeyPem.includes('-----BEGIN')) {
    return Promise.reject(new Error('decryptOaep: privateKeyPem must be PEM format'));
  }
  const native = getNativeModule();
  return native.decryptOaep(cipherB64, privateKeyPem);
}

export default {
  encryptOaep,
  decryptOaep,
};
