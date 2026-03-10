/**
 * React Native RSA-OAEP (SHA-256) - TypeScript definitions
 */

/**
 * Encrypt plaintext with an RSA public key using OAEP with SHA-256.
 * Compatible with Node.js crypto.privateDecrypt using RSA_PKCS1_OAEP_PADDING and oaepHash: 'sha256'.
 *
 * @param plainText - UTF-8 string to encrypt
 * @param publicKeyPem - PEM-encoded public key (PKCS#1 or SPKI/X.509)
 * @returns Base64-encoded ciphertext
 * @throws Error if native module is not linked or encryption fails
 */
export function encryptOaep(plainText: string, publicKeyPem: string): Promise<string>;

/**
 * Decrypt base64 ciphertext with an RSA private key using OAEP with SHA-256.
 *
 * @param cipherB64 - Base64-encoded ciphertext
 * @param privateKeyPem - PEM-encoded private key (PKCS#1 or PKCS#8)
 * @returns Decrypted UTF-8 plaintext
 * @throws Error if native module is not linked or decryption fails
 */
export function decryptOaep(cipherB64: string, privateKeyPem: string): Promise<string>;

export default {
  encryptOaep,
  decryptOaep,
};
