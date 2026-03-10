# react-native-rsa-oaep

React Native RSA-OAEP (SHA-256) encryption and decryption for iOS and Android. Compatible with Node.js `crypto.privateDecrypt` using `RSA_PKCS1_OAEP_PADDING` and `oaepHash: 'sha256'`.

## Features

- **RSA-OAEP with SHA-256** – Modern, secure padding (not PKCS#1 v1.5)
- **Node.js 22+ compatible** – Works with current Node.js without security reverts
- **PEM support** – PKCS#1 and PKCS#8/X.509 formats for public and private keys
- **TypeScript** – Includes type definitions

## Installation

```bash
npm install react-native-rsa-oaep
# or
yarn add react-native-rsa-oaep
```

### iOS

```bash
cd ios
pod install
cd ..
```

### Android

No extra steps. The library uses React Native autolinking.

## Usage

```javascript
import { encryptOaep, decryptOaep } from 'react-native-rsa-oaep';

// Encrypt with public key (PEM)
const cipherB64 = await encryptOaep('hello world', publicKeyPem);

// Decrypt with private key (PEM)
const plainText = await decryptOaep(cipherB64, privateKeyPem);
```

### Supported PEM formats

| Format | Header |
|--------|--------|
| Public (X.509/SPKI) | `-----BEGIN PUBLIC KEY-----` |
| Public (PKCS#1) | `-----BEGIN RSA PUBLIC KEY-----` |
| Private (PKCS#8) | `-----BEGIN PRIVATE KEY-----` |
| Private (PKCS#1) | `-----BEGIN RSA PRIVATE KEY-----` |

## Backend (Node.js)

Decrypt ciphertext produced by the mobile app:

```javascript
const crypto = require('crypto');
const fs = require('fs');

const privateKey = fs.readFileSync('private.pem', 'utf8');
const cipherB64 = '...'; // from mobile encryptOaep()

const decrypted = crypto.privateDecrypt(
  {
    key: privateKey,
    passphrase: process.env.KEY_PASSPHRASE || '',
    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: 'sha256',  // required to match mobile
  },
  Buffer.from(cipherB64, 'base64')
);

console.log(decrypted.toString('utf8'));
```

## API

### `encryptOaep(plainText: string, publicKeyPem: string): Promise<string>`

Encrypts UTF-8 plaintext with an RSA public key. Returns base64-encoded ciphertext.

- **plainText** – String to encrypt
- **publicKeyPem** – PEM-encoded public key
- **Returns** – Base64 ciphertext
- **Throws** – On invalid input or encryption failure

### `decryptOaep(cipherB64: string, privateKeyPem: string): Promise<string>`

Decrypts base64 ciphertext with an RSA private key. Returns UTF-8 plaintext.

- **cipherB64** – Base64-encoded ciphertext
- **privateKeyPem** – PEM-encoded private key
- **Returns** – Decrypted string
- **Throws** – On invalid input or decryption failure

## Requirements

- React Native >= 0.68
- iOS 11+
- Android API 21+ (minSdkVersion 21)

## Troubleshooting

**"RsaOaep native module not linked"**

- Run `pod install` in `ios/` and rebuild
- Ensure the package is in `node_modules` and autolinking is enabled

**"Invalid public key" / "Invalid private key"**

- Ensure the PEM includes headers (e.g. `-----BEGIN PUBLIC KEY-----`)
- Check that the key is valid and not corrupted

**Backend decryption fails with OAEP error**

- Use `oaepHash: 'sha256'` in `crypto.privateDecrypt` options
- Ensure the private key matches the public key used for encryption

## License

MIT
