# Ascon JS

TypeScript implementation of Ascon v1.2, an authenticated cipher and hash function http://ascon.iaik.tugraz.at/.

This implementation is a port of the [Python version](https://github.com/meichlseder/pyascon).

[![npm](https://img.shields.io/npm/v/ascon-js)](https://www.npmjs.com/package/ascon-js) ![npm](https://img.shields.io/npm/dw/ascon-js) [![NPM](https://img.shields.io/npm/l/ascon-js)](https://github.com/Simolation/ascon-js/blob/main/LICENSE)

## Usage

This library can be used both in the browser and in NodeJS.

Import the Ascon library as follows:

```ts
import { Ascon, randomBytes } from "ascon-js";
```

### Hash

```ts
const message = new TextEncoder().encode("ascon");

const hash = Ascon.hash(message); // 32 byte hash
```

All four algorithms can be used. Fixed hash length of 32 bytes:

- Ascon-Hash (default)
- Ascon-Hasha

Variable hash length (should be >= 32 bytes):

- Ascon-Xof
- Ascon-Xofa

```ts
Ascon.hash(message, {
  variant: "Ascon-Xof",
  length: 64,
});
```

### Encryption

```ts
// Generate a random key and a random nonce. This can be done using the helper method randomBytes
const key = randomBytes(16); // 16 bytes
const nonce = randomBytes(16); // 16 bytes

const plaintext = new TextEncoder().encode("ascon");

// Encrypt the plaintext using the key and the nonce
const ciphertext = Ascon.encrypt(key, nonce, plaintext);
```

#### Associated data

In addition to the plain text, associated data can be provided, which is used for additional data integrity checking.

```ts
Ascon.encrypt(key, nonce, plaintext, {
  associatedData: new TextEncoder().encode("additional data"),
});
```

#### Algorithms

All specified algorithms of Ascon encryption are implemented:

- Ascon-128 (default)
- Ascon-128a
- Ascon-80pq

The used algorithm can be specified using the options parameter.

```ts
const key = randomBytes(20); // 20 bytes

Ascon.encrypt(key, nonce, plaintext, {
  variant: "Ascon-80pq",
});
```

### Decryption

```ts
const key = ...; // 16 bytes
const nonce = ...; // 16 bytes

const ciphertext = ...; // Encrypted data

// Decrypt the ciphertext using the key and the nonce
const plaintextResult = Ascon.decrypt(key, nonce, ciphertext);

const text = new TextDecoder().decode(plaintextResult); // "ascon"
```
