import {
  arrayEquals,
  assertHashLength,
  assertHashVariant,
  assertLength,
  assertVariant,
  bytesToInt,
  bytesToState,
  concatArrays,
  intToBytes,
  rotr,
  toBytes,
  transformArrayBufferToBigInt,
  transformBigIntToArrayBufferLike,
  zeroBytes,
} from "./helper";
import type {
  AsconEncryptionOptions,
  AsconHashOptions,
  BytesLike,
} from "./interfaces";

export class Ascon {
  /**
   * Ascon hash function and extendable-output function.
   * @param message a Uint8Array of arbitrary length
   * @param options additional parameters including the variant and the length of the hash
   *
   * @returns a Uint8Array containing the hash
   *
   * @example
   * ```typescript
   * // Normal mode (Ascon-Hash)
   * const message = new TextEncoder().encode("ascon");
   * const hash = Ascon.hash(message);
   * hash // 32 bytes hash
   *
   * // XOF mode (Ascon-Xof)
   * const message = new TextEncoder().encode("ascon");
   * const hash = Ascon.hash(message, { variant: "Ascon-Xof", length: 64 });
   * hash // 64 bytes hash (default is 32 bytes)
   * ```
   */
  public static hash(
    message: Uint8Array,
    options?: AsconHashOptions
  ): Uint8Array {
    const bigArray = transformArrayBufferToBigInt(message);

    const variant = options?.variant ?? "Ascon-Hash";
    const hashLength = (options as { length?: number })?.length ?? 32;

    assertHashVariant(variant);
    assertHashLength(hashLength, variant);

    const a = 12; // rounds
    const b = ["Ascon-Hasha", "Ascon-Xofa"].includes(variant) ? 8 : 12;
    const rate = 8; // bytes

    const tagSpec = intToBytes(
      ["Ascon-Hash", "Ascon-Hasha"].includes(variant) ? 256n : 0n,
      4
    );

    const S = bytesToState(
      concatArrays(
        toBytes([0n, BigInt(rate * 8), BigInt(a), BigInt(a - b)]),
        tagSpec,
        zeroBytes(32)
      )
    );

    this.permutation(S, a);

    const mPadded = concatArrays(
      bigArray,
      toBytes([0x80n]),
      zeroBytes(rate - (bigArray.length % rate) - 1)
    );

    // first s - 1 blocks
    for (let i = 0; i < mPadded.length - rate; i += rate) {
      S[0] ^= bytesToInt(mPadded.slice(i, i + 8)); // rate = 8
      this.permutation(S, b);
    }

    const i = mPadded.length - rate;
    S[0] ^= bytesToInt(mPadded.slice(i, i + 8)); // rate = 8

    this.permutation(S, a);

    let hash = new BigInt64Array();
    while (hash.length < hashLength) {
      hash = concatArrays(hash, intToBytes(S[0], 8)); // rate = 8
      this.permutation(S, b);
    }

    return transformBigIntToArrayBufferLike(hash.slice(0, hashLength));
  }

  /**
   * Ascon encryption.
   * @param key a Uint8Array of size 16 (for Ascon-128, Ascon-128a; 128-bit security) or 20 (for Ascon-80pq; 128-bit security)
   * @param nonce a Uint8Array of size 16 (must not repeat for the same key!)
   * @param plaintext a Uint8Array of arbitrary length
   * @param options additional parameters including the variant and associated data as a Uint8Array
   *
   * @returns a Uint8Array of length plaintext.length + 16 containing the ciphertext and tag
   *
   * @example
   * ```typescript
   * const key = new Uint8Array([...]);
   * const nonce = new Uint8Array([...]);
   * const plaintext = new TextEncoder().encode("ascon");
   *
   * const ciphertext = Ascon.encrypt(key, nonce, plaintext);
   *
   * // With associated data
   * const key = new Uint8Array([...]);
   * const nonce = new Uint8Array([...]);
   * const plaintext = new TextEncoder().encode("ascon");
   * const associatedData = new TextEncoder().encode("more data");
   *
   * const ciphertext = Ascon.encrypt(key, nonce, plaintext, { associatedData });
   * ```
   */
  public static encrypt(
    key: Uint8Array,
    nonce: Uint8Array,
    plaintext: Uint8Array,
    options?: AsconEncryptionOptions
  ): Uint8Array {
    const bigKey = transformArrayBufferToBigInt(key);
    const bigNonce = transformArrayBufferToBigInt(nonce);
    const bigPlaintext = transformArrayBufferToBigInt(plaintext);
    const bigAssociatedData = options?.associatedData
      ? transformArrayBufferToBigInt(options?.associatedData)
      : undefined;

    const variant = options?.variant ?? "Ascon-128";
    assertVariant(variant);
    assertLength(bigKey, bigNonce, variant);

    let S = Array(5).fill(BigInt(0));
    const k = bigKey.length * 8; // bits
    const a = 12; // rounds
    const b = variant === "Ascon-128a" ? 8 : 6; // rounds
    const rate = variant === "Ascon-128a" ? 16 : 8; // bytes

    S = this.initialize(S, k, rate, a, b, bigKey, bigNonce);
    this.processAssociatedData(S, b, rate, bigAssociatedData);

    const cipherText = this.processPlaintext(S, b, rate, bigPlaintext);
    const tag = this.finalize(S, rate, a, bigKey);

    return transformBigIntToArrayBufferLike(concatArrays(cipherText, tag));
  }

  /**
   * Ascon decryption.
   * @param key a Uint8Array of size 16 (for Ascon-128, Ascon-128a; 128-bit security) or 20 (for Ascon-80pq; 128-bit security)
   * @param nonce a Uint8Array of size 16 (must not repeat for the same key!)
   * @param ciphertext a Uint8Array of arbitrary length
   * @param options additional parameters including the variant and associated data as a Uint8Array
   *
   * @returns a Uint8Array containing the plaintext or throws when the verification fails
   * @throws when the verification fails
   *
   * @example
   * ```typescript
   * const key = new Uint8Array([...]);
   * const nonce = new Uint8Array([...]);
   * const ciphertext = new Uint8Array([...]);
   *
   * const plaintext = Ascon.decrypt(key, nonce, ciphertext);
   * plaintext // "ascon"
   *
   * // With associated data
   * const key = new Uint8Array([...]);
   * const nonce = new Uint8Array([...]);
   * const ciphertext = new Uint8Array([...]);
   * const associatedData = new TextEncoder().encode("more data");
   *
   * const plaintext = Ascon.decrypt(key, nonce, ciphertext, { associatedData });
   * plaintext // "ascon"
   *
   * ```
   */
  public static decrypt(
    key: Uint8Array,
    nonce: Uint8Array,
    ciphertext: Uint8Array,
    options?: AsconEncryptionOptions
  ): Uint8Array {
    const bigKey = transformArrayBufferToBigInt(key);
    const bigNonce = transformArrayBufferToBigInt(nonce);
    const bigCiphertext = transformArrayBufferToBigInt(ciphertext);
    const bigAssociatedData = options?.associatedData
      ? transformArrayBufferToBigInt(options?.associatedData)
      : undefined;

    const variant = options?.variant ?? "Ascon-128";

    assertVariant(variant);
    assertLength(bigKey, bigNonce, variant);

    if (ciphertext.length < 16) {
      throw new Error("Could not be decrypted. Ciphertext too short.");
    }

    let S = Array(5).fill(BigInt(0));
    const k = bigKey.length * 8; // bits
    const a = 12; // rounds
    const b = variant === "Ascon-128a" ? 8 : 6; // rounds
    const rate = variant === "Ascon-128a" ? 16 : 8; // bytes

    S = this.initialize(S, k, rate, a, b, bigKey, bigNonce);
    this.processAssociatedData(S, b, rate, bigAssociatedData);

    const plainText = this.processCipherText(
      S,
      b,
      rate,
      bigCiphertext.slice(0, -16)
    );

    const tag = this.finalize(S, rate, a, bigKey);

    if (!arrayEquals(tag, bigCiphertext.slice(-16))) {
      throw new Error("Could not be decrypted. Tags don't match.");
    }

    return transformBigIntToArrayBufferLike(plainText);
  }

  private static initialize(
    S: bigint[],
    k: number,
    rate: number,
    a: number,
    b: number,
    key: BytesLike,
    nonce: BytesLike
  ) {
    const iv_zero_key_nonce = concatArrays(
      toBytes([
        BigInt(k),
        BigInt(rate * 8),
        BigInt(a),
        BigInt(b),
        ...new Array(20 - key.length).fill(0n),
      ]),
      key,
      nonce
    );

    S = S.map((_, i) => bytesToState(iv_zero_key_nonce)[i]);

    // Permute the state.
    this.permutation(S, a);

    const zeroKey = bytesToState(concatArrays(zeroBytes(40 - key.length), key));

    // Apply the zeroKey to the state.
    S = S.map((s, i) => s ^ zeroKey[i]);

    return S;
  }

  private static processAssociatedData(
    S: bigint[],
    b: number,
    rate: number,
    associatedData: BytesLike | undefined
  ) {
    if (associatedData && associatedData.length > 0) {
      const aZeros = rate - (associatedData.length % rate) - 1;
      const aPadded = concatArrays(
        associatedData,
        toBytes([0x80n]),
        zeroBytes(Number(aZeros))
      );

      for (let i = 0; i < aPadded.length; i += Number(rate)) {
        S[0] ^= bytesToInt(aPadded.slice(i, i + 8));
        if (rate === 16) {
          S[1] ^= bytesToInt(aPadded.slice(i + 8, i + 16));
        }

        this.permutation(S, b);
      }
    }

    S[4] ^= 1n;
  }

  private static processPlaintext(
    S: bigint[],
    b: number,
    rate: number,
    plaintext: BytesLike
  ): BytesLike {
    const pLastLen = plaintext.length % rate;
    const pPadded = concatArrays(
      plaintext,
      toBytes([0x80n]),
      zeroBytes(rate - pLastLen - 1)
    );

    let ciphertext = new BigInt64Array();
    for (let i = 0; i < pPadded.length - rate; i += rate) {
      if (rate === 8) {
        S[0] ^= bytesToInt(pPadded.slice(i, i + 8));

        ciphertext = concatArrays(ciphertext, intToBytes(S[0], 8));
      } else if (rate === 16) {
        S[0] ^= bytesToInt(pPadded.slice(i, i + 8));
        S[1] ^= bytesToInt(pPadded.slice(i + 8, i + 16));

        ciphertext = concatArrays(
          ciphertext,
          intToBytes(S[0], 8),
          intToBytes(S[1], 8)
        );
      }

      this.permutation(S, b);
    }

    // last block t
    const i = pPadded.length - rate;
    if (rate === 8) {
      S[0] ^= bytesToInt(pPadded.slice(i, i + 8));

      ciphertext = concatArrays(
        ciphertext,
        intToBytes(S[0], 8).slice(0, pLastLen)
      );
    } else if (rate === 16) {
      S[0] ^= bytesToInt(pPadded.slice(i, i + 8));
      S[1] ^= bytesToInt(pPadded.slice(i + 8, i + 16));

      ciphertext = concatArrays(
        ciphertext,
        intToBytes(S[0], 8).slice(0, Math.min(8, pLastLen)),
        intToBytes(S[1], 8).slice(0, Math.max(0, pLastLen - 8))
      );
    }

    return ciphertext;
  }

  private static processCipherText(
    S: bigint[],
    b: number,
    rate: number,
    ciphertext: BytesLike
  ) {
    const cLastLen = ciphertext.length % rate;
    const cPadded = concatArrays(ciphertext, zeroBytes(rate - cLastLen));

    let plaintext = new BigInt64Array();
    for (let i = 0; i < cPadded.length - rate; i += rate) {
      if (rate === 8) {
        const c = bytesToInt(cPadded.slice(i, i + 8));

        plaintext = concatArrays(plaintext, intToBytes(S[0] ^ c, 8));

        S[0] = c;
      } else if (rate === 16) {
        const c0 = bytesToInt(cPadded.slice(i, i + 8));
        const c1 = bytesToInt(cPadded.slice(i + 8, i + 16));

        plaintext = concatArrays(
          plaintext,
          intToBytes(S[0] ^ c0, 8),
          intToBytes(S[1] ^ c1, 8)
        );

        S[0] = c0;
        S[1] = c1;
      }

      this.permutation(S, b);
    }

    // last block t
    const i = cPadded.length - rate;
    if (rate === 8) {
      const cPadding = 0x80n << (BigInt(rate - cLastLen - 1) * 8n);
      const cMask = 0xffffffffffffffffn >> BigInt(cLastLen * 8);
      const c = bytesToInt(cPadded.slice(i, i + 8));

      plaintext = concatArrays(
        plaintext,
        intToBytes(c ^ S[0], 8).slice(0, cLastLen)
      );
      S[0] = c ^ (S[0] & cMask) ^ cPadding;
    } else if (rate === 16) {
      const cLastLenWord = BigInt(cLastLen % 8);
      const cPadding = 0x80n << ((8n - cLastLenWord - 1n) * 8n);
      const cMask = 0xffffffffffffffffn >> (cLastLenWord * 8n);
      const c0 = bytesToInt(cPadded.slice(i, i + 8));
      const c1 = bytesToInt(cPadded.slice(i + 8, i + 16));

      plaintext = concatArrays(
        plaintext,
        concatArrays(intToBytes(S[0] ^ c0, 8), intToBytes(S[1] ^ c1, 8)).slice(
          0,
          cLastLen
        )
      );

      if (cLastLen < 8) {
        S[0] = c0 ^ (S[0] & cMask) ^ cPadding;
      } else {
        S[0] = c0;
        S[1] = c1 ^ (S[1] & cMask) ^ cPadding;
      }
    }

    return plaintext;
  }

  private static finalize(
    S: bigint[],
    rate: number,
    a: number,
    key: BytesLike
  ) {
    const numRate = rate;
    S[Math.floor(numRate / 8) + 0] ^= bytesToInt(key.slice(0, 8));
    S[Math.floor(numRate / 8) + 1] ^= bytesToInt(key.slice(8, 16));
    const pKey = concatArrays(key, zeroBytes(24 - key.length));
    S[Math.floor(numRate / 8) + 2] ^= bytesToInt(pKey.slice(16));

    this.permutation(S, a);

    S[3] ^= bytesToInt(key.slice(-16, -8));
    S[4] ^= bytesToInt(key.slice(-8));

    return concatArrays(intToBytes(S[3], 8), intToBytes(S[4], 8));
  }

  private static permutation(S: bigint[], rounds = 1) {
    for (let r = 12 - rounds; r < 12; r++) {
      // add round constants
      S[2] ^= 0xf0n - BigInt(r) * 0x10n + BigInt(r) * 0x1n;

      // substitution layer
      S[0] ^= S[4];
      S[4] ^= S[3];
      S[2] ^= S[1];
      const T: bigint[] = [];
      for (let i = 0; i < 5; i++) {
        T.push((S[i] ^ 0xffffffffffffffffn) & S[(i + 1) % 5]);
      }
      for (let i = 0; i < 5; i++) {
        S[i] ^= T[(i + 1) % 5];
      }
      S[1] ^= S[0];
      S[0] ^= S[4];
      S[3] ^= S[2];
      S[2] ^= 0xffffffffffffffffn;

      // linear diffusion layer
      S[0] ^= rotr(S[0], 19n) ^ rotr(S[0], 28n);
      S[1] ^= rotr(S[1], 61n) ^ rotr(S[1], 39n);
      S[2] ^= rotr(S[2], 1n) ^ rotr(S[2], 6n);
      S[3] ^= rotr(S[3], 10n) ^ rotr(S[3], 17n);
      S[4] ^= rotr(S[4], 7n) ^ rotr(S[4], 41n);
    }
  }
}
