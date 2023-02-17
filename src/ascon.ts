import {
  arrayEquals,
  assertLength,
  assertVariant,
  bytesToInt,
  bytesToState,
  concatArrays,
  intToBytes,
  rotr,
  toBytes,
  zeroBytes,
} from "./helper";
import { AsconEcnryptionOptions, BytesLike } from "./interfaces";

export class Ascon {
  public static encrypt(
    key: BytesLike,
    nonce: BytesLike,
    plaintext: BytesLike,
    options?: AsconEcnryptionOptions
  ) {
    const variant = options?.variant ?? "Ascon-128";
    assertVariant(variant);
    assertLength(key, nonce, variant);

    let S = Array(5).fill(BigInt(0));
    const k = key.length * 8; // bits
    const a = 12; // rounds
    const b = variant === "Ascon-128a" ? 8 : 6; // rounds
    const rate = variant === "Ascon-80pq" ? 16 : 8; // bytes

    S = this.initialize(S, k, rate, a, b, key, nonce);

    this.processAssociatedData(S, b, rate, options?.associatedData);

    const cipherText = this.processPlaintext(S, b, rate, plaintext);

    const tag = this.finalize(S, rate, a, key);

    return concatArrays(cipherText, tag);
  }

  public static decrypt(
    key: BytesLike,
    nonce: BytesLike,
    ciphertext: BytesLike,
    options?: AsconEcnryptionOptions
  ) {
    const variant = options?.variant ?? "Ascon-128";

    assertVariant(variant);
    assertLength(key, nonce, variant);

    let S = Array(5).fill(BigInt(0));
    const k = key.length * 8; // bits
    const a = 12; // rounds
    const b = variant === "Ascon-128a" ? 8 : 6; // rounds
    const rate = variant === "Ascon-80pq" ? 16 : 8; // bytes

    S = this.initialize(S, k, rate, a, b, key, nonce);
    this.processAssociatedData(S, b, rate, options?.associatedData);

    const plainText = this.processCipherText(
      S,
      b,
      rate,
      ciphertext.slice(0, -16)
    );

    const tag = this.finalize(S, rate, a, key);

    if (!arrayEquals(tag, ciphertext.slice(-16))) {
      throw new Error("Could not be decrypted. Tags don't match.");
    }

    return plainText;
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
        intToBytes(S[0] ^ c0, 8),
        intToBytes(S[1] ^ c1, 8)
      ).slice(0, cLastLen);

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
    S[Math.floor(numRate / 8) + 2] ^= bytesToInt(key.slice(16));

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
