import type {
  AsconEncryptionVariant,
  AsconHashVariant,
  BytesLike,
} from "./interfaces";

/**
 * Assert that the variant is a valid Ascon variant.
 * @param variant The variant to assert.
 */
export function assertVariant(
  variant: string
): asserts variant is AsconEncryptionVariant {
  if (!["Ascon-128", "Ascon-128a", "Ascon-80pq"].includes(variant)) {
    throw new Error(
      `Invalid Ascon variant. "${variant}" is not a valid Ascon variant out of "Ascon-128", "Ascon-128a", "Ascon-80pq".`
    );
  }
}

export function assertHashVariant(
  variant: string
): asserts variant is AsconHashVariant {
  if (
    !["Ascon-Hash", "Ascon-Hasha", "Ascon-Xof", "Ascon-Xofa"].includes(variant)
  ) {
    throw new Error(
      `Invalid Ascon hash variant. "${variant}" is not a valid Ascon hash variant out of "Ascon-Hash", "Ascon-Hasha", "Ascon-Xof", "Ascon-Xofa".`
    );
  }
}

/**
 * Assert that the key and nonce are of the correct length.
 * @param key The key to assert.
 * @param nonce The nonce to assert.
 * @param variant The used variant.
 */
export function assertLength(
  key: BytesLike,
  nonce: BytesLike,
  variant: AsconEncryptionVariant
) {
  // Check the correct nonce length.
  if (nonce.length != 16) {
    throw new Error(
      `Invalid nonce length. Received ${nonce.length} bytes but expected 16 bytes.`
    );
  }

  // Check the correct key length.
  if (!(key.length == 16 || (key.length == 20 && variant == "Ascon-80pq"))) {
    throw new Error(
      `Invalid key length. Received ${key.length} bytes but expected ${
        variant == "Ascon-80pq" ? 20 : 16
      } bytes.`
    );
  }

  return true;
}

export function assertHashLength(
  hashLength: number,
  variant: AsconHashVariant
) {
  if (["Ascon-Hash", "Ascon-Hasha"].includes(variant) && hashLength != 32) {
    throw new Error(
      `Invalid hash length. Received ${hashLength} bytes but expected 32 bytes for ${variant}.`
    );
  }
  // else if (["Ascon-Xof", "Ascon-Xofa"].includes(variant) && hashLength < 32) {
  //   throw new Error(
  //     `Invalid hash length. Received ${hashLength} bytes but expected >= 32 bytes.`
  //   );
  // }
}

export function toBytes(value: bigint[]): BytesLike {
  return new BigInt64Array(value);
}

export function zeroBytes(length: number): BytesLike {
  return new BigInt64Array(length);
}

export function concatArrays(...arrays: BytesLike[]): BytesLike {
  const totalLength = arrays.reduce((acc, val) => acc + val.length, 0);
  const result = new BigInt64Array(totalLength);
  let offset = 0;

  for (const array of arrays) {
    result.set(array, offset);
    offset += array.length;
  }

  return result;
}

export function bytesToInt(bytes: BytesLike): bigint {
  return bytes.reduce(
    (acc, bi, i) => acc + (BigInt(bi) << BigInt((bytes.length - 1 - i) * 8)),
    BigInt(0)
  );
}

export function intToBytes(integer: bigint, nBytes: number): BytesLike {
  const result: bigint[] = [];
  for (let i = 0; i < nBytes; i++) {
    result.push((integer >> BigInt((nBytes - 1 - i) * 8)) & 0xffn);
  }
  return new BigInt64Array(result);
}

export function bytesToState(bytes: BytesLike): bigint[] {
  return Array(5)
    .fill(BigInt(0))
    .map((_, w) => bytesToInt(bytes.subarray(w * 8, (w + 1) * 8)));
}

export function rotr(val: bigint, r: bigint): bigint {
  return (val >> r) | ((val & ((1n << r) - 1n)) << (64n - r));
}

export function arrayEquals(a: BytesLike, b: BytesLike): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

export function transformArrayBufferToBigInt(array: Uint8Array): BytesLike {
  return array.reduce((acc, val, i) => {
    acc[i] = BigInt(val);
    return acc;
  }, new BigInt64Array(array.length));
}

export function transformBigIntToArrayBufferLike(array: BytesLike): Uint8Array {
  return array.reduce((acc, val, i) => {
    acc[i] = Number(val);
    return acc;
  }, new Uint8Array(array.length));
}

export const randomBytes = (n: number): Uint8Array => {
  // @ts-ignore
  if (typeof self !== "undefined" && (self.crypto || self.msCrypto)) {
    // Browsers
    // @ts-ignore
    const crypto = self.crypto || self.msCrypto;
    const QUOTA = 65536;
    const a = new Uint8Array(n);
    for (let i = 0; i < n; i += QUOTA) {
      crypto.getRandomValues(a.subarray(i, i + Math.min(n - i, QUOTA)));
    }
    return a;
  } else {
    // Node
    return require("crypto").randomBytes(n);
  }
};

/**
 * Convert a buffer to a hex string.
 * @param buffer The buffer to convert.
 * @returns The hex string.
 */
export const toHex = (buffer: Uint8Array): string => {
  return Array.prototype.map
    .call(buffer, (n) => n.toString(16).padStart(2, "0"))
    .join("");
};

/**
 * Convert a hex string to a buffer.
 * @param hexString The hex string to convert.
 * @returns The buffer.
 */
export const fromHex = (hexString: string) => {
  return Uint8Array.from(
    hexString.match(/.{1,2}/g)?.map((byte) => parseInt(byte, 16)) ?? []
  );
};
