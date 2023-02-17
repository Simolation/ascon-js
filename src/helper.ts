import { AsconEncryptionVariant, BytesLike } from "./interfaces";

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

export const toBase64 = (array: BytesLike) =>
  btoa(String.fromCharCode(...new Uint8Array(array.buffer)));

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
