export type BytesLike = BigInt64Array;

export type AsconEncryptionVariant = "Ascon-128" | "Ascon-128a" | "Ascon-80pq";
export type AsconHashVariant =
  | "Ascon-Hash"
  | "Ascon-Hasha"
  | "Ascon-Xof"
  | "Ascon-Xofa";

export interface AsconEncryptionOptions {
  variant?: AsconEncryptionVariant;
  associatedData?: Uint8Array;
}

export interface AsconHashOptionsFixLength {
  variant?: "Ascon-Hash" | "Ascon-Hasha";
}

export interface AsconHashOptionsVariableLength {
  variant?: "Ascon-Xof" | "Ascon-Xofa";
  length?: number;
}

export type AsconHashOptions =
  | AsconHashOptionsFixLength
  | AsconHashOptionsVariableLength;
