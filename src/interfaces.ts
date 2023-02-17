export type BytesLike = BigInt64Array;

export type AsconEncryptionVariant = "Ascon-128" | "Ascon-128a" | "Ascon-80pq";
export type AsconHashVariant =
  | "Ascon-Hash"
  | "Ascon-Hasha"
  | "Ascon-Xof"
  | "Ascon-Xofa";

export interface AsconEcnryptionOptions {
  variant?: AsconEncryptionVariant;
  associatedData?: BytesLike;
}
