import { describe, it, expect } from "vitest";
import { Ascon } from "./ascon";
import { fromHex, toHex } from "./helper";
import { AsconEncryptionVariant, AsconHashVariant } from "./interfaces";

const key = fromHex("e4ea93530575bd6f5dc68cb241e32d1c");
const key20 = fromHex("417de9f4e80d795a9ed9885878f03db21fa52eef");
const nonce = fromHex("6c27fff03b58975180cf12de2fd2d6e2");

const arrayToLong = fromHex("01020304050607080900010203040506070809");
const plainText = new TextEncoder().encode("ascon");
const associatedData = new TextEncoder().encode("ASCON");

describe("Ascon.hash", () => {
  it.each([
    {
      variant: "Ascon-Hash" as AsconHashVariant,
      length: 32,
      expected: fromHex(
        "02c895cb92d79f195ed9e3e2af89ae307059104aaa819b9a987a76cf7cf51e6e"
      ),
    },
    {
      variant: "Ascon-Hasha" as AsconHashVariant,
      length: 32,
      expected: fromHex(
        "d5919be57877fb2216f9b3e2df202bdf0002131c2fa496ee0de2cdaebc2d7902"
      ),
    },
    {
      variant: "Ascon-Xof" as AsconHashVariant,
      length: 64,
      expected: fromHex(
        "85483cc9c035082b093c520b46274aff8c68c05aea11488e636d7db86e4c39d545dbec021b9d80dc2c436c5dbab9fef37956bd4fbb8e606e23fc7013d58d360b"
      ),
    },
    {
      variant: "Ascon-Xofa" as AsconHashVariant,
      length: 64,
      expected: fromHex(
        "1948e5fedc1e016f5a1c32014900303727ac6f3ea31bba72ced3f964f8d21394feb85a539017da13e58a50fe6b99ca1ecaf06e34ef4f3ee1df421eb4e0db44eb"
      ),
    },
  ])(
    "should hash with $variant ($length byte)",
    ({ variant, length, expected }) => {
      const hashed = Ascon.hash(plainText, { variant, length });

      expect(hashed).toHaveLength(length || 32);
      expect(hashed).toEqual(expected);
    }
  );
});

describe("Ascon.encrypt", () => {
  it("should not work with invalid variant", () => {
    expect(
      // @ts-ignore
      () => Ascon.encrypt(key, key, fromHex(""), { variant: "Invalid variant" })
    ).toThrow();
  });

  it("should not work with invalid key or nonce length", () => {
    expect(() => Ascon.encrypt(arrayToLong, key, fromHex(""))).toThrow();

    expect(() => Ascon.encrypt(key, arrayToLong, fromHex(""))).toThrow();

    expect(() =>
      Ascon.encrypt(arrayToLong, arrayToLong, fromHex(""))
    ).toThrow();
  });

  it.each([
    {
      variant: "Ascon-128" as AsconEncryptionVariant,
      associatedData,
      expected: fromHex("8c2787b639a7313202269e6018607e184f88908d46"),
    },
    {
      variant: "Ascon-128" as AsconEncryptionVariant,
      associatedData: undefined,
      expected: fromHex("716868c0bf7619bb8288d11833c3153ee8495c71d4"),
    },
    {
      variant: "Ascon-128a" as AsconEncryptionVariant,
      associatedData,
      expected: fromHex("4bd5fc8198f62a4e2cdf26a8804f82bb46c9c83358"),
    },
    {
      variant: "Ascon-128a" as AsconEncryptionVariant,
      associatedData: undefined,
      expected: fromHex("481a69a1ecb5c9e50f4a830144d3d095e3b44dcb71"),
    },
    {
      variant: "Ascon-80pq" as AsconEncryptionVariant,
      associatedData,
      expected: fromHex("a6d74ad80a8f247a53ed30ddfb5ad0ca85be47beda"),
    },
    {
      variant: "Ascon-80pq" as AsconEncryptionVariant,
      associatedData: undefined,
      expected: fromHex("fa7f5761d9472a7974197fb0148a7c0561b4a201d2"),
    },
  ])(
    "should encrypt with $variant",
    ({ variant, associatedData, expected }) => {
      const encrypted = Ascon.encrypt(
        variant === "Ascon-80pq" ? key20 : key,
        nonce,
        plainText,
        {
          associatedData,
          variant,
        }
      );

      // Check the length of the encrypted text + 16 bytes for the tag
      expect(encrypted).toHaveLength(plainText.length + 16);
      expect(encrypted).toEqual(expected);
      expect(encrypted.slice(0, -16)).toEqual(expected.slice(0, -16));
      expect(encrypted.slice(-16)).toEqual(expected.slice(-16));
    }
  );
});

describe("Ascon.decrypt", () => {
  it("should not work with invalid variant", () => {
    expect(
      // @ts-ignore
      () => Ascon.decrypt(key, key, fromHex(""), { variant: "Invalid variant" })
    ).toThrow();
  });

  it("should not work with invalid key or nonce length", () => {
    expect(() => Ascon.decrypt(arrayToLong, key, fromHex(""))).toThrow();

    expect(() => Ascon.decrypt(key, arrayToLong, fromHex(""))).toThrow();

    expect(() =>
      Ascon.decrypt(arrayToLong, arrayToLong, fromHex(""))
    ).toThrow();
  });

  it.each([
    {
      variant: "Ascon-128" as AsconEncryptionVariant,
      associatedData,
      ciphertext: fromHex("8c2787b639a7313202269e6018607e184f88908d46"),
    },
    {
      variant: "Ascon-128" as AsconEncryptionVariant,
      associatedData: undefined,
      ciphertext: fromHex("716868c0bf7619bb8288d11833c3153ee8495c71d4"),
    },
    {
      variant: "Ascon-128a" as AsconEncryptionVariant,
      associatedData,
      ciphertext: fromHex("4bd5fc8198f62a4e2cdf26a8804f82bb46c9c83358"),
    },
    {
      variant: "Ascon-128a" as AsconEncryptionVariant,
      associatedData: undefined,
      ciphertext: fromHex("481a69a1ecb5c9e50f4a830144d3d095e3b44dcb71"),
    },
    {
      variant: "Ascon-80pq" as AsconEncryptionVariant,
      associatedData,
      ciphertext: fromHex("a6d74ad80a8f247a53ed30ddfb5ad0ca85be47beda"),
    },
    {
      variant: "Ascon-80pq" as AsconEncryptionVariant,
      associatedData: undefined,
      ciphertext: fromHex("fa7f5761d9472a7974197fb0148a7c0561b4a201d2"),
    },
  ])(
    "should decrypt with $variant",
    ({ variant, associatedData, ciphertext }) => {
      const decrypted = Ascon.decrypt(
        variant === "Ascon-80pq" ? key20 : key,
        nonce,
        ciphertext,
        {
          associatedData,
          variant,
        }
      );

      // Check the length of the encrypted text + 16 bytes for the tag
      expect(decrypted).toHaveLength(plainText.length);
      expect(decrypted).toEqual(plainText);
    }
  );

  it("should fail when the ciphertext is invalid", () => {
    expect(() =>
      Ascon.decrypt(
        key,
        nonce,
        fromHex("fa7f5761d9472a7974197fb0148a7c0561b4a201d3")
      )
    ).toThrow("Could not be decrypted. Tags don't match.");
  });
});
