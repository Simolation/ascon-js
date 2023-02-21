import { describe, it, expect } from "vitest";
import {
  arrayEquals,
  assertHashVariant,
  assertVariant,
  concatArrays,
  fromHex,
  randomBytes,
  toHex,
} from "./helper";

describe("helper", () => {
  describe("assertVariant", () => {
    it("should throw on invalid variant", () => {
      expect(() => assertVariant("Invalid variant")).toThrow();
    });

    it.each([["Ascon-128"], ["Ascon-128a"], ["Ascon-80pq"]])(
      "should not throw on valid variant: %i",
      (variant) => {
        expect(() => assertVariant(variant)).not.toThrow();
      }
    );
  });

  describe("assertHashVariant", () => {
    it("should throw on invalid variant", () => {
      expect(() => assertVariant("Invalid variant")).toThrow();
    });

    it.each([["Ascon-Hash"], ["Ascon-Hasha"], ["Ascon-Xof"], ["Ascon-Xofa"]])(
      "should not throw on valid variant: %i",
      (variant) => {
        expect(() => assertHashVariant(variant)).not.toThrow();
      }
    );
  });

  describe("concatArrays", () => {
    it("should return an empty array when no arrays are passed", () => {
      expect(concatArrays()).toEqual(new BigInt64Array([]));
    });

    it("should return the same array when only one array is passed", () => {
      expect(concatArrays(new BigInt64Array([1n, 2n]))).toEqual(
        new BigInt64Array([1n, 2n])
      );
    });

    it("should return the concatenated array", () => {
      expect(
        concatArrays(new BigInt64Array([1n, 2n]), new BigInt64Array([3n, 4n]))
      ).toEqual(new BigInt64Array([1n, 2n, 3n, 4n]));
    });
  });

  describe("arrayEquals", () => {
    it("should return true when the arrays are equal", () => {
      expect(
        arrayEquals(new BigInt64Array([1n, 2n]), new BigInt64Array([1n, 2n]))
      ).toBe(true);
    });

    it("should return false when the arrays are not equal", () => {
      expect(
        arrayEquals(new BigInt64Array([1n, 2n]), new BigInt64Array([1n, 3n]))
      ).toBe(false);
    });

    it("should return false when the arrays are not equal", () => {
      expect(
        arrayEquals(
          new BigInt64Array([1n, 2n]),
          new BigInt64Array([1n, 2n, 3n])
        )
      ).toBe(false);
    });
  });

  describe("randomBytes", () => {
    it("should return an array of the correct length", () => {
      expect(randomBytes(10).length).toBe(10);
      expect(randomBytes(16).length).toBe(16);
      expect(randomBytes(32).length).toBe(32);
    });
  });

  describe("toHex", () => {
    it("should return an empty string when an empty array is passed", () => {
      expect(toHex(new Uint8Array([]))).toBe("");
    });

    it("should return the correct hex string", () => {
      expect(toHex(new Uint8Array([1, 2, 3, 4]))).toBe("01020304");
    });
  });

  describe("fromHex", () => {
    it("should return an empty array when an empty string is passed", () => {
      expect(fromHex("")).toEqual(new Uint8Array([]));
    });

    it("should return the correct array", () => {
      expect(fromHex("01020304")).toEqual(new Uint8Array([1, 2, 3, 4]));
    });
  });

  // describe("assertLength", () => {
  //   // Nonce length
  //   it("should throw on invalid nonce length", () => {
  //     expect(() => assertLength("", "", "Ascon-128")).toThrowError(
  //       "Invalid nonce length. Received 0 bytes but expected 16 bytes."
  //     );
  //   });

  //   it("should throw on invalid nonce length", () => {
  //     expect(() =>
  //       assertLength("", "12345678910111213141", "Ascon-128")
  //     ).toThrowError(
  //       "Invalid nonce length. Received 20 bytes but expected 16 bytes."
  //     );
  //   });

  //   it("should not throw on valid nonce length", () => {
  //     expect(() =>
  //       assertLength("", "1234567890123456", "Ascon-128")
  //     ).toThrowError(
  //       "Invalid key length. Received 0 bytes but expected 16 bytes."
  //     );
  //   });

  //   // Key length
  //   it("should throw on invalid key length", () => {
  //     expect(() =>
  //       assertLength("", "1234567890123456", "Ascon-128")
  //     ).toThrowError(
  //       "Invalid key length. Received 0 bytes but expected 16 bytes."
  //     );
  //   });

  //   it("should throw on valid key length (too long)", () => {
  //     expect(() =>
  //       assertLength("12345678901234567890", "1234567890123456", "Ascon-128")
  //     ).toThrowError(
  //       "Invalid key length. Received 20 bytes but expected 16 bytes."
  //     );
  //   });

  //   it("should not throw on valid key length", () => {
  //     expect(() =>
  //       assertLength("1234567890123456", "1234567890123456", "Ascon-128")
  //     ).not.toThrow();
  //   });

  //   it("should not throw on valid key length for Ascon-80pq", () => {
  //     expect(() =>
  //       assertLength("12345678901234567890", "1234567890123456", "Ascon-80pq")
  //     ).not.toThrow();
  //   });
  // });
});
