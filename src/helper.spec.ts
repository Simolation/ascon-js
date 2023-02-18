import { describe, it, expect } from "vitest";
import { assertLength, assertVariant } from "./helper";

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

  describe("assertLength", () => {
    // Nonce length
    it("should throw on invalid nonce length", () => {
      expect(() => assertLength("", "", "Ascon-128")).toThrowError(
        "Invalid nonce length. Received 0 bytes but expected 16 bytes."
      );
    });

    it("should throw on invalid nonce length", () => {
      expect(() =>
        assertLength("", "12345678910111213141", "Ascon-128")
      ).toThrowError(
        "Invalid nonce length. Received 20 bytes but expected 16 bytes."
      );
    });

    it("should not throw on valid nonce length", () => {
      expect(() =>
        assertLength("", "1234567890123456", "Ascon-128")
      ).toThrowError(
        "Invalid key length. Received 0 bytes but expected 16 bytes."
      );
    });

    // Key length
    it("should throw on invalid key length", () => {
      expect(() =>
        assertLength("", "1234567890123456", "Ascon-128")
      ).toThrowError(
        "Invalid key length. Received 0 bytes but expected 16 bytes."
      );
    });

    it("should throw on valid key length (too long)", () => {
      expect(() =>
        assertLength("12345678901234567890", "1234567890123456", "Ascon-128")
      ).toThrowError(
        "Invalid key length. Received 20 bytes but expected 16 bytes."
      );
    });

    it("should not throw on valid key length", () => {
      expect(() =>
        assertLength("1234567890123456", "1234567890123456", "Ascon-128")
      ).not.toThrow();
    });

    it("should not throw on valid key length for Ascon-80pq", () => {
      expect(() =>
        assertLength("12345678901234567890", "1234567890123456", "Ascon-80pq")
      ).not.toThrow();
    });
  });
});
