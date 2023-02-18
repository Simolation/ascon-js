import { describe, it, expect } from "vitest";
import { Ascon } from "./ascon";

describe.skip("ascon", () => {
  it("should not work with invalid variant", () => {
    // @ts-ignore
    expect(Ascon.encrypt("", "", "", "", "Invalid variant")).toThrow();
  });
});
