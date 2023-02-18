import { Ascon, randomBytes } from ".";

const main = () => {
  const key = Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6);
  const nonce = new Uint8Array(16);
  const associated = new Uint8Array([4, 5]);

  const plaintext = new TextEncoder().encode("ascon");

  const encrypted = Ascon.encrypt(key, nonce, plaintext);

  // console.log("----------------------");

  const decrypted = Ascon.decrypt(key, nonce, encrypted);

  const text = new TextDecoder().decode(decrypted);

  console.log("Decrypted", text);

  const hash = Ascon.hash(plaintext, { variant: "Ascon-Hash" });

  const r = randomBytes(32);

  console.log(r);
};

main();
