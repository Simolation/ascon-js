import { Ascon, randomBytes } from ".";

const main = () => {
  const key = BigInt64Array.of(
    1n,
    2n,
    3n,
    4n,
    5n,
    6n,
    7n,
    8n,
    9n,
    0n,
    1n,
    2n,
    3n,
    4n,
    5n,
    6n
  );
  const nonce = new BigInt64Array(16);
  const associated = new BigInt64Array([4n, 5n]);

  const plaintext = new TextEncoder().encode("ascon");

  // const encrypted = Ascon.encrypt(key, nonce, plainText);

  // console.log("----------------------");

  // const modifiedEncrypted = concatArrays(encrypted, new BigInt64Array([]));

  // const decrypted = Ascon.decrypt(key, nonce, modifiedEncrypted);

  // console.log("Decrypted", decrypted);

  const hash = Ascon.hash(plaintext, { variant: "Ascon-Hash" });

  const r = randomBytes(32);

  console.log(r);
};

main();
