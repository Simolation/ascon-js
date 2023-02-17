import { Ascon } from ".";
import { concatArrays } from "./helper";

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

  // const str2ab = (text: string): ArrayBufferLike => {
  //   return new TextEncoder().encode(text);
  // };

  //const plainText = str2ab("Hello world");
  const plainText = new BigInt64Array([26n, 32n, 88n, 155n]);

  const encrypted = Ascon.encrypt(key, nonce, plainText);

  console.log("----------------------");

  const modifiedEncrypted = concatArrays(encrypted, new BigInt64Array([]));

  const decrypted = Ascon.decrypt(key, nonce, modifiedEncrypted);

  console.log("Decrypted", decrypted);
};

main();
