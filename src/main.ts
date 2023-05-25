import { Ascon, fromHex, randomBytes, toHex } from ".";

const main = () => {
  const key = fromHex("e4ea93530575bd6f5dc68cb241e32d1c");
  console.log("HeyKey", toHex(key));

  const nonce = fromHex("6c27fff03b58975180cf12de2fd2d6e2");
  const associated = new TextEncoder().encode("ASCON");

  const plaintext = new TextEncoder().encode(
    "Hallo mein Name ist Simon Osterlehner und ich bin in Muenchen geboren."
  );

  console.log("Plaintext", plaintext);

  const encrypted = Ascon.encrypt(key, nonce, plaintext, {
    variant: "Ascon-128a",
    associatedData: associated,
  });

  console.log("Encrypted", toHex(encrypted));

  // console.log("----------------------");

  const decrypted = Ascon.decrypt(key, nonce, encrypted, {
    variant: "Ascon-128a",
    associatedData: associated,
  });

  const text = new TextDecoder().decode(decrypted);

  console.log("Decrypted", decrypted);

  console.log("Decrypted", text);
};

main();
