import { generateKeyPair } from "jose";

import {
  Algorithms,
  ProtectedHeaders,
  UnprotectedHeaders,
  Headers,
  Sign1,
} from "#dist";

const alg = 'ES256';

(async () => {
  const { publicKey, privateKey } = await generateKeyPair(alg);

  //Creating a Cose Sign1:
  const cose = await Sign1.sign(
    new ProtectedHeaders([
      [Headers.Algorithm, Algorithms[alg]]
    ]),
    new UnprotectedHeaders([
      [Headers.ContentType, 0]
    ]),
    Buffer.from('hello world', 'utf8'),
    privateKey
  ).then(s => s.encode());

  // Cose is a buffer

  console.log('COSE Sign1 created:');
  console.log(cose.toString('hex'));

  const decode = Sign1.decode(cose);
  await decode.verify(
    publicKey,
    {
      algorithms: [Algorithms[alg]]
    }
  );

  console.log('COSE Sign1 verified succesfully!')
})();
