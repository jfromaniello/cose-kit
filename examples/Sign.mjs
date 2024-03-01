import { generateKeyPair } from "jose";

import {
  Algorithms,
  ProtectedHeaders,
  UnprotectedHeaders,
  Headers,
  Sign,
} from "#dist";

const alg = 'ES256';

(async () => {
  const signer1 = await generateKeyPair(alg);
  const signer2 = await generateKeyPair(alg);

  //Creating a Cose_Sign1:
  const cose = await Sign.sign(
    new ProtectedHeaders([]),
    new UnprotectedHeaders([
      [Headers.ContentType, 0]
    ]),
    Buffer.from('hello world', 'utf8'),
    [
      {
        key: signer1.privateKey,
        protectedHeaders: new ProtectedHeaders([
          [Headers.Algorithm, Algorithms[alg]]
        ])
      },
      {
        key: signer2.privateKey,
        protectedHeaders: new ProtectedHeaders([
          [Headers.Algorithm, Algorithms[alg]]
        ])
      }
    ]
  ).then(s => s.encode());

  // Cose is a buffer

  console.log('COSE_Sign created:');
  console.log(cose.toString('hex'));

  const decode = Sign.decode(cose);
  await decode.verify(signer1.publicKey);
  await decode.verify(signer2.publicKey);

  console.log('COSE_Sign verified succesfully for the two recipients!')
})();
