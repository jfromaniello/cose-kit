import {
  EncryptionAlgorithms,
  Headers,
  Encrypt,
  Recipient,
} from "#dist";

import crypto from "node:crypto";

const alg = EncryptionAlgorithms.A128GCM;

(async () => {
  const secret = crypto.randomBytes(16);

  //Creating a Cose Encrypt:
  const cose = await Encrypt.encrypt(
    [
      [Headers.Algorithm, alg]
    ],
    [
      [Headers.ContentType, 0]
    ],
    Buffer.from('hello world', 'utf8'),
    secret,
    new Uint8Array(),
    [
      Recipient.create(
        [],
        [
          [Headers.Algorithm, EncryptionAlgorithms.Direct],
          [Headers.KeyID, Buffer.from('our-secret', 'utf8')]
        ]
      )
    ]
  ).then(s => s.encode());

  console.log('COSE Encrypt created:');
  console.log(cose.toString('hex'));

  const decode = Encrypt.decode(cose);
  const content = await decode.decrypt(
    secret,
    {
      //limit supported algs
      algorithms: [alg]
    }
  );

  console.log('COSE Encrypt verified succesfully!')
  console.log(`content: ${content.toString('utf8')}`)
})();
