import {
  EncryptionAlgorithms,
  Headers,
  Encrypt0,
} from "#dist";

import crypto from "node:crypto";

const alg = EncryptionAlgorithms.A128GCM;

(async () => {
  const secret = crypto.randomBytes(16);

  //Creating a Cose Encrypt0:
  const cose = await Encrypt0.encrypt(
    [
      [Headers.Algorithm, alg]
    ],
    [
      [Headers.ContentType, 0]
    ],
    Buffer.from('hello world', 'utf8'),
    secret
  ).then(s => s.encode());

  console.log('COSE Encrypt0 created:');
  console.log(cose.toString('hex'));

  const decode = Encrypt0.decode(cose);
  const content = await decode.decrypt(
    secret,
    {
      //limit supported algs
      algorithms: [alg]
    }
  );

  console.log('COSE Encrypt0 verified succesfully!')
  console.log(`content: ${content.toString('utf8')}`)
})();
