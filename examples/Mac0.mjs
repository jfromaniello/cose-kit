import {
  MacAlgorithms,
  Headers,
  Mac0,
} from "#dist";

import crypto from 'node:crypto';

const alg = MacAlgorithms.HS256;

(async () => {
  const secret = crypto.randomBytes(16);

  //Create a Cose Mac0:
  const cose = await Mac0.create(
    [
      [Headers.Algorithm, alg]
    ],
    [
      [Headers.ContentType, 0]
    ],
    Buffer.from('hello world', 'utf8'),
    secret
  ).then(s => s.encode());

  console.log('COSE Mac0 created:');
  console.log(cose.toString('hex'));

  const decode = Mac0.decode(cose);
  await decode.verify(
    secret,
    {
      algorithms: [alg]
    }
  );

  console.log('COSE Mac0 verified succesfully!')
})();
