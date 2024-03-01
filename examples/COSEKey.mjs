import { Algorithms, COSEKey } from '#dist';
import { inspect } from 'node:util';

(async () => {
  const {privateKey, publicKey}  = await COSEKey.generate(Algorithms.ES256);
  console.log('COSE Key created.');

  console.log(`
Private Key:
${inspect(privateKey)}

Public Key:
${inspect(privateKey)}

Private key as JWK:
${inspect(privateKey.toJWK())}

Public key as JWK:
${inspect(publicKey.toJWK())}

Private key encoded as CBOR:
${privateKey.encode().toString('hex')}

Public key encoded as cbor:
${publicKey.encode().toString('hex')}

Export to JWK and import JWK as COSEKey:
${inspect(COSEKey.fromJWK(privateKey.toJWK()))}
`);
})();
