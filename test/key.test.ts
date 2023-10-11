import fs from "fs";
import { COSEKeyFromJWK, COSEKeyToJWK, importCOSEKey } from "../src/key/index.js";
import { encoder } from "../src/cbor.js";

describe('COSE key', () => {
  const examplesDir = `${__dirname}/Examples/key-examples`;
  fs.readdirSync(examplesDir)
    .map(f => {
      return {
        type: f.includes('private') ? 'private' : 'public',
        ...JSON.parse(fs.readFileSync(`${examplesDir}/${f}`, 'utf8'))
      };
    })
    .forEach((testCase) => {
      describe(testCase.type, () => {
        describe(testCase.title, () => {
          const coseKey = Buffer.from(testCase.output.cbor, 'hex');
          it('should properly decode to JWK', () => {
            const jwk = COSEKeyToJWK(coseKey);
            expect(jwk).toEqual(testCase.jwk);
          });
          it('should be able to import the key', async () => {
            await importCOSEKey(coseKey);
          });
          it('should properly encode the jwk to cose', () => {
            expect(encoder.decode(COSEKeyFromJWK(testCase.jwk)))
              .toEqual(encoder.decode(coseKey));
          });
        });
      });
    });
});
