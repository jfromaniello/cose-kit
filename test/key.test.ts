import fs from "fs";
import { COSEKey } from "../src/key/index.js";

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
            const jwk = COSEKey.import(coseKey).toJWK();
            expect(jwk).toEqual(testCase.jwk);
          });
          it('should be able to import the key', async () => {
            await COSEKey.import(coseKey).toKeyLike();
          });
          it('should properly encode the jwk to cose', () => {
            const actual = COSEKey.fromJWK(testCase.jwk);
            const expected = COSEKey.import(coseKey);
            expect(actual).toEqual(expected);
          });
        });
      });
    });
});
