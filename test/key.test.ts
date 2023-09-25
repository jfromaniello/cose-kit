import { COSEKeyToJWK, importCOSEKey } from "../src/key/index.js";

describe('COSE key', () => {
  describe('when parsing a public key', () => {
    const coseKey = Buffer.from('a5200121582065eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d2258201e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c01020278246d65726961646f632e6272616e64796275636b406275636b6c616e642e6578616d706c65', 'hex');
    it('should properly decode to JWK', () => {
      const jwk = COSEKeyToJWK(coseKey);
      expect(jwk).toMatchSnapshot();
    });

    it('should be able to be imported as jwk', () => {
      const keyLike = importCOSEKey(coseKey);
      expect(keyLike).toMatchSnapshot();
    });
  });
  describe('when parsing a private key', () => {
    const coseKey = Buffer.from('a601020278246d65726961646f632e6272616e64796275636b406275636b6c616e642e6578616d706c65200121582065eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d2258201e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c235820aff907c99f9ad3aae6c4cdf21122bce2bd68b5283e6907154ad911840fa208cf', 'hex');

    it('should properly decode to JWK', () => {
      const jwk = COSEKeyToJWK(coseKey);
      expect(jwk).toMatchSnapshot();
    });

    it('should be able to be imported as jwk', () => {
      const keyLike = importCOSEKey(coseKey);
      expect(keyLike).toMatchSnapshot();
    });
  });
})
