import { importJWK } from 'jose';
import HMac01 from './Examples/mac0-tests/HMac-01.json';
import HMac01Fail from './Examples/mac0-tests/mac-fail-01.json';
import HMac02Fail from './Examples/mac0-tests/mac-fail-02.json';
import HMac03Fail from './Examples/mac0-tests/mac-fail-03.json';
import MacPass01 from './Examples/mac0-tests/mac-pass-01.json';
import MacPass02 from './Examples/mac0-tests/mac-pass-02.json';
import MacPass03 from './Examples/mac0-tests/mac-pass-03.json';
import { Mac0, errors } from '../src/index.js';
import { Headers, MacAlgorithms, MacProtectedHeaders } from '../src/headers.js';

describe('Mac0', () => {
  it('should fail when key is not provided', async () => {
    const cbor = Buffer.from(HMac01.output.cbor, 'hex');
    const mac0 = Mac0.decode(cbor);
    // @ts-ignore
    await expect(() => mac0.verify(null)).rejects.toThrow();
  });

  it('should fail when the alg is not allowed', async () => {
    const key = await importJWK(HMac01.input.mac0.recipients[0].key);
    const cbor = Buffer.from(HMac01.output.cbor, 'hex');
    const mac0 = Mac0.decode(cbor);
    await expect(mac0.verify(key, { algorithms: [MacAlgorithms.HS512] }))
      .rejects
      .toThrowErrorMatching(errors.COSEAlgNotAllowed, '[1] (algorithm) Header Parameter not allowed');
  });

  it('should properly verify the hmac', async () => {
    const key = await importJWK(HMac01.input.mac0.recipients[0].key);
    const cbor = Buffer.from(HMac01.output.cbor, 'hex');
    const mac0 = Mac0.decode(cbor);
    await expect(mac0.verify(key)).resolves.toBeUndefined();
  });

  it('should properly create a Mac0 message', async () => {
    const key = await importJWK(HMac01.input.mac0.recipients[0].key);
    const expected = Buffer.from(HMac01.output.cbor, 'hex');
    const actual = await Mac0.create(
      new MacProtectedHeaders([
        [Headers.Algorithm, MacAlgorithms.HS256]
      ]),
      [], //HMac01.input.mac0.recipients[0].unprotected,
      Buffer.from(HMac01.input.plaintext, 'utf-8'),
      key,
    ).then(c => c.encode());
    expect(actual.compare(expected)).toBe(0);
  });

  it('should return false for a wrong mac', async () => {
    const key = await importJWK(MacPass01.input.mac0.recipients[0].key);
    const cbor = Buffer.from(MacPass01.output.cbor, 'hex');
    const mac0 = Mac0.decode(cbor);
    await expect(() => mac0.verify(key)).rejects.toThrow(errors.COSESignatureVerificationFailed);
  });

  it('should return true when the signature matches using an external aad', async () => {
    const externalAAD = Buffer.from(MacPass02.input.mac0.external, 'hex');
    const key = await importJWK(MacPass02.input.mac0.recipients[0].key);
    const cbor = Buffer.from(MacPass02.output.cbor, 'hex');
    const mac0 = Mac0.decode(cbor);
    await expect(mac0.verify(key, { externalAAD })).resolves.toBeUndefined();
  });

  it('should be able to verify an untagged mac0', async () => {
    const key = await importJWK(MacPass03.input.mac0.recipients[0].key);
    const cbor = Buffer.from(MacPass03.output.cbor, 'hex');
    const mac0 = Mac0.decode(cbor);
    await expect(mac0.verify(key))
      .resolves
      .toBeUndefined();
  });

  it('should throw an error when the tag is wrong', () => {
    const cbor = Buffer.from(HMac01Fail.output.cbor, 'hex');
    expect(() => Mac0.decode(cbor))
      .toThrowErrorMatching(
        errors.COSEInvalid,
        'Unexpected CBOR tag. Expected tag 17 (Mac0) but got 992'
      );
  });

  it('should return false when the signature is wrong', async () => {
    const key = await importJWK(HMac02Fail.input.mac0.recipients[0].key);
    const cbor = Buffer.from(HMac02Fail.output.cbor, 'hex');
    const mac0 = Mac0.decode(cbor);
    await expect(mac0.verify(key))
      .rejects
      .toThrow(errors.COSESignatureVerificationFailed);
  });

  it('should throw an error when the alg is not supported', async () => {
    const key = await importJWK(HMac03Fail.input.mac0.recipients[0].key);
    const cbor = Buffer.from(HMac03Fail.output.cbor, 'hex');
    const mac0 = Mac0.decode(cbor);
    await expect(mac0.verify(key))
      .rejects
      .toThrowErrorMatching(errors.COSEInvalid, 'Unsupported MAC algorithm -999');
  });

});
