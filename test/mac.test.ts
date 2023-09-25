import { importJWK } from 'jose';
import HMac01 from './Examples/mac0-tests/HMac-01.json';
import HMac01Fail from './Examples/mac0-tests/mac-fail-01.json';
import HMac02Fail from './Examples/mac0-tests/mac-fail-02.json';
import HMac03Fail from './Examples/mac0-tests/mac-fail-03.json';
import MacPass01 from './Examples/mac0-tests/mac-pass-01.json';
import MacPass02 from './Examples/mac0-tests/mac-pass-02.json';
import MacPass03 from './Examples/mac0-tests/mac-pass-03.json';
import { coseVerifyMAC0, Mac0 } from '../src/index.js';
import { MacProtectedHeader } from '../src/headers';

describe('Mac0', () => {
  it('should properly verify the hmac', async () => {
    const key = await importJWK(HMac01.input.mac0.recipients[0].key);
    const cbor = Buffer.from(HMac01.output.cbor, 'hex');
    const result = await coseVerifyMAC0(cbor, key);
    expect(result.isValid).toBeTruthy();
    expect(result).toMatchSnapshot();
  });

  it('should properly create a Mac0 message', async () => {
    const key = await importJWK(HMac01.input.mac0.recipients[0].key);
    const expected = Buffer.from(HMac01.output.cbor, 'hex');
    const actual = await Mac0.create(
      HMac01.input.mac0.protected as MacProtectedHeader,
      {}, //HMac01.input.mac0.recipients[0].unprotected,
      Buffer.from(HMac01.input.plaintext, 'utf-8'),
      key,
    ).then(c => c.encode());
    expect(actual.compare(expected)).toBe(0);
  });

  it('should return false for a wrong mac', async () => {
    const key = await importJWK(MacPass01.input.mac0.recipients[0].key);
    const cbor = Buffer.from(MacPass01.output.cbor, 'hex');
    const result = await coseVerifyMAC0(cbor, key);
    expect(result.isValid).toBeFalsy();
  });

  it('should return true when the signature matches using an external aad', async () => {
    const external = Buffer.from(MacPass02.input.mac0.external, 'hex');
    const key = await importJWK(MacPass02.input.mac0.recipients[0].key);
    const cbor = Buffer.from(MacPass02.output.cbor, 'hex');
    const result = await coseVerifyMAC0(cbor, key, external);
    expect(result.isValid).toBeTruthy();
  });

  it('should be able to verify an untagged mac0', async () => {
    const key = await importJWK(MacPass03.input.mac0.recipients[0].key);
    const cbor = Buffer.from(MacPass03.output.cbor, 'hex');
    const result = await coseVerifyMAC0(cbor, key);
    expect(result.isValid).toBeTruthy();
  });

  it('should throw an error when the tag is wrong', async () => {
    const key = await importJWK(HMac01Fail.input.mac0.recipients[0].key);
    const cbor = Buffer.from(HMac01Fail.output.cbor, 'hex');
    await expect(() => coseVerifyMAC0(cbor, key)).rejects.toThrow('unexpected COSE type');
  });

  it('should return false when the signature is wrong', async () => {
    const key = await importJWK(HMac02Fail.input.mac0.recipients[0].key);
    const cbor = Buffer.from(HMac02Fail.output.cbor, 'hex');
    const { isValid } = await coseVerifyMAC0(cbor, key);
    expect(isValid).toBeFalsy();
  });

  it('should throw an error when the alg is not supported', async () => {
    const key = await importJWK(HMac03Fail.input.mac0.recipients[0].key);
    const cbor = Buffer.from(HMac03Fail.output.cbor, 'hex');
    await expect(() => coseVerifyMAC0(cbor, key)).rejects.toThrow('unknown algorithm: -999');
  });

});
