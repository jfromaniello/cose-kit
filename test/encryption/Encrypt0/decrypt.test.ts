import { importJWK } from 'jose';
import EncryptExample01 from '../../Examples/aes-gcm-examples/aes-gcm-enc-01.json';
import EncryptExample02 from '../../Examples/aes-gcm-examples/aes-gcm-enc-02.json';
import EncryptExample03 from '../../Examples/aes-gcm-examples/aes-gcm-enc-03.json';
import EncryptExample04 from '../../Examples/aes-gcm-examples/aes-gcm-enc-04.json';
import { EncryptionAlgorithms, Encrypt0, Headers, errors } from '../../../src/index.js';

describe('encryption - COSE_Encrypt0 - decrypt', () => {
  it('should fail when no key is provided', async () => {
    const cbor = Buffer.from(EncryptExample01.output.cbor, 'hex');
    const encrypt0 = Encrypt0.decode(cbor);
    //@ts-ignore
    await expect(encrypt0.decrypt(null)).rejects.toThrow();
  });

  it('should fail when the alg is not allowed', async () => {
    const key = await importJWK(EncryptExample01.input.encrypted.recipients[0].key);
    const cbor = Buffer.from(EncryptExample01.output.cbor, 'hex');
    const encrypt0 = Encrypt0.decode(cbor);
    await expect(encrypt0.decrypt(key, { algorithms: [EncryptionAlgorithms.A256GCM] }))
      .rejects
      .toThrowErrorMatching(errors.COSEAlgNotAllowed, '[1] (algorithm) Header Parameter not allowed');
  });

  it('should properly decrypt EncryptExample01 (decode)', async () => {
    const key = await importJWK(EncryptExample01.input.encrypted.recipients[0].key);
    const cbor = Buffer.from(EncryptExample01.output.cbor, 'hex');
    const encrypt0 = Encrypt0.decode(cbor);
    const decrypted = await encrypt0.decrypt(key);

    expect(encrypt0.protectedHeaders.get(Headers.Algorithm))
      .toBe(EncryptionAlgorithms.A128GCM);

    expect(decrypted).toEqual(
      Buffer.from(EncryptExample01.input.plaintext, 'utf8')
    );
  });

  it('should properly decrypt EncryptExample01', async () => {
    const key = await importJWK(EncryptExample01.input.encrypted.recipients[0].key);
    const cbor = Buffer.from(EncryptExample01.output.cbor, 'hex');
    const encrypt0 = Encrypt0.decode(cbor);
    const decrypted = await encrypt0.decrypt(key);
    expect(decrypted).toEqual(Buffer.from(EncryptExample01.input.plaintext, 'utf8'));
  });

  it('should properly decrypt EncryptExample02', async () => {
    const key = await importJWK(EncryptExample02.input.encrypted.recipients[0].key);
    const cbor = Buffer.from(EncryptExample02.output.cbor, 'hex');
    const encrypt0 = Encrypt0.decode(cbor);
    const decrypted = await encrypt0.decrypt(key);
    expect(decrypted).toEqual(Buffer.from(EncryptExample02.input.plaintext, 'utf8'));
  });

  it('should properly decrypt EncryptExample03', async () => {
    const key = await importJWK(EncryptExample03.input.encrypted.recipients[0].key);
    const cbor = Buffer.from(EncryptExample03.output.cbor, 'hex');
    const encrypt0 = Encrypt0.decode(cbor);
    const decrypted = await encrypt0.decrypt(key);
    expect(decrypted).toEqual(Buffer.from(EncryptExample03.input.plaintext, 'utf8'));
  });

  it('should fail to decrypt EncryptExample04', async () => {
    const key = await importJWK(EncryptExample04.input.encrypted.recipients[0].key);
    const cbor = Buffer.from(EncryptExample04.output.cbor, 'hex');
    const encrypt0 = Encrypt0.decode(cbor);
    await expect(encrypt0.decrypt(key))
      .rejects
      .toThrow(errors.COSEDecryptionFailed);
  });

  it('should fail to decrypt with an unsupported alg', async () => {
    const key = await importJWK(EncryptExample04.input.encrypted.recipients[0].key);
    const encrypt0 = new Encrypt0(
      new Map([[
        Headers.Algorithm,
        89467
      ]]),
      new Map(),
      Buffer.from(EncryptExample04.intermediates.AAD_hex, 'hex')
    );
    await expect(encrypt0.decrypt(key))
      .rejects
      .toThrowErrorMatching(errors.COSEInvalid, 'Unsupported encryption algorithm 89467');
  });

});
