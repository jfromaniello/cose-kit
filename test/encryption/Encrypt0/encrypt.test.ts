import { importJWK } from 'jose';
import EncryptExample01 from '../../Examples/aes-gcm-examples/aes-gcm-enc-01.json';
import EncryptExample02 from '../../Examples/aes-gcm-examples/aes-gcm-enc-02.json';
import EncryptExample03 from '../../Examples/aes-gcm-examples/aes-gcm-enc-03.json';
import { EncryptionAlgorithms, EncryptProtectedHeaders, UnprotectedHeaders, decode, Encrypt0, Headers } from '../../../src/index.js';

describe('encryption - COSE_Encrypt0 - decrypt', () => {
  it('should be able to properly encrypt with A128GCM', async () => {
    const key = await importJWK(EncryptExample01.input.encrypted.recipients[0].key);

    const content = Buffer.from(EncryptExample01.input.plaintext, 'utf8');
    //encrypt
    const cose = await Encrypt0.encrypt(
      new EncryptProtectedHeaders([
        [Headers.Algorithm, EncryptionAlgorithms.A128GCM]
      ]),
      new UnprotectedHeaders([
        [
          Headers.KeyID,
          Buffer.from(EncryptExample01.input.encrypted.recipients[0].unprotected.kid, 'utf-8')
        ],
      ]),
      content,
      key
    ).then(c => c.encode());

    const encrypted = decode(cose, Encrypt0);

    expect(encrypted.decrypt(key)).resolves.toEqual(content);
  });

  it('should be able to properly encrypt with A192GCM', async () => {
    const key = await importJWK(EncryptExample02.input.encrypted.recipients[0].key);

    const content = Buffer.from(EncryptExample02.input.plaintext, 'utf8');

    const cose = await Encrypt0.encrypt(
      new EncryptProtectedHeaders([
        [Headers.Algorithm, EncryptionAlgorithms.A192GCM]
      ]),
      new UnprotectedHeaders([
        [
          Headers.KeyID,
          Buffer.from(EncryptExample02.input.encrypted.recipients[0].unprotected.kid, 'utf-8')
        ],
      ]),
      content,
      key
    ).then(c => c.encode());

    const encrypted = decode(cose, Encrypt0);

    expect(encrypted.decrypt(key)).resolves.toEqual(content);
  });

  it('should be able to properly encrypt with A256GCM', async () => {
    const key = await importJWK(EncryptExample03.input.encrypted.recipients[0].key);

    const content = Buffer.from(EncryptExample03.input.plaintext, 'utf8');

    const cose = await Encrypt0.encrypt(
      new EncryptProtectedHeaders([
        [Headers.Algorithm, EncryptionAlgorithms.A256GCM]
      ]),
      new UnprotectedHeaders([
        [
          Headers.KeyID,
          Buffer.from(EncryptExample03.input.encrypted.recipients[0].unprotected.kid, 'utf-8')
        ],
      ]),
      content,
      key
    ).then(c => c.encode());

    const encrypted = decode(cose, Encrypt0);

    expect(encrypted.decrypt(key)).resolves.toEqual(content);
  });
});
