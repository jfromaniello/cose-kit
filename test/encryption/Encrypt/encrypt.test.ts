import EncryptExample01 from '../../Examples/aes-gcm-examples/aes-gcm-01.json';
import EncryptExample02 from '../../Examples/aes-gcm-examples/aes-gcm-02.json';
import EncryptExample03 from '../../Examples/aes-gcm-examples/aes-gcm-03.json';
import EncryptExample05 from '../../Examples/aes-gcm-examples/aes-gcm-05.json';

import {
  EncryptionAlgorithms,
  EncryptProtectedHeaders,
  Encrypt,
  Headers,
  COSEKey,
  Recipient,
  UnprotectedHeaders,
  COSEKeyParam
} from '../../../src/index.js';

describe('encryption - COSE_Encrypt0 - decrypt', () => {
  it('should be able to properly encrypt with A128GCM', async () => {
    const key = COSEKey.fromJWK(EncryptExample01.input.enveloped.recipients[0].key);

    const content = Buffer.from(EncryptExample01.input.plaintext, 'utf8');

    const recipient = Recipient.create(
      [],
      new UnprotectedHeaders([
        [Headers.Algorithm, EncryptionAlgorithms.Direct],
        [Headers.KeyID, Buffer.from('our-secret', 'utf8')]
      ])
    );

    //encrypt
    const cose = await Encrypt.encrypt(
      new EncryptProtectedHeaders([
        [Headers.Algorithm, EncryptionAlgorithms.A128GCM]
      ]),
      [],
      content,
      key,
      new Uint8Array(),
      [
        recipient
      ]
    ).then(c => c.encode());

    const encrypted = Encrypt.decode(cose);

    expect(encrypted.decrypt(key)).resolves.toEqual(content);
  });

  it('should be able to properly encrypt with A192GCM', async () => {
    const key = COSEKey.fromJWK(EncryptExample02.input.enveloped.recipients[0].key);
    const content = Buffer.from(EncryptExample02.input.plaintext, 'utf8');
    const recipient = Recipient.create(
      [],
      new UnprotectedHeaders([
        [Headers.Algorithm, EncryptionAlgorithms.Direct],
        [Headers.KeyID, Buffer.from('our-secret', 'utf8')]
      ])
    );

    //encrypt
    const cose = await Encrypt.encrypt(
      new EncryptProtectedHeaders([
        [Headers.Algorithm, EncryptionAlgorithms.A192GCM]
      ]),
      [],
      content,
      key,
      new Uint8Array(),
      [
        recipient
      ]
    ).then(c => c.encode());

    const encrypted = Encrypt.decode(cose);
    expect(encrypted.decrypt(key)).resolves.toEqual(content);
  });

  it('should be able to properly encrypt with A256GCM', async () => {
    const key = COSEKey.fromJWK(EncryptExample03.input.enveloped.recipients[0].key);
    const content = Buffer.from(EncryptExample03.input.plaintext, 'utf8');
    const recipient = Recipient.create(
      [],
      new UnprotectedHeaders([
        [Headers.Algorithm, EncryptionAlgorithms.Direct],
        [Headers.KeyID, Buffer.from('our-secret', 'utf8')]
      ])
    );

    //encrypt
    const cose = await Encrypt.encrypt(
      new EncryptProtectedHeaders([
        [Headers.Algorithm, EncryptionAlgorithms.A256GCM]
      ]),
      [],
      content,
      key,
      new Uint8Array(),
      [
        recipient
      ]
    ).then(c => c.encode());

    const encrypted = Encrypt.decode(cose);
    expect(encrypted.decrypt(key)).resolves.toEqual(content);
  });

  it('should be able to properly encrypt with partial iv', async () => {
    const key = COSEKey.fromJWK(EncryptExample05.input.enveloped.recipients[0].key);
    key.set(COSEKeyParam.BaseIV, Buffer.from(
      EncryptExample05.input.enveloped.unsent.IV_hex.slice(0, -4),
      'hex'
    ));
    const content = Buffer.from(EncryptExample05.input.plaintext, 'utf8');
    const recipient = Recipient.create(
      [],
      new UnprotectedHeaders([
        [Headers.Algorithm, EncryptionAlgorithms.Direct],
        [Headers.KeyID, Buffer.from('our-secret', 'utf8')]
      ])
    );

    //encrypt
    const cose = await Encrypt.encrypt(
      new EncryptProtectedHeaders([
        [Headers.Algorithm, EncryptionAlgorithms.A128GCM]
      ]),
      new UnprotectedHeaders([
        [Headers.PartialIV, Buffer.from(EncryptExample05.input.enveloped.unprotected.partialIV_hex, 'hex')]
      ]),
      content,
      key,
      new Uint8Array(),
      [
        recipient
      ]
    ).then(c => c.encode());

    const encrypted = Encrypt.decode(cose);
    expect(encrypted.decrypt(key)).resolves.toEqual(content);
  });
});
