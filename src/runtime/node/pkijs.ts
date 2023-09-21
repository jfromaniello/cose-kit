import * as pkijs from 'pkijs';
import * as crypto from 'crypto';
import { Crypto as WebCrypto } from '@peculiar/webcrypto';

let webcrypto: WebCrypto;

if (!crypto.webcrypto || !crypto.webcrypto.subtle) {
  webcrypto = new WebCrypto();
} else {
  webcrypto = crypto.webcrypto as WebCrypto;
}

pkijs.setEngine('webcrypto', new pkijs.CryptoEngine({
  name: 'webcrypto',
  crypto: webcrypto,
  subtle: webcrypto.subtle
}));

export * as pkijs from 'pkijs';
