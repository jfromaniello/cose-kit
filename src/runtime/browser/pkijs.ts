import * as pkijs from 'pkijs';

pkijs.setEngine('webcrypto', new pkijs.CryptoEngine({
  name: 'webcrypto', crypto,
  subtle: crypto.subtle
}));

export * as pkijs from 'pkijs';
