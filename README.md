This is an early prototype of a RFC8152 COSE library for node.js.

It is inspired by and uses [panva/jose](https://github.com/panva/jose).

Example:

```js
const { importJWK } = require('jose');
const { coseVerify }  = require('cose-kit');

const key = await importJWK(jwk);

const cose = Buffer.from(coseHEX, 'hex');

const { isValid } = await coseVerify(cose, key);
```

Multi-signature:

```js
const { importJWK } = require('jose');
const { coseVerifyMultiSignature }  = require('cose-kit');

const key = await importJWK(jwk);

const cose = Buffer.from(coseHEX, 'hex');

const { isValid } = await coseVerifyMultiSignature(cose, [ key ]);
```


X509 certificates:

```js
const { coseVerifyX509 }  = require('cose-kit');

const caRoots = [
  `-----BEGIN CERTIFICATE-----...`
];

const cose = Buffer.from(coseHEX, 'hex');

const { isValid } = await coseVerifyX509(cose, caRoots);
```

Signing a payload:


```js
const { importJWK } = require('jose');
const { coseSign }  = require('cose-kit');

const key = await importJWK(jwk);

const cose = await coseSign(
  { alg: 'ES256' },
  { ctyp: 0 },
  Buffer.from('hello world', 'utf8'),
  key
);
```

Using [COSE keys](https://datatracker.ietf.org/doc/html/rfc8152#section-7):

```js
const { coseSign, importCOSEKey }  = require('cose-kit');
const key = await importCOSEKey(coseKey);
const cose = await coseSign(
  { alg: 'ES256' },
  { ctyp: 0 },
  Buffer.from('hello world', 'utf8'),
  key
);
```


## Credits
-  [panva/jose](https://github.com/panva/jose) A node.js library for JOSE.


## License

MIT
