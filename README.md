This is an early prototype of a RFC8152 COSE library for node.js.

It is inspired and uses a lot of code from [panva/jose](https://github.com/panva/jose).

Example:

```js
const { importJWK } = require('jose');
const { coseVerify }  = require('cose');

const key = await importJWK(jwk);

const cose = Buffer.from(coseHEX, 'hex');

const { isValid } = await coseVerify(cose, key);
```

Multi-signature:

```js
const { importJWK } = require('jose');
const { coseVerifyMultiSignature }  = require('cose');

const key = await importJWK(jwk);

const cose = Buffer.from(coseHEX, 'hex');

const { isValid } = await coseVerifyMultiSignature(cose, [ key ]);
```


X509 certificates:

```js
const { coseVerifyX509 }  = require('cose');

const caRoots = [
  `-----BEGIN CERTIFICATE-----...`
];

const cose = Buffer.from(coseHEX, 'hex');

const { isValid } = await coseVerifyX509(cose, caRoots);
```

Signing a payload:


```js
const { importJWK } = require('jose');
const { sign }  = require('cose');

const key = await importJWK(jwk);

const cose = await sign(
  { alg: 'ES256' },
  { ctyp: 0 },
  'hello world',
  key
);

```


## Credits
-  [panva/jose](https://github.com/panva/jose) A node.js library for JOSE.


## License

MIT
