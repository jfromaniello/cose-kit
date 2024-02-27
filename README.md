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
import { importJWK } from "jose";
import { Algorithms, ProtectedHeaders, Headers, coseSign, UnprotectedHeaders } from "cose-kit";

(async () => {
  const key = await importJWK({
    "kty": "EC",
    "crv": "P-256",
    "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
    "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
    "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM"
  });

  const cose = await coseSign(
    new ProtectedHeaders([
      [Headers.Algorithm, Algorithms.ES256]
    ]),
    new UnprotectedHeaders([
      [Headers.ContentType, 3]
    ]),
    Buffer.from('hello world', 'utf8'),
    key
  );
  console.log(cose);
})();
```

Using [COSE keys](https://datatracker.ietf.org/doc/html/rfc8152#section-7):

```js
import {
  Algorithms,
  ProtectedHeaders,
  UnprotectedHeaders,
  Headers,
  coseSign,
  importCOSEKey
} from "cose-kit";

(async () => {
  const key = await importCOSEKey(
    Buffer.from('a501022001215820bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff22582020138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e23582057c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3', 'hex')
  );

  const cose = await coseSign(
    new ProtectedHeaders([
      [Headers.Algorithm, Algorithms.ES256]
    ]),
    new UnprotectedHeaders([
      [Headers.ContentType, 3]
    ]),
    Buffer.from('hello world', 'utf8'),
    key
  );
  console.log(cose);
})();
```

## Credits
-  [panva/jose](https://github.com/panva/jose) A node.js library for JOSE.


## License

MIT
