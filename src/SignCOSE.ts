import { KeyLike } from "jose";
import sign from "jose/sign";

export class SignJWT {
  // private _protectedHeader!: JWTHeaderParameters

  // /**
  //  * Sets the JWS Protected Header on the SignJWT object.
  //  *
  //  * @param protectedHeader JWS Protected Header. Must contain an "alg" (JWS Algorithm) property.
  //  */
  // setProtectedHeader(protectedHeader: JWTHeaderParameters) {
  //   this._protectedHeader = protectedHeader
  //   return this
  // }

  // /**
  //  * Signs and returns the JWT.
  //  *
  //  * @param key Private Key or Secret to sign the JWT with. See
  //  *   {@link https://github.com/panva/jose/issues/210#jws-alg Algorithm Key Requirements}.
  //  * @param options JWT Sign options.
  //  */
  async sign(key: KeyLike | Uint8Array): Promise<Uint8Array> {
    console.dir(key);
    throw new Error("Not implemented");
  }
  //   const sig = new CompactSign(encoder.encode(JSON.stringify(this._payload)))
  //   sig.setProtectedHeader(this._protectedHeader)
  //   if (
  //     Array.isArray(this._protectedHeader?.crit) &&
  //     this._protectedHeader.crit.includes('b64') &&
  //     // @ts-expect-error
  //     this._protectedHeader.b64 === false
  //   ) {
  //     throw new JWTInvalid('JWTs MUST NOT use unencoded payload')
  //   }
  //   return sig.sign(key, options)
  // }
}
