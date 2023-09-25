import { KeyLike } from "jose";
import { COSEVerifyGetKey } from "./jwks/local.js";
import { encoder } from "./cbor.js";
import { Sign1 } from "./cose/Sign1.js";
import { Sign } from "./cose/Sign.js";
import { Mac0 } from "./cose/Mac0.js";

type VerifyResult = {
  isValid: boolean;
  decoded: Sign1;
  key?: KeyLike | Uint8Array;
};

type MultiSigVerifyResult = {
  isValid: boolean;
  decoded: Sign;
  key?: KeyLike | Uint8Array;
};

/**
 * Verify the signature of a COSE_Sign1 message.
 *
 * @param cose the buffer containing the Cose Sign1 tagged message.
 * @param key the key to use to verify the signature.
 * @returns
 */
export const coseVerify = async (
  cose: Uint8Array,
  key: KeyLike | Uint8Array | COSEVerifyGetKey
): Promise<VerifyResult> => {
  const decoded = encoder.decode(cose);

  if (!(decoded instanceof Sign1)) {
    throw new Error('unknown COSE type');
  }

  const isValid = await decoded.verify(key);

  return { isValid, decoded };
};

/**
 *  Verify the signature of a COSE_Sign message.
 *
 * @param cose the buffer containing the Cose Sign tagged message.
 * @param keys the keys to use to verify the signature.
 * @returns
 */
export const coseVerifyMultiSignature = async (
  cose: Uint8Array,
  keys: KeyLike[] | Uint8Array[] | COSEVerifyGetKey
): Promise<MultiSigVerifyResult> => {
  const decoded = encoder.decode(cose);

  if (!(decoded instanceof Sign)) {
    throw new Error('unexpected COSE type');
  }

  const isValid = await decoded.verify(keys);

  return { isValid, decoded };
};

export const coseVerifyX509 = async (
  cose: Uint8Array,
  roots: string[]
) => {

  const decoded = encoder.decode(cose);

  if (!(decoded instanceof Sign1 || decoded instanceof Sign)) {
    throw new Error('unknown COSE type');
  }

  const isValid = await decoded.verifyX509(roots)

  return { isValid, decoded };
};

export const coseVerifyMAC0 = async (
  cose: Uint8Array,
  key: KeyLike | Uint8Array,
  externalAAD: Uint8Array = new Uint8Array()
) => {
  let decoded = encoder.decode(cose);

  if (Array.isArray(decoded) && decoded.length === 4) {
    const params = decoded as ConstructorParameters<typeof Mac0>;
    decoded = new Mac0(...params);
  }

  if (!(decoded instanceof Mac0)) {
    throw new Error('unexpected COSE type');
  }

  const isValid = await decoded.verify(key, externalAAD);

  return { isValid, decoded };
}
