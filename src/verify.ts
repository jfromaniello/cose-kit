import { KeyLike } from "jose";
import { COSEVerifyGetKey } from "./jwks/local.js";
import { encoder } from "./cbor.js";
import { Sign1 } from "./cose/Sign1.js";
import { Sign } from "./cose/Sign.js";

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
