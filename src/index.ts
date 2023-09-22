import { Sign } from './cose/Sign.js';
import { Sign1 } from './cose/Sign1.js';
export {
  coseVerify,
  coseVerifyX509,
  coseVerifyMultiSignature,
} from './verify.js';
export { Sign1 } from './cose/Sign1.js';
export { Sign } from './cose/Sign.js';
import { encoder } from './cbor.js';

export const coseSign = async (...args: Parameters<typeof Sign1.sign>): Promise<Uint8Array> => {
  const sign1 = await Sign1.sign(...args);
  const encoded = encoder.encode(sign1);
  return encoded;
};

export const coseMultiSign = async (...args: Parameters<typeof Sign.sign>): Promise<Uint8Array> => {
  const sign = await Sign.sign(...args);
  return encoder.encode(sign);
};
