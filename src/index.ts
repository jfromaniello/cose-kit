import { Sign } from './cose/Sign';
import { Sign1 } from './cose/Sign1';
import { encoder } from './cbor';

export {
  coseVerify,
  coseVerifyX509,
  coseVerifyMultiSignature,
} from './verify';

export { Sign1 } from './cose/Sign1';
export { Sign } from './cose/Sign';

export const coseSign = async (...args: Parameters<typeof Sign1.sign>): Promise<Uint8Array> => {
  const sign1 = await Sign1.sign(...args);
  return encoder.encode(sign1)
};

export const coseMultiSign = async (...args: Parameters<typeof Sign.sign>): Promise<Uint8Array> => {
  const sign = await Sign.sign(...args);
  return encoder.encode(sign);
};
