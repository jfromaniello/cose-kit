import { Sign1 } from './cose/Sign1';
import { encoder } from './cbor';

export {
  coseVerify,
  coseVerifyX509,
  coseVerifyMultiSignature,
} from './verify';

export { Sign1 } from './cose/Sign1';

export const coseSign = async (...args: Parameters<typeof Sign1.sign>): Promise<Uint8Array> => {
  const sign1 = await Sign1.sign(...args);
  return encoder.encode(sign1)
};
