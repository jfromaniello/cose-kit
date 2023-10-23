import { Sign } from './cose/Sign.js';
import { Sign1 } from './cose/Sign1.js';

export {
  coseVerify,
  coseVerifyX509,
  coseVerifyMultiSignature,
  coseVerifyMAC0
} from './verify.js';

export { Sign1 } from './cose/Sign1.js';
export { Sign } from './cose/Sign.js';
export { Mac0 } from './cose/Mac0.js';

export const coseSign = async (...args: Parameters<typeof Sign1.sign>): Promise<Uint8Array> => {
  return Sign1.sign(...args).then(s => s.encode());
};

export const coseMultiSign = async (...args: Parameters<typeof Sign.sign>): Promise<Uint8Array> => {
  return Sign.sign(...args).then(s => s.encode());
};

export {
  importCOSEKey,
  COSEKeyToJWK,
  COSEKeyFromJWK,
} from './key/index.js';

export { ProtectedHeader, UnprotectedHeaders } from './headers.js';
