import { Encrypt0 } from './Encrypt0.js';
import { Mac0 } from './Mac0.js';
import { Sign } from './Sign.js';
import { Sign1 } from './Sign1.js';
import { encoder } from '../cbor.js';
import { COSEInvalid } from '../util/errors.js';
import { Encrypt } from './Encrypt.js';

export type ObjectType<T> = {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  new(...args: any): T;
  tag: number
};

/**
 *
 * Decode a buffer into a COSE message.
 * The cbor structure could be tagged or untagged.
 *
 * @param cose {Uint8Array} - The buffer containing the Cose message.
 * @param expectedType {ObjectType<T>} - The expected type of the COSE message.
 * @returns {T} - The decoded COSE message.
 */
export const decode = <T extends Mac0 | Sign | Sign1 | Encrypt0 | Encrypt>(
  cose: Uint8Array,
  expectedType: ObjectType<T>
): T => {
  let decoded = encoder.decode(cose);

  if (Array.isArray(decoded)) {
    const params = decoded as ConstructorParameters<typeof expectedType>;
    decoded = new expectedType(...params);
  }

  if (!(decoded instanceof expectedType)) {
    throw new COSEInvalid(
      `Unexpected CBOR tag. Expected tag ${expectedType.tag} (${expectedType.name}) but got ${decoded.tag}`
    );
  }

  return decoded;
};
