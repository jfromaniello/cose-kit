import { KeyObject, createSecretKey } from 'crypto'
import { isCryptoKey } from './webcrypto'
import { checkSigCryptoKey } from '../../lib/crypto_key'
import invalidKeyInput from '../../lib/invalid_key_input'
import { types } from './is_key_like'

export default function getSignVerifyKey(alg: string, key: unknown, usage: KeyUsage) {
  if (key instanceof Uint8Array) {
    if (!alg.startsWith('HS')) {
      throw new TypeError(invalidKeyInput(key, ...types))
    }
    return createSecretKey(key)
  }
  if (key instanceof KeyObject) {
    return key
  }
  if (isCryptoKey(key)) {
    checkSigCryptoKey(key, alg, usage)
    return KeyObject.from(key)
  }
  throw new TypeError(invalidKeyInput(key, ...types, 'Uint8Array'))
}
