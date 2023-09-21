import * as crypto from 'crypto'
import * as util from 'util'

const webcrypto = <Crypto>crypto.webcrypto

export default webcrypto

export const isCryptoKey = util.types.isCryptoKey
  ? (key: unknown): key is CryptoKey => util.types.isCryptoKey(key)
  : // @ts-ignore
  (key: unknown): key is CryptoKey => false
