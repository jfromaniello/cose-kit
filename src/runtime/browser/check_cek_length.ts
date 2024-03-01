import { COSEInvalid } from '../../util/errors.js'

const checkCekLength = (cek: Uint8Array, expected: number) => {
  const actual = cek.byteLength << 3
  if (actual !== expected) {
    throw new COSEInvalid(
      `Invalid Content Encryption Key length. Expected ${expected} bits, got ${actual} bits`,
    )
  }
}

export default checkCekLength
