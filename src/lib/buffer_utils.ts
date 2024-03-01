const MAX_INT32 = 2 ** 32

export const encoder = new TextEncoder()
export const decoder = new TextDecoder()
export function concat(...buffers: Uint8Array[]): Uint8Array {
  const size = buffers.reduce((acc, { length }) => acc + length, 0)
  const buf = new Uint8Array(size)
  let i = 0
  buffers.forEach((buffer) => {
    buf.set(buffer, i)
    i += buffer.length
  })
  return buf
}

export function areEqual(buf1: Uint8Array, buf2: Uint8Array): boolean {
  if (buf1 === buf2) {
    return true;
  }

  if (buf1.byteLength !== buf2.byteLength) {
    return false;
  }

  for (let i = 0; i < buf1.byteLength; i++) {
    if (buf1[i] !== buf2[i]) {
      return false;
    }
  }

  return true;
}

export const fromUTF8 = (input: string): Uint8Array => encoder.encode(input);

export const toUTF8 = (input: Uint8Array): string => decoder.decode(input);

function writeUInt32BE(buf: Uint8Array, value: number, offset?: number) {
  if (value < 0 || value >= MAX_INT32) {
    throw new RangeError(`value must be >= 0 and <= ${MAX_INT32 - 1}. Received ${value}`)
  }
  buf.set([value >>> 24, value >>> 16, value >>> 8, value & 0xff], offset)
}

export function uint64be(value: number) {
  const high = Math.floor(value / MAX_INT32)
  const low = value % MAX_INT32
  const buf = new Uint8Array(8)
  writeUInt32BE(buf, high, 0)
  writeUInt32BE(buf, low, 4)
  return buf
}
