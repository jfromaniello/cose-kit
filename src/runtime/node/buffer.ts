// For some cases we prefer node.js buffer than uint8array.
// It helps simplify tests and comparisoons.

export const toBuffer = (input: Uint8Array | string): Uint8Array => {
  if (input instanceof Uint8Array) {
    return Buffer.from(input);
  } else if (typeof input === 'string') {
    return Buffer.from(input, 'utf-8');
  } else {
    throw new TypeError('Input must be a string or Uint8Array');
  }
}
