export const toBuffer = (input: Uint8Array | string): Uint8Array => {
  if (input instanceof Uint8Array) {
    return input;
  } else if (typeof input === 'string') {
    return new TextEncoder().encode(input);
  } else {
    throw new TypeError('Input must be a string or Uint8Array');
  }
}
