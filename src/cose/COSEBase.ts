import { encoder } from '../cbor.js';

export class COSEBase {
  #encodedProtectedHeaders?: Uint8Array;
  public readonly protectedHeaders: Map<number, unknown>;

  constructor(
    protectedHeaders: Uint8Array | Map<number, unknown>,
    public readonly unprotectedHeaders: Map<number, unknown>) {
    if (protectedHeaders instanceof Uint8Array) {
      this.#encodedProtectedHeaders = protectedHeaders;
      this.protectedHeaders = protectedHeaders.length === 0 ?
        new Map() :
        encoder.decode(protectedHeaders);
    } else {
      this.protectedHeaders = protectedHeaders;
      this.#encodedProtectedHeaders = encoder.encode(protectedHeaders);
    }
  }

  protected get encodedProtectedHeaders(): Uint8Array | undefined {
    return this.#encodedProtectedHeaders;
  }
  public encode() {
    return encoder.encode(this);
  }
}
