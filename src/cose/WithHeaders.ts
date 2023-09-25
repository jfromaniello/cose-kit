import { encoder } from '../cbor.js';

export class WithHeaders {
  #decodedProtectedHeader?: Map<number, unknown>;

  protected encodedProtectedHeader?: Uint8Array;

  constructor(
    protectedHeader: Uint8Array | Map<number, unknown>,
    public readonly unprotectedHeader: Map<number, unknown>) {
    if (protectedHeader instanceof Uint8Array) {
      this.encodedProtectedHeader = protectedHeader;
    } else {
      this.#decodedProtectedHeader = protectedHeader;
      // TODO: https://github.com/kriszyp/cbor-x/issues/83
      this.encodedProtectedHeader = encoder.encode(protectedHeader);
    }
  }

  public get protectedHeader(): Map<number, unknown> {
    if (!this.#decodedProtectedHeader) {
      if (!this.encodedProtectedHeader || this.encodedProtectedHeader.byteLength === 0) {
        this.#decodedProtectedHeader = new Map();
      } else {
        this.#decodedProtectedHeader = encoder.decode(this.encodedProtectedHeader as Uint8Array);
      }
    }
    return this.#decodedProtectedHeader as Map<number, unknown>;
  }
}
