import { encoder } from '../cbor.js';

export class WithHeaders {
  #decodedProtectedHeaders?: Map<number, unknown>;

  protected encodedProtectedHeaders?: Uint8Array;

  constructor(
    protectedHeaders: Uint8Array | Map<number, unknown>,
    public readonly unprotectedHeaders: Map<number, unknown>) {
    if (protectedHeaders instanceof Uint8Array) {
      this.encodedProtectedHeaders = protectedHeaders;
    } else {
      this.#decodedProtectedHeaders = protectedHeaders;
      // TODO: https://github.com/kriszyp/cbor-x/issues/83
      this.encodedProtectedHeaders = encoder.encode(protectedHeaders);
    }
  }

  public get protectedHeaders(): Map<number, unknown> {
    if (!this.#decodedProtectedHeaders) {
      if (!this.encodedProtectedHeaders || this.encodedProtectedHeaders.byteLength === 0) {
        this.#decodedProtectedHeaders = new Map();
      } else {
        this.#decodedProtectedHeaders = encoder.decode(this.encodedProtectedHeaders as Uint8Array);
      }
    }
    return this.#decodedProtectedHeaders as Map<number, unknown>;
  }
}
