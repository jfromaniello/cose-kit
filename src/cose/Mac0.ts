import verify from "#runtime/verify.js";
import sign from '#runtime/sign.js';
import { KeyLike } from 'jose';
import { addExtension, encoder } from '../cbor.js';
import { WithHeaders } from './WithHeaders.js';
import { MacProtectedHeader, UnprotectedHeaders, headers, macAlgs, macAlgsToValue } from '../headers.js';
import { fromUTF8 } from "../lib/buffer_utils.js";

export class Mac0 extends WithHeaders {
  constructor(
    protectedHeader: Map<number, unknown> | Uint8Array,
    unprotectedHeader: Map<number, unknown>,
    public readonly payload: Uint8Array,
    public tag: Uint8Array,
  ) {
    super(protectedHeader, unprotectedHeader);
  }

  private static createMAC0(
    protectedHeader: Uint8Array,
    applicationHeaders: Uint8Array,
    payload: Uint8Array,
  ) {
    return encoder.encode([
      'MAC0',
      protectedHeader,
      applicationHeaders,
      payload,
    ]);
  }

  public getContentForEncoding() {
    return [
      this.encodedProtectedHeaders,
      this.unprotectedHeaders,
      this.payload,
      this.tag,
    ];
  }

  public encode() {
    return encoder.encode(this);
  }

  public async verify(
    key: KeyLike | Uint8Array,
    externalAAD: Uint8Array = new Uint8Array()
  ) {
    if (!key) {
      throw new Error('key not found');
    }

    const mac0Structure = Mac0.createMAC0(
      this.encodedProtectedHeaders || new Uint8Array(),
      externalAAD,
      this.payload,
    );

    if (!this.algName) {
      throw new Error('unknown algorithm: ' + this.alg);
    }

    return verify(this.algName, key, this.tag, mac0Structure);
  }

  public get alg(): number | undefined {
    return this.protectedHeaders.get(headers.alg) as number ||
      this.unprotectedHeaders.get(headers.alg) as number;
  }

  public get algName(): string | undefined {
    return this.alg ? macAlgs.get(this.alg)?.name : undefined;
  }

  public hasSupportedAlg() {
    return !!this.algName;
  }

  static async create(
    protectedHeader: MacProtectedHeader,
    unprotectedHeader: UnprotectedHeaders | undefined,
    payload: Uint8Array,
    key: KeyLike | Uint8Array,
  ) {
    const { alg } = protectedHeader;

    const encodedProtectedHeaders = encoder.encode(new Map(Object.entries(protectedHeader).map(([k, v]: [string, unknown]) => {
      if (k === 'alg') {
        v = macAlgsToValue.get(v as string);
      } else if (typeof v === 'string') {
        v = fromUTF8(v);
      }
      return [headers[k], v];
    })));

    const unprotectedHeadersMap = new Map(Object.entries(unprotectedHeader || {}).map(([k, v]: [string, unknown]) => {
      if (typeof v === 'string') {
        v = fromUTF8(v);
      }
      return [headers[k], v];
    }));

    const toBeSigned = Mac0.createMAC0(
      encodedProtectedHeaders,
      new Uint8Array(),
      payload,
    );

    if (!alg) {
      throw new Error('The alg header must be set.');
    }

    const tag = await sign(alg, key, toBeSigned);

    return new Mac0(
      encodedProtectedHeaders,
      unprotectedHeadersMap,
      payload,
      tag
    );
  }
}

addExtension({
  Class: Mac0,
  tag: 17,
  encode(instance: Mac0, encodeFn: (obj: unknown) => Uint8Array) {
    return encodeFn(instance.getContentForEncoding());
  },
  decode: (data: ConstructorParameters<typeof Mac0>) => {
    return new Mac0(data[0], data[1], data[2], data[3]);
  }
});

