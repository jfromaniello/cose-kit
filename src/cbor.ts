import { Encoder, addExtension } from 'cbor-x';
import { Sign1 } from './cose/Sign1';
import { Sign, Signature } from './cose/Sign';

addExtension({
  Class: Sign1,
  tag: 18,
  encode(instance: Sign1) {
    return instance.encode();
  },
  decode: (data: ConstructorParameters<typeof Sign1>) => {
    return new Sign1(data[0], data[1], data[2], data[3]);
  }
})

addExtension({
  Class: Sign,
  tag: 98,
  encode(instance: Sign) {
    return instance.encode();
  },
  decode: (data: [Uint8Array, Map<number, unknown>, Uint8Array, ConstructorParameters<typeof Sign>[]]) => {
    const signatures = data[3].map(signature => new Signature(signature[0], signature[1], signature[2]));
    return new Sign(data[0], data[1], data[2], signatures);
  }
})

export const encoder = new Encoder({
  tagUint8Array: false,
  useRecords: false,
  mapsAsObjects: false,
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  useTag259ForMaps: false,
});

