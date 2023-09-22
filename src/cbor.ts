import { Encoder, addExtension as addExtInt } from 'cbor-x';

export const buildEncoder = () => new Encoder({
  tagUint8Array: false,
  useRecords: false,
  mapsAsObjects: false,
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  useTag259ForMaps: false,
});

export const encoder = buildEncoder();

type addExtensionArgs = Parameters<typeof addExtInt>[0];

export const addExtension = (extCallback: (encoder: Encoder) => addExtensionArgs) => {
  const extEncoder = buildEncoder();
  const extParams = extCallback(extEncoder);
  addExtInt(extParams);
};
