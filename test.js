const { Encoder } = require('cbor-x');

const encoder = new Encoder({
  tagUint8Array: false,
  useRecords: false,
  mapsAsObjects: false,
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  useTag259ForMaps: false,
});

const m = new Map([
  [1,2],
  [2, 'meriadoc.brandybuck@buckland.example'],
  [-1, 1],
  [-2, Buffer.from('65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d', 'hex')],
  [-3, Buffer.from('1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c', 'hex')],
  [-4, Buffer.from('aff907c99f9ad3aae6c4cdf21122bce2bd68b5283e6907154ad911840fa208cf', 'hex')]
]);

console.log(encoder.encode(m).toString('hex'));
