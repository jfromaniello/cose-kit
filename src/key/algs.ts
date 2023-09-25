type KeyTypeDefinition = {
  name: string;
  value: number;
  keyType: 'EC2' | 'OKP';
  description: string;
};

const table: KeyTypeDefinition[] = [
  { name: "P-256", value: 1, keyType: "EC2", description: "NIST P-256 also known as secp256r1" },
  { name: "P-384", value: 2, keyType: "EC2", description: "NIST P-384 also known as secp384r1" },
  { name: "P-521", value: 3, keyType: "EC2", description: "NIST P-521 also known as secp521r1" },
  { name: "X25519", value: 4, keyType: "OKP", description: "X25519 for use w/ ECDH only" },
  { name: "X448", value: 5, keyType: "OKP", description: "X448 for use w/ ECDH only" },
  { name: "Ed25519", value: 6, keyType: "OKP", description: "Ed25519 for use w/ EdDSA only" },
  { name: "Ed448", value: 7, keyType: "OKP", description: "Ed448 for use w/ EdDSA only" }
];

export const valueToKeyTypeMap = new Map<number, KeyTypeDefinition>();

for (const entry of table) {
  valueToKeyTypeMap.set(entry.value, entry);
}

export enum Curves {
  P_256 = 1,
  P_384 = 2,
  P_521 = 3,
  X25519 = 4,
  X448 = 5,
  Ed25519 = 6,
  Ed448 = 7,
}

export const ValuesToCurves = new Map([
  [1, 'P-256'],
  [2, 'P-384'],
  [3, 'P-521'],
  [4, 'X25519'],
  [5, 'X448'],
  [6, 'Ed25519'],
  [7, 'Ed448'],
]);
