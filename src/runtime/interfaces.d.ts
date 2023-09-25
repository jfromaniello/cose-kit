export interface SignFunction {
  (alg: string, key: unknown, data: Uint8Array): Promise<Uint8Array>
}

export interface VerifyFunction {
  (alg: string, key: unknown, signature: Uint8Array, data: Uint8Array): Promise<boolean>
}

export interface DigestFunction {
  (digest: 'sha256' | 'sha384' | 'sha512', data: Uint8Array): AsyncOrSync<Uint8Array>
}
