import type { KeyLike } from 'jose';

export interface TimingSafeEqual {
  (a: Uint8Array, b: Uint8Array): boolean
}

export interface SignFunction {
  (alg: string, key: unknown, data: Uint8Array): Promise<Uint8Array>
}

export interface VerifyFunction {
  (alg: string, key: unknown, signature: Uint8Array, data: Uint8Array): Promise<boolean>
}

export interface DigestFunction {
  (digest: 'sha256' | 'sha384' | 'sha512', data: Uint8Array): AsyncOrSync<Uint8Array>
}

export interface EncryptFunction {
  (
    enc: string,
    plaintext: Uint8Array,
    cek: unknown,
    iv: Uint8Array,
    aad: Uint8Array,
  ): AsyncOrSync<{
    ciphertext: Uint8Array
    tag: Uint8Array
  }>
}

export interface DecryptFunction {
  (
    enc: string,
    cek: KeyLike | Uint8Array,
    ciphertext: Uint8Array,
    iv: Uint8Array | undefined,
    tag: Uint8Array | undefined,
    additionalData: Uint8Array,
  ): AsyncOrSync<Uint8Array>
}
