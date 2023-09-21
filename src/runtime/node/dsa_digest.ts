import { COSENotSupported } from '../../util/errors';

export default function dsaDigest(alg: string) {
  switch (alg) {
    case 'PS256':
    case 'RS256':
    case 'ES256':
    case 'ES256K':
      return 'sha256'

    case 'PS384':
    case 'RS384':
    case 'ES384':
      return 'sha384'

    case 'PS512':
    case 'RS512':
    case 'ES512':
      return 'sha512'

    case 'EdDSA':
      return undefined

    default:
      throw new COSENotSupported(
        `alg ${alg} is not supported either by JOSE or your javascript runtime`,
      )
  }
}
