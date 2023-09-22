import { encodeBase64 } from '#runtime/base64.js';

export const pemToCert = (cert: string): string => {
  const pem = /-----BEGIN (\w*)-----([^-]*)-----END (\w*)-----/g.exec(cert.toString());
  if (pem && pem.length > 0) {
    return pem[2].replace(/[\n|\r\n]/g, '');
  }
  return '';
};

export const certToPEM = (cert: Uint8Array): string => {
  return `-----BEGIN CERTIFICATE-----
${encodeBase64(cert).trim()}
-----END CERTIFICATE-----`;
}
