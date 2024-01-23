import crypto, { KeyObject, KeyPairSyncResult } from 'crypto';
// rsa: sha256

export const createKeyPair = (): KeyPairSyncResult<string, string> => {
  return crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'pkcs1',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs1',
      format: 'pem',
    },
  });
};

export const encrypt = (publicKey: KeyObject, data: string): string => {
  const encryptedString = crypto.publicEncrypt(
    {
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_PADDING,
      oaepHash: 'sha256',
    },
    Buffer.from(data)
  );
  return encryptedString.toString('base64');
};

export const decrypt = (privateKey: KeyObject, data: string): string => {
  const decryptedString = crypto.privateDecrypt(
    {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_PADDING,
      oaepHash: 'sha256',
    },
    Buffer.from(data, 'base64')
  );
  return decryptedString.toString();
};
