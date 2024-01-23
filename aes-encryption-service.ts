import crypto from 'crypto';
// aes: 256-gcm

export const createRandomPassword = (): string => {
  return crypto.randomBytes(32).toString('base64');
};

export const encrypt = (password: string, data: string): string => {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(password, 'base64'), iv);

  const enc1 = cipher.update(data, 'utf8');
  const enc2 = cipher.final();

  return Buffer.concat([enc1, enc2, iv, cipher.getAuthTag()]).toString('base64');
};

export const decrypt = (password: string, data: string): string => {
  let enc = Buffer.from(data, 'base64');
  const iv = enc.subarray(enc.length - 28, enc.length - 16);
  const tag = enc.subarray(enc.length - 16);
  enc = enc.subarray(0, enc.length - 28);

  const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(password, 'base64'), iv);
  decipher.setAuthTag(tag);
  let str = decipher.update(enc, undefined, 'utf8');
  str += decipher.final('utf8');
  return str;
};
