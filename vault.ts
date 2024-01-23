import * as rsa from './rsa-encryption-service';
import * as aes from './aes-encryption-service';
import { createPrivateKey, createPublicKey } from 'crypto';

const password = aes.createRandomPassword();
const encrypted = aes.encrypt(password, 'Hello world');
const decrypted = aes.decrypt(password, encrypted);

console.log(password);
console.log(encrypted);
console.log(decrypted);

const keyPair = rsa.createKeyPair();
const cipher = rsa.encrypt(createPublicKey(keyPair.publicKey), 'Hello world');
const text = rsa.decrypt(createPrivateKey(keyPair.privateKey), cipher);

console.log(keyPair);
console.log(cipher);
console.log(text);
