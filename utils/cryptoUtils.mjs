import crypto from 'crypto';
import CryptoJS from 'crypto-js';

export function generateKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  });

  return { publicKey, privateKey };
}

export function encryptPrivateKey(privateKey, password) {
  const salt = CryptoJS.lib.WordArray.random(128 / 8);
  const key = CryptoJS.PBKDF2(password, salt, {
    keySize: 256 / 32,
    iterations: 1000
  });

  const encrypted = CryptoJS.AES.encrypt(privateKey, key.toString());
  return {
    encryptedPrivateKey: encrypted.toString(),
    salt: salt.toString()
  };
}

export function decryptPrivateKey(encryptedPrivateKey, password, salt) {
  const key = CryptoJS.PBKDF2(password, CryptoJS.enc.Hex.parse(salt), {
    keySize: 256 / 32,
    iterations: 1000
  });

  const decrypted = CryptoJS.AES.decrypt(encryptedPrivateKey, key.toString());
  return decrypted.toString(CryptoJS.enc.Utf8);
}

