const crypto = require('crypto');
const config = require('../config/config');

const algorithm = 'aes-256-cbc';

/**
 * Get encryption key from config or generate from JWT secret
 * @returns {Buffer}
 */
const getEncryptionKey = () => {
  const key = config.mt5.encryptionKey || config.jwt.secret;
  return crypto.createHash('sha256').update(key).digest();
};

/**
 * Encrypt text
 * @param {string} text - Text to encrypt
 * @returns {string} Encrypted text
 */
const encrypt = (text) => {
  if (!text) {
    return text;
  }
  const key = getEncryptionKey();
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return `${iv.toString('hex')}:${encrypted}`;
};

/**
 * Decrypt text
 * @param {string} encryptedText - Encrypted text
 * @returns {string} Decrypted text
 */
const decrypt = (encryptedText) => {
  if (!encryptedText) {
    return encryptedText;
  }
  try {
    const parts = encryptedText.split(':');
    if (parts.length !== 2) {
      return encryptedText; // Not encrypted, return as-is
    }
    const key = getEncryptionKey();
    const iv = Buffer.from(parts[0], 'hex');
    const encrypted = parts[1];
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (error) {
    return encryptedText; // Return original if decryption fails
  }
};

module.exports = {
  encrypt,
  decrypt,
};
