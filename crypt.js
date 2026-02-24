require("dotenv").config();
const crypto = require("crypto");
const fs = require("fs");
const Module = require("module");
const path = require("path");

// Reads .env paths

const PRIVATE_KEY_PATH = path.join(__dirname, process.env.PRIVATEKEYPATH || './keys/myCA.key');
const PUBLIC_KEY_PATH = path.join(__dirname, process.env.PUBLIC_KEY_PATH || './keys/myCA.pem');

const privateKey = fs.readFileSync(PRIVATE_KEY_PATH, "utf-8");
const publicKey = fs.readFileSync(PUBLIC_KEY_PATH, "utf-8");

/**
 * Encrypt Function:
 *  1. Generate random AES-256 Key and IV
 *  2. Encrypt text with AES-GCM
 *  3. Encrypt AES Key with RSA public key
 */
const encrypt = (plaintext) => {
  const aesKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);

  const cipher = crypto.createCipheriv("aes-256-gcm", aesKey, iv);
  let cipherText = cipher.update(plaintext, "utf-8", "hex");
  cipherText += cipher.final("hex");
  const authTag = cipher.getAuthTag().toString("hex");

  const encryptedAESKey = crypto.publicEncrypt(
    {
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    aesKey,
  );

  return {
    cipherText,
    iv: iv.toString("hex"),
    authTag,
    encryptedAESKey: encryptedAESKey.toString("base64"),
  };
};

/**
 * Decrypt Function:
 *  1. Decrypts AES key using RSA Private Key
 *  2. Uses recovered AES key to decrypt the ciphertext
 */
const decrypt = (payload) => {
  const { cipherText, iv, authTag, encryptedAESKey } = payload;
  const decryptedAESKey = crypto.privateDecrypt(
    {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    Buffer.from(encryptedAESKey, "base64"),
  );

  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    decryptedAESKey,
    Buffer.from(iv, "hex"),
  );

  decipher.setAuthTag(Buffer.from(authTag, "hex"));

  let decrypted = decipher.update(cipherText, "hex", "utf-8");
  decrypted += decipher.final("utf-8");

  return decrypted;
};

module.exports = { encrypt, decrypt };
