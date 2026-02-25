require("dotenv").config();
const crypto = require("crypto");
const fs = require("fs");
const Module = require("module");
const path = require("path");

// IDENTITY & TRUST FUNCTIONS
// Verify that a certificate (UserA.pem) was signed by your Root CA (rootCA.pem)
const verifyCertificate = (certPEM, rootCAPrem) => {
  try {
    const cert = new crypto.X509Certificate(certPEM);
    const root = new crypto.X509Certificate(rootCAPrem);

    // check if certificate is currently valid (date-wise)
    const now = new Date();
    if (now < new Date(cert.validFrom) || now > new Date(cert.validTo)) {
      return false;
    }

    // Verify signature using Root CA's public key
    return cert.verify(root.publicKey);
  } catch (err) {
    console.error("Verification Error", err.message);
    return false;
  }
};

const getPublicKeyFromCert = (certPEM) => {
  const cert = new crypto.X509Certificate(certPEM);
  return cert.publicKey;
};

// Key Exchange (Asymmetric) used to encrypt the small "Secret Session Key" so only the owner of the private key can read it

const asymmetricEncrypt = (publicKey, dataBuffer) => {
  return crypto.publicEncrypt(
    {
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    dataBuffer,
  );
};

const asymmetricDecrypt = (privateKeyPEM, encryptedBuffer) => {
  return crypto.privateDecrypt(
    {
      key: privateKeyPEM,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    encryptedBuffer,
  );
};

// Chat Encryption (Symmetric AES 256 GCM)
// Used for the actual chat message once the secret key is established

const encryptMessage = (plaintext, sessionKey) => {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-gcm", sessionKey, iv);

  let cipherText = cipher.update(plaintext, "utf-8", "hex");
  cipherText += cipher.final("hex");
  const authTag = cipher.getAuthTag().toString("hex");

  return {
    cipherText,
    iv: iv.toString("hex"),
    authTag,
  };
};

const decryptMessage = (payload, sessionKey) => {
  const { cipherText, iv, authTag } = payload;

  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    sessionKey,
    Buffer.from(iv, "hex"),
  );

  decipher.setAuthTag(Buffer.from(authTag, "hex"));

  let decrypted = decipher.update(cipherText, "hex", "utf-8");
  decrypted += decipher.final("utf-8");

  return decrypted;
};

module.exports = {
  verifyCertificate,
  getPublicKeyFromCert,
  asymmetricEncrypt,
  asymmetricDecrypt,
  encryptMessage,
  decryptMessage,
};
