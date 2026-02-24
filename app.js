const readLine = require("readline-sync");
const fs = require("fs");
const { encrypt, decrypt } = require("./crypt");

function startApp() {
  console.log("---E2EE CLI Messenger---");
  const options = [
    "Encrypt & Save Message",
    "Read & Decrypt the Message",
    "Exit",
  ];
  const index = readLine.keyInSelect(options, "What would you like to do? ");

  switch (index) {
    case 0:
      handleEncryption();
      break;
    case 1:
      handleDecryption();
      break;
    default:
      process.exit();
  }
}

function handleEncryption() {
  const message = readLine.question("Enter message to encrypt: ");
  try {
    const encrypted = encrypt(message);
    fs.writeFileSync("vault.json", JSON.stringify(encrypted, null, 2));
    console.log("\n[SUCCESS] Message encrypted and saved to vault.json");
  } catch (err) {
    console.error("\n[ERROR] Encryption failed:", err.message);
  }
  startApp();
}

function handleDecryption() {
  if (!fs.existsSync("vault.json")) {
    console.log("\n[!] No vault.json found. Encrypt a message first.\n");
    return startApp();
  }

  try {
    const rawData = fs.readFileSync("vault.json");
    const encryptedPayLoad = JSON.parse(rawData);
    const decryptedMessage = decrypt(encryptedPayLoad);
    
    console.log(`\n[DECRYPTED]: ${decryptedMessage}\n`);
    fs.unlinkSync('./vault.json');
  } catch (err) {
    console.error("\n[ERROR] Decryption Failed", err.message);
  }
}

startApp();