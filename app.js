const net = require("net");
const fs = require("fs");
const readline = require("readline");
const {
  verifyCertificate,
  getPublicKeyFromCert,
  asymmetricEncrypt,
  asymmetricDecrypt,
  encryptMessage,
  decryptMessage,
} = require("./crypt");

// Configuration
const ROOT_CA = fs.readFileSync("./keys/rootCA.pem");
const PORT = 5000;

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

let sessionKey = null;

// Role Selection

rl.question("Start as (s)erver or (c)lient? ", (choice) => {
  if (choice.toLowerCase() === "s") {
    startServer();
  } else {
    startClient();
  }
});

// Server Side (User B)
function startServer() {
  const myCert = fs.readFileSync("./keys/userB.pem");
  const myKey = fs.readFileSync("./keys/userB.key");

  const server = net.createServer((socket) => {
    console.log("\n[!] Client Connected. Initializing Handshake...");

    // 1. Send our certificate to the client
    socket.write(JSON.stringify({ type: "CERT", data: myCert.toString() }));

    socket.on("data", (data) => {
      try {
        const packet = JSON.parse(data);

        // 2. Receive the encrypted session key from client
        if (packet.type === "SESSION_KEY") {
          const encryptedKey = Buffer.from(packet.data, "base64");
          sessionKey = asymmetricDecrypt(myKey, encryptedKey);
          console.log("[SUCCESS] Session Key Established Securely");
          setupChat(socket);
        }

        // 3. Receive encrypted messages
        else if (packet.type === "MSG") {
          const decrypted = decryptMessage(packet.data, sessionKey);
          console.log(`\nPeer: ${decrypted}`);
          process.stdout.write("You: ");
        }
      } catch (err) {
        console.log("[ERROR]", err.message);
      }
    });
  });

  server.listen(PORT, () => console.log(`Server listening on PORT ${5000}...`));
}

// Client Side (User A)
function startClient() {
  const socket = net.createConnection({ port: PORT }, () => {
    console.log("\n[!] Connected to Server");
  });

  socket.on("data", (data) => {
    try {
      const packet = JSON.parse(data);

      // 1. Receive Server Certificate
      if (packet.type === "CERT") {
        console.log("[!] Verifying Server Certificate...");

        if (verifyCertificate(packet.data, ROOT_CA)) {
          console.log("[SUCCESS] Server identity verified via Root CA");

          // 2. Generate Session Key
          sessionKey = require("crypto").randomBytes(32);

          // 3. Encrypt session key with server's public key
          const serverPubKey = getPublicKeyFromCert(packet.data);
          const encryptedKey = asymmetricEncrypt(serverPubKey, sessionKey);

          socket.write(
            JSON.stringify({
              type: "SESSION_KEY",
              data: encryptedKey.toString("base64"),
            }),
          );

          setupChat(socket);
        } else {
          console.log("[FAILURE] Invalid Certification. Closing Connection");
          socket.destroy();
        }
      }

      // Receive encrypted message
      else if (packet.type === "MSG") {
        const decrypted = decryptMessage(packet.data, sessionKey);
        console.log(`\nPeer: ${decrypted}`);
        process.stdout.write("You: ");
      }
    } catch (err) {
      console.error("[ERROR]", err.message);
    }
  });
}

// Chat Interface
function setupChat(socket) {
  console.log("-------Secure Chat Started-------");
  rl.setPrompt("You: ");
  rl.prompt();

  rl.on("line", (line) => {
    if (sessionKey) {
      const encrypted = encryptMessage(line, sessionKey);
      socket.write(JSON.stringify({ type: "MSG", data: encrypted }));
    }
    rl.prompt();
  });
}
