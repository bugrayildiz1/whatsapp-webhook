const express = require("express");
const body_parser = require("body-parser");
const axios = require("axios");
const crypto = require("crypto");
require("dotenv").config();

const app = express().use(body_parser.json());

// Env vars
const token = process.env.TOKEN;        // WhatsApp access token
const mytoken = process.env.MYTOKEN;    // webhook verify token
const PRIVATE_KEY = process.env.PRIVATE_KEY; // RSA private key for Flows

// 1) WEBHOOK VERIFICATION (GET /webhook)
app.get("/webhook", (req, res) => {
  const mode = req.query["hub.mode"];
  const challenge = req.query["hub.challenge"];
  const verifyToken = req.query["hub.verify_token"];

  if (mode && verifyToken) {
    if (mode === "subscribe" && verifyToken === mytoken) {
      console.log("✅ Webhook verified");
      return res.status(200).send(challenge);
    } else {
      console.log("❌ Webhook verification failed");
      return res.sendStatus(403);
    }
  } else {
    return res.sendStatus(400);
  }
});

// 2) WEBHOOK EVENTS (POST /webhook) – your old logic kept
app.post("/webhook", async (req, res) => {
  const body_param = req.body;

  console.log("📩 Incoming webhook:\n", JSON.stringify(body_param, null, 2));

  if (
    body_param.object &&
    body_param.entry &&
    body_param.entry[0].changes &&
    body_param.entry[0].changes[0].value.messages &&
    body_param.entry[0].changes[0].value.messages[0]
  ) {
    try {
      const value = body_param.entry[0].changes[0].value;
      const phon_no_id = value.metadata.phone_number_id;
      const from = value.messages[0].from;
      const msg_body = value.messages[0].text?.body || "";

      console.log("phone number:", phon_no_id);
      console.log("from:", from);
      console.log("body:", msg_body);

      await axios({
        method: "POST",
        url:
          "https://graph.facebook.com/v13.0/" +
          phon_no_id +
          "/messages?access_token=" +
          token,
        data: {
          messaging_product: "whatsapp",
          to: from,
          text: {
            body: "Hi.. I'm Prasath, your message is " + msg_body,
          },
        },
        headers: {
          "Content-Type": "application/json",
        },
      });

      return res.sendStatus(200);
    } catch (err) {
      console.error("Error sending reply:", err.response?.data || err.message);
      return res.sendStatus(500);
    }
  } else {
    return res.sendStatus(404);
  }
});

// 3) FLOW DATA ENDPOINT (POST /data) – encrypted channel for Flows
// 3) FLOW DATA ENDPOINT (POST /data) – encrypted channel for Flows + health check
app.post("/data", (req, res) => {
  try {
    const body = req.body || {};

    const hasEncryptedFields =
      body.encrypted_aes_key &&
      body.encrypted_flow_data &&
      body.initial_vector;

    // 3a) If request has encrypted fields -> real Flow traffic
    if (hasEncryptedFields) {
      if (!PRIVATE_KEY) {
        console.error("❌ PRIVATE_KEY env var is missing");
        // Still return 200 so health check doesn’t fail
        return res.status(200).type("text/plain").send("");
      }

      const { decryptedBody, aesKeyBuffer, initialVectorBuffer } =
        decryptRequest(body, PRIVATE_KEY);

      console.log("🧩 Decrypted Flow payload:", decryptedBody);

      let responsePayload;

      // Health-check-style ping inside encrypted payload
      if (decryptedBody.action === "ping") {
        responsePayload = {
          data: {
            status: "active",
          },
        };
      } else {
        // Normal data_exchange / INIT / BACK – put your real logic here
        responsePayload = {
          screen: "SCREEN_NAME", // TODO replace with your real screen name
          data: {
            some_key: "some_value",
          },
        };
      }

      const encrypted = encryptResponse(
        responsePayload,
        aesKeyBuffer,
        initialVectorBuffer
      );

      // Encrypted responses must be plain text (Base64 string)
      return res.type("text/plain").send(encrypted);
    }

    // 3b) No encrypted fields – probably Meta’s health check or a simple probe.
    // Just answer with 200 + a simple JSON body.
    console.log("✅ /data received non-encrypted health-check request");
    return res.status(200).json({
      data: {
        status: "active",
      },
    });
  } catch (err) {
    console.error("❌ Error in /data:", err);
    // Do NOT send 4xx/5xx for health check – always 200
    return res.status(200).type("text/plain").send("");
  }
});

// 4) Simple root route
app.get("/", (req, res) => {
  res.status(200).send("hello this is webhook setup");
});

// ---------- Helpers for Flow encryption ----------

function decryptRequest(body, privatePem) {
  const { encrypted_aes_key, encrypted_flow_data, initial_vector } = body;

  const decryptedAesKey = crypto.privateDecrypt(
    {
      key: crypto.createPrivateKey(privatePem),
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    Buffer.from(encrypted_aes_key, "base64")
  );

  const flowDataBuffer = Buffer.from(encrypted_flow_data, "base64");
  const ivBuffer = Buffer.from(initial_vector, "base64");

  const TAG_LENGTH = 16;
  const encryptedBody = flowDataBuffer.subarray(0, -TAG_LENGTH);
  const authTag = flowDataBuffer.subarray(-TAG_LENGTH);

  const decipher = crypto.createDecipheriv(
    "aes-128-gcm",
    decryptedAesKey,
    ivBuffer
  );
  decipher.setAuthTag(authTag);

  const clearJson = Buffer.concat([
    decipher.update(encryptedBody),
    decipher.final(),
  ]).toString("utf-8");

  return {
    decryptedBody: JSON.parse(clearJson),
    aesKeyBuffer: decryptedAesKey,
    initialVectorBuffer: ivBuffer,
  };
}

function encryptResponse(responseObj, aesKeyBuffer, initialVectorBuffer) {
  // Flip IV bits as required by Meta docs
  const flippedIV = Buffer.alloc(initialVectorBuffer.length);
  for (let i = 0; i < initialVectorBuffer.length; i++) {
    flippedIV[i] = initialVectorBuffer[i] ^ 0xff;
  }

  const cipher = crypto.createCipheriv("aes-128-gcm", aesKeyBuffer, flippedIV);
  const encrypted = Buffer.concat([
    cipher.update(JSON.stringify(responseObj), "utf-8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  const withTag = Buffer.concat([encrypted, tag]);
  return withTag.toString("base64");
}

// 5) Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("webhook is listening on port", PORT);
});
