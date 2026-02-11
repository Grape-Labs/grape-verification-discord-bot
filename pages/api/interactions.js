// pages/api/interactions.js
const { verifyKey } = require("discord-interactions");
//const { handleSlashCommand } = require("../../lib/discord/commands");
const { handleSlashCommand } = require("../../lib/discord/slash-commands");

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function normHeader(h) {
  if (!h) return "";
  return Array.isArray(h) ? h[0] : String(h);
}

function sendPong(res) {
  const body = '{"type":1}';
  res.statusCode = 200;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Content-Length", Buffer.byteLength(body));
  res.setHeader("Cache-Control", "no-store");
  res.end(body);
}

module.exports = async (req, res) => {
  // Allow OPTIONS/HEAD probes (useful behind some proxies)
  if (req.method === "OPTIONS" || req.method === "HEAD") {
    res.statusCode = 204;
    res.setHeader("Cache-Control", "no-store");
    return res.end();
  }

  if (req.method !== "POST") {
    res.statusCode = 405;
    res.setHeader("Allow", "POST, OPTIONS, HEAD");
    return res.end("Method Not Allowed");
  }

  const publicKey = String(process.env.DISCORD_PUBLIC_KEY || "").trim();
  if (!publicKey) {
    res.statusCode = 500;
    return res.end("Missing DISCORD_PUBLIC_KEY");
  }

  // IMPORTANT: raw body must be exact
  const rawBuf = await readRawBody(req);
  const rawBody = rawBuf.toString("utf8");

  let interaction;
  try {
    interaction = JSON.parse(rawBody);
  } catch {
    res.statusCode = 400;
    return res.end("Invalid JSON");
  }

  const sig = normHeader(req.headers["x-signature-ed25519"]);
  const ts = normHeader(req.headers["x-signature-timestamp"]);

  // Optional tolerance: if something sends unsigned PING, reply only to type=1
  if ((!sig || !ts) && interaction?.type === 1) {
    return sendPong(res);
  }

  if (!sig || !ts) {
    res.statusCode = 400;
    return res.end("Missing signature headers");
  }

  const isValid = verifyKey(rawBody, sig, ts, publicKey);
  if (!isValid) {
    console.error("[discord] Invalid signature", {
      type: interaction?.type,
      hasSig: Boolean(sig),
      hasTs: Boolean(ts),
      ua: normHeader(req.headers["user-agent"]),
    });
    res.statusCode = 401;
    return res.end("Invalid signature");
  }

  if (interaction.type === 1) {
    return sendPong(res);
  }

  if (interaction.type === 2) {
    return handleSlashCommand(interaction, res);
  }

  res.statusCode = 200;
  return res.end();
};

module.exports.config = {
  api: { bodyParser: false },
};
