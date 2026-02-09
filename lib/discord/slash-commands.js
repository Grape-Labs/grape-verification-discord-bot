// /lib/discord/slash-commands.js
// Discord slash commands for Grape Verification Registry (Next.js API handler friendly)

const crypto = require("crypto");
const nacl = require("tweetnacl");
const bs58 = require("bs58");
const { Connection, Keypair, PublicKey, Transaction } = require("@solana/web3.js");

const {
  PROGRAM_ID,
  VerificationPlatform,
  identityHash,
  walletHash,
  TAG_DISCORD,
  TAG_TELEGRAM,
  TAG_TWITTER,
  TAG_EMAIL,
  deriveSpacePda,
  deriveIdentityPda,
  deriveLinkPda,
  buildInitializeSpaceIx,
  buildAttestIdentityIx,
  buildRevokeIdentityIx,
  buildLinkWalletIx,
  buildLinkWalletSelfIx,
} = require("@grapenpm/grape-verification-registry");

/* -----------------------------
   Discord response helpers
------------------------------ */

function json(res, code, body) {
  res.statusCode = code;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.end(JSON.stringify(body));
}

function reply(content, opts = {}) {
  // Discord Interaction response format
  return {
    type: 4, // CHANNEL_MESSAGE_WITH_SOURCE
    data: {
      content,
      flags: opts.ephemeral ? 64 : 0,
    },
  };
}

function replyWithEmbed(title, description, opts = {}) {
  return {
    type: 4,
    data: {
      flags: opts.ephemeral ? 64 : 0,
      embeds: [
        {
          title,
          description,
        },
      ],
    },
  };
}

/* -----------------------------
   Env / Config
------------------------------ */

function mustEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Missing ${name}`);
  return v;
}

function rpcUrl() {
  return (
    process.env.NEXT_PUBLIC_SOLANA_RPC ||
    process.env.NEXT_PUBLIC_RPC_SOLANA_MAINNET ||
    process.env.REACT_APP_RPC_ENDPOINT ||
    process.env.SOLANA_RPC_URL ||
    "https://api.mainnet-beta.solana.com"
  );
}

function parseKeypairFromEnv(name) {
  const raw = mustEnv(name).trim();

  // JSON array
  if (raw.startsWith("[") && raw.endsWith("]")) {
    const arr = JSON.parse(raw);
    return Keypair.fromSecretKey(Uint8Array.from(arr));
  }

  // base58
  try {
    const b = bs58.decode(raw);
    if (b?.length) return Keypair.fromSecretKey(new Uint8Array(b));
  } catch {}

  // base64
  try {
    const b = Buffer.from(raw, "base64");
    if (b?.length) return Keypair.fromSecretKey(new Uint8Array(b));
  } catch {}

  throw new Error(`${name} invalid format (use JSON array, base58, or base64)`);
}

/* -----------------------------
   Platform helpers
------------------------------ */

function platformEnum(platform) {
  switch ((platform || "").toLowerCase()) {
    case "discord":
      return VerificationPlatform.Discord;
    case "telegram":
      return VerificationPlatform.Telegram;
    case "twitter":
      return VerificationPlatform.Twitter;
    case "email":
      return VerificationPlatform.Email;
    default:
      return VerificationPlatform.Discord;
  }
}

function platformSeed(platform) {
  return platformEnum(platform);
}

function platformTag(platform) {
  switch ((platform || "").toLowerCase()) {
    case "discord":
      return TAG_DISCORD;
    case "telegram":
      return TAG_TELEGRAM;
    case "twitter":
      return TAG_TWITTER;
    case "email":
      return TAG_EMAIL;
    default:
      return TAG_DISCORD;
  }
}

/* -----------------------------
   On-chain parsing (Space salt)
------------------------------ */

function parseSpaceSalt(spaceDataU8) {
  // matches your layout: disc(8) + version(1) + dao(32) + authority(32) + attestor(32) + is_frozen(1) + bump(1) + salt(32)
  const SALT_OFFSET = 8 + 1 + 32 + 32 + 32 + 1 + 1; // 107
  return spaceDataU8.slice(SALT_OFFSET, SALT_OFFSET + 32);
}

/* -----------------------------
   Discord command registration
------------------------------ */

const COMMANDS = [
  {
    name: "gv",
    description: "Grape Verification",
    options: [
      {
        type: 1,
        name: "ping",
        description: "Health check",
      },
      {
        type: 1,
        name: "status",
        description: "Show PDAs and on-chain status",
        options: [
          { type: 3, name: "dao", description: "DAO pubkey", required: true },
          {
            type: 3,
            name: "platform",
            description: "discord|telegram|twitter|email",
            required: true,
            choices: [
              { name: "discord", value: "discord" },
              { name: "email", value: "email" },
              { name: "telegram", value: "telegram" },
              { name: "twitter", value: "twitter" },
            ],
          },
          {
            type: 3,
            name: "platform_user_id",
            description: "Platform user id (discord id, email id, etc)",
            required: true,
          },
          { type: 3, name: "wallet", description: "Wallet pubkey (optional)", required: false },
        ],
      },
      {
        type: 1,
        name: "space-init",
        description: "Initialize Space PDA for a DAO (admin/bot)",
        options: [
          { type: 3, name: "dao", description: "DAO pubkey", required: true },
          { type: 3, name: "salt_hex", description: "32-byte hex (64 chars)", required: true },
        ],
      },
      {
        type: 1,
        name: "attest",
        description: "Attest identity (attestor signs tx)",
        options: [
          { type: 3, name: "dao", description: "DAO pubkey", required: true },
          {
            type: 3,
            name: "platform",
            description: "discord|telegram|twitter|email",
            required: true,
            choices: [
              { name: "discord", value: "discord" },
              { name: "email", value: "email" },
              { name: "telegram", value: "telegram" },
              { name: "twitter", value: "twitter" },
            ],
          },
          { type: 3, name: "platform_user_id", description: "Platform user id", required: true },
          { type: 4, name: "expires_seconds", description: "Expiry in seconds (0 = none)", required: false },
        ],
      },
      {
        type: 1,
        name: "revoke",
        description: "Revoke identity (attestor signs tx)",
        options: [
          { type: 3, name: "dao", description: "DAO pubkey", required: true },
          {
            type: 3,
            name: "platform",
            description: "discord|telegram|twitter|email",
            required: true,
            choices: [
              { name: "discord", value: "discord" },
              { name: "email", value: "email" },
              { name: "telegram", value: "telegram" },
              { name: "twitter", value: "twitter" },
            ],
          },
          { type: 3, name: "platform_user_id", description: "Platform user id", required: true },
        ],
      },
      {
        type: 1,
        name: "link",
        description: "Link a wallet to identity (attestor signs tx)",
        options: [
          { type: 3, name: "dao", description: "DAO pubkey", required: true },
          {
            type: 3,
            name: "platform",
            description: "discord|telegram|twitter|email",
            required: true,
            choices: [
              { name: "discord", value: "discord" },
              { name: "email", value: "email" },
              { name: "telegram", value: "telegram" },
              { name: "twitter", value: "twitter" },
            ],
          },
          { type: 3, name: "platform_user_id", description: "Platform user id", required: true },
          { type: 3, name: "wallet", description: "Wallet pubkey", required: true },
        ],
      },
      {
        type: 1,
        name: "link-self",
        description: "Link wallet where the wallet is a signer (requires wallet signature on tx)",
        options: [
          { type: 3, name: "dao", description: "DAO pubkey", required: true },
          {
            type: 3,
            name: "platform",
            description: "discord|telegram|twitter|email",
            required: true,
            choices: [
              { name: "discord", value: "discord" },
              { name: "email", value: "email" },
              { name: "telegram", value: "telegram" },
              { name: "twitter", value: "twitter" },
            ],
          },
          { type: 3, name: "platform_user_id", description: "Platform user id", required: true },
          { type: 3, name: "wallet", description: "Wallet pubkey", required: true },
        ],
      },
    ],
  },
];

async function discordApi(path, { method = "GET", body } = {}) {
  const token = mustEnv("DISCORD_BOT_TOKEN");
  const url = `https://discord.com/api/v10${path}`;
  const res = await fetch(url, {
    method,
    headers: {
      Authorization: `Bot ${token}`,
      "Content-Type": "application/json",
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text().catch(() => "");
  if (!res.ok) {
    throw new Error(`Discord API ${res.status}: ${text}`);
  }
  return text ? JSON.parse(text) : null;
}

async function registerCommands({ guildId } = {}) {
  const appId = mustEnv("DISCORD_APPLICATION_ID");

  if (guildId) {
    return discordApi(`/applications/${appId}/guilds/${guildId}/commands`, {
      method: "PUT",
      body: COMMANDS,
    });
  }

  return discordApi(`/applications/${appId}/commands`, {
    method: "PUT",
    body: COMMANDS,
  });
}

/* -----------------------------
   Solana tx helper
------------------------------ */

async function sendTx(connection, tx, signers) {
  tx.feePayer = signers[0].publicKey;

  const { blockhash, lastValidBlockHeight } = await connection.getLatestBlockhash("confirmed");
  tx.recentBlockhash = blockhash;

  tx.sign(...signers);

  const sig = await connection.sendRawTransaction(tx.serialize(), {
    skipPreflight: false,
    maxRetries: 3,
  });

  await connection.confirmTransaction(
    { signature: sig, blockhash, lastValidBlockHeight },
    "confirmed"
  );

  return sig;
}

/* -----------------------------
   Command handlers
------------------------------ */

function optMap(interaction) {
  const opts = {};
  const sub = interaction?.data?.options?.[0];
  const subOpts = sub?.options || [];
  for (const o of subOpts) opts[o.name] = o.value;
  return { sub: sub?.name, opts };
}

async function fetchSpaceSaltOrThrow(connection, daoPk) {
  const [spacePda] = deriveSpacePda(daoPk);
  const acct = await connection.getAccountInfo(spacePda, "confirmed");
  if (!acct) throw new Error(`Space not found: ${spacePda.toBase58()}`);
  const salt = parseSpaceSalt(acct.data);
  if (!salt || salt.length !== 32) throw new Error("Failed to parse space salt");
  return { spacePda, salt };
}

async function handlePing(res) {
  return json(res, 200, reply("✅ gv pong", { ephemeral: true }));
}

async function handleStatus(interaction, res) {
  const { opts } = optMap(interaction);

  const daoPk = new PublicKey(String(opts.dao));
  const platform = String(opts.platform);
  const platformUserId = String(opts.platform_user_id).trim();
  const walletStr = opts.wallet ? String(opts.wallet).trim() : "";

  const connection = new Connection(rpcUrl(), { commitment: "confirmed" });

  const [spacePda] = deriveSpacePda(daoPk);
  const spaceAcct = await connection.getAccountInfo(spacePda, "confirmed");

  let salt = null;
  if (spaceAcct) salt = parseSpaceSalt(spaceAcct.data);

  const idh = salt ? identityHash(salt, platformTag(platform), platformUserId) : null;

  const idSeed = platformSeed(platform);
  const identityPda = salt ? deriveIdentityPda(spacePda, idSeed, idh)[0] : null;

  let linkPda = null;
  if (walletStr && salt && identityPda) {
    const walletPk = new PublicKey(walletStr);
    const wh = walletHash(salt, walletPk);
    linkPda = deriveLinkPda(identityPda, wh)[0];
  }

  const lines = [
    `**Program:** \`${PROGRAM_ID.toBase58()}\``,
    `**DAO:** \`${daoPk.toBase58()}\``,
    `**Space PDA:** \`${spacePda.toBase58()}\`  ${spaceAcct ? "✅ exists" : "❌ missing"}`,
    salt ? `**Salt:** \`${Buffer.from(salt).toString("hex")}\`` : `**Salt:** —`,
    `**Platform:** \`${platform}\` (seed=${idSeed})`,
    `**Platform User ID:** \`${platformUserId}\``,
    idh ? `**id_hash:** \`${Buffer.from(idh).toString("hex")}\`` : `**id_hash:** —`,
    identityPda ? `**Identity PDA:** \`${identityPda.toBase58()}\`` : `**Identity PDA:** —`,
    linkPda ? `**Link PDA:** \`${linkPda.toBase58()}\`` : `**Link PDA:** —`,
  ];

  return json(res, 200, replyWithEmbed("Grape Verification Status", lines.join("\n"), { ephemeral: true }));
}

async function handleSpaceInit(interaction, res) {
  const { opts } = optMap(interaction);

  const daoPk = new PublicKey(String(opts.dao));
  const saltHex = String(opts.salt_hex || "").trim();
  if (!/^[0-9a-fA-F]{64}$/.test(saltHex)) {
    return json(res, 200, reply("❌ salt_hex must be 64 hex chars (32 bytes)", { ephemeral: true }));
  }

  const payer = parseKeypairFromEnv("BOT_FEE_PAYER_SECRET_KEY"); // your bot wallet funds tx
  const connection = new Connection(rpcUrl(), { commitment: "confirmed" });

  const salt = Uint8Array.from(Buffer.from(saltHex, "hex"));

  const { ix } = buildInitializeSpaceIx({
    daoId: daoPk,
    salt,
    authority: payer.publicKey,
    payer: payer.publicKey,
    programId: PROGRAM_ID,
  });

  const tx = new Transaction().add(ix);
  const sig = await sendTx(connection, tx, [payer]);

  return json(res, 200, reply(`✅ Space initialized.\nTx: \`${sig}\``, { ephemeral: true }));
}

async function handleAttest(interaction, res) {
  const { opts } = optMap(interaction);

  const daoPk = new PublicKey(String(opts.dao));
  const platform = String(opts.platform);
  const platformUserId = String(opts.platform_user_id).trim();
  const expiresSeconds = opts.expires_seconds ? Number(opts.expires_seconds) : 0;

  const connection = new Connection(rpcUrl(), { commitment: "confirmed" });
  const payer = parseKeypairFromEnv("BOT_FEE_PAYER_SECRET_KEY"); // also acts as attestor

  const { salt } = await fetchSpaceSaltOrThrow(connection, daoPk);

  const idh = identityHash(salt, platformTag(platform), platformUserId);
  const seed = platformSeed(platform);

  const now = Math.floor(Date.now() / 1000);
  const expiresAt = BigInt(expiresSeconds > 0 ? now + expiresSeconds : 0);

  const { ix } = buildAttestIdentityIx({
    daoId: daoPk,
    platform: platformEnum(platform),
    platformSeed: seed,
    idHash: idh,
    expiresAt,
    attestor: payer.publicKey,
    payer: payer.publicKey,
    programId: PROGRAM_ID,
  });

  const tx = new Transaction().add(ix);
  const sig = await sendTx(connection, tx, [payer]);

  return json(res, 200, reply(`✅ Identity attested.\nTx: \`${sig}\``, { ephemeral: true }));
}

async function handleRevoke(interaction, res) {
  const { opts } = optMap(interaction);

  const daoPk = new PublicKey(String(opts.dao));
  const platform = String(opts.platform);
  const platformUserId = String(opts.platform_user_id).trim();

  const connection = new Connection(rpcUrl(), { commitment: "confirmed" });
  const payer = parseKeypairFromEnv("BOT_FEE_PAYER_SECRET_KEY"); // also attestor

  const { salt } = await fetchSpaceSaltOrThrow(connection, daoPk);

  const idh = identityHash(salt, platformTag(platform), platformUserId);
  const seed = platformSeed(platform);

  const { ix } = buildRevokeIdentityIx({
    daoId: daoPk,
    platform: platformEnum(platform),
    platformSeed: seed,
    idHash: idh,
    attestor: payer.publicKey,
    programId: PROGRAM_ID,
  });

  const tx = new Transaction().add(ix);
  const sig = await sendTx(connection, tx, [payer]);

  return json(res, 200, reply(`✅ Identity revoked.\nTx: \`${sig}\``, { ephemeral: true }));
}

async function handleLink(interaction, res) {
  const { opts } = optMap(interaction);

  const daoPk = new PublicKey(String(opts.dao));
  const platform = String(opts.platform);
  const platformUserId = String(opts.platform_user_id).trim();
  const walletPk = new PublicKey(String(opts.wallet));

  const connection = new Connection(rpcUrl(), { commitment: "confirmed" });
  const payer = parseKeypairFromEnv("BOT_FEE_PAYER_SECRET_KEY");

  const { salt } = await fetchSpaceSaltOrThrow(connection, daoPk);

  const idh = identityHash(salt, platformTag(platform), platformUserId);
  const wh = walletHash(salt, walletPk);
  const seed = platformSeed(platform);

  const { ix } = buildLinkWalletIx({
    daoId: daoPk,
    platformSeed: seed,
    idHash: idh,
    wallet: walletPk,
    walletHash: wh,
    attestor: payer.publicKey,
    payer: payer.publicKey,
    programId: PROGRAM_ID,
  });

  const tx = new Transaction().add(ix);
  const sig = await sendTx(connection, tx, [payer]);

  return json(res, 200, reply(`✅ Wallet linked (attestor-driven).\nTx: \`${sig}\``, { ephemeral: true }));
}

async function handleLinkSelf(interaction, res) {
  // NOTE: This requires the *wallet* to be a signer on the transaction.
  // Discord cannot make a user's wallet sign. This is useful only when your "wallet"
  // is also a server-controlled keypair (e.g. a service wallet) OR you provide a client flow.
  const { opts } = optMap(interaction);

  const daoPk = new PublicKey(String(opts.dao));
  const platform = String(opts.platform);
  const platformUserId = String(opts.platform_user_id).trim();
  const walletStr = String(opts.wallet);

  const connection = new Connection(rpcUrl(), { commitment: "confirmed" });

  const payer = parseKeypairFromEnv("BOT_FEE_PAYER_SECRET_KEY");
  const walletSigner = parseKeypairFromEnv("BOT_WALLET_SIGNER_SECRET_KEY"); // must match opts.wallet

  if (walletSigner.publicKey.toBase58() !== walletStr) {
    return json(
      res,
      200,
      reply(
        `❌ link-self requires BOT_WALLET_SIGNER_SECRET_KEY to match wallet argument.\n` +
          `wallet arg: ${walletStr}\n` +
          `wallet signer: ${walletSigner.publicKey.toBase58()}`,
        { ephemeral: true }
      )
    );
  }

  const { salt } = await fetchSpaceSaltOrThrow(connection, daoPk);

  const idh = identityHash(salt, platformTag(platform), platformUserId);
  const wh = walletHash(salt, walletSigner.publicKey);
  const seed = platformSeed(platform);

  const { ix } = buildLinkWalletSelfIx({
    daoId: daoPk,
    platformSeed: seed,
    idHash: idh,
    wallet: walletSigner.publicKey, // signer
    walletHash: wh,
    payer: payer.publicKey,
    programId: PROGRAM_ID,
  });

  const tx = new Transaction().add(ix);

  // both payer + wallet signer must sign
  const sig = await sendTx(connection, tx, [payer, walletSigner]);

  return json(res, 200, reply(`✅ Wallet self-linked.\nTx: \`${sig}\``, { ephemeral: true }));
}

/* -----------------------------
   Main entry: handle slash commands
------------------------------ */

async function handleSlashCommand(interaction, res) {
  try {
    const sub = interaction?.data?.options?.[0]?.name;

    if (!sub) return json(res, 200, reply("Unknown command", { ephemeral: true }));

    if (sub === "ping") return handlePing(res);
    if (sub === "status") return handleStatus(interaction, res);
    if (sub === "space-init") return handleSpaceInit(interaction, res);
    if (sub === "attest") return handleAttest(interaction, res);
    if (sub === "revoke") return handleRevoke(interaction, res);
    if (sub === "link") return handleLink(interaction, res);
    if (sub === "link-self") return handleLinkSelf(interaction, res);

    return json(res, 200, reply("Unknown subcommand", { ephemeral: true }));
  } catch (e) {
    console.error("[slash] error:", e);
    return json(res, 200, reply(`❌ ${String(e?.message || e)}`, { ephemeral: true }));
  }
}

module.exports = {
  registerCommands,
  handleSlashCommand,
};