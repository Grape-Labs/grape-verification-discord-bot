require("dotenv").config();
const { registerCommands } = require("../lib/discord/slash-commands");

const BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;
const APP_ID = process.env.DISCORD_APPLICATION_ID || process.env.DISCORD_APP_ID;

// OPTIONAL but recommended while developing
const GUILD_ID = process.env.DISCORD_TEST_GUILD_ID;

if (!APP_ID || !BOT_TOKEN) {
  console.error("Missing DISCORD_APPLICATION_ID (or DISCORD_APP_ID) or DISCORD_BOT_TOKEN");
  process.exit(1);
}

(async () => {
  console.log(
    `Registering slash commands for ${GUILD_ID ? `guild ${GUILD_ID}` : "global"} (app ${APP_ID})...`
  );
  await registerCommands({ guildId: GUILD_ID });
  console.log("✅ Commands registered successfully");
})().catch((err) => {
  console.error("❌ Failed to register commands:", err?.message || err);
  process.exit(1);
});
