#!/usr/bin/env node

const fs = require("fs");
const path = require("path");

function patchFile(filePath) {
  if (!fs.existsSync(filePath)) return { changed: false, skipped: true };

  const before = fs.readFileSync(filePath, "utf8");
  const after = before
    // Normalize any sha256 import form to the v2-exported sha2.js entry.
    .replace(/@noble\/hashes\/sha256(?:\.js)*/g, "@noble/hashes/sha2.js")
    // Normalize utils import so repeated postinstall runs stay stable.
    .replace(/@noble\/hashes\/utils(?:\.js)*/g, "@noble/hashes/utils.js");

  if (after === before) return { changed: false, skipped: false };
  fs.writeFileSync(filePath, after, "utf8");
  return { changed: true, skipped: false };
}

function main() {
  let entryPath;
  try {
    entryPath = require.resolve("@grapenpm/grape-verification-registry");
  } catch (e) {
    console.warn("[patch-gvr-imports] package not installed, skipping");
    return;
  }

  const packageRoot = path.resolve(path.dirname(entryPath), "..");
  const esmPath = path.join(packageRoot, "dist", "index.js");
  const result = patchFile(esmPath);

  if (result.skipped) {
    console.warn(`[patch-gvr-imports] file not found: ${esmPath}`);
    return;
  }

  if (result.changed) {
    console.log(`[patch-gvr-imports] patched ${esmPath}`);
  } else {
    console.log("[patch-gvr-imports] already patched");
  }
}

main();
