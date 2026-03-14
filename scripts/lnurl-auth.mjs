#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════════
// lnurl-auth.mjs — LNURL-auth CLI for AI agents
// ═══════════════════════════════════════════════════════════════════
// Authenticates to services (LNMarkets, Stacker News, etc.) using
// LNURL-auth — no email, no password, just your Lightning seed.
//
// Compatibility: @noble/secp256k1 v1.7.1 (uses secp.utils, NOT secp.etc)
//
// Usage:
//   node lnurl-auth.mjs --seed "word1 word2 ... word12" --service lnmarkets
//   node lnurl-auth.mjs --seed "word1 word2 ..." --lnurl "lnurl1..."
//   node lnurl-auth.mjs --key abc123... --lnurl "lnurl1..."
//   node lnurl-auth.mjs --seed "word1..." --service predyx --proxy socks5://host:port
//   node lnurl-auth.mjs --seed "word1..." --service lnmarkets --dry-run
//   node lnurl-auth.mjs --seed "word1..." --service lnmarkets --verbose
// ═══════════════════════════════════════════════════════════════════

import crypto from 'crypto';
import https from 'https';
import http from 'http';
import { SocksProxyAgent } from 'socks-proxy-agent';
import { bech32 } from 'bech32';
import * as secp from '@noble/secp256k1';

// ─── secp256k1 v1.7.1 hashing setup ──────────────────────────────
// v1 requires us to provide HMAC-SHA256 and SHA256 implementations.
// These go on secp.utils (NOT secp.etc, which is the v2 API).
secp.utils.hmacSha256Sync = (key, ...msgs) => {
  const h = crypto.createHmac('sha256', key);
  for (const msg of msgs) h.update(msg);
  return h.digest();
};
secp.utils.sha256Sync = (...msgs) => {
  const h = crypto.createHash('sha256');
  for (const msg of msgs) h.update(msg);
  return h.digest();
};

// ─── Known service endpoints ──────────────────────────────────────
// These are the LNURL-auth initiation endpoints. They return {lnurl, k1}
// or directly provide k1 + callback.
const SERVICES = {
  lnmarkets: 'https://api.lnmarkets.com/orpc/lnurl/auth/login',
  predyx:    'https://api.predyx.io/orpc/lnurl/auth/login',
};

// Stacker News uses a different flow — LNURL-auth is done via their
// web login which generates a LNURL. Users typically get the lnurl
// string directly from the site. We support it as a known service
// name but it requires --lnurl since there's no simple POST endpoint.

// ─── BIP39: Mnemonic → Seed ──────────────────────────────────────
// Standard BIP39 seed derivation using PBKDF2-HMAC-SHA512.
// Returns a 64-byte Buffer (the BIP39 master seed).
function mnemonicToSeed(mnemonic, passphrase = '') {
  return crypto.pbkdf2Sync(
    Buffer.from(mnemonic, 'utf8'),
    Buffer.from('mnemonic' + passphrase, 'utf8'),
    2048, 64, 'sha512'
  );
}

// ─── BIP32: HD Key Derivation ────────────────────────────────────
// Minimal BIP32 implementation for deriving keys from the master seed.
// Only hardened child derivation is needed for LNURL-auth (m/138'/0).

function hmac512(key, data) {
  return crypto.createHmac('sha512', key).update(data).digest();
}

// Derive master key from BIP39 seed using BIP32 "Bitcoin seed" magic.
function masterKeyFromSeed(seed) {
  const I = hmac512(Buffer.from('Bitcoin seed', 'utf8'), seed);
  return { key: I.slice(0, 32), chainCode: I.slice(32) };
}

// Derive a single hardened child key.
// Hardened indices are offset by 0x80000000.
function deriveHardened(parent, index) {
  const indexBuf = Buffer.alloc(4);
  indexBuf.writeUInt32BE(index, 0);
  // Hardened derivation: data = 0x00 || parentKey || index
  const data = Buffer.concat([Buffer.from([0x00]), parent.key, indexBuf]);
  const I = hmac512(parent.chainCode, data);
  return { key: I.slice(0, 32), chainCode: I.slice(32) };
}

// Walk a BIP32 derivation path (all indices must be hardened).
function derivePath(master, path) {
  let key = master;
  for (const idx of path) key = deriveHardened(key, idx);
  return key;
}

// ─── LNURL Protocol ──────────────────────────────────────────────
//
// LNURL-auth key derivation (LUD-05):
//
//   1. Start with master key from BIP39 seed
//   2. Derive hashing key at path m/138'/0
//   3. For each service domain, compute:
//        domainHash = HMAC-SHA256(hashingKey, domain)
//   4. Linking private key = masterPrivKey + domainHash (mod curve order n)
//   5. Linking public key = point(linkingPrivKey)
//
// This means the same seed produces a DIFFERENT identity for each service.
// Compromising one service's linking key reveals nothing about others.
//
// The service never sees your master key, only the domain-specific linking key.

// LNURL-auth BIP32 path for the hashing key
const LNURL_AUTH_PATH = [0x80000000 + 138, 0x80000000 + 0];

// secp256k1 curve order
const CURVE_ORDER = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');

// Compute the linking keypair for a given domain from the master key.
// Returns { privKey: Uint8Array(32), pubKey: Uint8Array(33 compressed) }
function deriveLinkingKey(masterKey, domain) {
  // Step 1: derive hashing key at m/138'/0
  const hashingKey = derivePath(masterKey, LNURL_AUTH_PATH);

  // Step 2: HMAC-SHA256(hashingKey, domain) → domain tweak
  const domainHash = crypto.createHmac('sha256', hashingKey.key)
    .update(domain)
    .digest();

  // Step 3: linkingPriv = masterPriv + domainHash (mod n)
  // This "tweak" ensures each domain gets a unique key, but the
  // master seed is the single source of truth.
  const privNum = BigInt('0x' + masterKey.key.toString('hex'));
  const tweakNum = BigInt('0x' + domainHash.toString('hex'));
  const linkingPrivNum = (privNum + tweakNum) % CURVE_ORDER;
  const linkingPrivHex = linkingPrivNum.toString(16).padStart(64, '0');
  const linkingPriv = secp.utils.hexToBytes(linkingPrivHex);

  // Step 4: derive compressed public key
  const linkingPub = secp.getPublicKey(linkingPriv, true); // compressed

  return { privKey: linkingPriv, pubKey: linkingPub };
}

// Sign a k1 challenge with the linking private key.
// Returns the 64-byte compact signature as hex string.
// NOTE: secp.sign() in v1.7.1 returns a Promise → must await.
async function signK1(k1Hex, linkingPriv) {
  const k1Bytes = secp.utils.hexToBytes(k1Hex);
  // LNURL-auth spec requires DER-encoded signature (LUD-05)
  // DER is variable length, typically 70-72 bytes
  const sig = await secp.sign(k1Bytes, linkingPriv, { der: true });
  return secp.utils.bytesToHex(sig);
}

// ─── LNURL Bech32 Decode ─────────────────────────────────────────
// LNURLs are bech32-encoded URLs. Decode to get the callback endpoint.
function decodeLnurl(lnurl) {
  const { words } = bech32.decode(lnurl, 2000);
  return Buffer.from(bech32.fromWords(words)).toString('utf8');
}

// ─── HTTP Helpers ────────────────────────────────────────────────
// All HTTP functions support optional SOCKS5 proxy.

function createAgent(proxyUrl) {
  if (!proxyUrl) return undefined;
  return new SocksProxyAgent(proxyUrl, { timeout: 20000 });
}

function httpGet(url, { agent, verbose } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const mod = u.protocol === 'https:' ? https : http;
    const opts = {
      hostname: u.hostname,
      port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname + u.search,
      method: 'GET',
      agent,
      timeout: 25000,
      headers: { 'Accept': 'application/json' },
    };
    if (verbose) console.error(`  [http] GET ${url.slice(0, 100)}...`);
    const req = mod.request(opts, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => resolve({ status: res.statusCode, body: data, headers: res.headers }));
    });
    req.on('error', reject);
    req.on('timeout', function () { this.destroy(); reject(new Error('HTTP timeout')); });
    req.end();
  });
}

function httpPost(url, body, { agent, verbose } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const mod = u.protocol === 'https:' ? https : http;
    const postData = typeof body === 'string' ? body : JSON.stringify(body);
    const opts = {
      hostname: u.hostname,
      port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname + u.search,
      method: 'POST',
      agent,
      timeout: 25000,
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData),
      },
    };
    if (verbose) console.error(`  [http] POST ${url.slice(0, 100)}`);
    const req = mod.request(opts, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => resolve({ status: res.statusCode, body: data, headers: res.headers }));
    });
    req.on('error', reject);
    req.on('timeout', function () { this.destroy(); reject(new Error('HTTP timeout')); });
    req.write(postData);
    req.end();
  });
}

// ─── CLI Argument Parsing ────────────────────────────────────────

function parseArgs(argv) {
  const args = {};
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--seed')      args.seed = argv[++i];
    else if (a === '--key')  args.key = argv[++i];
    else if (a === '--lnurl') args.lnurl = argv[++i];
    else if (a === '--service') args.service = argv[++i];
    else if (a === '--proxy')   args.proxy = argv[++i];
    else if (a === '--dry-run') args.dryRun = true;
    else if (a === '--verbose') args.verbose = true;
    else if (a === '--help' || a === '-h') args.help = true;
    else {
      console.error(`Unknown option: ${a}`);
      process.exit(1);
    }
  }
  return args;
}

function printHelp() {
  console.log(`
lnurl-auth.mjs — LNURL-auth CLI for AI agents

USAGE
  node lnurl-auth.mjs --seed "word1 word2 ... word12" [options]
  node lnurl-auth.mjs --key <hex-privkey> [options]

OPTIONS
  --seed <mnemonic>    12-word BIP39 mnemonic (or use SEED env var)
  --key <hex>          Raw hex private key (for testing with random keys)
  --service <name>     Known service: lnmarkets, predyx
  --lnurl <string>     Raw LNURL bech32 string (alternative to --service)
  --proxy <url>        SOCKS5 proxy URL (e.g. socks5://host:port)
  --dry-run            Show what would happen without submitting
  --verbose            Show each step with debug output
  --help, -h           Show this help

EXAMPLES
  node lnurl-auth.mjs --seed "word1 word2 ..." --service lnmarkets
  node lnurl-auth.mjs --seed "word1 word2 ..." --lnurl "lnurl1..."
  node lnurl-auth.mjs --key abc123... --lnurl "lnurl1..."
  node lnurl-auth.mjs --seed "word1..." --service predyx --proxy socks5://host:port
  SEED="word1 word2 ..." node lnurl-auth.mjs --service lnmarkets --dry-run

ENVIRONMENT
  SEED                 Alternative to --seed flag
`);
}

// ─── Main ────────────────────────────────────────────────────────

async function main() {
  const args = parseArgs(process.argv);

  if (args.help) {
    printHelp();
    process.exit(0);
  }

  // Validate inputs
  const seed = args.seed || process.env.SEED;
  const privKeyHex = args.key;

  if (!seed && !privKeyHex) {
    console.error('Error: provide --seed "mnemonic words" or --key <hex>');
    console.error('       (or set SEED environment variable)');
    process.exit(1);
  }

  if (!args.service && !args.lnurl) {
    console.error('Error: provide --service <name> or --lnurl <string>');
    console.error(`       Known services: ${Object.keys(SERVICES).join(', ')}`);
    process.exit(1);
  }

  const verbose = args.verbose;
  const dryRun = args.dryRun;
  const agent = createAgent(args.proxy);

  // ─── Step 0: Derive or load the base private key ───────────────
  let masterKey;
  let basePrivKey; // Uint8Array(32)

  if (seed) {
    console.error('▸ Deriving master key from mnemonic...');
    const seedBuf = mnemonicToSeed(seed.trim());
    masterKey = masterKeyFromSeed(seedBuf);
    basePrivKey = secp.utils.hexToBytes(masterKey.key.toString('hex'));
    if (verbose) {
      console.error(`  Master key: ${masterKey.key.toString('hex').slice(0, 16)}...`);
      console.error(`  Chain code: ${masterKey.chainCode.toString('hex').slice(0, 16)}...`);
    }
  } else {
    // Direct hex key mode — no derivation, just use the key as-is.
    // For LNURL-auth with a raw key, we use it directly as the "master"
    // (effectively domainHash = 0, linking key = input key).
    console.error('▸ Using provided hex private key...');
    basePrivKey = secp.utils.hexToBytes(privKeyHex);
    if (basePrivKey.length !== 32) {
      console.error('Error: private key must be 32 bytes (64 hex chars)');
      process.exit(1);
    }
    // Synthesize a masterKey struct for deriveLinkingKey compatibility
    masterKey = { key: Buffer.from(basePrivKey), chainCode: Buffer.alloc(32) };
  }

  // ─── Step 1: Get the LNURL string ──────────────────────────────
  let lnurlString;
  let k1;

  if (args.lnurl) {
    // Direct LNURL provided — decode it to get callback URL
    lnurlString = args.lnurl;
    console.error('▸ Using provided LNURL string');
  } else {
    // Fetch from service endpoint
    const endpoint = SERVICES[args.service.toLowerCase()];
    if (!endpoint) {
      console.error(`Error: unknown service "${args.service}"`);
      console.error(`       Known services: ${Object.keys(SERVICES).join(', ')}`);
      process.exit(1);
    }

    console.error(`▸ Fetching LNURL auth challenge from ${args.service}...`);
    if (verbose) console.error(`  POST ${endpoint}`);

    const authRes = await httpPost(endpoint, {}, { agent, verbose });

    if (authRes.status !== 200) {
      console.error(`  ✗ HTTP ${authRes.status}: ${authRes.body.slice(0, 200)}`);
      process.exit(1);
    }

    const authData = JSON.parse(authRes.body);
    // LNMarkets format: { json: { lnurl, k1 } }
    // Some services: { lnurl, k1 } directly
    const payload = authData.json || authData;
    lnurlString = payload.lnurl;
    k1 = payload.k1;

    if (!lnurlString) {
      console.error('  ✗ No lnurl in response:', JSON.stringify(authData).slice(0, 200));
      process.exit(1);
    }

    console.error(`  ✓ Got lnurl: ${lnurlString.slice(0, 40)}...`);
    if (k1) console.error(`  ✓ Got k1:    ${k1.slice(0, 32)}...`);
  }

  // ─── Step 2: Decode LNURL to get callback URL ──────────────────
  console.error('▸ Decoding LNURL (bech32)...');
  const callbackUrl = decodeLnurl(lnurlString);
  console.error(`  Callback: ${callbackUrl.slice(0, 80)}...`);

  // ─── Step 3: If we only have lnurl (no k1 yet), get k1 ──────────
  // When a raw LNURL is provided, the decoded callback URL may already
  // contain k1 as a query param (Predyx-style). If not, GET the URL
  // to receive { k1, tag: "login" } (LNMarkets-style).
  if (!k1) {
    const cbUrl = new URL(callbackUrl);
    if (cbUrl.searchParams.get('k1')) {
      k1 = cbUrl.searchParams.get('k1');
      console.error(`  ✓ k1 from callback URL: ${k1.slice(0, 32)}...`);
    } else {
      console.error('▸ Fetching k1 challenge from decoded URL...');
      const k1Res = await httpGet(callbackUrl, { agent, verbose });
      if (k1Res.status !== 200) {
        console.error(`  ✗ HTTP ${k1Res.status}: ${k1Res.body.slice(0, 200)}`);
        process.exit(1);
      }
      const k1Data = JSON.parse(k1Res.body);
      k1 = k1Data.k1;
      if (!k1) {
        console.error('  ✗ No k1 in response:', k1Res.body.slice(0, 200));
        process.exit(1);
      }
      console.error(`  ✓ Got k1: ${k1.slice(0, 32)}...`);
    }
  }

  // ─── Step 4: Derive the domain-specific linking key ────────────
  const domain = new URL(callbackUrl).hostname;
  console.error(`▸ Deriving linking key for domain: ${domain}`);

  const linkingKey = deriveLinkingKey(masterKey, domain);
  const linkingPubHex = secp.utils.bytesToHex(linkingKey.pubKey);

  if (verbose) {
    console.error(`  Linking priv: ${secp.utils.bytesToHex(linkingKey.privKey).slice(0, 32)}...`);
    console.error(`  Linking pub:  ${linkingPubHex.slice(0, 32)}...`);
  }

  // ─── Step 5: Sign k1 with the linking private key ──────────────
  console.error('▸ Signing k1 challenge...');
  const sigHex = await signK1(k1, linkingKey.privKey);
  console.error(`  Signature: ${sigHex.slice(0, 40)}...`);

  // ─── Step 6: Build the callback URL with signature ─────────────
  const submitUrl = new URL(callbackUrl);
  submitUrl.searchParams.set('sig', sigHex);
  submitUrl.searchParams.set('key', linkingPubHex);
  submitUrl.searchParams.set('t', Date.now().toString());

  // ─── Dry run: show everything but don't submit ─────────────────
  if (dryRun) {
    console.error('\n── DRY RUN (not submitting) ──');
    console.log(JSON.stringify({
      dryRun: true,
      domain,
      callbackUrl: callbackUrl.slice(0, 100) + '...',
      linkingPubKey: linkingPubHex,
      signature: sigHex,
      submitUrl: submitUrl.toString().slice(0, 120) + '...',
      k1: k1,
    }, null, 2));
    process.exit(0);
  }

  // ─── Step 7: Submit the signed authentication ──────────────────
  console.error('▸ Submitting signed auth...');
  const submitRes = await httpGet(submitUrl.toString(), { agent, verbose });

  console.error(`  Status: ${submitRes.status}`);

  // Parse and output result
  let result;
  try {
    result = JSON.parse(submitRes.body);
  } catch {
    result = { raw: submitRes.body };
  }

  // Check for session cookies
  const cookies = submitRes.headers['set-cookie'];
  const cookieStr = cookies
    ? cookies.map(c => c.split(';')[0]).join('; ')
    : null;

  // Also log raw cookie headers in verbose mode
  if (verbose && cookies) {
    console.error(`  Set-Cookie: ${cookies.join('\n  Set-Cookie: ')}`);
  }

  // Build output
  const output = {
    status: submitRes.status,
    success: false,
    ...(cookieStr ? { cookies: cookieStr } : {}),
    response: result,
  };

  // Determine success
  if (result.status === 'OK' || result.json?.token || result.json?.status === 'OK') {
    output.success = true;
    if (result.json?.token) output.token = result.json.token;
    console.error('  ✅ LNURL Auth successful!');
  } else {
    console.error('  ⚠️  Auth completed but service did not confirm OK');
  }

  // Print JSON result to stdout (for piping)
  console.log(JSON.stringify(output, null, 2));
}

main().catch(e => {
  console.error(`Fatal: ${e.message}`);
  if (process.env.DEBUG) console.error(e.stack);
  process.exit(1);
});
