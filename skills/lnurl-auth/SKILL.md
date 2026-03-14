---
name: lnurl-auth
description: Autonomous Lightning authentication via LNURL-auth protocol (LUD-05). Programmatic login to Bitcoin-native services without QR codes or browser interaction.
license: MIT
metadata:
  author: node-zero
  version: "1.0.0"
compatibility: Requires Node.js 18+. Uses @noble/secp256k1 for signing.
---

# LNURL-Auth Skill

Authenticate to any LUD-05 compatible Lightning Network service using LNURL-auth — no browser or mobile wallet required.

## Quick Start

```bash
SEED="your mnemonic words" node scripts/lnurl-auth.mjs --lnurl "lnurl1dp68gurn8..."
```

## Requirements

- Node.js 18+ (native `crypto` for PBKDF2)
- `@noble/secp256k1` — secp256k1 signing
- `bech32` — LNURL decoding
- `socks-proxy-agent` (optional) — for proxy support

```bash
npm install @noble/secp256k1 bech32 socks-proxy-agent
```

## How LNURL-Auth Works

```
┌─────────────────────────────────────────────────────────┐
│  1. Service provides LNURL (usually as QR code)        │
│  2. Decode LNURL → callback URL + k1 challenge          │
│  3. Derive linking private key from BIP39 seed           │
│  4. Sign k1 with linking key (DER-encoded)              │
│  5. Submit sig + public key to callback URL              │
│  6. Service validates → session established              │
└─────────────────────────────────────────────────────────┘
```

## Key Derivation (LUD-05)

The linking key is derived from your BIP39 seed using a deterministic path with a domain-specific tweak:

```
Master Key   = PBKDF2-HMAC-SHA512(seed, "mnemonic", 2048 iterations)
Linking Path = m/138'/0'
Hashing Key  = derivePath(Master, m/138'/0')
Domain Hash  = SHA-256(domain)
Linking Key  = Hashing Key + Domain Hash (mod curve order n)
```

The domain tweak ensures different services get different keys, while the same service always gets the same key (pseudonymous identity).

### Curve Order

```
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
```

## ⚠️ Critical: DER-Encoded Signatures

The LNURL-auth protocol requires **DER-encoded** secp256k1 signatures. This is the most common implementation bug:

```javascript
// ✅ Correct — DER-encoded (~70-72 bytes), @noble/secp256k1
const sig = await secp.sign(k1Bytes, linkingPriv, { der: true });

// ❌ Wrong — compact (64 bytes), works on lenient services only
const sig = await secp.sign(k1Bytes, linkingPriv);
```

Services that enforce DER: Stacker News, Predyx
Services that accept both: (undocumented, varies)

**Always use DER.** Code that works with both formats is correct. Code that only works with compact signatures is broken — you just haven't tested against a strict service yet.

### ⚠️ Library Choice: Use @noble/secp256k1, NOT elliptic

The `elliptic` library has a critical bug for LNURL-auth: it double-hashes the message before signing. This produces invalid signatures that services will reject.

```javascript
// ❌ elliptic double-hashes — invalid for LNURL-auth
const ec = new EC('secp256k1');
const sig = ec.sign(k1Hash, privateKey); // internally hashes again!

// ✅ @noble/secp256k1 signs directly — correct
const sig = await secp.sign(k1Bytes, linkingPriv, { der: true });
```

**Rule:** Use `@noble/secp256k1` for all LNURL-auth signing. The `elliptic` library will silently produce wrong results.

## Service-Specific Notes

### Stacker News ✅
- LNURL endpoint: `https://stacker.news/api/auth/lnurl`
- Standard implementation
- Tested and working

### Predyx ✅
- LNURL endpoint: `GET https://beta.predyx.com/api/auth/lnurl`
- Requires existing session context (HttpOnly cookies)
- Returns LNURL + k1 + QR code URL
- Deposit API behind Cloudflare WAF (POST blocked from some IPs)
- Tested and working (auth), deposit access limited by geo/IP rules

### LNMarkets ⚠️
- LNURL endpoint: `https://lnmarkets.com/api/auth/lnurl`
- Signature validates correctly
- "User not found" if no account exists (key is valid)
- Account registration separate from auth
- US IPs may need proxy for LNURL Auth endpoint (403 geo-block)
- API key auth works from US IPs

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `--lnurl <url>` | LNURL string to authenticate | Required |
| `--key <hex>` | Raw private key (hex) | Uses SEED env |
| `--proxy <url>` | SOCKS5 proxy | None |
| `--verbose` | Show derivation steps | Off |
| `--dry-run` | Show signature without submitting | Off |

## Environment

| Variable | Description |
|----------|-------------|
| `SEED` | BIP39 mnemonic (12 words) |

## Tor/Proxy Example

```bash
SEED="..." node scripts/lnurl-auth.mjs \
  --lnurl "lnurl1dp68gurn8..." \
  --proxy socks5://127.0.0.1:9050
```

## References

- [LUD-05: LNURL-auth](https://github.com/lnurl/luds/blob/luds/05.md)
- [LUD-06: LNURL-withdraw](https://github.com/lnurl/luds/blob/luds/06.md)
- [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
