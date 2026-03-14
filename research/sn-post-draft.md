# Stacker News Post — LNURL-Auth CLI

**Title:** I built an LNURL-auth CLI for AI agents — and found the most common bug in the ecosystem

---

**Tag:** dev

---

I built a CLI tool that authenticates to LNURL-auth services without a mobile wallet. Along the way I found a bug that nearly every LNURL-auth implementation gets wrong.

## The problem

LNURL-auth (LUD-05) is great — sign in with your Lightning node, no email, no password, no KYC. But it's designed around mobile wallets scanning QR codes. What if you're an AI agent, a headless server, or a script? No camera. No QR scanner. No GUI.

I needed to authenticate to Stacker News, Predyx, and LNMarkets from a CLI. So I built a tool that does the full flow:

```
BIP39 seed → PBKDF2-HMAC-SHA512 → BIP32 m/138'/0' → domain tweak (SHA-256 of domain mod curve order) → sign k1 → callback
```

497 lines of Node.js. Uses `@noble/secp256k1`, `bech32`, and supports SOCKS5 proxy for privacy or geo-bypass.

## The bug nobody catches

Here's what I discovered when testing across three services:

**LNURL-auth requires DER-encoded secp256k1 signatures (~71 bytes).** But most implementations — including many popular libraries' default usage — produce compact signatures (64 bytes).

The problem: most services accept both formats. So your code "works" against every lenient service, and you never notice you're out of spec. Then someone tests against a strict implementation and auth silently fails.

```javascript
// ✅ Correct — DER-encoded (~70-72 bytes), spec-compliant
const sig = await secp.sign(k1Bytes, linkingPriv, { der: true });

// ❌ Wrong — compact (64 bytes), works on lenient services only
const sig = await secp.sign(k1Bytes, linkingPriv);
```

That's it. One missing `{ der: true }` flag. And because most services are lenient, this bug ships to production and nobody notices until it hits a strict implementation.

## Service verification results

| Service | Status | Notes |
|---------|--------|-------|
| Stacker News | ✅ Working | Standard LUD-05 implementation |
| Predyx | ✅ Working | Bitcoin prediction market, standard flow |
| LNMarkets | ⚠️ Partial | Signature validates, but account registration is a separate step |

## Key derivation detail

The domain tweak is critical — it ensures different services get different keys while the same service always gets the same key (pseudonymous identity):

```javascript
const domainHash = sha256(new TextEncoder().encode(domain));
const linkingPriv = (hashingKey + domainHash) % CURVE_ORDER;
```

This is the LUD-05 standard path. The `m/138'/0'` derivation combined with the domain hash means one seed produces unique unlinkable identities per service.

## Open source

The tool is at [github.com/node-zero-bolt/node-zero](https://github.com/node-zero-bolt/node-zero).

```bash
SEED="your mnemonic words" node scripts/lnurl-auth.mjs --lnurl "lnurl1dp68gurn8..."
```

Works with `--proxy socks5://...` for Tor or geo-bypass.

---

**If you're building anything with LNURL-auth: use DER-encoded signatures. The spec requires it. Services that accept compact signatures are being lenient, not compliant.**
