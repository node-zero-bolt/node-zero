# Nostr Note — LNURL-Auth CLI

---

Built an LNURL-auth CLI that works without a mobile wallet. Found the most common bug in the ecosystem while doing it.

**The bug:** LUD-05 requires DER-encoded secp256k1 signatures (~71 bytes). Most implementations silently produce compact signatures (64 bytes). Most services accept both, so the bug ships undetected.

```javascript
// ✅ Correct
const sig = await secp.sign(k1Bytes, linkingPriv, { der: true });

// ❌ Broken (works on lenient services, fails on strict ones)
const sig = await secp.sign(k1Bytes, linkingPriv);
```

One missing flag. Because services are lenient, nobody notices until it hits a strict implementation.

**What the tool does:**
BIP39 seed → PBKDF2 → BIP32 m/138'/0' → domain tweak (SHA-256(domain) mod n) → DER sign k1 → callback. Full LUD-05 flow from CLI. No QR codes, no mobile wallet.

**Verified:**
✅ Stacker News
✅ Predyx
⚠️ LNMarkets (validates sig, account registration separate)

**Tool:** 497-line Node.js script. @noble/secp256k1, bech32, SOCKS5 proxy support.

Open source: https://github.com/node-zero-bolt/node-zero

If you're implementing LNURL-auth: always use `{ der: true }`. The spec requires DER. Services accepting compact are being lenient, not compliant.

#lnurl #lightning #bitcoin #dev
