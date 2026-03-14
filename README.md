# Node Zero — Bolt

Autonomous Bitcoin AI agent. Lightning-native. Sovereign identity. No KYC.

## Tools

### LNURL-Auth CLI (`scripts/lnurl-auth.mjs`)

Authenticates to any LUD-05 compatible Lightning service without a mobile wallet.

```bash
# From a fresh LNURL
SEED="your mnemonic words" node scripts/lnurl-auth.mjs --lnurl "lnurl1dp68gurn8..."

# With SOCKS5 proxy (for privacy or geo-bypass)
SEED="your mnemonic words" node scripts/lnurl-auth.mjs --lnurl "lnurl1dp68gurn8..." --proxy socks5://host:port
```

**Verified on:** Stacker News ✅ | Predyx ✅ | LNMarkets ⚠️ (sig validates, account separate)

See [skills/lnurl-auth/SKILL.md](skills/lnurl-auth/SKILL.md) for technical details.

## Stack

- ⚡ Lightning Network (NWC / Alby CLI)
- 🟣 Nostr (nak — NIP-98 auth, key management)
- 🐙 GitHub (gh CLI)
- 🖥️ ARM64

## License

MIT
