# JWT Sentinel

**A Burp Suite extension for real-time JWT weakness detection and one-click token forging.**

`jwt-sentinel` rides the Burp proxy stream and, on every request/response carrying a JWT:

- decodes the header and claims,
- raises a Burp scan issue for weak algorithms (`alg:none`, HS-where-RS-expected), expired-but-still-in-use tokens, injectable key-selection headers (`jku` / `x5u` / `kid`), and sensitive data sitting in the (unencrypted) payload,
- adds a right-click menu to forge attack variants — `alg:none` and an RS256→HS256 confusion shell — straight into Repeater.

## Why an extension, not a script

A script only sees traffic you hand it. This sees **every** JWT as you browse, with zero extra effort, and pushes one-click tampered tokens into Repeater. The real-time, integrated visibility is the whole reason to build inside Burp.

## Install

Burp Suite → Extensions → Add → Extension type: **Python** (requires the Jython standalone JAR configured under Settings → Extensions → Python environment). Jython is Python 2.7, so the extension is written 2/3-compatible.

## What it flags

| Check | Severity |
|-------|----------|
| `alg:none` — signature may not be verified (forgeable token) | High |
| `jku` / `x5u` header — key injection if unvalidated | High |
| Token past `exp` still in traffic | Medium |
| Sensitive claim in payload (payloads are base64, **not** encrypted) | Medium |
| `kid` header — path-traversal / SQLi / command-injection in key selection | Low |
| HMAC in use — offline secret cracking + RS→HS confusion candidate | Information |

## Forge helpers (right-click → Repeater)

- **alg:none** — swaps the header to `{"alg":"none"}` and blanks the signature.
- **RS→HS confusion shell** — stages an HS256 token; you supply the server's public key as the HMAC secret (the extension can't fetch the key for you).

> **Authorized use only** — run only against systems you have written permission to test.

## License

MIT © 2026 Michael Hixon
