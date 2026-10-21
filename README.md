# JWT Sentinel

A Burp Suite extension that watches proxied traffic for JSON Web Tokens, raises a passive scan issue when a token looks weak, and adds right-click Repeater helpers that forge tampered variants of a token already in a request. It decodes every JWT it sees as you browse, so you get coverage without feeding tokens to a separate script. The forge helpers stage the two classic attack tokens in Repeater so you can fire them with one click.

## Writeup

No writeup yet.

## Requirements

- Burp Suite with the legacy Extender API (`IBurpExtender`, `IScannerCheck`, `IScanIssue`, `IContextMenuFactory`). The passive checks surface as scan issues through Burp's passive scanner, which means Burp Suite Professional. The Repeater forge helpers run from the context menu and work in any edition.

- A Jython standalone JAR configured under Burp's Python environment. The code targets Jython 2.7 (Python 2.7) and is written to run under both Python 2 and 3.

- No third-party packages. The extension imports only the Python standard library (`base64`, `json`, `re`, `time`) plus the Burp and Java classes it is loaded with.

## Install

1. Download the Jython standalone JAR and point Burp at it: Settings → Extensions → Python environment.

2. Burp Suite → Extensions → Add → Extension type: **Python**, and select `jwt_sentinel.py`.

On load the extension registers under the name `JWT Sentinel` and prints this line to its output:

```
[JWT Sentinel] loaded — passive JWT scanning + Repeater forge helpers active.
```

## Checks

The passive scan runs on every proxied request and response. It extracts each unique, parseable JWT from the combined request and response text, decodes the header and payload, and raises one scan issue per token. The issue is named `JWT weakness (JWT Sentinel)`, its confidence is always `Tentative`, and its severity is the highest severity among that token's findings. The issue detail lists the decoded token and every finding below.

| Finding | What triggers it | Severity |
|---------|------------------|----------|
| `alg:none` | Header `alg` equals `none`. Signature may not be verified. | High |
| `jku` / `x5u` header | Either header key is present. If unvalidated, it can point signing at an attacker-hosted key set. | High |
| Token past `exp` | Payload has an `exp` claim whose value is earlier than the current system time, yet the token is still in traffic. | Medium |
| Sensitive-looking claim | Any claim key (searched recursively) contains one of: `password`, `pwd`, `secret`, `ssn`, `credit`, `card`, `api_key`, `apikey`, `private`, `pin`. Payloads are base64, not encrypted. | Medium |
| `kid` header | Header `kid` is present. Flags it as a spot to test for path traversal, SQLi, or command injection in key selection. | Low |
| No `exp` claim | Payload has no `exp`. Token may never expire. | Low |
| HMAC algorithm | Header `alg` starts with `hs` (HS256/384/512). Candidate for offline secret cracking, and for algorithm confusion if the server also accepts RS. | Information |
| Asymmetric algorithm | Header `alg` starts with `rs` or `es`. Candidate for RS→HS confusion using the server's public key as the HMAC secret. | Information |

Duplicate issues are consolidated: a new issue with the same detail as an existing one is treated as a duplicate.

## Repeater helpers

Right-click a request that contains a JWT (Proxy history, Repeater, anywhere Burp offers the context menu). The extension reads the request of the first selected message, finds the first JWT in it, and adds two items. Each one rebuilds that token, keeps the original payload segment unchanged, and sends the whole request to a new Repeater tab with the forged token swapped in for the first occurrence.

- **JWT Sentinel: forge alg:none → Repeater** rebuilds the header as `{"alg":"none","typ":"JWT"}` and sets the signature segment to empty. Tab name: `JWT alg:none`.

- **JWT Sentinel: stage RS→HS confusion → Repeater** rebuilds the header as `{"alg":"HS256","typ":"JWT"}` and sets the signature segment to the literal placeholder `SIGN_WITH_PUBKEY_HMAC`. You replace that placeholder with an HMAC-SHA256 of `header.payload` computed using the server's public key as the secret. The extension does not fetch the key or compute the signature. Tab name: `JWT RS->HS shell`.

Both helpers drop any original header fields (such as `kid` or `jku`); the forged header is rebuilt from scratch with only `alg` and `typ`.

## Limits and known gaps

- Passive issues need Burp's scanner, so they appear in Professional only. In Community edition the Repeater forge helpers still work, but no scan issues are raised.

- Detection is regex-based on the token's text in the request and response bytes. A token is found only if it is the standard three-segment base64url form whose header begins with `eyJ`. Encrypted tokens (JWE), tokens split across fields, and tokens that are not present as plaintext are not detected.

- The sensitive-claim check is a substring match on claim key names, so names like `cardholder` (contains `card`) or `pinCode` (contains `pin`) can false positive.

- The `exp` check compares against the local system clock; skew affects the verdict. `nbf` and `iat` are not checked.

- The RS→HS helper only stages the token. It does not sign it.

- The forge helpers act on the request only, on the first JWT only, and replace only the first occurrence of that token string.

- There is no active-scan insertion; the active scan hook returns nothing.

## Authorized use only

Run this only against systems you have written permission to test.

## Development

The extension is a single file, `jwt_sentinel.py`, with no build step and no dependencies beyond the Jython standard library and Burp's API.

## License

MIT. See the [LICENSE](LICENSE) file.

More projects: [michaelhixon.com/making](https://michaelhixon.com/making/)
