# mesh-sidecar

A small mTLS sidecar proxy in Rust, with a built-in CA. Learning project,
**not production-ready**.

## What it does
(3-4 sentences: inbound/outbound sidecars, SPIFFE identity in certs,
policy file, CA with single-use tokens and 4h certs.)

## Threat model

### Defends against
- Eavesdropping or tampering on the link between sidecars (TLS).
- A caller with no cert, or a cert from another CA (rejected in handshake).
- A genuine mesh identity calling a service it isn't allowed to (policy).
- Connecting to an imposter instead of the intended service (outbound
  checks the peer's SPIFFE ID).
- Requesting a cert for an identity you weren't given a token for.
- Reusing a spent enrollment token.

### Does NOT defend against
- Theft of `ca.key` (anyone holding it can mint any identity).
- A compromised host: it can read its own private key.
- A token stolen before it's used.
- CA restart: the used-token list lives in memory, so tokens revive.
- Anyone who can reach the CA port: it's plain text, bound to localhost only.
- Denial of service, and no revocation (certs simply expire in 4h).
- Policy changes without restart (policy is read at startup).

## Known limitations / roadmap
(rotation, mTLS-authenticated renewal, persisted token state, L7 rules)