# mesh-sidecar

A lightweight mTLS service-mesh sidecar and built-in certificate authority, written in Rust.

> **Status: learning project, not production-ready.**
> mesh-sidecar is a working skeleton of the core ideas behind a service mesh such as Istio or Linkerd. Every essential mechanism exists and is tested, but it lacks the hardening, revocation and operational tooling a production system requires. Do not use it to protect real traffic. See [Threat model](#threat-model) and [Known limitations](#known-limitations).

## Overview

mesh-sidecar places a small proxy next to each service. The services keep speaking plain text on the local machine and need no security code. The proxies speak mutual TLS (mTLS) to each other, so every connection between services is encrypted and both ends are authenticated.

The easiest way to picture it is customs at a border. Each service has a checkpoint at its door:

- The **outbound** checkpoint opens a secure tunnel and confirms it has reached the intended destination.
- The **inbound** checkpoint inspects the caller's passport (a certificate) and checks it against the guest list (the policy) before letting a single byte through.

The service behind the checkpoint only ever sees requests that passed both checks.

## How it works

```
client (plain) ──► outbound :9000 ══(mTLS)══► inbound :9443 ──► backend :9001
                   cert: orders               cert: payments

enrollment (once):   sidecar ──(token + CSR)──────► CA :9100 ──► short-lived cert
renewal (periodic):  sidecar ══(mTLS, current cert + fresh CSR)══► CA :9101 ──► new cert
```

Every connection passes through two independent layers:

| Layer | Question | Mechanism |
|---|---|---|
| 1. Authentication | Who are you? | mTLS handshake. Each side verifies the other's certificate against the trusted CA and proof of private-key ownership. |
| 2. Authorization | Are you allowed to do this? | The caller's SPIFFE identity is read from the verified certificate and checked against an allow-list (`policy.toml`). |

If either layer fails, the connection is closed and no payload is ever read. Identity is never derived from request contents or IP addresses, only from the certificate.

### Components

| Binary | Role |
|---|---|
| `outbound` | Accepts plain-text connections locally, opens an mTLS connection to the peer, and verifies the peer's SPIFFE identity matches the one it intends to reach. |
| `inbound` | Terminates mTLS, reads the caller's SPIFFE identity from the certificate, enforces the policy, and forwards permitted traffic to the backend. Fails closed. |
| `ca` | A small certificate authority with two listeners: `:9100` redeems single-use enrollment tokens, and `:9101` (mTLS) renews certificates for sidecars that already hold a valid one. |
| `backend` | A demo echo service used for testing. |

### Certificate lifecycle

1. **Enrollment.** At startup a sidecar generates a key pair in memory and sends the CA its single-use token and a certificate signing request (CSR). The CA issues a certificate for the identity bound to the token.
2. **Renewal.** A background task in each sidecar renews at two-thirds of the certificate's actual lifetime. Renewal authenticates with the *current certificate* over mTLS, so no secret is sent again. The sidecar generates a fresh key each time, and the CA refuses a CSR that reuses the current key.
3. **Hot swap.** Certificates are held in a shared store that rustls consults at every new handshake. A swap affects only new connections; connections already open continue undisturbed.
4. **Failure behavior.** If renewal fails, the sidecar logs the error, retries with exponential backoff (1s up to 30s) and keeps serving with its old certificate. Once that certificate expires, it fails closed.

The certificate lifetime defaults to 4 hours and can be changed with the `MESH_CERT_TTL_SECS` environment variable (for example, set it to `30` to watch rotation happen in real time).

### Design decisions

- **No custom cryptography.** All TLS and certificate handling is done by `rustls` and `rcgen`. This project contains the proxy, identity and policy logic only.
- **Identity in the certificate.** Services are named by a SPIFFE URI in the certificate's Subject Alternative Name (for example `spiffe://mesh/orders`), not by IP address.
- **Private keys never leave the sidecar.** Each sidecar generates its key in memory and sends the CA only a CSR.
- **The CA ignores what the CSR claims.** The issued identity comes solely from the redeemed token (enrollment) or the verified certificate (renewal). The CSR contributes only its public key.
- **Short-lived certificates.** Limiting lifetime limits the window in which a stolen certificate is useful.
- **TLS session resumption is disabled.** Resumed TLS 1.3 sessions skip certificate checks, which let expired certificates keep working. This was found while testing rotation, and resumption is now off on the inbound, outbound and CA renewal listeners.
- **Fail closed.** A missing or malformed policy file, missing certificate, or unknown identity results in denial, never in open access.

## Getting started

### Prerequisites

- Linux (developed on Pop!_OS)
- Rust (stable) and Cargo
- `openssl` and `nc` (netcat)
- A C toolchain and CMake (`sudo apt install build-essential cmake`)

### 1. Create the CA

```bash
mkdir certs && cd certs
openssl genpkey -algorithm ED25519 -out ca.key
openssl req -x509 -new -key ca.key -days 365 -subj "/CN=mesh-ca" -out ca.crt
cd ..
```

`certs/` is git-ignored. Never commit `ca.key`.

### 2. Define the policy

Create `policy.toml` in the project root:

```toml
# Services allowed to call this one. Anything not listed is denied.
allow = ["spiffe://mesh/orders"]
```

### 3. Run the stack

```bash
chmod +x dev.sh
./dev.sh
```

`dev.sh` generates fresh single-use enrollment tokens (overwriting the git-ignored `tokens.toml`), starts the CA, the backend and both sidecars, and stops everything on Ctrl+C.

To watch rotation, use short-lived certificates:

```bash
MESH_CERT_TTL_SECS=30 ./dev.sh
```

### 4. Try it

```bash
nc 127.0.0.1 9000
hello
```

The message is echoed back, and the `inbound` log shows `ALLOWED: spiffe://mesh/orders`.

### Run the tests

```bash
cargo test            # unit tests
./scripts/attack.sh   # end-to-end attack suite
```

## Attack tests

`scripts/attack.sh` starts the stack and checks that each attack fails and each legitimate path succeeds. The two control cases must pass, so an attack cannot "pass" merely because the stack is down.

| Case | Expected result |
|---|---|
| Legitimate call through outbound (control) | Succeeds |
| No client certificate | Refused in the TLS handshake |
| Certificate from a rogue CA | Refused in the TLS handshake |
| Valid certificate, not on the allow-list | Denied by policy |
| Reused enrollment token | `ERR invalid token` |
| CSR claiming a different identity than its token | Certificate carries the token's identity only |
| Valid renewal (control) | Renewed for the same identity |
| Renewal with a rogue-CA certificate | `UnknownCA` |
| Renewal with an expired certificate | `CertificateExpired` |

## Threat model

### What it defends against

- Eavesdropping on or tampering with traffic between sidecars (TLS confidentiality and integrity).
- Callers with no certificate, or with a certificate signed by an untrusted CA.
- A genuine mesh identity calling a service it is not permitted to call (policy).
- Sending traffic to an imposter instead of the intended service (outbound verifies the peer's SPIFFE ID).
- Obtaining a certificate for an identity other than the one a token or current certificate is bound to.
- Replaying a spent enrollment token.
- Using an expired certificate, either to connect or to obtain a renewal.

### What it does not defend against

- **Theft of `ca.key`.** Anyone holding it can mint any identity. Production systems keep this key in an HSM or KMS, or use an offline root with an intermediate CA.
- **A compromised host.** An attacker on the machine can use that service's key and certificate.
- **A stolen certificate being kept alive.** Any valid certificate can be renewed indefinitely. With no revocation, a thief who holds a key and keeps renewing keeps the identity.
- **A leaked token used before its owner redeems it.**
- **CA restarts.** Used-token state is held in memory, so spent tokens become valid again.
- **Network exposure of the CA.** Enrollment on `:9100` is plain text, so the CA is intended for localhost only.
- **Denial of service.** Only basic request size and timeout limits exist.
- **Policy changes at runtime.** The policy is read once at startup.

## Known limitations

- CA private key stored as a file.
- Enrollment tokens are tracked in memory only.
- Enrollment traffic is unencrypted (localhost only).
- No revocation: certificates cannot be killed before they expire, and a valid certificate can be renewed forever.
- The CA's own TLS certificate for the renewal port lives in memory for 30 days, so the CA must be restarted within that period.
- TCP (L4) only. No HTTP or gRPC awareness, so no path- or method-based rules.
- No transparent traffic interception. Services are pointed at the sidecar's port explicitly.
- No metrics, health checks or graceful shutdown.
- No independent security review or fuzzing.

## Roadmap

1. Persist token state in the CA.
2. Revocation or a bound on total renewal lifetime.
3. TLS on the enrollment port.
4. L7 awareness: HTTP/gRPC path and method rules, and basic metrics.
5. Transparent interception with `iptables`.

## Project layout

```
src/
  lib.rs          shared helpers: certificate loading, SPIFFE ID parsing,
                  enrollment, renewal, certificate store and renewal loop
  bin/
    ca.rs         certificate authority (enrollment :9100, renewal :9101)
    inbound.rs    receiving sidecar (mTLS server + policy)
    outbound.rs   sending sidecar (mTLS client + peer identity check)
    backend.rs    demo echo service
scripts/
  attack.sh       end-to-end attack suite
dev.sh            starts the full stack with fresh tokens
policy.toml       allow-list for the inbound sidecar
```

## Acknowledgements

Design influenced by Linkerd's `linkerd2-proxy`, Istio's `ztunnel`, and the SPIFFE specification. For real workloads, use one of those.