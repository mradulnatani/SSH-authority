# SSH-Authority — Introductory background

This project implements a secure, policy-driven SSH Certificate Authority (CA) for issuing short-lived SSH certificates to control access across distributed infrastructure. Before diving into the implementation and usage, this document explains foundational concepts you should understand:

- A concise overview of the SSH protocol
- How chain of trust works for SSH certificates
- What OpenSSH certificates are (fields, types, constraints)
- Recommended certificate generation and signing workflows, including the usual OpenSSH approach and how OpenSSL can participate (with caveats)

---

## 1. SSH protocol — quick overview

SSH (Secure Shell) is a network protocol for secure remote login and other secure network services over an insecure network. Key points:

- SSH provides confidentiality and integrity using public-key cryptography and symmetric encryption negotiated per-connection.
- Clients authenticate to servers using:
  - Passwords (legacy, less desirable)
  - Public-key authentication — the client proves ownership of a private key corresponding to a public key listed (or approved) on the server
  - SSH certificates — a signed public key asserting one or more principals (usernames or hostnames) and metadata (validity etc.)
- The server and client exchange cryptographic keys, then derive session keys for encryption and MACs.
- SSH supports two common certificate use-cases:
  - Host certificates — used by servers to prove their identity to clients
  - User certificates — used by clients to authenticate to servers

SSH certificates allow central, auditable, and short-lived credentials rather than distributing long-lived public keys into many servers' authorized_keys files.

---

## 2. Chain of trust in SSH

The SSH certificate model is much simpler than X.509 but shares the same trust principles:

- A CA (Certificate Authority) holds a private signing key (the CA private key).
- The CA's public key is distributed to the verifying party (typically placed in `TrustedUserCAKeys` or `TrustedHostCAKeys` on SSH servers).
- When a certificate (an SSH public key with CA signature and metadata) is presented, the server verifies the signature using the CA public key it trusts.
- If the signature is valid and certificate metadata (principals, validity window, critical options, and extensions) satisfies local policy, authentication is granted.

Important properties:

- The "chain" is shallow: a certificate is directly signed by a single CA public key trusted by the verifier. OpenSSH does not use multi-level certificate chains in the same sense as PKI X.509 intermediate CAs.
- Trust is established by configuring servers with the CA public key(s). A server trusts any certificate signed by the CA.
- Revocation is not built into OpenSSH certificates (no standard CRL). Revocation patterns:
  - Use very short certificate lifetimes (recommended).
  - Rotate the CA key if needed (heavy-handed).
  - Server-side allowlists (e.g., authorized principals files or external policy) that are checked at login time.
  - External authorization systems (like this project) that validate and supply short-lived certificates according to policy.

---

## 3. OpenSSH certificates — structure and fields

OpenSSH certificates (the format produced and consumed by `ssh-keygen` and modern `sshd`) wrap a public key and metadata signed by a CA key. High-level structure and notable fields:

- Type
  - `ssh-user-cert` — for user authentication
  - `ssh-host-cert` — for host authentication (signed with `-h`)
- Key (the public key being certified)
- Serial number — arbitrary 64-bit integer chosen by signer
- Key ID (`-I`) — a human-readable identifier (recommended to be unique)
- Principals (`-n`) — list of allowed usernames (for user certs) or hostnames (for host certs)
- Validity (`-V`) — "valid after" and "valid before" timestamps (or intervals)
- Critical options — options that must be enforced by the server; examples:
  - `source-address` — restrict which source IPs may use the cert
  - `force-command` — force a command to run (mainly for automation)
- Extensions — server-side features allowed; common extensions:
  - `permit-pty`, `permit-port-forwarding` etc.
- Signature — the CA's signature over the above fields

Behavioral notes:

- When `sshd` is configured with `TrustedUserCAKeys /etc/ssh/ca_pubkey` any user certificate signed by that CA and otherwise acceptable will be treated as a valid authentication method.
- Use of `AuthorizedPrincipalsFile` or `AuthorizedPrincipalsCommand` can control which principals on a server are allowed, giving extra fine-grained control.

---

## 4. Recommended certificate generation & signing (OpenSSH canonical flow)

OpenSSH provides native tooling for SSH certificate creation and signing. This is the straightforward, recommended approach.

1. Create a CA key (private and public)
```bash
# CA private key (protected, stored securely)
ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_ca -C "org-ca@example.com" -N "" 

# CA public key (distribute this to servers, e.g., TrustedUserCAKeys)
cat /etc/ssh/ssh_ca.pub
```

2. Generate a user's key pair (on the user machine)
```bash
ssh-keygen -t rsa -b 3072 -f ~/.ssh/id_rsa_user -C "alice@example.com"
# This creates ~/.ssh/id_rsa_user and ~/.ssh/id_rsa_user.pub
```

3. Sign the user's public key with the CA
```bash
# run as the CA operator (not on the user's machine)
ssh-keygen -s /etc/ssh/ssh_ca \
    -I "alice-2025-12-23" \        # key id
    -n "alice" \                   # principal(s)
    -V +24h \                      # validity: 24 hours from now
    -z 42 \                        # serial (optional)
    /path/to/alice/id_rsa_user.pub
```

4. Result: ssh certificate file
- The signing step produces `id_rsa_user-cert.pub`. The user stores this alongside their private key and the SSH client automatically uses the certificate when authenticating.

5. Server configuration (example `/etc/ssh/sshd_config`)
```text
TrustedUserCAKeys /etc/ssh/ca_pubkey
# Optionally use an AuthorizedPrincipalsCommand to map cert principals to local accounts
```

6. Inspect a certificate
```bash
ssh-keygen -L -f id_rsa_user-cert.pub
```

Why use short lifetimes?
- Because OpenSSH certificates do not use a revocation list, short lifetimes (minutes/hours) limit the impact of a compromised key.

---

## 5. Using OpenSSL in the workflow — caveats and recommended uses

OpenSSH certificates use a specific internal format (not X.509). The recommended toolset for generating SSH certificates is OpenSSH's `ssh-keygen`. OpenSSL is designed for X.509 certificates and PKCS formats, so it is not a drop-in tool for creating OpenSSH certificates. However, OpenSSL is still useful for:

- Generating raw RSA/ECDSA key material if you prefer OpenSSL tooling.
- Managing an X.509-based PKI in parallel (if you also need TLS certificates).
- Creating keys in PEM format that can be converted for use with ssh tools.

Important caveats:
- You cannot use OpenSSL alone to create OpenSSH certificates readable by `sshd`. The final signing step must be performed by `ssh-keygen` or equivalent OpenSSH-compatible signer.
- If you generate keys with OpenSSL, you must convert or export them into a format `ssh-keygen` understands before signing or using them as SSH keys.

Example: generate a private key with OpenSSL, produce an OpenSSH public key, and sign it with OpenSSH CA

1. Generate an RSA private key with OpenSSL
```bash
openssl genpkey -algorithm RSA -out id_rsa.pem -pkeyopt rsa_keygen_bits:3072
```

2. Extract the public key and convert to OpenSSH public-key format
- Many versions of `ssh-keygen` can read PEM private keys directly and emit the OpenSSH public key:
```bash
ssh-keygen -y -f id_rsa.pem > id_rsa.pub
```
- If `ssh-keygen -y` fails to parse the private key, convert it to an OpenSSH-compatible or PKCS8 PEM first:
```bash
# Convert to PKCS8 (if needed)
openssl pkcs8 -topk8 -inform PEM -outform PEM -in id_rsa.pem -nocrypt -out id_rsa_pk8.pem
ssh-keygen -y -f id_rsa_pk8.pem > id_rsa.pub
```

3. Prepare a CA private key for `ssh-keygen` signing
- Best practice: create the CA private key using `ssh-keygen` directly. If you already have a CA private key in PEM produced by OpenSSL, convert it into an OpenSSH private key format so `ssh-keygen -s` can use it. Some versions of `ssh-keygen` accept PEM private keys directly for signing; others require OpenSSH private key format.
- Example preferred CA creation:
```bash
ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_ca -N ""
```

4. Sign with `ssh-keygen`
```bash
ssh-keygen -s /etc/ssh/ssh_ca -I "user-cert" -n "alice" -V +8h id_rsa.pub
# Produces id_rsa-cert.pub
```

Summary:
- Use OpenSSL for key generation if you must, but convert keys to OpenSSH-compatible forms and perform certificate signing with `ssh-keygen`.
- For most SSH CA workflows you will only need `ssh-keygen` (recommended).

---

## 6. Quick example: full flow (recommended)

1. Create CA (on secure machine)
```bash
ssh-keygen -t ed25519 -f /etc/ssh/ca_ed25519 -C "example-org CA" -N ""
# Keep /etc/ssh/ca_ed25519 private and secure. Distribute /etc/ssh/ca_ed25519.pub
```

2. Configure servers to trust the CA
- Copy `/etc/ssh/ca_ed25519.pub` to servers and configure `/etc/ssh/sshd_config`:
```text
TrustedUserCAKeys /etc/ssh/ca_ed25519.pub
```
- Restart or reload sshd.

3. User key generation (client)
```bash
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -C "alice@example.com"
```

4. Sign user's public key (CA operator)
```bash
ssh-keygen -s /etc/ssh/ca_ed25519 -I "alice@laptop-2025-12-23" -n alice -V +4h ~/.ssh/id_ed25519.pub
# gives id_ed25519-cert.pub
```

5. User places `id_ed25519-cert.pub` next to their private key and connects:
```bash
ssh -i ~/.ssh/id_ed25519 alice@server.example.com
```

---

If helpful, next sections will cover:
- How `sshd` enforces certificate fields (examples of `sshd_config` knobs)
- Common signing policies and metadata (serial schemes, key IDs, principals)
- Integration patterns: distributing CA public keys with Consul/Confd, dynamically issuing certs on login, and audit/logging of issuance (relevant to this project)
- Secure storage and rotation of the CA private key (HSMs, offline signing workflows)

If you'd like, I can now produce:
- A more detailed step-by-step "operator's guide" for creating and rotating a CA
- Example scripts to sign certificates automatically in response to API requests (aligned with this project's architecture)
- A shorter "cheat sheet" of `ssh-keygen` commands and `sshd_config` snippets

```
