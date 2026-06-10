# AttentionMarket Gateway

A **Cloudflare Email Worker** — the entire gateway is a single edge function.
No server, no process to run, no SMTP port to expose.

## How it works

Cloudflare Email Routing receives emails at your gateway domain (`attention.email`)
and triggers this Worker. Every registered seller gets a unique address like
`alice@attention.email`, resolved from the on-chain Registry at routing time.

Reply routing uses a `reply.attention.email` subdomain with a catch-all rule.
The seller never sees the winner's real address, and the winner never sees the seller's.

---

### Inbound (winner → seller)

```
winner@example.com  →  alice@attention.email
Subject: Hey Alice! [attn:BASE64SIG]
```

Worker checks:

1. `[attn:SIG]` present in subject
2. Resolves `alice` → vaultId via on-chain Registry
3. Fetches vault fields from Sui RPC
4. Computes `paymentId = sha256(sha256(from) + vaultId)`
5. Looks up `SlotWon` event — confirms winning bid exists for this paymentId
6. `sha256(from)` matches on-chain `sender_email_hash`
7. Ed25519 signature valid — signer matches on-chain `bidder` address
8. Thread not closed on-chain (`vault.closed_threads[paymentId]`)
9. Rate limit: max 1 email per hour (per winner per vault)
10. Decrypts seller's real email from on-chain encrypted blob
11. Forwards to seller. Sets `Reply-To: <paymentId>@reply.attention.email`

---

### Outbound (seller → winner)

Seller hits **Reply** in their mail client. Their client automatically addresses
the email to the `Reply-To` set in step 11 above.

```
seller@example.com  →  <paymentId>@reply.attention.email
Subject: Re: Hey Alice! [attn:BASE64SIG]
In-Reply-To: <original-message-id>
```

Worker checks:

1. `In-Reply-To` or `References` header present → outbound flow
2. Extracts `paymentId` from `To:` local-part
3. Looks up winner address + vaultId from KV (written during inbound)
4. Decrypts vault's stored seller email — confirms `From:` matches (anti-spoof)
5. Thread not closed on-chain
6. `SlotWon` record still exists on-chain
7. Rate limit: max 1 reply per hour (per seller per winner)
8. Forwards to winner from `alice@attention.email`

**Emails failing any check are rejected with an SMTP error. No silent drops.**

---

## Setup

### 1. Install Wrangler

```bash
npm install
npx wrangler login
```

### 2. Create KV namespace

```bash
npx wrangler kv namespace create ALIASES
```

Copy the returned `id` into `wrangler.toml`:

```toml
[[kv_namespaces]]
binding = "ALIASES"
id = "your-namespace-id-here"
```

### 3. Set secrets

```bash
wrangler secret put PRIVATE_KEY       # Base64-encoded P-256 private key for email decryption
wrangler secret put REGISTRY_ID       # Sui object ID of the shared Registry
wrangler secret put PACKAGE_ID        # Deployed Move package ID
wrangler secret put SUI_RPC_URL       # https://fullnode.testnet.sui.io:443
```

### 4. Configure Cloudflare Email Routing

In your Cloudflare dashboard under **Email → Email Routing → Routing Rules**:

- **Main domain** (`attention.email`): catch-all → Send to Worker → `attentionmarket-gateway`
- **Reply subdomain** (`reply.attention.email`): catch-all → Send to Worker → `attentionmarket-gateway`

The catch-all on the reply subdomain is important — it prevents mail clients
(e.g. ProtonMail) from warning that the reply address doesn't exist.

### 5. Deploy

```bash
npm run deploy
```

### 6. Test inbound

Send an email to a gateway address **without** an `[attn:]` tag — it should be rejected.

Then win a slot on the marketplace, generate your `[attn:SIG]`, and send:

```
To: alice@attention.email
Subject: Hello! [attn:YOUR_SIGNATURE_HERE]
```

---

## Closing a conversation

Call `close_conversation(vaultId, paymentId)` on the smart contract.
The gateway checks `vault.closed_threads[paymentId]` on every email
and rejects anything from that thread in both directions.

---

## Environment variables

| Secret | Description |
|--------|-------------|
| `PRIVATE_KEY` | Base64-encoded P-256 private key (32 bytes) for decrypting seller emails stored on-chain. |
| `REGISTRY_ID` | Sui object ID of the shared Registry mapping gateway addresses to vaults. |
| `PACKAGE_ID` | Deployed Move package ID for querying `SlotWon` events. |
| `SUI_RPC_URL` | Sui fullnode RPC endpoint. |

| Var (non-secret) | Description |
|-----------------|-------------|
| `SUI_NETWORK` | `testnet`, `mainnet`, or `devnet`. Default: `testnet`. |
| `GATEWAY_DOMAIN` | Primary gateway domain. Default: `attention.email`. |
| `REPLY_SUBDOMAIN` | Reply routing subdomain. Default: `reply.<GATEWAY_DOMAIN>`. |

| Binding | Description |
|---------|-------------|
| `ALIASES` | KV namespace. Stores winner routing records and rate limit keys. |
| `EMAIL` | Send Email binding for outbound delivery. |