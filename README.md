# AttentionMarket Gateway

A **Cloudflare Email Worker** — the entire gateway is a single edge function.
No server, no process to run, no SMTP port to expose.

## How it works

Cloudflare Email Routing receives emails at your gateway address
(e.g. `alice@attentionmarket.xyz`) and triggers this Worker.

### Inbound (winner → seller)

```
winner@example.com  →  alice@attentionmarket.xyz
Subject: Hey Alice! [attn:BASE64SIG]
```

Worker checks:
1. `[attn:SIG]` present in subject
2. Fetches vault from Sui RPC
3. `sha256(from)` matches on-chain `sender_email_hash` from `SlotWon` event
4. Thread not closed (`vault.closed_threads[payment_id]`)
5. Ed25519 signature valid — signer is the on-chain `bidder` address
6. Forwards to `SELLER_REAL_EMAIL` (env secret, never on-chain), stripping `[attn:]`

### Outbound (seller replies)

```
real_inbox@gmail.com  →  alice@attentionmarket.xyz
Subject: Re: your question [reply-to:winner@example.com]
```

Worker checks:
1. `From:` matches `SELLER_REAL_EMAIL` exactly
2. `[reply-to:email]` present in subject
3. Thread not closed on Sui
4. Forwards to winner's address, stripping `[reply-to:]`

**Emails without the correct tag are silently dropped.** No bounce, no error.

---

## Setup

### 1. Install Wrangler

```bash
npm install
npx wrangler login
```

### 2. Set secrets

```bash
wrangler secret put SELLER_REAL_EMAIL      # your real inbox — never on-chain
wrangler secret put SELLER_GATEWAY_EMAIL   # public MX address e.g. alice@attentionmarket.xyz
wrangler secret put VAULT_ID               # AttentionVault object ID from deploy
wrangler secret put PACKAGE_ID             # Move package ID from deploy
wrangler secret put SUI_RPC_URL            # https://fullnode.testnet.sui.io:443
```

### 3. Configure Cloudflare Email Routing

In your Cloudflare dashboard:
- **Email → Email Routing → Routing Rules**
- Add rule: emails to `alice@yourdomain.com` → **Send to Worker** → `attentionmarket-gateway`

### 4. Deploy

```bash
npm run deploy
```

### 5. Test inbound

Send an email to your gateway address **without** an `[attn:]` tag.
It should be silently rejected.

Then win a slot on the marketplace, get your `[attn:SIG]`, and send:
```
To: alice@attentionmarket.xyz
Subject: Hello! [attn:YOUR_SIGNATURE_HERE]
```

---

## Seller reply workflow

To reply to a winner without revealing your real email:

1. Reply from your real inbox **to the gateway address** (not directly to the winner)
2. Put the winner's address in the subject: `Re: their message [reply-to:winner@example.com]`
3. The gateway forwards it — the winner sees it came from the gateway address

---

## Closing a conversation

Call `close_conversation(vault, cap, payment_id)` on the smart contract.
The gateway checks `vault.closed_threads[payment_id]` on every email
and drops anything from that thread in both directions.

---

## Environment variables

| Secret | Description |
|--------|-------------|
| `SELLER_REAL_EMAIL` | Your actual inbox. Never on-chain. Worker reads this to forward inbound. |
| `SELLER_GATEWAY_EMAIL` | Public MX address. Stored on-chain as `vault.gateway_email`. |
| `VAULT_ID` | `AttentionVault` object ID on Sui. |
| `PACKAGE_ID` | Deployed Move package ID. |
| `SUI_RPC_URL` | Sui fullnode RPC endpoint. |

| Var (non-secret) | Description |
|-----------------|-------------|
| `SUI_NETWORK` | `testnet` or `mainnet` (informational only). |
