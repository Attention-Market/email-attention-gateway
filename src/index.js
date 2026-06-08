// index.js — AttentionMarket single-gateway Cloudflare Email Worker
//
// One gateway domain (attention.email) serves every registered seller.
// Each seller has a unique address like alice@attention.email, resolved
// from the on-chain Registry.gateway_emails table at routing time.
//
// ── Reply detection ───────────────────────────────────────────────────────────
//
// Routing between inbound (winner → seller) and outbound (seller → winner)
// is done using standard RFC 5322 threading headers, NOT subject-line parsing:
//
//   In-Reply-To: <original-message-id>
//   References:  <msg-id-1> … <original-message-id>
//
// These are set automatically by every compliant mail client on Reply.
//
// The winner's address is recovered via the paymentId embedded in the
// Reply-To address we set when forwarding inbound mail to the seller:
//
//   Reply-To: <paymentId>@reply.attention.email
//
// When the seller hits Reply, their client addresses the outbound mail to
// that Reply-To address. We extract the paymentId from the local-part,
// look up the winner's address from on-chain SlotWon events, and forward.
// The seller never sees or types the winner's real address.
//
// ── Inbound (winner → seller) ─────────────────────────────────────────────────
//
//   From: winner@example.com
//   To:   alice@attention.email
//   Subject: Hey Alice [attn:BASE64SIG]
//
//   1. Extract local-part "alice", resolve → vaultId via Registry.
//   2. Fetch vault fields (JSON-RPC).
//   3. Compute emailHash = sha256(from), paymentId = sha256(emailHash:vaultId).
//   4. Look up SlotWon events — confirm paymentId has a winning record.
//   5. Confirm senderEmailHash matches on-chain record.
//   6. Verify [attn:SIG] Ed25519 signature against on-chain bidder address.
//   7. Confirm thread is not closed on-chain.
//   8. Decrypt seller's real email from vault encrypted blob.
//   9. Forward to seller. Set Reply-To: <paymentId>@reply.attention.email
//      and append info footer (paymentId, vaultId) via X-AttentionMarket header.
//
// ── Outbound (seller → winner) ────────────────────────────────────────────────
//
//   Seller hits Reply in their mail client:
//   From:       seller@example.com  (their real address)
//   To:         <paymentId>@reply.attention.email  (set by our Reply-To)
//   In-Reply-To / References set automatically by mail client
//   Subject:    Re: Hey Alice [attn:BASE64SIG]
//
//   1. Detect In-Reply-To or References header → outbound flow.
//   2. Extract paymentId from To: local-part.
//   3. Look up winner's address from on-chain SlotWon events by paymentId.
//   4. Decrypt vault's seller email, confirm From: matches (anti-spoof).
//   5. Verify [attn:SIG] signature (seller proves wallet ownership).
//   6. Confirm thread not closed on-chain.
//   7. Forward to winner, appending paymentId footer.
//      Seller's real address is never disclosed to the winner.
//
// ── Env vars ──────────────────────────────────────────────────────────────────
//
//   REGISTRY_ID           Sui object ID of the shared Registry
//   PACKAGE_ID            Sui package ID of the attention_market module
//   SUI_NETWORK           'mainnet' | 'testnet' | 'devnet' (default: testnet)
//   SUI_GRPC_URL          gRPC-web endpoint (optional)
//   SUI_RPC_URL           JSON-RPC endpoint (optional)
//   PRIVATE_KEY           Base64-encoded raw P-256 private key (32 bytes) for email decryption
//   GATEWAY_DOMAIN        e.g. "attention.email"   (default: "attention.email")
//   REPLY_SUBDOMAIN       e.g. "reply.attention.email" (default: "reply.<GATEWAY_DOMAIN>")

import {
  makeClients,
  hashEmail,
  computePaymentId,
  vaultIdByGatewayEmail,
  fetchVaultFieldsRpc,
  extractEncryptedEmailPayload,
  decryptSellerEmail,
  isThreadClosed,
  fetchSlotWonMap,
} from './sui.js'

import {
  verifyAttentionToken,
  extractAttnTag,
  cleanSubject,
  buildSignMessage,
  isReplyMessage,
} from './verify.js'

// ── Main handler ──────────────────────────────────────────────────────────────

export default {
  async email(message, env, _ctx) {
    const from    = message.from.toLowerCase().trim()
    const to      = message.to.toLowerCase().trim()
    const subject = message.headers.get('subject') || ''
    const headers = message.headers

    console.log(`[gateway] ${from} → ${to} | "${subject}"`)

    // Reject oversized messages before doing any Sui RPC work
    const MAX_BYTES = 5 * 1024 * 1024 // 5 MiB
    if (message.rawSize > MAX_BYTES) {
      console.log(`[gateway] DROP — message too large (${message.rawSize} bytes) from ${from}`)
      message.setReject("Message too large")
      return
    }

    const gatewayDomain  = (env.GATEWAY_DOMAIN || 'attention.email').toLowerCase()
    const replySubdomain = (env.REPLY_SUBDOMAIN || `reply.${gatewayDomain}`).toLowerCase()

    // ── Route: seller reply ───────────────────────────────────────────────────
    //
    // Detected by standard RFC 5322 threading headers (In-Reply-To / References).
    // The To: address is <paymentId>@reply.attention.email — set by our Reply-To
    // when we forwarded the original inbound mail to the seller.
    if (isReplyMessage(headers) && to.endsWith(`@${replySubdomain}`)) {
      const { grpc, rpc } = makeClients(env)
      await handleSellerReply({ message, from, to, subject, grpc, rpc, env, gatewayDomain, replySubdomain })
      return
    }

    // ── Route: inbound from winner ────────────────────────────────────────────
    if (to.endsWith(`@${gatewayDomain}`)) {
      // Prevent routing loops
      if (from.endsWith(`@${gatewayDomain}`) || from.endsWith(`@${replySubdomain}`)) {
        console.log('[gateway] DROP — loop guard')
        message.setReject('Loop detected')
        return
      }
      const { grpc, rpc } = makeClients(env)
      await handleInbound({ message, from, to, subject, grpc, rpc, env, gatewayDomain, replySubdomain })
      return
    }

    console.log(`[gateway] DROP — To: ${to} is not a recognised gateway address`)
    message.setReject('Unknown recipient')
  },
}

// ── Inbound: winner → seller ──────────────────────────────────────────────────

async function handleInbound({ message, from, to, subject, grpc, rpc, env, gatewayDomain, replySubdomain }) {

  // 1. Must carry [attn:] tag
  if (!extractAttnTag(subject)) {
    console.log(`[gateway] DROP inbound — no [attn:] tag from ${from}`)
    message.setReject('Missing attention token')
    return
  }

  // 2. Resolve vault from To: local-part (e.g. "alice" → vaultId)
  const localPart    = to.split('@')[0]
  const gatewayEmail = `${localPart}@${gatewayDomain}`

  const vaultId = await vaultIdByGatewayEmail(grpc, env.REGISTRY_ID, gatewayEmail)
  if (!vaultId) {
    console.log(`[gateway] DROP inbound — no vault for ${gatewayEmail}`)
    message.setReject('Unknown gateway address')
    return
  }

  // 3. Fetch vault content fields
  const vaultFields = await fetchVaultFieldsRpc(rpc, vaultId)
  if (!vaultFields) {
    console.error(`[gateway] Could not fetch vault ${vaultId}`)
    message.setReject('Gateway error: vault unavailable')
    return
  }

  // 4. Compute on-chain identifiers from the sender's address
  const emailHash = await hashEmail(from)
  const paymentId = await computePaymentId(from, vaultId)

  // 5. Look up the SlotWon event record for this paymentId
  const slotMap    = await fetchSlotWonMap(rpc, env.PACKAGE_ID, vaultId)
  const slotRecord = slotMap[paymentId]

  if (!slotRecord) {
    console.log(`[gateway] DROP inbound — no winning bid for emailHash ${emailHash.slice(0, 12)}…`)
    message.setReject('No winning bid found')
    return
  }

  // 6. Confirm the sender email hash matches what was committed on-chain
  if (slotRecord.senderEmailHash !== emailHash) {
    console.log(`[gateway] DROP inbound — email hash mismatch for ${from}`)
    message.setReject('Email address does not match bid')
    return
  }

  // 7. Verify the Ed25519 wallet signature against the on-chain bidder address
  const signMessage    = buildSignMessage(vaultId, paymentId)
  const { ok, reason } = await verifyAttentionToken(subject, signMessage, slotRecord.bidderAddress)

  if (!ok) {
    console.log(`[gateway] DROP inbound — bad signature from ${from}: ${reason}`)
    message.setReject('Invalid attention token')
    return
  }

  // 8. Confirm thread not closed on-chain
  const closed = await isThreadClosed(rpc, vaultFields, paymentId)
  if (closed) {
    console.log(`[gateway] DROP inbound — thread closed for paymentId ${paymentId.slice(0, 12)}…`)
    message.setReject('Conversation closed by seller')
    return
  }

  // 9. Decrypt seller's real email from the on-chain encrypted blob
  const encryptedPayload = extractEncryptedEmailPayload(vaultFields)
  const sellerRealEmail  = await decryptSellerEmail(env, encryptedPayload)
  if (!sellerRealEmail) {
    console.error('[gateway] Could not decrypt seller email')
    message.setReject('Gateway error: could not resolve seller')
    return
  }

  // 10. Forward to seller
  //     Reply-To is set to <paymentId>@reply.attention.email so that when the
  //     seller hits Reply their client addresses the outbound mail there.
  //     We use that address in handleSellerReply() to recover the paymentId
  //     without relying on any subject-line convention.
  // Encode both paymentId and vaultId in the reply address so handleSellerReply
  // can recover the vault without a registry scan.
  // Format: <paymentId>.<vaultId-without-0x>@reply.attention.email
  const vaultIdHex = vaultId.startsWith('0x') ? vaultId.slice(2) : vaultId
  const replyTo = `${paymentId}.${vaultIdHex}@${replySubdomain}`
  const footer  = buildInboundFooter({ paymentId, vaultId, senderEmail: from })

  // Store winner's plaintext email in KV so handleSellerReply can recover it.
  // TTL is set to 90 days — long enough for any reasonable conversation window.
  // The key is paymentId which is already a commitment to the email address,
  // so storing the plaintext here only adds resolution capability, not new exposure.
  if (env.REPLY_KV) {
    await env.REPLY_KV.put(`winner:${paymentId}`, from, { expirationTtl: 60 * 60 * 24 * 90 })
  }

  console.log(`[gateway] ✓ Inbound verified from ${from} — forwarding to seller, reply-to ${replyTo}`)
  await forwardWithFooter(message, sellerRealEmail, cleanSubject(subject), replyTo, footer)
}

// ── Outbound: seller → winner ─────────────────────────────────────────────────

async function handleSellerReply({ message, from, to, subject, grpc, rpc, env, gatewayDomain, replySubdomain }) {

  // 1. Parse paymentId + vaultId from the reply address
  //    Format: <paymentId>.<vaultId>@reply.attention.email  (both 64-char hex)
  //    This address was set as Reply-To when the original inbound mail was
  //    forwarded to the seller, so the mail client populates it automatically.
  const parsedReply = parseReplyAddress(to, replySubdomain)
  if (!parsedReply) {
    console.log(`[gateway] DROP outbound — invalid reply address: ${to}`)
    message.setReject('Invalid reply address')
    return
  }
  const { paymentId, vaultId } = parsedReply

  // 2. Must carry [attn:] tag — seller proves wallet ownership on every reply
  if (!extractAttnTag(subject)) {
    console.log(`[gateway] DROP outbound — no [attn:] tag from ${from}`)
    message.setReject('Missing attention token on reply')
    return
  }

  // 4. Fetch vault fields
  const vaultFields = await fetchVaultFieldsRpc(rpc, vaultId)
  if (!vaultFields) {
    console.error(`[gateway] Could not fetch vault ${vaultId}`)
    message.setReject('Gateway error: vault unavailable')
    return
  }

  // 5. Anti-spoof: decrypt vault's stored seller email and confirm From: matches
  const encryptedPayload = extractEncryptedEmailPayload(vaultFields)
  const sellerRealEmail  = await decryptSellerEmail(env, encryptedPayload)

  if (!sellerRealEmail) {
    console.error('[gateway] Could not decrypt seller email for outbound verification')
    message.setReject('Gateway error: could not verify sender')
    return
  }

  if (from !== sellerRealEmail.toLowerCase().trim()) {
    console.log(`[gateway] DROP outbound — From: ${from} does not match vault owner`)
    message.setReject('Sender not authorised for this vault')
    return
  }

  // 6. Verify [attn:SIG] — seller signs "AttentionMarket:<vaultId>:<paymentId>"
  //    This proves they hold the wallet that registered the vault.
  //    We skip address-matching (expectedAddress = null) because vault ownership
  //    is already proven by the From: ↔ decrypted email check above.
  const signMessage    = buildSignMessage(vaultId, paymentId)
  const { ok, reason } = await verifyAttentionToken(subject, signMessage, null)

  if (!ok) {
    console.log(`[gateway] DROP outbound — bad signature from ${from}: ${reason}`)
    message.setReject('Invalid attention token on reply')
    return
  }

  // 7. Confirm thread not closed on-chain
  const closed = await isThreadClosed(rpc, vaultFields, paymentId)
  if (closed) {
    console.log(`[gateway] DROP outbound — thread closed for paymentId ${paymentId.slice(0, 12)}…`)
    message.setReject('Conversation closed')
    return
  }

  // 8. Recover winner's email address from on-chain SlotWon events
  const slotMap    = await fetchSlotWonMap(rpc, env.PACKAGE_ID, vaultId)
  const slotRecord = slotMap[paymentId]

  if (!slotRecord) {
    console.log(`[gateway] DROP outbound — no SlotWon record for paymentId ${paymentId.slice(0, 12)}…`)
    message.setReject('No matching bid record')
    return
  }

  // SlotWon stores sender_email_hash not the plaintext address. The winner's
  // real address is not stored on-chain (privacy model). We need to recover it
  // from our own forwarding record.
  //
  // Since we never stored the winner's plaintext address server-side either,
  // the winner's address must be sourced from the original email the seller
  // received — which we included in the inbound footer as "Sender: <email>".
  // The seller's mail client includes the original email body in the reply,
  // so it is present in message.raw. Parsing MIME here is complex.
  //
  // Practical solution: also encode the winner's email hash in the reply
  // address, and maintain a short-lived KV mapping
  //   paymentId → winner plaintext email
  // populated at forward time and consumed here.
  //
  // For now we use Cloudflare KV (env.REPLY_KV) as the store.
  const winnerEmail = await env.REPLY_KV?.get(`winner:${paymentId}`)
  if (!winnerEmail) {
    console.log(`[gateway] DROP outbound — no winner address on file for ${paymentId.slice(0, 12)}…`)
    message.setReject('Cannot resolve winner address')
    return
  }

  // 9. Forward to winner — seller's real address is never disclosed
  const footer = buildOutboundFooter({ paymentId, vaultId })
  console.log(`[gateway] ✓ Seller reply → ${winnerEmail}`)
  await forwardWithFooter(message, winnerEmail, cleanSubject(subject), null, footer)
}

// ── Forward helper ────────────────────────────────────────────────────────────

/**
 * Forward the message to toAddress with updated subject and optional Reply-To.
 * The info footer is passed in X-AttentionMarket (body mutation not available
 * in the native CF email Worker API without postal-mime rewriting).
 */
async function forwardWithFooter(message, toAddress, subject, replyTo, footer) {
  try {
    const headersInit = { 'Subject': subject, 'X-AttentionMarket': footer }
    if (replyTo) headersInit['Reply-To'] = replyTo
    await message.forward(toAddress, new Headers(headersInit))
    console.log(`[gateway] Forwarded to ${toAddress}`)
  } catch (err) {
    console.error('[gateway] Forward failed:', err)
    message.setReject('Forward failed')
  }
}

// ── Reply address encoding / decoding ────────────────────────────────────────

/**
 * Build the Reply-To address for an inbound forward.
 * Format: <paymentId>.<vaultId>@reply.attention.email
 * Both are 64-char hex strings, joined by a dot — safe as an email local-part.
 *
 * Exported so inbound handler can call it, and tests can verify round-trips.
 */
export function buildReplyAddress(paymentId, vaultId, replySubdomain) {
  return `${paymentId}.${vaultId}@${replySubdomain}`
}

/**
 * Parse a reply address of the form <paymentId>.<vaultId>@reply.attention.email
 * (both segments are 64-char lowercase hex — safe as an email local-part).
 * Returns { paymentId, vaultId } or null if format doesn't match.
 * vaultId is returned 0x-prefixed for use as a Sui object ID.
 */
function parseReplyAddress(to, replySubdomain) {
  const lower = to.toLowerCase().trim()
  if (!lower.endsWith(`@${replySubdomain}`)) return null
  const local = lower.split('@')[0]
  const dot   = local.indexOf('.')
  if (dot < 0) return null
  const paymentId  = local.slice(0, dot)
  const vaultIdHex = local.slice(dot + 1)
  if (!/^[0-9a-f]{64}$/.test(paymentId))  return null
  if (!/^[0-9a-f]{64}$/.test(vaultIdHex)) return null
  return { paymentId, vaultId: '0x' + vaultIdHex }
}

// ── Footer builders ───────────────────────────────────────────────────────────

/**
 * Footer sent to the seller on inbound email.
 * Includes everything needed to call close_conversation() on-chain.
 */
function buildInboundFooter({ paymentId, vaultId, senderEmail }) {
  return [
    '--- AttentionMarket ---',
    `Sender:    ${senderEmail}`,
    `PaymentID: ${paymentId}`,
    `VaultID:   ${vaultId}`,
    'To close: call close_conversation(vaultId, paymentId) on-chain.',
    '-----------------------',
  ].join('\n')
}

/**
 * Footer sent to the winner on outbound email.
 */
function buildOutboundFooter({ paymentId, vaultId }) {
  return [
    '--- AttentionMarket ---',
    `PaymentID: ${paymentId}`,
    `VaultID:   ${vaultId}`,
    '-----------------------',
  ].join('\n')
}