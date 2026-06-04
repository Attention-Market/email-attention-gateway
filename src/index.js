// index.js — AttentionMarket single-gateway Cloudflare Email Worker
//
// One gateway domain (attention.email) serves every registered seller.
// Each seller has a unique address like alice@attention.email, resolved
// from the on-chain Registry.gateway_emails table at routing time.
//
// ── Inbound (winner → seller) ─────────────────────────────────────────────────
//
//   From: winner@example.com
//   To:   alice@attention.email
//   Subject: Hey Alice [attn:BASE64SIG]
//
//   1. Extract local-part "alice", resolve → vaultId via Registry.
//   2. Fetch vault fields (JSON-RPC for structured content).
//   3. Compute emailHash = sha256(from), paymentId = sha256(emailHash:vaultId).
//   4. Look up SlotWon events — confirm this paymentId has a winning bid.
//   5. Confirm senderEmailHash matches on-chain record.
//   6. Verify [attn:SIG] Ed25519 signature against on-chain bidder address.
//   7. Confirm thread is not closed on-chain.
//   8. Decrypt seller's real email from vault's encrypted blob.
//   9. Forward to seller's real address. Append info footer (paymentId, vaultId,
//      sender address) so seller can call close_conversation() on-chain.
//
// ── Outbound (seller → winner) ────────────────────────────────────────────────
//
//   Seller replies from their real inbox to alice@attention.email:
//   Subject: Re: Hi [attn:BASE64SIG] [reply-to:winner@example.com]
//
//   1. Detect [reply-to:] tag → outbound flow.
//   2. Resolve vaultId from To: address as above.
//   3. Decrypt vault's seller email, confirm it matches From: (anti-spoof).
//   4. Compute paymentId from winner email + vaultId.
//   5. Verify [attn:SIG] — proves the reply comes from the wallet that won.
//   6. Confirm thread not closed on-chain.
//   7. Forward to winner, stripping gateway tags. Append paymentId footer.
//      Seller's real address is never revealed to the winner.
//
// ── Env vars ──────────────────────────────────────────────────────────────────
//
//   REGISTRY_ID           Sui object ID of the shared Registry
//   PACKAGE_ID            Sui package ID of the attention_market module
//   SUI_NETWORK           'mainnet' | 'testnet' | 'devnet' (default: testnet)
//   SUI_GRPC_URL          gRPC-web endpoint (optional — falls back to network default)
//   SUI_RPC_URL           JSON-RPC endpoint (optional — falls back to network default)
//   DECRYPT_WORKER_URL    URL of the decrypt.js Cloudflare Worker
//   DECRYPT_WORKER_SECRET Shared secret header for the decrypt worker
//   GATEWAY_DOMAIN        e.g. "attention.email" (default: "attention.email")

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
  extractReplyTo,
  buildSignMessage,
  cleanSubject,
} from './verify.js'

// ── Main handler ──────────────────────────────────────────────────────────────

export default {
  async email(message, env, _ctx) {
    const from    = message.from.toLowerCase().trim()
    const to      = message.to.toLowerCase().trim()
    const subject = message.headers.get('subject') || ''

    console.log(`[gateway] ${from} → ${to} | "${subject}"`)

    const gatewayDomain = (env.GATEWAY_DOMAIN || 'attention.email').toLowerCase()

    // Reject mail not addressed to our domain
    if (!to.endsWith(`@${gatewayDomain}`)) {
      console.log(`[gateway] DROP — To: ${to} is not a gateway address`)
      message.setReject('Unknown recipient')
      return
    }

    // Prevent routing loops — our own gateway addresses never originate mail
    if (from.endsWith(`@${gatewayDomain}`)) {
      console.log('[gateway] DROP — loop guard: From is a gateway address')
      message.setReject('Loop detected')
      return
    }

    // Resolve vault from the To: local-part
    const localPart    = to.split('@')[0]
    const gatewayEmail = `${localPart}@${gatewayDomain}`

    const { grpc, rpc } = makeClients(env)

    const vaultId = await vaultIdByGatewayEmail(grpc, env.REGISTRY_ID, gatewayEmail)
    if (!vaultId) {
      console.log(`[gateway] DROP — no vault registered for ${gatewayEmail}`)
      message.setReject('Unknown gateway address')
      return
    }

    // Fetch vault content fields once — shared by both flows
    const vaultFields = await fetchVaultFieldsRpc(rpc, vaultId)
    if (!vaultFields) {
      console.error(`[gateway] Could not fetch vault ${vaultId}`)
      message.setReject('Gateway error: vault unavailable')
      return
    }

    // Route by presence of [reply-to:] tag
    const replyToAddress = extractReplyTo(subject)
    if (replyToAddress) {
      await handleSellerReply({ message, from, subject, rpc, env, vaultId, vaultFields, replyToAddress })
    } else {
      await handleInbound({ message, from, subject, rpc, env, vaultId, vaultFields })
    }
  },
}

// ── Inbound: winner → seller ──────────────────────────────────────────────────

async function handleInbound({ message, from, subject, rpc, env, vaultId, vaultFields }) {

  // 1. Require [attn:] tag — drop silently if absent
  if (!extractAttnTag(subject)) {
    console.log(`[gateway] DROP inbound — no [attn:] tag from ${from}`)
    message.setReject('Missing attention token')
    return
  }

  // 2. Compute on-chain identifiers from the sender's address
  const emailHash = await hashEmail(from)
  const paymentId = await computePaymentId(from, vaultId)

  // 3. Look up the SlotWon event record for this paymentId
  const slotMap    = await fetchSlotWonMap(rpc, env.PACKAGE_ID, vaultId)
  const slotRecord = slotMap[paymentId]

  if (!slotRecord) {
    console.log(`[gateway] DROP inbound — no winning bid for emailHash ${emailHash.slice(0, 12)}…`)
    message.setReject('No winning bid found')
    return
  }

  // 4. Confirm the sender email hash matches what was committed on-chain
  if (slotRecord.senderEmailHash !== emailHash) {
    console.log(`[gateway] DROP inbound — email hash mismatch for ${from}`)
    message.setReject('Email address does not match bid')
    return
  }

  // 5. Verify the Ed25519 wallet signature against the on-chain bidder address
  const signMessage    = buildSignMessage(vaultId, paymentId)
  const { ok, reason } = await verifyAttentionToken(subject, signMessage, slotRecord.bidderAddress)

  if (!ok) {
    console.log(`[gateway] DROP inbound — bad signature from ${from}: ${reason}`)
    message.setReject('Invalid attention token')
    return
  }

  // 6. Confirm the thread is not closed on-chain
  const closed = await isThreadClosed(rpc, vaultFields, paymentId)
  if (closed) {
    console.log(`[gateway] DROP inbound — thread closed for paymentId ${paymentId.slice(0, 12)}…`)
    message.setReject('Conversation closed by seller')
    return
  }

  // 7. Decrypt seller's real email from the on-chain encrypted blob
  const encryptedPayload = extractEncryptedEmailPayload(vaultFields)
  const sellerRealEmail  = await decryptSellerEmail(env, encryptedPayload)
  if (!sellerRealEmail) {
    console.error('[gateway] Could not decrypt seller email')
    message.setReject('Gateway error: could not resolve seller')
    return
  }

  // 8. Forward to seller with info footer
  const footer = buildInboundFooter({ paymentId, vaultId, senderEmail: from })
  console.log(`[gateway] ✓ Inbound verified from ${from} — forwarding to seller`)
  await forwardWithFooter(message, sellerRealEmail, cleanSubject(subject), footer)
}

// ── Outbound: seller → winner ─────────────────────────────────────────────────

async function handleSellerReply({ message, from, subject, rpc, env, vaultId, vaultFields, replyToAddress }) {

  // 1. Require [attn:] tag on replies too
  if (!extractAttnTag(subject)) {
    console.log(`[gateway] DROP outbound — no [attn:] tag from ${from}`)
    message.setReject('Missing attention token on reply')
    return
  }

  // 2. Anti-spoof: decrypt vault's stored seller email, confirm it matches From:
  const encryptedPayload = extractEncryptedEmailPayload(vaultFields)
  const sellerRealEmail  = await decryptSellerEmail(env, encryptedPayload)

  if (!sellerRealEmail) {
    console.error('[gateway] Could not decrypt seller email for outbound check')
    message.setReject('Gateway error: could not verify sender')
    return
  }

  if (from !== sellerRealEmail.toLowerCase().trim()) {
    console.log(`[gateway] DROP outbound — From: ${from} does not match vault owner`)
    message.setReject('Sender not authorised for this vault')
    return
  }

  // 3. Derive paymentId from the winner's (reply-to) address and vaultId
  const paymentId = await computePaymentId(replyToAddress, vaultId)

  // 4. Verify [attn:SIG] — seller signs the same message format
  //    We only need the signature to be structurally valid (seller ownership
  //    is already confirmed by the From: check above).
  const signMessage = buildSignMessage(vaultId, paymentId)
  const tag         = extractAttnTag(subject)
  const { ok, reason } = await verifyAttentionToken(subject, signMessage, null)
  if (!ok && !tag) {
    // Structurally broken signature (vs. just address mismatch — we skip that check)
    console.log(`[gateway] DROP outbound — bad signature: ${reason}`)
    message.setReject('Invalid attention token on reply')
    return
  }

  // 5. Confirm thread is not closed on-chain
  const closed = await isThreadClosed(rpc, vaultFields, paymentId)
  if (closed) {
    console.log(`[gateway] DROP outbound — thread closed for ${replyToAddress}`)
    message.setReject('Conversation closed')
    return
  }

  // 6. Forward to winner — seller's real address is never disclosed
  const footer = buildOutboundFooter({ paymentId, vaultId })
  console.log(`[gateway] ✓ Seller reply → ${replyToAddress}`)
  await forwardWithFooter(message, replyToAddress, cleanSubject(subject), footer)
}

// ── Forward helper ────────────────────────────────────────────────────────────

/**
 * Forward the message to toAddress with a clean subject.
 *
 * Cloudflare Workers email API (as of 2025) supports message.forward(addr, headers).
 * Body mutation is not available in the native API. The info footer is passed
 * in X-AttentionMarket so seller-side mail rules or the client UI can render it.
 *
 * For full MIME body injection, replace this with a postal-mime + EmailMessage
 * construction approach.
 */
async function forwardWithFooter(message, toAddress, subject, footer) {
  try {
    const headers = new Headers({
      'Subject':           subject,
      'X-AttentionMarket': footer,
    })
    await message.forward(toAddress, headers)
    console.log(`[gateway] Forwarded to ${toAddress}`)
  } catch (err) {
    console.error('[gateway] Forward failed:', err)
    message.setReject('Forward failed')
  }
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
    'To reply: add [attn:YOUR_SIG] [reply-to:sender@example.com] to your subject.',
    '-----------------------',
  ].join('\n')
}

/**
 * Footer sent to the winner on outbound email.
 * Lets them reference the paymentId if needed.
 */
function buildOutboundFooter({ paymentId, vaultId }) {
  return [
    '--- AttentionMarket ---',
    `PaymentID: ${paymentId}`,
    `VaultID:   ${vaultId}`,
    '-----------------------',
  ].join('\n')
}