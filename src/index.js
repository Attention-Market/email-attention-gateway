// index.js — AttentionMarket Cloudflare Email Worker
//
// Handles two directions:
//
//   INBOUND (winner → seller):
//     From: winner@example.com
//     To:   gateway@attentionmarket.xyz
//     Subject: Hey Alice, loved your talk [attn:BASE64SIG]
//
//     Gateway:
//       1. Compute emailHash = sha256(from) and paymentId = sha256(emailHash:vaultId)
//       2. Fetch vault from Sui via @mysten/sui SuiClient
//       3. Check whitelist, SlotWon events, closed_threads
//       4. Verify [attn:SIG] via @mysten/webcrypto-signer
//       5. Forward to SELLER_REAL_EMAIL (env secret, never on-chain)
//       6. Strip [attn:] tag from subject before forwarding
//
//   OUTBOUND (seller replies):
//     From: SELLER_REAL_EMAIL (env secret)
//     To:   gateway@attentionmarket.xyz
//     Subject: Re: their question [reply-to:winner@example.com]
//
//     Gateway:
//       1. Verify From: matches SELLER_REAL_EMAIL exactly
//       2. Extract [reply-to:winner@example.com] from subject
//       3. Compute paymentId from reply-to address + vaultId
//       4. Check thread isn't closed on Sui
//       5. Forward to winner's address, stripping [reply-to:] from subject
//       6. Seller's real address is never exposed to the winner
//
// Emails without the correct tag are silently rejected — no bounces.

import {
  makeClient,
  hashEmail,
  computePaymentId,
  fetchVaultFields,
  isThreadClosed,
  isWhitelisted,
  fetchSlotWonMap,
} from './sui.js'

import {
  verifyAttentionToken,
  extractAttnTag,
  extractReplyTo,
  buildSignMessage,
  cleanSubject,
} from './verify.js'

export default {
  async email(message, env, ctx) {
    const vaultId   = env.VAULT_ID
    const packageId = env.PACKAGE_ID
    const sellerRealEmail    = env.SELLER_REAL_EMAIL
    const sellerGatewayEmail = env.SELLER_GATEWAY_EMAIL

    const client  = makeClient(env)
    const from    = message.from
    const to      = message.to
    const subject = message.headers.get('subject') || ''

    console.log(`[gateway] ${from} → ${to} | "${subject}"`)

    // Route: seller replying outbound
    if (from.toLowerCase() === sellerRealEmail.toLowerCase()) {
      await handleSellerReply({ message, subject, client, vaultId })
      return
    }

    // Route: inbound from a potential winner
    await handleInbound({ message, from, subject, client, vaultId, packageId, sellerRealEmail })
  }
}

// ── Inbound handler ───────────────────────────────────────────────────────────

async function handleInbound({ message, from, subject, client, vaultId, packageId, sellerRealEmail }) {

  // 1. Must have [attn:] tag — drop silently if missing
  if (!extractAttnTag(subject)) {
    console.log(`[gateway] DROP — no [attn:] tag from ${from}`)
    message.setReject('Missing attention token')
    return
  }

  // 2. Fetch vault fields from Sui via @mysten/sui
  const vaultFields = await fetchVaultFields(client, vaultId)
  if (!vaultFields) {
    console.error('[gateway] Could not fetch vault — dropping')
    message.setReject('Gateway error')
    return
  }

  // 3. Compute identifiers from sender address
  const emailHash = await hashEmail(from)
  const paymentId = await computePaymentId(from, vaultId)

  // 4. Whitelist check — whitelisted senders bypass auction checks
  const whitelisted = await isWhitelisted(client, vaultFields, emailHash)
  if (whitelisted) {
    console.log(`[gateway] Whitelisted sender ${from} — forwarding`)
    await forward(message, sellerRealEmail, subject)
    return
  }

  // 5. Fetch SlotWon events to find this sender's winning bid record
  const slotMap    = await fetchSlotWonMap(client, packageId, vaultId)
  const slotRecord = slotMap[paymentId]

  if (!slotRecord) {
    console.log(`[gateway] DROP — no winning bid for hash ${emailHash.slice(0, 12)}…`)
    message.setReject('No winning bid found')
    return
  }

  // 6. Verify sender email hash matches what was committed on-chain
  if (slotRecord.senderEmailHash !== emailHash) {
    console.log(`[gateway] DROP — email hash mismatch for ${from}`)
    message.setReject('Email address does not match bid')
    return
  }

  // 7. Check thread isn't closed on-chain
  const closed = await isThreadClosed(client, vaultFields, paymentId)
  if (closed) {
    console.log(`[gateway] DROP — thread closed for ${paymentId.slice(0, 12)}…`)
    message.setReject('Conversation closed by seller')
    return
  }

  // 8. Verify Ed25519 wallet signature via @mysten/webcrypto-signer
  const signMessage    = buildSignMessage(vaultId, paymentId)
  const { ok, reason } = await verifyAttentionToken(subject, signMessage, slotRecord.bidderAddress)

  if (!ok) {
    console.log(`[gateway] DROP — bad signature from ${from}: ${reason}`)
    message.setReject('Invalid attention token')
    return
  }

  // 9. All checks pass — forward, stripping [attn:] from subject
  console.log(`[gateway] ✓ Verified ${from} — forwarding to seller`)
  await forward(message, sellerRealEmail, cleanSubject(subject))
}

// ── Seller reply handler ──────────────────────────────────────────────────────

async function handleSellerReply({ message, subject, client, vaultId }) {

  // 1. Must have [reply-to:email] — drop silently if missing
  const replyTo = extractReplyTo(subject)
  if (!replyTo) {
    console.log(`[gateway] DROP seller reply — no [reply-to:] tag`)
    message.setReject('Missing reply-to tag')
    return
  }

  // 2. Compute payment_id for this winner to check thread status
  const paymentId = await computePaymentId(replyTo, vaultId)

  // 3. Check thread isn't closed on Sui
  const vaultFields = await fetchVaultFields(client, vaultId)
  if (vaultFields) {
    const closed = await isThreadClosed(client, vaultFields, paymentId)
    if (closed) {
      console.log(`[gateway] DROP seller reply — thread closed for ${replyTo}`)
      message.setReject('Conversation closed')
      return
    }
  }

  // 4. Forward to winner, stripping [reply-to:] from subject
  console.log(`[gateway] ✓ Seller reply → ${replyTo}`)
  await forward(message, replyTo, cleanSubject(subject))
}

// ── Forward helper ────────────────────────────────────────────────────────────

async function forward(message, toAddress, subject) {
  try {
    await message.forward(toAddress, new Headers({ subject }))
    console.log(`[gateway] Forwarded to ${toAddress}`)
  } catch (err) {
    console.error(`[gateway] Forward failed:`, err)
    message.setReject('Forward failed')
  }
}
