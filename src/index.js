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
//   9. Send to seller. Set Reply-To: <paymentId>@reply.attention.email
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
//   7. Send to winner, appending paymentId footer.
//      Seller's real address is never disclosed to the winner.
//
// ── Env vars ──────────────────────────────────────────────────────────────────
//
//   REGISTRY_ID           Sui object ID of the shared Registry
//   PACKAGE_ID            Sui package ID of the attention_market module
//   SUI_NETWORK           'mainnet' | 'testnet' | 'devnet' (default: testnet)
//   SUI_RPC_URL           JSON-RPC endpoint (optional)
//   PRIVATE_KEY           Base64-encoded raw P-256 private key (32 bytes) for email decryption
//   GATEWAY_DOMAIN        e.g. "attention.email"   (default: "attention.email")
//   REPLY_SUBDOMAIN       e.g. "reply.attention.email" (default: "reply.<GATEWAY_DOMAIN>")
//   GATEWAY_FROM          Sender address for outgoing mail (default: noreply@<GATEWAY_DOMAIN>)

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
    if (isReplyMessage(headers) && to.endsWith(`@${replySubdomain}`)) {
      const { rpc } = makeClients(env)
      await handleSellerReply({ message, from, to, subject, rpc, env, gatewayDomain, replySubdomain })
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
      const { rpc } = makeClients(env)
      await handleInbound({ message, from, to, subject, rpc, env, gatewayDomain, replySubdomain })
      return
    }

    console.log(`[gateway] DROP — To: ${to} is not a recognised gateway address`)
    message.setReject('Unknown recipient')
  },
}

// ── Inbound: winner → seller ──────────────────────────────────────────────────

async function handleInbound({ message, from, to, subject, rpc, env, gatewayDomain, replySubdomain }) {

  // 1. Must carry [attn:] tag
  if (!extractAttnTag(subject)) {
    console.log(`[gateway] DROP inbound — no [attn:] tag from ${from}`)
    message.setReject('Missing attention token')
    return
  }

  // 2. Resolve vault from To: local-part (e.g. "alice" → vaultId)
  const localPart    = to.split('@')[0]
  const gatewayEmail = `${localPart}@${gatewayDomain}`

  const vaultId = await vaultIdByGatewayEmail(rpc, env.REGISTRY_ID, gatewayEmail)
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

  // 10. Store winner → paymentId mapping in KV for reply routing
  if (env.ALIASES) {
    await env.ALIASES.put(
      `winner:${paymentId}`,
      JSON.stringify({ email: from, vaultId,subject: subject }),
      { expirationTtl: 60 * 60 * 24 * 90 }
    )
  }

  // 11. Send to seller
  const replyTo = `${paymentId}@${replySubdomain}`
  const footer  = buildInboundFooter({ paymentId, vaultId, senderEmail: from })

  console.log(`[gateway] ✓ Inbound verified from ${from} — sending to seller, reply-to ${replyTo}`)
  // Use the address the winner wrote to (e.g. alice@attention.email) as the From —
  // this matches the wildcard address authorised for sending on this domain.
  await sendWithFooter(message, sellerRealEmail, subject, replyTo, footer, env, to)
}

// ── Outbound: seller → winner ─────────────────────────────────────────────────

async function handleSellerReply({ message, from, to, subject, rpc, env, gatewayDomain, replySubdomain }) {

  // 1. Parse paymentId + vaultId from the reply address
  const parsedReply = parseReplyAddress(to, replySubdomain)
  if (!parsedReply) {
    console.log(`[gateway] DROP outbound — invalid reply address: ${to}`)
    message.setReject('Invalid reply address')
    return
  }
  const { paymentId } = parsedReply

  // 3. Recover vaultId + winnerEmail from KV
  const kvRecord = await env.ALIASES?.get(`winner:${paymentId}`)
  if (!kvRecord) {
    console.log(`[gateway] DROP outbound — no KV record for ${paymentId.slice(0, 12)}…`)
    message.setReject('Cannot resolve winner address')
    return
  }
  const { email: winnerEmail, vaultId } = JSON.parse(kvRecord)

  // 4. Fetch vault fields
  const vaultFields = await fetchVaultFieldsRpc(rpc, vaultId)
  if (!vaultFields) {
    console.error(`[gateway] Could not fetch vault ${vaultId}`)
    message.setReject('Gateway error: vault unavailable')
    return
  }
  const outboundFrom = vaultFields.gateway_email // e.g. alice@attention.email
  
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


  // 7. Confirm thread not closed on-chain
  const closed = await isThreadClosed(rpc, vaultFields, paymentId)
  if (closed) {
    console.log(`[gateway] DROP outbound — thread closed for paymentId ${paymentId.slice(0, 12)}…`)
    message.setReject('Conversation closed')
    return
  }

  // 8. Confirm SlotWon record still exists on-chain
  const slotMap    = await fetchSlotWonMap(rpc, env.PACKAGE_ID, vaultId)
  const slotRecord = slotMap[paymentId]

  if (!slotRecord) {
    console.log(`[gateway] DROP outbound — no SlotWon record for paymentId ${paymentId.slice(0, 12)}…`)
    message.setReject('No matching bid record')
    return
  }

  // 9. Send to winner
  const footer = buildOutboundFooter({ paymentId, vaultId })
  console.log(`[gateway] ✓ Seller reply → ${winnerEmail}`)
  // Use the reply address the seller responded to as the From —
  // it is already authorised under the reply subdomain wildcard.
  await sendWithFooter(message, winnerEmail, subject, null, footer, env, outboundFrom)
}

// ── Send helper ───────────────────────────────────────────────────────────────

async function sendWithFooter(message, toAddress, subject, replyTo, footer, env, fromAddress) {
  try {

    // Read and decode the raw message body
    const rawBody  = await new Response(message.raw).text()
    const bodyText = extractTextBody(rawBody)

    // Only X-* headers are allowed by Cloudflare's send API.
    // Reply-To is a top-level field; threading headers are X-* prefixed.
    const extraHeaders = { 'X-Original-From': message.from }
    const inReplyTo  = message.headers.get('in-reply-to')
    const references = message.headers.get('references')
    const messageId  = message.headers.get('message-id')
    if (inReplyTo)  extraHeaders['X-In-Reply-To']  = inReplyTo
    if (references) extraHeaders['X-References']   = references
    if (messageId)  extraHeaders['X-Original-Message-Id'] = messageId

    const payload = {
      to:      toAddress,
      from:    fromAddress,
      subject,
      text:    bodyText + '\n\n' + footer,
      html:    buildHtml(bodyText, footer),
      headers: extraHeaders,
    }
    if (replyTo) payload.replyTo = replyTo

    await env.EMAIL.send(payload)

    console.log(`[gateway] Sent to ${toAddress}`)
  } catch (err) {
    console.error('[gateway] Send failed:', err)
    message.setReject('Send failed')
  }
}

// ── Body helpers ──────────────────────────────────────────────────────────────

/**
 * Extracts the plain-text portion from a raw RFC 5322 message.
 * For multipart messages it returns the first text/plain part.
 * Falls back to everything after the header block.
 */
function extractTextBody(raw) {
  const blankLine = raw.indexOf('\r\n\r\n')
  const body = blankLine >= 0 ? raw.slice(blankLine + 4) : raw

  const boundaryMatch = raw.match(/Content-Type:\s*multipart\/[^;]+;\s*boundary="?([^"\r\n]+)"?/i)
  if (boundaryMatch) {
    const boundary = '--' + boundaryMatch[1].trim()
    const parts = body.split(boundary)
    for (const part of parts) {
      if (/Content-Type:\s*text\/plain/i.test(part)) {
        const partBlank = part.indexOf('\r\n\r\n')
        const partBody = partBlank >= 0
          ? part.slice(partBlank + 4).replace(/--$/, '').trim()
          : part.trim()
        return decodeCTE(part, partBody)
      }
    }
  }

  return decodeCTE(raw, body.trim())
}

function decodeCTE(headers, body) {
  const cteMatch = headers.match(/Content-Transfer-Encoding:\s*(\S+)/i)
  const cte = cteMatch?.[1].toLowerCase().trim()

  if (cte === 'base64') {
    try {
      return atob(body.replace(/\s+/g, ''))
    } catch {
      return body
    }
  }
  if (cte === 'quoted-printable') {
    return body
      .replace(/=\r?\n/g, '')           // soft line breaks
      .replace(/=([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
  }
  return body
}

/** Wraps plain-text body + footer in minimal HTML. */
function buildHtml(bodyText, footer) {
  const esc = s =>
    s.replace(/&/g, '&amp;')
     .replace(/</g, '&lt;')
     .replace(/>/g, '&gt;')
     .replace(/\n/g, '<br>\n')

  return `<!DOCTYPE html><html><body>
<div style="font-family:sans-serif;font-size:14px;line-height:1.6">${esc(bodyText)}</div>
<hr style="margin:24px 0;border:none;border-top:1px solid #ddd">
<pre style="font-size:12px;color:#888;white-space:pre-wrap">${esc(footer)}</pre>
</body></html>`
}

// ── Reply address encoding / decoding ────────────────────────────────────────

export function buildReplyAddress(paymentId, vaultId, replySubdomain) {
  return `${paymentId}.${vaultId}@${replySubdomain}`
}

function parseReplyAddress(to, replySubdomain) {
  const lower = to.toLowerCase().trim()
  if (!lower.endsWith(`@${replySubdomain}`)) return null
  const paymentId = lower.split('@')[0]
  if (!/^[0-9a-f]{64}$/.test(paymentId)) return null
  return { paymentId }
}

// ── Footer builders ───────────────────────────────────────────────────────────

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

function buildOutboundFooter({ paymentId, vaultId }) {
  return [
    '--- AttentionMarket ---',
    `PaymentID: ${paymentId}`,
    `VaultID:   ${vaultId}`,
    '-----------------------',
  ].join('\n')
}
