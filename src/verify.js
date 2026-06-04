// verify.js — Sui personal message signature verification + reply detection

import { verifyPersonalMessageSignature } from '@mysten/sui/verify'

// ── Signature verification ────────────────────────────────────────────────────

/**
 * Verify a Sui personal-message signature and return the recovered address.
 *
 * @param {string} messageStr   — plaintext string that was signed
 * @param {string} signatureB64 — base64 signature from the [attn:…] tag
 * @returns {Promise<string|null>} Sui address (0x…) or null on failure
 */
export async function recoverSigner(messageStr, signatureB64) {
  try {
    const msgBytes  = new TextEncoder().encode(messageStr)
    const publicKey = await verifyPersonalMessageSignature(msgBytes, signatureB64)
    return publicKey.toSuiAddress()
  } catch (err) {
    console.error('[verify] Signature verification failed:', err.message ?? err)
    return null
  }
}

// ── Subject tag helpers ───────────────────────────────────────────────────────

/**
 * Extract [attn:BASE64SIG] from a subject line.
 * Returns the raw base64 string or null.
 */
export function extractAttnTag(subject) {
  const m = subject.match(/\[attn:([A-Za-z0-9+/=_-]+)\]/)
  return m ? m[1] : null
}

/**
 * Strip [attn:…] tags from a subject line, trimming residual whitespace.
 */
export function cleanSubject(subject) {
  return subject
    .replace(/\s*\[attn:[^\]]+\]/g, '')
    .trim()
}

/**
 * The message string signed on the frontend — must match Profile.jsx exactly.
 * Format: "AttentionMarket:<vaultId>:<paymentId>"
 */
export function buildSignMessage(vaultId, paymentId) {
  return `AttentionMarket:${vaultId}:${paymentId}`
}

// ── Reply detection via standard email threading headers ──────────────────────

/**
 * Determine whether an incoming message is a reply using the standard
 * RFC 5322 threading headers, NOT subject-line conventions:
 *
 *   In-Reply-To: <original-message-id>
 *   References:  <msg-id-1> … <original-message-id>
 *
 * Every compliant MUA (Gmail, Outlook, Apple Mail, Thunderbird, …) sets
 * these automatically when the user hits Reply. We use them as the sole
 * signal for routing — no "[reply-to:]" in subject needed.
 *
 * @param {Headers} headers — the message.headers Headers object
 * @returns {boolean}
 */
export function isReplyMessage(headers) {
  return !!(
    headers.get('in-reply-to') ||
    headers.get('references')
  )
}

// ── Full verification pipeline ────────────────────────────────────────────────

/**
 * Extract [attn:SIG] from subject, verify the Sui wallet signature,
 * and optionally confirm the recovered address matches an expected value.
 *
 * @param {string}      subject         — full email subject line
 * @param {string}      signMessage     — the message string that was signed
 * @param {string|null} expectedAddress — on-chain address to match, or null
 *                                        to skip address matching
 * @returns {Promise<{ ok: boolean, reason: string, recoveredAddress?: string }>}
 */
export async function verifyAttentionToken(subject, signMessage, expectedAddress) {
  const tag = extractAttnTag(subject)
  if (!tag) {
    return { ok: false, reason: 'No [attn:] tag found in subject line' }
  }

  const recovered = await recoverSigner(signMessage, tag)
  if (!recovered) {
    return { ok: false, reason: 'Signature invalid or could not be verified' }
  }

  if (expectedAddress !== null) {
    if (recovered.toLowerCase() !== expectedAddress.toLowerCase()) {
      return {
        ok:     false,
        reason: `Recovered ${recovered.slice(0, 14)}… but expected ${expectedAddress.slice(0, 14)}…`,
      }
    }
  }

  return { ok: true, reason: 'Valid', recoveredAddress: recovered }
}