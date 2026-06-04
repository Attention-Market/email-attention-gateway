// verify.js — Sui personal message signature verification
//
// Uses @mysten/sui/verify (verifyPersonalMessageSignature) which correctly handles:
//   - Sui intent prefix [3, 0, 0] + ULEB128 BCS length encoding
//   - Blake2b-256 hashing of the signing payload
//   - Ed25519 signature verification
//   - Sui address derivation from the recovered public key
//
// The frontend signs with useSignPersonalMessage (dapp-kit), producing:
//   base64( [0x00 flag] | [ed25519_sig 64 bytes] | [pubkey 32 bytes] )

import { verifyPersonalMessageSignature } from '@mysten/sui/verify'

// ── Signature verification ────────────────────────────────────────────────────

/**
 * Verify a Sui personal-message signature and return the recovered address.
 *
 * @param {string} messageStr   — plaintext string that was signed
 * @param {string} signatureB64 — base64 signature from the [attn:…] subject tag
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
 * Extract [reply-to:email@example.com] from a subject line.
 * Returns the email string or null.
 */
export function extractReplyTo(subject) {
  const m = subject.match(/\[reply-to:([^\]@\s]+@[^\]\s]+)\]/)
  return m ? m[1].trim() : null
}

/**
 * Strip [attn:…] and [reply-to:…] tags from a subject line.
 */
export function cleanSubject(subject) {
  return subject
    .replace(/\s*\[attn:[^\]]+\]/g, '')
    .replace(/\s*\[reply-to:[^\]]+\]/g, '')
    .trim()
}

/**
 * The message string signed on the frontend — must match Profile.jsx exactly.
 * Format: "AttentionMarket:<vaultId>:<paymentId>"
 */
export function buildSignMessage(vaultId, paymentId) {
  return `AttentionMarket:${vaultId}:${paymentId}`
}

// ── Full verification pipeline ────────────────────────────────────────────────

/**
 * Extract [attn:SIG] from subject, verify the Sui wallet signature,
 * and confirm the recovered address matches the on-chain bidder address.
 *
 * @param {string} subject         — full email subject line
 * @param {string} signMessage     — the message string that was signed
 * @param {string} expectedAddress — on-chain bidder address from SlotWon event
 * @returns {Promise<{ ok: boolean, reason: string }>}
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
  if (recovered.toLowerCase() !== expectedAddress.toLowerCase()) {
    return {
      ok:     false,
      reason: `Recovered ${recovered.slice(0, 14)}… but expected ${expectedAddress.slice(0, 14)}…`,
    }
  }
  return { ok: true, reason: 'Valid' }
}