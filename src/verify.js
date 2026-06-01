// verify.js — Sui personal message signature verification
//
// Uses @mysten/webcrypto-signer which correctly handles:
//   - Sui intent prefix [3, 0, 0] + ULEB128 BCS length encoding
//   - Blake2b-256 hashing of the signing payload
//   - Ed25519 signature verification
//   - Sui address derivation from public key
//
// The frontend signs with useSignPersonalMessage (dapp-kit), which produces:
//   base64( [0x00(flag)] | [ed25519_sig(64)] | [pubkey(32)] )
//
// @mysten/webcrypto-signer's verifyPersonalMessageSignature() takes that
// exact format and returns the public key, from which we derive the address.

import { verifyPersonalMessageSignature } from '@mysten/sui/verify'

// ── Signature verification ────────────────────────────────────────────────────

/**
 * Verify a Sui personal message signature.
 * Returns the recovered Sui address (0x...) or null on failure.
 *
 * @param {string} messageStr   — the plaintext string that was signed
 * @param {string} signatureB64 — base64 signature from [attn:...] subject tag
 * @returns {string|null}
 */
export async function recoverSigner(messageStr, signatureB64) {
  try {
    const msgBytes = new TextEncoder().encode(messageStr)

    // verifyPersonalMessageSignature handles:
    //   - Decoding the base64 signature envelope
    //   - Reconstructing the Sui intent-prefixed BCS payload
    //   - Blake2b-256 hashing
    //   - Ed25519 verification
    //   - Returning the PublicKey object
    const publicKey = await verifyPersonalMessageSignature(msgBytes, signatureB64)

    // Derive the Sui address: Blake2b_256([0x00] || pubkey_bytes)[0..32]
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
 * Strip [attn:...] and [reply-to:...] tags from a subject line.
 */
export function cleanSubject(subject) {
  return subject
    .replace(/\s*\[attn:[^\]]+\]/g, '')
    .replace(/\s*\[reply-to:[^\]]+\]/g, '')
    .trim()
}

/**
 * The message string signed on the frontend — must match Profile.jsx exactly.
 * "AttentionMarket:<vaultId>:<paymentId>"
 */
export function buildSignMessage(vaultId, paymentId) {
  return `AttentionMarket:${vaultId}:${paymentId}`
}

// ── Full verification pipeline ────────────────────────────────────────────────

/**
 * Extract [attn:SIG] from subject, verify the Sui wallet signature,
 * and confirm the recovered address matches the on-chain bidder.
 *
 * @param {string} subject         — full email subject line
 * @param {string} signMessage     — the message string that was signed
 * @param {string} expectedAddress — on-chain bidder address from SlotWon event
 * @returns {{ ok: boolean, reason: string }}
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

  const match = recovered.toLowerCase() === expectedAddress.toLowerCase()
  if (!match) {
    return {
      ok:     false,
      reason: `Recovered ${recovered.slice(0, 14)}… but expected ${expectedAddress.slice(0, 14)}…`,
    }
  }

  return { ok: true, reason: 'Valid' }
}
