// sui.js — Sui RPC client for the Cloudflare Email Worker
// Uses @mysten/sui for typed object fetching, event querying, and address hashing.

import { SuiJsonRpcClient, getJsonRpcFullnodeUrl } from '@mysten/sui/jsonRpc'
import { isValidSuiAddress } from '@mysten/sui/utils'

// ── Client factory ────────────────────────────────────────────────────────────

/**
 * Create a SuiClient from the worker environment.
 * Called once per email event — Workers are stateless.
 */
export function makeClient(env) {
  const url = env.SUI_RPC_URL || getJsonRpcFullnodeUrl('testnet')
  return new SuiJsonRpcClient({ url })
}

// ── Hashing ───────────────────────────────────────────────────────────────────

/**
 * sha256(str) using the Web Crypto API available in Cloudflare Workers.
 * Returns a lowercase hex string.
 */
export async function sha256hex(str) {
  const data   = new TextEncoder().encode(str)
  const buf    = await crypto.subtle.digest('SHA-256', data)
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
}

/**
 * Hash a sender email the same way the frontend does before bidding.
 * sha256( email.toLowerCase().trim() )
 */
export async function hashEmail(email) {
  return sha256hex(email.toLowerCase().trim())
}

/**
 * Compute payment_id from a sender email and vault ID.
 * payment_id = sha256( emailHash + ':' + vaultId )
 * Must match Profile.jsx exactly.
 */
export async function computePaymentId(email, vaultId) {
  const emailHash = await hashEmail(email)
  return sha256hex(`${emailHash}:${vaultId}`)
}

// ── Vault fetching ────────────────────────────────────────────────────────────

/**
 * Fetch the AttentionVault object fields from Sui.
 * Returns the raw content fields object or null.
 */
export async function fetchVaultFields(client, vaultId) {
  try {
    const obj = await client.getObject({
      id:      vaultId,
      options: { showContent: true },
    })
    return obj.data?.content?.fields ?? null
  } catch (err) {
    console.error('[sui] fetchVaultFields error:', err.message)
    return null
  }
}

// ── Dynamic field lookups ─────────────────────────────────────────────────────

/**
 * Look up a vector<u8> key in a Move Table dynamic field.
 * Returns true if the field exists (i.e. key is present in the table).
 *
 * @param {SuiClient} client
 * @param {string}    tableId   — the Table object ID (from fields.id.id)
 * @param {string}    hexKey    — the key as a hex string
 */
async function tableHasKey(client, tableId, hexKey) {
  if (!tableId) return false
  const keyBytes = hexToNumberArray(hexKey)
  try {
    const result = await client.getDynamicFieldObject({
      parentId: tableId,
      name:     { type: 'vector<u8>', value: keyBytes },
    })
    return !!result.data
  } catch {
    // getDynamicFieldObject throws if the field doesn't exist
    return false
  }
}

/**
 * Check if a conversation thread is closed on-chain.
 * Reads vault.closed_threads[payment_id].
 */
export async function isThreadClosed(client, vaultFields, paymentIdHex) {
  const tableId = vaultFields?.closed_threads?.fields?.id?.id
  return tableHasKey(client, tableId, paymentIdHex)
}

/**
 * Check if a sender email hash is in the vault whitelist.
 * Reads vault.whitelist[sha256(email)].
 */
export async function isWhitelisted(client, vaultFields, emailHashHex) {
  const tableId = vaultFields?.whitelist?.fields?.id?.id
  return tableHasKey(client, tableId, emailHashHex)
}

// ── SlotWon event index ───────────────────────────────────────────────────────

/**
 * Fetch all SlotWon events for this vault and return a lookup map:
 *   paymentId (hex) → { senderEmailHash (hex), bidderAddress (0x...) }
 *
 * The gateway uses this to verify that the arriving email's sender hash
 * matches what was committed on-chain, and to get the bidder address
 * for signature verification.
 */
export async function fetchSlotWonMap(client, packageId, vaultId) {
  const map = {}

  try {
    let cursor = null
    // Page through all SlotWon events for this package
    // In production with many events, filter by vaultId first if Sui supports it
    while (true) {
      const result = await client.queryEvents({
        query:  { MoveEventType: `${packageId}::attention_market::SlotWon` },
        cursor,
        limit:  50,
        order:  'ascending',
      })

      for (const event of result.data) {
        const p = event.parsedJson
        if (p.vault_id !== vaultId) continue

        const paymentId       = bytesToHex(p.payment_id)
        const senderEmailHash = bytesToHex(p.sender_email_hash)
        const bidderAddress   = p.bidder

        // Later events overwrite earlier ones — last bid for a payment_id wins
        map[paymentId] = { senderEmailHash, bidderAddress }
      }

      if (!result.hasNextPage) break
      cursor = result.nextCursor
    }
  } catch (err) {
    console.error('[sui] fetchSlotWonMap error:', err.message)
  }

  return map
}

// ── Utilities ─────────────────────────────────────────────────────────────────

/** Convert hex string to number array (for Move vector<u8> inputs) */
export function hexToNumberArray(hex) {
  const bytes = []
  for (let i = 0; i < hex.length; i += 2)
    bytes.push(parseInt(hex.slice(i, i + 2), 16))
  return bytes
}

/** Convert a byte array (or already-hex string) to a hex string */
export function bytesToHex(bytes) {
  if (typeof bytes === 'string') return bytes
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
}
