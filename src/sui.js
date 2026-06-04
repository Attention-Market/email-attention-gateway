// sui.js — Sui client helpers for the AttentionMarket gateway worker
//
// Client strategy (based on @mysten/sui@2.x package structure):
//
//   SuiGrpcClient  (@mysten/sui/grpc)    — object fetching, dynamic fields
//     Uses gRPC-web transport. Construct with { network, baseUrl }.
//
//   SuiJsonRpcClient (@mysten/sui/jsonRpc) — event querying (queryEvents)
//     The only client that exposes queryEvents / getDynamicFieldObject.
//     Not deprecated in source — it lives at the separate /jsonRpc subpath.
//
// We expose a thin `makeClients(env)` that returns both, so call-sites
// pick whichever surface they need.

import { SuiGrpcClient, GrpcWebFetchTransport } from '@mysten/sui/grpc'
import { SuiJsonRpcClient, getJsonRpcFullnodeUrl } from '@mysten/sui/jsonRpc'

// ── Client factory ────────────────────────────────────────────────────────────

/**
 * Create both Sui clients from the worker environment.
 *
 * Env vars (all optional — defaults to testnet):
 *   SUI_NETWORK      — 'mainnet' | 'testnet' | 'devnet' | 'localnet'
 *   SUI_GRPC_URL     — gRPC-web base URL, e.g. https://sui-mainnet.mystenlabs.com
 *   SUI_RPC_URL      — JSON-RPC endpoint (for queryEvents)
 *
 * Returns { grpc, rpc }
 */
export function makeClients(env) {
  const network = env.SUI_NETWORK || 'testnet'

  // gRPC client — object fetching, dynamic field reads
  const grpc = new SuiGrpcClient(
    env.SUI_GRPC_URL
      ? {
          network,
          transport: new GrpcWebFetchTransport({ baseUrl: env.SUI_GRPC_URL }),
        }
      : { network }
  )

  // JSON-RPC client — event querying
  const rpc = new SuiJsonRpcClient({
    url: env.SUI_RPC_URL || getJsonRpcFullnodeUrl(network),
  })

  return { grpc, rpc }
}

// ── Hashing ───────────────────────────────────────────────────────────────────

/**
 * sha256(str) → lowercase hex string.
 * Uses the Web Crypto API available natively in Cloudflare Workers.
 */
export async function sha256hex(str) {
  const data = new TextEncoder().encode(str)
  const buf  = await crypto.subtle.digest('SHA-256', data)
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
}

/**
 * Normalise and hash a sender email address.
 * sha256( email.toLowerCase().trim() )
 * Must match the frontend's pre-bid hashing exactly.
 */
export async function hashEmail(email) {
  return sha256hex(email.toLowerCase().trim())
}

/**
 * Compute the payment_id for a sender/vault pair.
 * payment_id = sha256( emailHash + ':' + vaultId )
 * Must match Profile.jsx and the Move contract exactly.
 */
export async function computePaymentId(email, vaultId) {
  const emailHash = await hashEmail(email)
  return sha256hex(`${emailHash}:${vaultId}`)
}

// ── Registry lookup ───────────────────────────────────────────────────────────

/**
 * Resolve a full gateway email (e.g. "alice@attention.email") to a vault ID
 * by querying the Registry's gateway_emails Table dynamic field.
 *
 * The Table<String, ID> stores entries as dynamic fields keyed by the
 * 0x1::string::String BCS encoding of the gateway email.
 *
 * Returns the vault ID string, or null if not found.
 */
export async function vaultIdByGatewayEmail(grpc, registryId, gatewayEmail) {
  if (!registryId) return null
  try {
    const result = await grpc.getDynamicField({
      parentId: registryId,
      name: {
        type: '0x1::string::String',
        bcs:  stringToBcs(gatewayEmail),
      },
    })
    // The value is a 0x2::object::ID — stored as an address-length BCS bytes
    const valueBcs = result?.dynamicField?.value?.bcs
    if (!valueBcs || valueBcs.length === 0) return null
    return '0x' + bytesToHex(valueBcs)
  } catch (err) {
    console.error('[sui] vaultIdByGatewayEmail error:', err.message)
    return null
  }
}

// ── Vault object ──────────────────────────────────────────────────────────────

/**
 * Fetch an AttentionVault object and return its content fields.
 * Uses the gRPC client for low-latency object reads.
 * Returns the raw fields object or null.
 */
export async function fetchVaultFields(grpc, vaultId) {
  try {
    const result = await grpc.getObject({
      objectId: vaultId,
      include:  { content: true },
    })
    // gRPC content is a BCS-encoded blob; for field access we fall back to
    // the JSON-RPC client's showContent path. Pass the rpc client here instead
    // if you need structured field access. See fetchVaultFieldsRpc() below.
    return result?.object ?? null
  } catch (err) {
    console.error('[sui] fetchVaultFields error:', err.message)
    return null
  }
}

/**
 * Fetch vault content fields via JSON-RPC (returns parsed field map).
 * Use this when you need structured field access (e.g. encrypted_email blobs).
 */
export async function fetchVaultFieldsRpc(rpc, vaultId) {
  try {
    const obj = await rpc.getObject({
      id:      vaultId,
      options: { showContent: true },
    })
    return obj?.data?.content?.fields ?? null
  } catch (err) {
    console.error('[sui] fetchVaultFieldsRpc error:', err.message)
    return null
  }
}

/**
 * Pull the three encrypted-email blobs from a vault fields object and
 * return them in the shape the decryption worker expects.
 *
 * Move fields (all vector<u8>):
 *   encrypted_email_ephemeral_pubkey
 *   encrypted_email_iv
 *   encrypted_email_ciphertext
 *
 * Sui JSON-RPC returns vector<u8> as number arrays; we normalise to Base64.
 */
export function extractEncryptedEmailPayload(vaultFields) {
  return {
    ephemeralPublicKey: bytesToBase64(vaultFields.encrypted_email_ephemeral_pubkey),
    iv:                 bytesToBase64(vaultFields.encrypted_email_iv),
    ciphertext:         bytesToBase64(vaultFields.encrypted_email_ciphertext),
  }
}

// ── Decryption worker call ────────────────────────────────────────────────────

/**
 * Call the decrypt.js Cloudflare Worker to decrypt the seller's real email.
 *
 * Env vars:
 *   DECRYPT_WORKER_URL    — internal URL of the decrypt worker
 *   DECRYPT_WORKER_SECRET — shared secret header to restrict access
 *
 * Returns the plaintext email string, or null on failure.
 */
export async function decryptSellerEmail(env, encryptedPayload) {
  const url    = env.DECRYPT_WORKER_URL
  const secret = env.DECRYPT_WORKER_SECRET
  if (!url) {
    console.error('[sui] DECRYPT_WORKER_URL not set')
    return null
  }
  try {
    const resp = await fetch(url, {
      method:  'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(secret ? { 'X-Internal-Secret': secret } : {}),
      },
      body: JSON.stringify(encryptedPayload),
    })
    if (!resp.ok) {
      console.error('[sui] Decrypt worker returned', resp.status)
      return null
    }
    const { email } = await resp.json()
    return email ?? null
  } catch (err) {
    console.error('[sui] decryptSellerEmail error:', err.message)
    return null
  }
}

// ── Dynamic field helpers ─────────────────────────────────────────────────────

/**
 * Check whether a vector<u8> key exists in a Move Table dynamic field.
 * Uses getDynamicFieldObject via the JSON-RPC client (supports vector<u8> keys).
 * Returns true if the entry is present.
 */
async function tableHasKey(rpc, tableId, hexKey) {
  if (!tableId) return false
  const keyBytes = hexToNumberArray(hexKey)
  try {
    const result = await rpc.getDynamicFieldObject({
      parentId: tableId,
      name:     { type: 'vector<u8>', value: keyBytes },
    })
    return !!result?.data
  } catch {
    return false
  }
}

/**
 * Check whether a conversation thread is closed on-chain.
 * vault.closed_threads[payment_id] present → closed.
 */
export async function isThreadClosed(rpc, vaultFields, paymentIdHex) {
  const tableId = vaultFields?.closed_threads?.fields?.id?.id
  return tableHasKey(rpc, tableId, paymentIdHex)
}

// ── SlotWon event index ───────────────────────────────────────────────────────

/**
 * Fetch all SlotWon events for a vault and return a lookup map:
 *   paymentId (hex) → { senderEmailHash: string, bidderAddress: string }
 *
 * Later events overwrite earlier ones — last winning bid for a paymentId wins.
 * Uses the JSON-RPC client (the only one with queryEvents).
 */
export async function fetchSlotWonMap(rpc, packageId, vaultId) {
  const map = {}
  try {
    let cursor = null
    while (true) {
      const result = await rpc.queryEvents({
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
        map[paymentId] = { senderEmailHash, bidderAddress: p.bidder }
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

/** Hex string → number array (for Move vector<u8> dynamic field keys) */
export function hexToNumberArray(hex) {
  const bytes = []
  for (let i = 0; i < hex.length; i += 2)
    bytes.push(parseInt(hex.slice(i, i + 2), 16))
  return bytes
}

/** Byte array or hex string → lowercase hex string */
export function bytesToHex(bytes) {
  if (typeof bytes === 'string') return bytes
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
}

/**
 * Encode a JS string as the BCS bytes for 0x1::string::String.
 * BCS String = ULEB128 length prefix + UTF-8 bytes.
 */
function stringToBcs(str) {
  const utf8 = new TextEncoder().encode(str)
  const len  = utf8.length
  // ULEB128 encode the length (for strings under 128 bytes this is just 1 byte)
  const lenBytes = []
  let remaining = len
  do {
    let byte = remaining & 0x7f
    remaining >>= 7
    if (remaining > 0) byte |= 0x80
    lenBytes.push(byte)
  } while (remaining > 0)
  const result = new Uint8Array(lenBytes.length + utf8.length)
  result.set(lenBytes)
  result.set(utf8, lenBytes.length)
  return result
}

/**
 * Convert a Sui vector<u8> field value to a Base64 string.
 * JSON-RPC returns these as number arrays; hex strings are also handled.
 */
function bytesToBase64(value) {
  if (!value) return ''
  const bytes = typeof value === 'string'
    ? hexToNumberArray(value)
    : Array.from(value)
  return btoa(String.fromCharCode(...bytes))
}