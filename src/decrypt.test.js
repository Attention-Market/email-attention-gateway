// decrypt.test.js — Unit tests for the ECDH + AES-GCM email encryption scheme
//
// Run with:  node --test decrypt.test.js
//
// Tests cover:
//   - Key generation produces the expected formats (raw public, pkcs8 private)
//   - encrypt → decrypt round-trip recovers the original email
//   - Decryption fails when the wrong private key is used
//   - Decryption fails when the ciphertext is tampered with
//   - Decryption fails when the IV is wrong
//   - decryptSellerEmail() works end-to-end with the env object pattern
//   - extractEncryptedEmailPayload() survives the number-array → base64 conversion
//
// No external dependencies — uses Node's built-in node:test + node:crypto.
// globalThis.crypto is available natively in Node 22.

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'

// ── Inline copies of the functions under test ─────────────────────────────────
// We inline rather than import sui.js so the test file is self-contained and
// doesn't require the @mysten/sui packages to be installed in the test env.

function base64ToBytes(b64) {
  const binary = atob(b64)
  const bytes  = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes
}

function bytesToBase64(value) {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value)
  return btoa(String.fromCharCode(...bytes))
}

function hexToNumberArray(hex) {
  const bytes = []
  for (let i = 0; i < hex.length; i += 2)
    bytes.push(parseInt(hex.slice(i, i + 2), 16))
  return bytes
}

// Matches encrypt.js (frontend)
async function encryptEmail(email, recipientPublicKeyBase64) {
  const recipientPublicKey = await crypto.subtle.importKey(
    'raw',
    base64ToBytes(recipientPublicKeyBase64),
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    []
  )

  const ephemeralKeyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveKey']
  )

  const aesKey = await crypto.subtle.deriveKey(
    { name: 'ECDH', public: recipientPublicKey },
    ephemeralKeyPair.privateKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  )

  const iv         = crypto.getRandomValues(new Uint8Array(12))
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    new TextEncoder().encode(email)
  )

  const ephemeralPublicKeyRaw = await crypto.subtle.exportKey('raw', ephemeralKeyPair.publicKey)

  return {
    ephemeralPublicKey: bytesToBase64(new Uint8Array(ephemeralPublicKeyRaw)),
    iv:                 bytesToBase64(iv),
    ciphertext:         bytesToBase64(new Uint8Array(ciphertext)),
  }
}

// Matches importPrivateKey() in sui.js
async function importPrivateKey(privateKeyBase64) {
  return crypto.subtle.importKey(
    'pkcs8',
    base64ToBytes(privateKeyBase64),
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    ['deriveKey']
  )
}

// Matches decryptSellerEmail() in sui.js (core logic, env.PRIVATE_KEY inlined)
async function decryptEmailPayload(privateKeyBase64, payload) {
  const { ephemeralPublicKey, iv, ciphertext } = payload

  const privateKey = await importPrivateKey(privateKeyBase64)

  const ephemeralPubKey = await crypto.subtle.importKey(
    'raw',
    base64ToBytes(ephemeralPublicKey),
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    []
  )

  const aesKey = await crypto.subtle.deriveKey(
    { name: 'ECDH', public: ephemeralPubKey },
    privateKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  )

  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: base64ToBytes(iv) },
    aesKey,
    base64ToBytes(ciphertext)
  )

  return new TextDecoder().decode(plaintext)
}

// Matches decryptSellerEmail(env, payload) in sui.js
async function decryptSellerEmail(env, payload) {
  if (!env.PRIVATE_KEY) return null
  try {
    return await decryptEmailPayload(env.PRIVATE_KEY, payload)
  } catch {
    return null
  }
}

// Matches extractEncryptedEmailPayload(vaultFields) in sui.js
function extractEncryptedEmailPayload(vaultFields) {
  function bytesToBase64Field(value) {
    if (!value) return ''
    const bytes = typeof value === 'string' ? hexToNumberArray(value) : Array.from(value)
    return btoa(String.fromCharCode(...bytes))
  }
  return {
    ephemeralPublicKey: bytesToBase64Field(vaultFields.encrypted_email_ephemeral_pubkey),
    iv:                 bytesToBase64Field(vaultFields.encrypted_email_iv),
    ciphertext:         bytesToBase64Field(vaultFields.encrypted_email_ciphertext),
  }
}

// ── Key generation helper (mirrors the keygen script) ────────────────────────

async function generateKeyPair() {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveKey']
  )
  const rawPub  = await crypto.subtle.exportKey('raw',   keyPair.publicKey)
  const rawPriv = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey)
  return {
    publicKeyBase64:  bytesToBase64(new Uint8Array(rawPub)),
    privateKeyBase64: bytesToBase64(new Uint8Array(rawPriv)),
  }
}

// ── Shared state ──────────────────────────────────────────────────────────────

let keys        // { publicKeyBase64, privateKeyBase64 }
let altKeys     // a second keypair for wrong-key tests

describe('Key generation', () => {
  before(async () => {
    keys    = await generateKeyPair()
    altKeys = await generateKeyPair()
  })

  it('exports public key as 65-byte uncompressed point (base64 ~88 chars)', () => {
    const raw = base64ToBytes(keys.publicKeyBase64)
    assert.equal(raw.length, 65, 'raw public key should be 65 bytes')
    assert.equal(raw[0], 0x04, 'uncompressed point must start with 0x04')
  })

  it('exports private key in PKCS#8 format (base64 ~100+ chars)', () => {
    const raw = base64ToBytes(keys.privateKeyBase64)
    // PKCS#8 for P-256 is 138 bytes
    assert.equal(raw.length, 138, 'PKCS#8 P-256 private key should be 138 bytes')
    // DER SEQUENCE tag
    assert.equal(raw[0], 0x30, 'PKCS#8 must start with DER SEQUENCE tag 0x30')
  })

  it('importPrivateKey() succeeds with PKCS#8 base64', async () => {
    const key = await importPrivateKey(keys.privateKeyBase64)
    assert.equal(key.type, 'private')
    assert.equal(key.algorithm.name, 'ECDH')
  })

  it('importPrivateKey() rejects garbage input', async () => {
    await assert.rejects(
      () => importPrivateKey(bytesToBase64(new Uint8Array(32).fill(0xff))),
      'should throw on invalid PKCS#8 bytes'
    )
  })
})

describe('Encrypt → decrypt round-trip', () => {
  before(async () => {
    if (!keys) keys = await generateKeyPair()
  })

  it('recovers the original email address', async () => {
    const email   = 'winner@example.com'
    const payload = await encryptEmail(email, keys.publicKeyBase64)
    const result  = await decryptEmailPayload(keys.privateKeyBase64, payload)
    assert.equal(result, email)
  })

  it('works for various email formats', async () => {
    const emails = [
      'simple@example.com',
      'user+tag@sub.domain.co.uk',
      'UPPER@CASE.COM',
      'numbers123@test456.io',
    ]
    for (const email of emails) {
      const payload = await encryptEmail(email, keys.publicKeyBase64)
      const result  = await decryptEmailPayload(keys.privateKeyBase64, payload)
      assert.equal(result, email, `round-trip failed for ${email}`)
    }
  })

  it('produces different ciphertext each call (fresh IV per encryption)', async () => {
    const email    = 'same@example.com'
    const payload1 = await encryptEmail(email, keys.publicKeyBase64)
    const payload2 = await encryptEmail(email, keys.publicKeyBase64)
    // Ephemeral key and IV are random — ciphertexts must differ
    assert.notEqual(payload1.ciphertext,         payload2.ciphertext)
    assert.notEqual(payload1.ephemeralPublicKey,  payload2.ephemeralPublicKey)
    assert.notEqual(payload1.iv,                  payload2.iv)
  })

  it('ephemeral public key is 65 bytes (uncompressed P-256)', async () => {
    const payload = await encryptEmail('test@example.com', keys.publicKeyBase64)
    const raw     = base64ToBytes(payload.ephemeralPublicKey)
    assert.equal(raw.length, 65)
    assert.equal(raw[0], 0x04)
  })

  it('IV is 12 bytes (96-bit AES-GCM nonce)', async () => {
    const payload = await encryptEmail('test@example.com', keys.publicKeyBase64)
    const iv      = base64ToBytes(payload.iv)
    assert.equal(iv.length, 12)
  })
})

describe('Decryption failure cases', () => {
  before(async () => {
    if (!keys) keys = await generateKeyPair()
    if (!altKeys) altKeys = await generateKeyPair()
  })

  it('fails with the wrong private key', async () => {
    const payload = await encryptEmail('test@example.com', keys.publicKeyBase64)
    await assert.rejects(
      () => decryptEmailPayload(altKeys.privateKeyBase64, payload),
      'decryption with wrong key must throw'
    )
  })

  it('fails when ciphertext is tampered', async () => {
    const payload    = await encryptEmail('test@example.com', keys.publicKeyBase64)
    const ctBytes    = base64ToBytes(payload.ciphertext)
    ctBytes[0]      ^= 0xff  // flip bits in first byte
    const tampered   = { ...payload, ciphertext: bytesToBase64(ctBytes) }
    await assert.rejects(
      () => decryptEmailPayload(keys.privateKeyBase64, tampered),
      'tampered ciphertext must throw'
    )
  })

  it('fails when IV is wrong', async () => {
    const payload  = await encryptEmail('test@example.com', keys.publicKeyBase64)
    const wrongIv  = crypto.getRandomValues(new Uint8Array(12))
    const tampered = { ...payload, iv: bytesToBase64(wrongIv) }
    await assert.rejects(
      () => decryptEmailPayload(keys.privateKeyBase64, tampered),
      'wrong IV must throw'
    )
  })

  it('fails when ephemeralPublicKey is replaced', async () => {
    const payload       = await encryptEmail('test@example.com', keys.publicKeyBase64)
    const otherPayload  = await encryptEmail('other@example.com', keys.publicKeyBase64)
    const tampered      = { ...payload, ephemeralPublicKey: otherPayload.ephemeralPublicKey }
    await assert.rejects(
      () => decryptEmailPayload(keys.privateKeyBase64, tampered),
      'wrong ephemeral key must throw'
    )
  })
})

describe('decryptSellerEmail() — env wrapper', () => {
  before(async () => {
    if (!keys) keys = await generateKeyPair()
  })

  it('returns decrypted email when env.PRIVATE_KEY is set', async () => {
    const email   = 'seller@example.com'
    const payload = await encryptEmail(email, keys.publicKeyBase64)
    const result  = await decryptSellerEmail({ PRIVATE_KEY: keys.privateKeyBase64 }, payload)
    assert.equal(result, email)
  })

  it('returns null when env.PRIVATE_KEY is missing', async () => {
    const payload = await encryptEmail('test@example.com', keys.publicKeyBase64)
    const result  = await decryptSellerEmail({}, payload)
    assert.equal(result, null)
  })

  it('returns null on decryption error (wrong key) instead of throwing', async () => {
    const payload = await encryptEmail('test@example.com', keys.publicKeyBase64)
    const result  = await decryptSellerEmail({ PRIVATE_KEY: altKeys.privateKeyBase64 }, payload)
    assert.equal(result, null)
  })
})

describe('extractEncryptedEmailPayload() — Sui field format simulation', () => {
  before(async () => {
    if (!keys) keys = await generateKeyPair()
  })

  it('converts number-array vault fields to base64 and decrypts correctly', async () => {
    const email   = 'vaulttest@example.com'
    const payload = await encryptEmail(email, keys.publicKeyBase64)

    // Simulate how Sui JSON-RPC returns vector<u8> fields — as number arrays
    const toNumberArray = b64 => Array.from(base64ToBytes(b64))
    const vaultFields = {
      encrypted_email_ephemeral_pubkey: toNumberArray(payload.ephemeralPublicKey),
      encrypted_email_iv:               toNumberArray(payload.iv),
      encrypted_email_ciphertext:       toNumberArray(payload.ciphertext),
    }

    const extracted = extractEncryptedEmailPayload(vaultFields)
    const result    = await decryptSellerEmail({ PRIVATE_KEY: keys.privateKeyBase64 }, extracted)
    assert.equal(result, email)
  })

  it('also handles hex-string vault fields', async () => {
    const email   = 'hextest@example.com'
    const payload = await encryptEmail(email, keys.publicKeyBase64)

    // Simulate hex-string format (gRPC transport variant)
    const toHex = b64 => Array.from(base64ToBytes(b64))
      .map(b => b.toString(16).padStart(2, '0')).join('')
    const vaultFields = {
      encrypted_email_ephemeral_pubkey: toHex(payload.ephemeralPublicKey),
      encrypted_email_iv:               toHex(payload.iv),
      encrypted_email_ciphertext:       toHex(payload.ciphertext),
    }

    const extracted = extractEncryptedEmailPayload(vaultFields)
    const result    = await decryptSellerEmail({ PRIVATE_KEY: keys.privateKeyBase64 }, extracted)
    assert.equal(result, email)
  })
})