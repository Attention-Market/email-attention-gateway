/**
 * test-vault-lookup.mjs
 *
 * Tests vaultIdByGatewayEmail by walking through each step manually
 * so you can see exactly where it fails if something is wrong.
 *
 * Usage:
 *   SUI_NETWORK=testnet \
 *   REGISTRY_ID=0x... \
 *   GATEWAY_EMAIL=alice@attention.email \
 *   node test-vault-lookup.mjs
 */


import { SuiJsonRpcClient, getJsonRpcFullnodeUrl } from '@mysten/sui/jsonRpc'
import { vaultIdByGatewayEmail } from './sui.js'

const REGISTRY_ID   = process.env.REGISTRY_ID
const GATEWAY_EMAIL = process.env.GATEWAY_EMAIL
const NETWORK       = process.env.SUI_NETWORK || 'testnet'
const GRPC_URL      = process.env.SUI_GRPC_URL

if (!REGISTRY_ID)   { console.error('Missing REGISTRY_ID');   process.exit(1) }
if (!GATEWAY_EMAIL) { console.error('Missing GATEWAY_EMAIL'); process.exit(1) }


const rpc = new SuiJsonRpcClient({
  url: process.env.SUI_RPC_URL || getJsonRpcFullnodeUrl(NETWORK),
})


console.log(`\n── Config ───────────────────────────────`)
console.log(`Network:      ${NETWORK}`)
console.log(`Registry ID:  ${REGISTRY_ID}`)
console.log(`Email:        ${GATEWAY_EMAIL}`)
console.log(`─────────────────────────────────────────\n`)

// ── Step 1: fetch the registry object and inspect its raw shape ───────────────
console.log('Step 1: fetching registry object...')
const regObj = await rpc.getObject({
  id:      REGISTRY_ID,
  options: { showContent: true },
})

if (!regObj?.data?.content?.fields) {
  console.error('FAIL — registry object returned no content fields')
  console.error(JSON.stringify(regObj, null, 2))
  process.exit(1)
}

const fields = regObj.data.content.fields
console.log('Registry fields keys:', Object.keys(fields))
console.log('gateway_emails raw:', JSON.stringify(fields.gateway_emails, null, 2))

// ── Step 2: resolve the table ID ─────────────────────────────────────────────
const tableId = fields?.gateway_emails?.fields?.id?.id
if (!tableId) {
  console.error('\nFAIL — could not resolve tableId from gateway_emails')
  console.error('Expected path: fields.gateway_emails.fields.id.id')
  console.error('Actual gateway_emails shape:', JSON.stringify(fields.gateway_emails, null, 2))
  process.exit(1)
}
console.log(`\nStep 2: tableId resolved → ${tableId}`)

// ── Step 3: query the dynamic field ──────────────────────────────────────────
console.log(`\nStep 3: querying dynamic field for "${GATEWAY_EMAIL}"...`)
let field
try {
  field = await rpc.getDynamicFieldObject({
    parentId: tableId,
    name: {
      type:  '0x1::string::String',
      value: GATEWAY_EMAIL,
    },
  })
} catch (err) {
  console.error('FAIL — getDynamicFieldObject threw:', err.message)
  process.exit(1)
}

if (!field?.data) {
  console.error('FAIL — no dynamic field found for that email (email not registered?)')
  console.error(JSON.stringify(field, null, 2))
  process.exit(1)
}

console.log('Dynamic field raw:', JSON.stringify(field.data?.content?.fields, null, 2))

// ── Step 4: extract the vault ID ─────────────────────────────────────────────
const vaultId = field.data?.content?.fields?.value
if (!vaultId) {
  console.error('\nFAIL — could not read vaultId from field.data.content.fields.value')
  console.error('Actual fields shape:', JSON.stringify(field.data?.content?.fields, null, 2))
  process.exit(1)
}
console.log(`\nStep 4: vaultId → ${vaultId}`)

// ── Step 5: run the actual function and compare ───────────────────────────────
console.log('\nStep 5: running vaultIdByGatewayEmail()...')
const result = await vaultIdByGatewayEmail(rpc, REGISTRY_ID, GATEWAY_EMAIL)

if (result === vaultId) {
  console.log(`\n✓ PASS — vaultIdByGatewayEmail returned correct ID: ${result}`)
} else {
  console.error(`\n✗ FAIL — mismatch`)
  console.error(`  expected: ${vaultId}`)
  console.error(`  got:      ${result}`)
}
