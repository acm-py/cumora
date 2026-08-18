import assert from 'node:assert/strict'
import test from 'node:test'
import { hashLocalPassword, verifyLocalPassword } from '../local-auth.js'

test('local password hashes verify only their original password', async () => {
  const hash = await hashLocalPassword('correct-password')

  assert.equal(await verifyLocalPassword('correct-password', hash), true)
  assert.equal(await verifyLocalPassword('wrong-password', hash), false)
})

test('local password verification rejects malformed hashes', async () => {
  assert.equal(await verifyLocalPassword('anything', 'not-a-password-hash'), false)
})
