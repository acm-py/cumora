import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto'
import { promisify } from 'node:util'

const scryptAsync = promisify(scrypt)
const SCRYPT_KEY_LENGTH = 64

/** Password hashes are stored as `scrypt:<salt-base64url>:<key-base64url>`. */
export async function hashLocalPassword(password: string): Promise<string> {
  const salt = randomBytes(16).toString('base64url')
  const derived = await scryptAsync(password, salt, SCRYPT_KEY_LENGTH) as Buffer
  return `scrypt:${salt}:${derived.toString('base64url')}`
}

export async function verifyLocalPassword(password: string, encoded: string): Promise<boolean> {
  const [algorithm, salt, expected] = encoded.split(':')
  if (algorithm !== 'scrypt' || !salt || !expected) return false

  try {
    const actual = await scryptAsync(password, salt, SCRYPT_KEY_LENGTH) as Buffer
    const expectedBuffer = Buffer.from(expected, 'base64url')
    return actual.length === expectedBuffer.length && timingSafeEqual(actual, expectedBuffer)
  } catch {
    return false
  }
}
