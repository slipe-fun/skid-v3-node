import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'

export function hkdfExpand(key, salt, info, length) {
  return hkdf(sha256, key, salt, info, length)
}