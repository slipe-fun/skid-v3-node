import { gcmsiv } from '@noble/ciphers/aes.js'
import { generateSalt } from './keys.js'

export function encrypt(key, content, nonce, aad) {
  const cipher = gcmsiv(key, nonce, aad)
  return {
    ciphertext: cipher.encrypt(content),
    nonce
  }
}

export function decrypt(key, ciphertext, nonce, aad) {
  const cipher = gcmsiv(key, nonce, aad)
  return cipher.decrypt(ciphertext)
}