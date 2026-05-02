import { gcmsiv } from '@noble/ciphers/aes.js'

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