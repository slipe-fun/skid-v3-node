import { gcmsiv } from '@noble/ciphers/aes.js'
import { generateSalt } from './keys.js'

export function encrypt(key, content, iv, aad) {
  const cipher = gcmsiv(key, iv, aad)
  return {
    ciphertext: cipher.encrypt(content),
    iv
  }
}

export function decrypt(key, ciphertext, iv, aad) {
  const cipher = gcmsiv(key, iv, aad)
  return cipher.decrypt(ciphertext)
}