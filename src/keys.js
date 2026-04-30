import { x448 } from '@noble/curves/ed448.js'
import * as ed from '@noble/ed25519'
import { sha512 } from '@noble/hashes/sha2.js'
import { ml_kem512 } from '@noble/post-quantum/ml-kem.js'

import { randomBytes } from '@noble/hashes/utils.js'

ed.hashes.sha512 = sha512
ed.hashes.sha512Async = (message) => Promise.resolve(sha512(message))

export function generate_E2EE_Keys() {
  const { publicKey: kyberPublicKey, secretKey: kyberSecretKey } = ml_kem512.keygen()
  const { publicKey: ecdhPublicKey, secretKey: ecdhSecretKey } = x448.keygen()
  const { publicKey: edPublicKey, secretKey: edSecretKey } = ed.keygen()

  return {
    ml_kem: {
      public_key: kyberPublicKey,
      secret_key: kyberSecretKey,
    },
    ecdh: {
      public_key: ecdhPublicKey,
      secret_key: ecdhSecretKey,
    },
    ed: {
      public_key: edPublicKey,
      esecret_key: edSecretKey,
    }
  }
}

export function generateByteKey(length) {
  return randomBytes(length);
}

export function generateSalt() {
  return randomBytes(12);
}