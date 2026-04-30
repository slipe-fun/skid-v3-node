import { x448 } from '@noble/curves/ed448.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { ml_kem512 } from '@noble/post-quantum/ml-kem.js'

export function hybridEncapsulate(receiverECDHPub, receiverKyberPub, senderECDHPriv) {
  const { cipherText, sharedSecret: pqcSharedSecret } = ml_kem512.encapsulate(receiverKyberPub)
  const ecdhSecret = x448.getSharedSecret(senderECDHPriv, receiverECDHPub).slice(1)
  const sessionKey = sha256(new Uint8Array([...pqcSharedSecret, ...ecdhSecret]))
  return { sessionKey, cipherText }
}

export function hybridDecapsulate(
  senderECDHPub,
  receiverECDHPriv,
  receiverKyberPriv,
  ciphertext,
) {
  const pqcSharedSecret = ml_kem512.decapsulate(ciphertext, receiverKyberPriv)
  const ecdhSecret = x448.getSharedSecret(receiverECDHPriv, senderECDHPub).slice(1)
  const sessionKey = sha256(new Uint8Array([...pqcSharedSecret, ...ecdhSecret]))
  return { sessionKey }
}