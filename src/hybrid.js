import { x448 } from '@noble/curves/ed448.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { ml_kem512 } from '@noble/post-quantum/ml-kem.js'

export function hybridEncapsulate(receiverECDHPub, receiverKyberPub, senderECDHPriv) {
  const { publicKey: ephemeralECDHPublicKey, secretKey: ephemeralECDHSecretKey } = x448.keygen();
  const ephemeralECDHSharedSecret = x448.getSharedSecret(ephemeralECDHSecretKey, receiverECDHPub)

  const { cipherText, sharedSecret: pqcSharedSecret } = ml_kem512.encapsulate(receiverKyberPub)
  const ecdhSharedSecret = x448.getSharedSecret(senderECDHPriv, receiverECDHPub).slice(1)

  const sessionKey = sha256(new Uint8Array([...pqcSharedSecret, ...ephemeralECDHSharedSecret, ...ecdhSharedSecret]))

  return { sessionKey, cipherText, publicKey: ephemeralECDHPublicKey }
}

export function hybridDecapsulate(
  ephemeralPublicKey,
  senderECDHPub,
  receiverECDHPriv,
  receiverKyberPriv,
  ciphertext,
) {
  const ephemeralECDHSharedSecret = x448.getSharedSecret(receiverECDHPriv, ephemeralPublicKey)

  const pqcSharedSecret = ml_kem512.decapsulate(ciphertext, receiverKyberPriv)

  const ecdhSharedSecret = x448.getSharedSecret(receiverECDHPriv, senderECDHPub).slice(1)

  const sessionKey = sha256(new Uint8Array([...pqcSharedSecret, ...ephemeralECDHSharedSecret, ...ecdhSharedSecret]))

  return { sessionKey }
}