import { x448 } from "@noble/curves/ed448.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { decrypt, encrypt } from "./aes.js";
import { generateSalt } from "./keys.js";

export function wrapKeyWithECDH(publicKey, sessionKey) {
    const { publicKey: ephemeralECDHPublicKey, secretKey: ephemeralECDHSecretKey } = x448.keygen();

    const shared = x448.getSharedSecret(ephemeralECDHSecretKey, publicKey)

    const key = sha256(shared)

    const nonce = generateSalt();

    const encypted = encrypt(key, sessionKey, nonce)

    return {
        ...encypted,
        publicKey: ephemeralECDHPublicKey
    }
}

export function unwrapKeyWithECDH(secretKey, ephemeralPublicKey, ciphertext, nonce) {
    const shared = x448.getSharedSecret(secretKey, ephemeralPublicKey)

    const key = sha256(shared)

    return decrypt(key, ciphertext, nonce)
}