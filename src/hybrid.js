import { x448 } from '@noble/curves/ed448.js'
import { ml_kem512 } from '@noble/post-quantum/ml-kem.js'
import { decrypt, encrypt } from './aes.js';
import { hkdfExpand } from './hkdf.js';
import { numberToBytes } from './utils.js';
import { generateSalt } from './keys.js';

export function initiateKeyExchange(chat_id, sender_keys, receiver_keys) {
    const { cipherText: senderCipherText, sharedSecret: senderPqcSharedSecret } = ml_kem512.encapsulate(sender_keys?.ml_kem?.public_key);
    const { cipherText: receiverCipherText, sharedSecret: receiverPqcSharedSecret } = ml_kem512.encapsulate(receiver_keys?.ml_kem?.public_key);

    const ecdhSharedSecret = x448.getSharedSecret(sender_keys?.ecdh?.secret_key, receiver_keys?.ecdh?.public_key);

    const syncMaterial = new Uint8Array([...senderPqcSharedSecret, ...ecdhSharedSecret]);
    const syncKey = hkdfExpand(syncMaterial, numberToBytes(chat_id), new TextEncoder().encode(`skid:v3:sync_key`), 32);

    const encryptedSync = encrypt(syncKey, receiverPqcSharedSecret, generateSalt())

    const material = new Uint8Array([...receiverPqcSharedSecret, ...ecdhSharedSecret]);

    const root_key = hkdfExpand(material, numberToBytes(chat_id), new TextEncoder().encode(`skid:v3:root_key`), 32)

    const chat_key = hkdfExpand(root_key, numberToBytes(chat_id), new TextEncoder().encode(`skid:v3:chat_key`), 32)

    return {
        payload: { receiverCipherText, senderCipherText, encryptedSync },
        chat_key
    }
}

export function finalizeKeyExchange(chat_id, payload, sender_keys, receiver_keys, isSelf = false) {
    let pqcSharedSecret;

    const ecdhSharedSecret = x448.getSharedSecret(receiver_keys?.ecdh?.secret_key, sender_keys?.ecdh?.public_key);

    if (isSelf) {
        const pqcSharedSecret_A = ml_kem512.decapsulate(payload?.senderCipherText, sender_keys?.ml_kem?.secret_key);

        const syncMaterial = new Uint8Array([...pqcSharedSecret_A, ...ecdhSharedSecret]);
        const syncKey = hkdfExpand(syncMaterial, numberToBytes(chat_id), new TextEncoder().encode(`skid:v3:sync_key`), 32);

        pqcSharedSecret = decrypt(syncKey, payload.encryptedSync.ciphertext, payload.encryptedSync.nonce);
    } else {
        pqcSharedSecret = ml_kem512.decapsulate(payload?.receiverCipherText, receiver_keys?.ml_kem?.secret_key);
    }

    const material = new Uint8Array([...pqcSharedSecret, ...ecdhSharedSecret]);

    const root_key = hkdfExpand(material, numberToBytes(chat_id), new TextEncoder().encode(`skid:v3:root_key`), 32)

    const chat_key = hkdfExpand(root_key, numberToBytes(chat_id), new TextEncoder().encode(`skid:v3:chat_key`), 32)

    return chat_key
}