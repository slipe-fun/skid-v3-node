import { x448 } from '@noble/curves/ed448.js'
import { ml_kem512 } from '@noble/post-quantum/ml-kem.js'
import { decrypt, encrypt } from './aes.js';
import { hkdfExpand } from './hkdf.js';
import { numberToBytes } from './utils.js';
import { generateSalt } from './keys.js';
import { buildAAD } from './aad.js';

export function initiateKeyExchange(chat_id, sender, receiver) {
    const { cipherText: senderCipherText, sharedSecret: senderPqcSharedSecret } = ml_kem512.encapsulate(sender?.ml_kem?.public_key);
    const { cipherText: receiverCipherText, sharedSecret: receiverPqcSharedSecret } = ml_kem512.encapsulate(receiver?.ml_kem?.public_key);

    const ecdhSharedSecret = x448.getSharedSecret(sender?.ecdh?.secret_key, receiver?.ecdh?.public_key);

    const syncMaterial = new Uint8Array([...senderPqcSharedSecret, ...ecdhSharedSecret]);
    const syncKey = hkdfExpand(syncMaterial, numberToBytes(chat_id), new TextEncoder().encode(`skid:v3:sync_key`), 32);

    const nonce = generateSalt();

    const aad = buildAAD("sync_material", {
        chat_id,
        sender_id: sender?.id,
        receiver_id: receiver?.id,
        senderCipherText,
        receiverCipherText
    });

    const encryptedSync = encrypt(syncKey, receiverPqcSharedSecret, nonce, aad)

    const material = new Uint8Array([...receiverPqcSharedSecret, ...ecdhSharedSecret]);

    const root_key = hkdfExpand(material, numberToBytes(chat_id), new TextEncoder().encode(`skid:v3:root_key`), 32)

    const chat_key = hkdfExpand(root_key, numberToBytes(chat_id), new TextEncoder().encode(`skid:v3:chat_key`), 32)

    return {
        payload: { receiverCipherText, senderCipherText, encryptedSync },
        chat_key
    }
}

export function finalizeKeyExchange(chat_id, payload, sender, receiver, isSelf = false) {
    let pqcSharedSecret;

    const ecdhSharedSecret = x448.getSharedSecret(receiver?.ecdh?.secret_key, sender?.ecdh?.public_key);

    if (isSelf) {
        const pqcSharedSecret_A = ml_kem512.decapsulate(payload?.senderCipherText, sender?.ml_kem?.secret_key);

        const syncMaterial = new Uint8Array([...pqcSharedSecret_A, ...ecdhSharedSecret]);
        const syncKey = hkdfExpand(syncMaterial, numberToBytes(chat_id), new TextEncoder().encode(`skid:v3:sync_key`), 32);

        const aad = buildAAD("sync_material", {
            chat_id,
            sender_id: sender?.id,
            receiver_id: receiver?.id,
            senderCipherText: payload?.senderCipherText,
            receiverCipherText: payload?.receiverCipherText
        })

        pqcSharedSecret = decrypt(syncKey, payload.encryptedSync.ciphertext, payload.encryptedSync.nonce, aad);
    } else {
        pqcSharedSecret = ml_kem512.decapsulate(payload?.receiverCipherText, receiver?.ml_kem?.secret_key);
    }

    const material = new Uint8Array([...pqcSharedSecret, ...ecdhSharedSecret]);

    const root_key = hkdfExpand(material, numberToBytes(chat_id), new TextEncoder().encode(`skid:v3:root_key`), 32)

    const chat_key = hkdfExpand(root_key, numberToBytes(chat_id), new TextEncoder().encode(`skid:v3:chat_key`), 32)

    return chat_key
}