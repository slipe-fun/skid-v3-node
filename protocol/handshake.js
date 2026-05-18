import { x448 } from '@noble/curves/ed448.js'
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js'
import { decrypt, encrypt } from '../src/aes.js';
import { hkdfExpand } from '../src/hkdf.js';
import { numberToBytes } from '../src/utils.js';
import { generateNonce, generateSalt } from '../src/keys.js';
import { buildAAD } from '../src/aad.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes } from '@noble/hashes/utils.js';

export function initiateKeyExchange(sender, receiver) {
    const { cipherText: sender_cipher_text, sharedSecret: sender_pqc_shared_secret } = ml_kem768.encapsulate(sender?.ml_kem?.public_key);
    const { cipherText: receiver_cipher_text, sharedSecret: receiver_pqc_shared_secret } = ml_kem768.encapsulate(receiver?.ml_kem?.public_key);

    const ecdhSharedSecret = x448.getSharedSecret(sender?.ecdh?.secret_key, receiver?.ecdh?.public_key);

    const contextData = concatBytes(
        new TextEncoder().encode(sender.id),
        new TextEncoder().encode(receiver.id),
        sender.ecdh.public_key,
        receiver.ecdh.public_key,
        sender.ml_kem.public_key,
        receiver.ml_kem.public_key,
        sender_cipher_text,
        receiver_cipher_text
    );

    const session_id = sha256(contextData);

    const syncMaterial = concatBytes(sender_pqc_shared_secret, ecdhSharedSecret);
    const syncKey = hkdfExpand(syncMaterial, session_id, new TextEncoder().encode(`skid:v3:sync_key`), 32);

    const nonce = generateNonce();

    const aad = buildAAD("sync_material", {
        session_id,
        sender_id: sender?.id,
        receiver_id: receiver?.id,
        sender_cipher_text,
        receiver_cipher_text
    });

    const encrypted_sync_key = encrypt(syncKey, receiver_pqc_shared_secret, nonce, aad)

    const material = concatBytes(receiver_pqc_shared_secret, ecdhSharedSecret);

    const root_key = hkdfExpand(material, session_id, new TextEncoder().encode(`skid:v3:root_key`), 32)

    const chat_key = hkdfExpand(root_key, session_id, new TextEncoder().encode(`skid:v3:chat_key`), 32)

    return {
        payload: { receiver_cipher_text, sender_cipher_text, encrypted_sync_key },
        chat_key
    }
}

export function finalizeKeyExchange(payload, sender, receiver, isSelf = false) {
    let pqcSharedSecret;
    let ecdhSharedSecret;

    const contextData = concatBytes(
        new TextEncoder().encode(sender.id),
        new TextEncoder().encode(receiver.id),
        sender.ecdh.public_key,
        receiver.ecdh.public_key,
        sender.ml_kem.public_key,
        receiver.ml_kem.public_key,
        payload?.sender_cipher_text,
        payload?.receiver_cipher_text
    );

    const session_id = sha256(contextData);

    if (isSelf) {
        ecdhSharedSecret = x448.getSharedSecret(sender?.ecdh?.secret_key, receiver?.ecdh?.public_key);

        const pqcSharedSecret_A = ml_kem768.decapsulate(payload?.sender_cipher_text, sender?.ml_kem?.secret_key);

        const syncMaterial = concatBytes(pqcSharedSecret_A, ecdhSharedSecret);
        const syncKey = hkdfExpand(syncMaterial, session_id, new TextEncoder().encode(`skid:v3:sync_key`), 32);

        const aad = buildAAD("sync_material", {
            session_id,
            sender_id: sender?.id,
            receiver_id: receiver?.id,
            sender_cipher_text: payload?.sender_cipher_text,
            receiver_cipher_text: payload?.receiver_cipher_text
        })

        pqcSharedSecret = decrypt(syncKey, payload.encrypted_sync_key.ciphertext, payload.encrypted_sync_key.nonce, aad);
    } else {
        ecdhSharedSecret = x448.getSharedSecret(receiver?.ecdh?.secret_key, sender?.ecdh?.public_key);
        pqcSharedSecret = ml_kem768.decapsulate(payload?.receiver_cipher_text, receiver?.ml_kem?.secret_key);
    }

    const material = concatBytes(pqcSharedSecret, ecdhSharedSecret);

    const root_key = hkdfExpand(material, session_id, new TextEncoder().encode(`skid:v3:root_key`), 32)

    const chat_key = hkdfExpand(root_key, session_id, new TextEncoder().encode(`skid:v3:chat_key`), 32)

    return chat_key
}