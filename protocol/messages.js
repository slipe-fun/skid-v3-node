import { buildAAD } from "../src/aad.js";
import { decrypt, encrypt } from "../src/aes.js";
import { hkdfExpand } from "../src/hkdf.js";
import { hybridDecapsulate, hybridEncapsulate } from "../src/hybrid.js";
import { generateSalt } from "../src/keys.js";

export function encryptMessage(receiver, sender, content) {
    const { sessionKey, cipherText: encapsulated_key, publicKey: ephemeral_ecdh_key } = hybridEncapsulate(receiver?.ecdh?.public_key, receiver?.ml_kem?.public_key, sender?.ecdh?.secret_key);

    const salt = generateSalt();
    const nonce = generateSalt();

    const derivedKey = hkdfExpand(sessionKey, salt, new TextEncoder().encode(`skid:v3:message:${sender?.id}:${receiver?.id}`), 32);

    const aad = buildAAD('message', {
        sender_id: sender?.id,
        receiver_id: receiver?.id,
        sender_keys: {
            public_key: sender?.ecdh?.public_key,
        },
        receiver_keys: {
            public_key: receiver?.ecdh?.public_key,
        },
        nonce
    })

    return {
        ...encrypt(derivedKey, content, nonce, aad),
        encapsulated_key,
        ephemeral_ecdh_key,
        salt
    }
}

export function decryptMessage(receiver, sender, message) {
    const { sessionKey } = hybridDecapsulate(message?.ephemeral_ecdh_key, sender?.ecdh?.public_key, receiver?.ecdh?.secret_key, receiver?.ml_kem?.secret_key, message?.encapsulated_key);

    const derivedKey = hkdfExpand(sessionKey, message?.salt, new TextEncoder().encode(`skid:v3:message:${sender?.id}:${receiver?.id}`), 32);

    const aad = buildAAD('message', {
        sender_id: sender?.id,
        receiver_id: receiver?.id,
        sender_keys: {
            public_key: sender?.ecdh?.public_key,
        },
        receiver_keys: {
            public_key: receiver?.ecdh?.public_key,
        },
        nonce: message?.iv
    })

    return decrypt(derivedKey, message?.ciphertext, message?.iv, aad);
}
