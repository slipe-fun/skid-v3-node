import { ed448 } from "@noble/curves/ed448.js";
import { buildAAD } from "../src/aad.js";
import { decrypt, encrypt } from "../src/aes.js";
import { hkdfExpand } from "../src/hkdf.js";
import { hybridDecapsulate, hybridEncapsulate } from "../src/hybrid.js";
import { generateSalt } from "../src/keys.js";

export function encryptMessage(receiver, sender, secret_sign_key, content) {
    const { sessionKey, cipherText: encapsulated_key, publicKey: ephemeral_ecdh_key } = hybridEncapsulate(receiver?.ecdh?.public_key, receiver?.ml_kem?.public_key, sender?.ecdh?.secret_key);

    const salt = generateSalt();
    const nonce = generateSalt();

    const derivedKey = hkdfExpand(sessionKey, salt, new TextEncoder().encode(`skid:v3:message:${sender?.id}:${receiver?.id}`), 32);

    const aad = buildAAD('message', {
        nonce,
        encapsulated_key,
        ephemeral_ecdh_key,
        sender_id: sender?.id,
        receiver_id: receiver?.id,
        sender_keys: {
            public_key: sender?.ecdh?.public_key,
        },
        receiver_keys: {
            public_key: receiver?.ecdh?.public_key,
        }
    })

    const encrypted = encrypt(derivedKey, content, nonce, aad);

    const signature = ed448.sign(new TextEncoder().encode(JSON.stringify({
        ...encrypted,
        encapsulated_key,
        ephemeral_ecdh_key,
        sender_id: sender?.id,
        receiver_id: receiver?.id,
        sender_keys: { public_key: sender?.ecdh?.public_key },
        receiver_keys: { public_key: receiver?.ecdh?.public_key },
    })), secret_sign_key)

    return {
        ...encrypted,
        encapsulated_key,
        ephemeral_ecdh_key,
        signature,
        salt
    }
}

export function decryptMessage(receiver, sender, public_sign_key, message) {
    const { sessionKey } = hybridDecapsulate(message?.ephemeral_ecdh_key, sender?.ecdh?.public_key, receiver?.ecdh?.secret_key, receiver?.ml_kem?.secret_key, message?.encapsulated_key);

    const derivedKey = hkdfExpand(sessionKey, message?.salt, new TextEncoder().encode(`skid:v3:message:${sender?.id}:${receiver?.id}`), 32);

    const aad = buildAAD('message', {
        nonce: message?.nonce,
        encapsulated_key: message?.encapsulated_key,
        ephemeral_ecdh_key: message?.ephemeral_ecdh_key,
        sender_id: sender?.id,
        receiver_id: receiver?.id,
        sender_keys: {
            public_key: sender?.ecdh?.public_key,
        },
        receiver_keys: {
            public_key: receiver?.ecdh?.public_key,
        }
    })

    if (!ed448.verify(message?.signature, new TextEncoder().encode(JSON.stringify({
        ciphertext: message?.ciphertext,
        nonce: message?.nonce,
        encapsulated_key: message?.encapsulated_key,
        ephemeral_ecdh_key: message?.ephemeral_ecdh_key,
        sender_id: sender?.id,
        receiver_id: receiver?.id,
        sender_keys: { public_key: sender?.ecdh?.public_key },
        receiver_keys: { public_key: receiver?.ecdh?.public_key },
    })), public_sign_key)) throw new Error("invalid signature");

    return decrypt(derivedKey, message?.ciphertext, message?.nonce, aad);
}
