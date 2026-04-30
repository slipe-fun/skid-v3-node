import { buildAAD } from "../src/aad.js";
import { decrypt, encrypt } from "../src/aes.js";
import { hkdfExpand } from "../src/hkdf.js";
import { hybridDecapsulate, hybridEncapsulate } from "../src/hybrid.js";
import { generateSalt } from "../src/keys.js";

export function encryptMessage(receiver, sender, content) {
    const { sessionKey, cipherText: encapsulated_key } = hybridEncapsulate(receiver?.ecdh?.public_key, receiver?.ml_kem?.public_key, sender?.ecdh?.secret_key);

    const salt = generateSalt();

    const derivedKey = hkdfExpand(sessionKey, salt, new TextEncoder().encode("skid:v3:message"), 32);

    const aad = buildAAD('message', {
        sender: sender?.id,
        receiver: receiver?.id
    })

    return {
        ...encrypt(derivedKey, content, aad),
        encapsulated_key,
        salt
    }
}

export function decryptMessage(receiver, sender, message) {
    const { sessionKey } = hybridDecapsulate(sender?.ecdh?.public_key, receiver?.ecdh?.secret_key, receiver?.ml_kem?.secret_key, message?.encapsulated_key);

    const derivedKey = hkdfExpand(sessionKey, message?.salt, new TextEncoder().encode("skid:v3:message"), 32);

    const aad = buildAAD('message', {
        sender: sender?.id,
        receiver: receiver?.id
    })

    return decrypt(derivedKey, message?.ciphertext, message?.iv, aad);
}
