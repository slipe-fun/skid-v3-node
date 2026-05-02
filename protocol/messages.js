import { ed448 } from "@noble/curves/ed448.js";
import { buildAAD } from "../src/aad.js";
import { decrypt, encrypt } from "../src/aes.js";
import { hkdfExpand } from "../src/hkdf.js";
import { generateSalt } from "../src/keys.js";

export function encryptMessage(key, content, sender, receiver, secret_sign_key) {
    const salt = generateSalt();
    const nonce = generateSalt();

    const derivedKey = hkdfExpand(key, salt, new TextEncoder().encode(`skid:v3:message:${sender?.id}:${receiver?.id}`), 32);

    const aad = buildAAD('message', {
        nonce,
        sender_id: sender?.id,
        receiver_id: receiver?.id,
    })

    const encrypted = encrypt(derivedKey, content, nonce, aad);

    const signature = ed448.sign(new TextEncoder().encode(JSON.stringify({
        ...encrypted,
        sender_id: sender?.id,
        receiver_id: receiver?.id,
    })), secret_sign_key)

    return {
        ...encrypted,
        signature,
        salt
    }
}

export function decryptMessage(key, message, sender, receiver, public_sign_key) {
    if (!ed448.verify(message?.signature, new TextEncoder().encode(JSON.stringify({
        ciphertext: message?.ciphertext,
        nonce: message?.nonce,
        sender_id: sender?.id,
        receiver_id: receiver?.id,
    })), public_sign_key)) throw new Error("invalid signature");

    const aad = buildAAD('message', {
        nonce: message?.nonce,
        sender_id: sender?.id,
        receiver_id: receiver?.id,
    })

    const derivedKey = hkdfExpand(key, message?.salt, new TextEncoder().encode(`skid:v3:message:${sender?.id}:${receiver?.id}`), 32);

    return decrypt(derivedKey, message?.ciphertext, message?.nonce, aad);
}
