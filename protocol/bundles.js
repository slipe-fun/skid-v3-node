import { ed448 } from "@noble/curves/ed448.js";
import { buildAAD } from "../src/aad.js";
import { decrypt, encrypt } from "../src/aes.js";
import { hkdfExpand } from "../src/hkdf.js";
import { generateSalt } from "../src/keys.js";

export function encryptBundle(key, secret_sign_key, keys) {
    const bundle = keys?.filter(Boolean).map(key => ({
        chat_id: key?.chat_id,
        ml_kem: {
            public_key: key?.ml_kem?.public_key,
            secret_key: key?.ml_kem?.secret_key,
        },
        ecdh: {
            public_key: key?.ecdh?.public_key,
            secret_key: key?.ecdh?.secret_key,
        }
    }));

    const salt = generateSalt();
    const nonce = generateSalt();

    const derivedKey = hkdfExpand(key, salt, new TextEncoder().encode("skid:v3:bundle"), 32);

    const aad = buildAAD("bundle", {
        nonce
    })

    const encrypted = encrypt(derivedKey, new TextEncoder().encode(JSON.stringify(bundle)), nonce, aad);

    const signature = ed448.sign(new TextEncoder().encode(JSON.stringify({
        ...encrypted,
    })), secret_sign_key)

    return {
        ...encrypted,
        signature,
        salt
    }
}

export function decryptBundle(key, public_sign_key, bundle) {
    const derivedKey = hkdfExpand(key, bundle?.salt, new TextEncoder().encode("skid:v3:bundle"), 32);

    const aad = buildAAD("bundle", {
        nonce: bundle?.nonce
    })

    const decrypted = decrypt(derivedKey, bundle?.ciphertext, bundle?.nonce, aad)

    if (!ed448.verify(bundle?.signature, new TextEncoder().encode(JSON.stringify({
        ciphertext: bundle?.ciphertext,
        nonce: bundle?.nonce
    })), public_sign_key)) throw new Error("invalid signature");

    return JSON.parse(new TextDecoder().decode(decrypted))
}