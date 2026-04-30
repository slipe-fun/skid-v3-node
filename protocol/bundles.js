import { decrypt, encrypt } from "../src/aes.js";
import { hkdfExpand } from "../src/hkdf.js";
import { generateSalt } from "../src/keys.js";

export function encryptBundle(key, keys) {
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

    const derivedKey = hkdfExpand(key, salt, new TextEncoder().encode("skid:v3:bundle"), 32);

    return {
        ...encrypt(derivedKey, new TextEncoder().encode(JSON.stringify(bundle))),
        salt
    }
}

export function decryptBundle(key, bundle) {
    const derivedKey = hkdfExpand(key, bundle?.salt, new TextEncoder().encode("skid:v3:bundle"), 32);

    const decrypted = decrypt(derivedKey, bundle?.ciphertext, bundle?.iv)

    return JSON.parse(new TextDecoder().decode(decrypted))
}