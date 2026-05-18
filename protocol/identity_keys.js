import { ed448 } from "@noble/curves/ed448.js";
import { buildAAD } from "../src/aad.js";
import { decrypt, encrypt } from "../src/aes.js";
import { hkdfExpand } from "../src/hkdf.js";
import { generateNonce, generateSalt } from "../src/keys.js";
import { base64ToBytes, prepareForSigning } from "../src/utils.js";

export function encryptIdentityKeys(identity_keys, master_key, secret_sign_key) {
    const toEncrypt = new TextEncoder().encode(JSON.stringify({
        ml_kem_secret_key: Buffer.from(identity_keys?.ml_kem?.secret_key).toString("base64"),
        ecdh_secret_key: Buffer.from(identity_keys?.ecdh?.secret_key).toString("base64"),
        ed_secret_key: Buffer.from(identity_keys?.ed?.secret_key).toString("base64"),
    }));

    const salt = generateSalt();
    const nonce = generateNonce();

    const derivedKey = hkdfExpand(master_key, salt, new TextEncoder().encode("skid:v3:master_key"), 32);

    const aad = buildAAD("master_key", {
        nonce,
        ml_kem_public_key: identity_keys?.ml_kem?.public_key,
        ecdh_public_key: identity_keys?.ecdh?.public_key,
        ed_public_key: identity_keys?.ed?.public_key,
    })

    const encrypted = encrypt(derivedKey, toEncrypt, nonce, aad);

    const signature = ed448.sign(new TextEncoder().encode(JSON.stringify(prepareForSigning({
        ...encrypted,
        ml_kem_public_key: identity_keys?.ml_kem?.public_key,
        ecdh_public_key: identity_keys?.ecdh?.public_key,
        ed_public_key: identity_keys?.ed?.public_key,
        salt
    }))), secret_sign_key, { context: new Uint8Array(0) })

    return {
        ...encrypted,
        signature,
        salt
    }
}

export function decryptIdentityKeys(encrypted_identity_keys, public_identity_keys, master_key, public_sign_key) {
    const derivedKey = hkdfExpand(master_key, encrypted_identity_keys?.salt, new TextEncoder().encode("skid:v3:master_key"), 32);

    const aad = buildAAD("master_key", {
        nonce: encrypted_identity_keys?.nonce,
        ml_kem_public_key: public_identity_keys?.ml_kem?.public_key,
        ecdh_public_key: public_identity_keys?.ecdh?.public_key,
        ed_public_key: public_identity_keys?.ed?.public_key,
    })

    if (!ed448.verify(encrypted_identity_keys?.signature, new TextEncoder().encode(JSON.stringify(prepareForSigning({
        ciphertext: encrypted_identity_keys?.ciphertext,
        nonce: encrypted_identity_keys?.nonce,
        ml_kem_public_key: public_identity_keys?.ml_kem?.public_key,
        ecdh_public_key: public_identity_keys?.ecdh?.public_key,
        ed_public_key: public_identity_keys?.ed?.public_key,
        salt: encrypted_identity_keys?.salt
    }))), public_sign_key, { context: new Uint8Array(0) })) throw new Error("invalid signature");

    let identity_keys = decrypt(derivedKey, encrypted_identity_keys?.ciphertext, encrypted_identity_keys?.nonce, aad);

    identity_keys = new TextDecoder().decode(identity_keys)
    identity_keys = JSON.parse(identity_keys)

    return {
        ml_kem_secret_key: base64ToBytes(identity_keys?.ml_kem_secret_key),
        ecdh_secret_key: base64ToBytes(identity_keys?.ecdh_secret_key),
        ed_secret_key: base64ToBytes(identity_keys?.ed_secret_key),
    };
}