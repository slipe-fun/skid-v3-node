import { ed448 } from "@noble/curves/ed448.js";
import { buildAAD } from "../src/aad.js";
import { decrypt, encrypt } from "../src/aes.js";
import { hkdfExpand } from "../src/hkdf.js";
import { generateSalt } from "../src/keys.js";

export function encryptMasterKey(master_key, recovery_key, secret_sign_key) {
    const salt = generateSalt();
    const nonce = generateSalt();

    const derivedKey = hkdfExpand(recovery_key, salt, new TextEncoder().encode("skid:v3:recovery_key"), 32);

    const aad = buildAAD("master_key", {
        nonce
    })

    const encrypted = encrypt(derivedKey, master_key, nonce, aad);

    const signature = ed448.sign(new TextEncoder().encode(JSON.stringify({
        ...encrypted,
    })), secret_sign_key)

    return {
        ...encrypted,
        signature,
        salt
    }
}

export function decryptMasterKey(encrypted_master_key, recovery_key, public_sign_key) {
    const derivedKey = hkdfExpand(recovery_key, encrypted_master_key?.salt, new TextEncoder().encode("skid:v3:recovery_key"), 32);

    const aad = buildAAD("master_key", {
        nonce: encrypted_master_key?.nonce
    })

    if (!ed448.verify(encrypted_master_key?.signature, new TextEncoder().encode(JSON.stringify({
        ciphertext: encrypted_master_key?.ciphertext,
        nonce: encrypted_master_key?.nonce
    })), public_sign_key)) throw new Error("invalid signature");

    return decrypt(derivedKey, encrypted_master_key?.ciphertext, encrypted_master_key?.nonce, aad)
}