import { buildAAD } from "../src/aad.js";
import { decrypt, encrypt } from "../src/aes.js";
import { hkdfExpand } from "../src/hkdf.js";
import { generateSalt } from "../src/keys.js";

export function encryptMasterKey(master_key, recovery_key) {
    const salt = generateSalt();
    const nonce = generateSalt();

    const derivedKey = hkdfExpand(recovery_key, salt, new TextEncoder().encode("skid:v3:master_key"), 32);

    const aad = buildAAD("master_key", {
        nonce
    })

    return {
        ...encrypt(derivedKey, master_key, nonce, aad),
        salt
    }
}

export function decryptMasterKey(encrypted_master_key, recovery_key) {
    const derivedKey = hkdfExpand(recovery_key, encrypted_master_key?.salt, new TextEncoder().encode("skid:v3:master_key"), 32);

    const aad = buildAAD("master_key", {
        nonce: encrypted_master_key?.iv
    })

    return decrypt(derivedKey, encrypted_master_key?.ciphertext, encrypted_master_key?.iv, aad)
}