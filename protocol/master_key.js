import { ed448 } from "@noble/curves/ed448.js";
import { buildAAD } from "../src/aad.js";
import { decrypt, encrypt } from "../src/aes.js";
import { hkdfExpand } from "../src/hkdf.js";
import { generateNonce, generateSalt } from "../src/keys.js";
import { prepareForSigning } from "../src/utils.js";

export function encryptMasterKey(master_key, recovery_key, secret_sign_key) {
    const salt = generateSalt();
    const nonce = generateNonce();

    const derivedKey = hkdfExpand(recovery_key, salt, new TextEncoder().encode("skid:v3:recovery_key"), 32);

    const aad = buildAAD("master_key", {
        nonce
    })

    const encrypted = encrypt(derivedKey, master_key, nonce, aad);

    const signature = ed448.sign(new TextEncoder().encode(JSON.stringify(prepareForSigning({
        ...encrypted,
        salt
    }))), secret_sign_key, { context: new Uint8Array(0) })

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

    if (!ed448.verify(encrypted_master_key?.signature, new TextEncoder().encode(JSON.stringify(prepareForSigning({
        ciphertext: encrypted_master_key?.ciphertext,
        nonce: encrypted_master_key?.nonce,
        salt: encrypted_master_key?.salt
    }))), public_sign_key, { context: new Uint8Array(0) })) throw new Error("invalid signature");

    return decrypt(derivedKey, encrypted_master_key?.ciphertext, encrypted_master_key?.nonce, aad)
}