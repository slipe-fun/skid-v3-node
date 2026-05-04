import { skid } from "./index.js";
import { finalizeKeyExchange, initiateKeyExchange } from "./protocol/handshake.js";
import { decryptIdentityKeys, encryptIdentityKeys } from "./protocol/identity_keys.js";

// generate user keys

const user_keys_A = { id: 1, ...skid.keys.identity.generate() }
const user_keys_B = { id: 2, ...skid.keys.identity.generate() }

// generate master key

const master_key = skid.keys.master_key.generate();

// encrypt and decrypt bundle by master_key

const encryptedIdentityKeys = skid.keys.identity.encrypt(user_keys_A, master_key, user_keys_A.ed.secret_key);
const decryptedIdentityKeys = skid.keys.identity.decrypt(encryptedIdentityKeys, user_keys_A, master_key, user_keys_A.ed.public_key);

// generate recovery key

const recovery_key = skid.keys.recovery_key.generate();

// get recovery_key mnemonic and entropy from mnemonic

const mnemonic = skid.keys.recovery_key.mnemonic.get(recovery_key);
const entropy = skid.keys.recovery_key.entropy.get(mnemonic);

// encrypt and decrypt master_key

const encryptedMasterKey = skid.keys.master_key.encrypt(master_key, recovery_key, user_keys_A.ed.secret_key);
const decryptedMasterKey = skid.keys.master_key.decrypt(encryptedMasterKey, recovery_key, user_keys_A.ed.public_key);

// get chat key

const handshake = skid.handshake.initiate(10, user_keys_A, user_keys_B);

const senderKey = handshake?.chat_key;
const syncedKey = skid.handshake.finalize(10, handshake?.payload, user_keys_A, user_keys_B, true);
const receiverKey = skid.handshake.finalize(10, handshake.payload, user_keys_A, user_keys_B, false);

// encrypt and decrypt message by e2ee keys

const encryptedMessage = skid.message.encrypt(senderKey, new TextEncoder().encode("the first skid v3 message"), user_keys_A, user_keys_B, user_keys_A.ed.secret_key)
const decryptedMessage = skid.message.decrypt(receiverKey, encryptedMessage, user_keys_A, user_keys_B, user_keys_A.ed.public_key)