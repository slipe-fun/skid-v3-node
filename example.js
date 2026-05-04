import { skid } from "./index.js";
import { finalizeKeyExchange, initiateKeyExchange } from "./protocol/handshake.js";

// just test data

const chats = [
    {
        chat_id: 1,
        ...skid.keys.e2ee.generate(),
    },
    {
        chat_id: 10,
        ...skid.keys.e2ee.generate(),
    },
    {
        chat_id: 3,
        ...skid.keys.e2ee.generate(),
    },
]

// generate user keys

const user_keys_A = { id: 1, ...skid.keys.e2ee.generate() }
const user_keys_B = { id: 2, ...skid.keys.e2ee.generate() }

// generate master key

const master_key = skid.keys.master_key.generate();

// encrypt and decrypt bundle by master_key

const encryptedBundle = skid.bundle.encrypt(master_key, user_keys_A.ed.secret_key, chats)
const decryptedBundle = skid.bundle.decrypt(master_key, user_keys_A.ed.public_key, encryptedBundle)

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