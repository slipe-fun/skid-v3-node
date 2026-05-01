import { skid } from "./index.js";

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

const user_keys_A = skid.keys.e2ee.generate()
const user_keys_B = skid.keys.e2ee.generate()

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

// generate e2ee keys

const chat_user_A = { id: 1, chat_id: 5, ...skid.keys.e2ee.generate() };
const chat_user_B = { id: 2, chat_id: 5, ...skid.keys.e2ee.generate() };

// encrypt and decrypt message by e2ee keys

const encryptedMessage = skid.message.encrypt(chat_user_B, chat_user_A, user_keys_A.ed.secret_key, new TextEncoder().encode("the first skid v3 message"))
const decryptedMessage = skid.message.decrypt(chat_user_B, chat_user_A, user_keys_A.ed.public_key, encryptedMessage)