import { finalizeKeyExchange, initiateKeyExchange } from "./protocol/handshake.js";
import { decryptIdentityKeys, encryptIdentityKeys } from "./protocol/identity_keys.js";
import { decryptMasterKey, encryptMasterKey } from "./protocol/master_key.js";
import { decryptMessage, encryptMessage } from "./protocol/messages.js";
import { getEntropy, getMnemonic } from "./src/bip.js";
import { generate_E2EE_Keys, generateByteKey } from "./src/keys.js";

export const skid = {
    keys: {
        identity: {
            generate: generate_E2EE_Keys,
            encrypt: encryptIdentityKeys,
            decrypt: decryptIdentityKeys
        },
        master_key: {
            generate: () => generateByteKey(32),
            encrypt: encryptMasterKey,
            decrypt: decryptMasterKey
        },
        recovery_key: {
            generate: () => generateByteKey(32),
            mnemonic: {
                get: getMnemonic
            },
            entropy: {
                get: getEntropy
            }
        }
    },
    handshake: {
        initiate: initiateKeyExchange,
        finalize: finalizeKeyExchange
    },
    message: {
        encrypt: encryptMessage,
        decrypt: decryptMessage
    }
}