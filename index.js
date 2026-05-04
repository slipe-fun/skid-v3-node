import { decryptBundle, encryptBundle } from "./protocol/bundles.js";
import { finalizeKeyExchange, initiateKeyExchange } from "./protocol/handshake.js";
import { decryptMasterKey, encryptMasterKey } from "./protocol/keys.js";
import { decryptMessage, encryptMessage } from "./protocol/messages.js";
import { getEntropy, getMnemonic } from "./src/bip.js";
import { generate_E2EE_Keys, generateByteKey } from "./src/keys.js";

export const skid = {
    keys: {
        e2ee: {
            generate: generate_E2EE_Keys
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
    },
    bundle: {
        encrypt: encryptBundle,
        decrypt: decryptBundle
    }
}