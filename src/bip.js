import * as bip39 from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';

export function getMnemonic(key) {
    return bip39.entropyToMnemonic(key, wordlist);
}

export function getEntropy(mnemonic) {
    return bip39.mnemonicToEntropy(mnemonic, wordlist)
}