import { x25519 } from "@noble/curves/ed25519";
import { ECDHPair, EncryptedMessage, EncryptedPayload, UnencryptedPayload, X25519Pair } from "./types";

/**
 * X25519ECDHMessageChannel is a class that provides a simple API for encrypting and decrypting messages between two parties with X25519 ECDH.
 */
export default class X25519ECDHMessageChannel {
    private myKeyPair: X25519Pair;
    /**
     * Generate a new X25519ECDHMessageChannel: a simple API for encrypting and decrypting messages between two parties with X25519 ECDH.
     * @param {X25519Pair} myKeyPair - optional X25519 key pair. If not provided, a key pair will be generated.
     * @returns {X25519ECDHMessageChannel} X25519ECDHMessageChannel
     */
    constructor(myKeyPair?: X25519Pair) {
        if (myKeyPair) {
            this.myKeyPair = myKeyPair;
        } else {
            this.myKeyPair = X25519ECDHMessageChannel.generateX25KeyPair();
        }
    }

    /**
     * Generate a ECDH derived shared secret from a provided public key. See https://github.com/paulmillr/noble-curves.
     * @param {string} theirPub
     * @returns {ECDHPair} ECDHPair
     */
    private generateSharedSecret(theirPub: Uint8Array): ECDHPair {
        const myPriv = this.myKeyPair.priv;
        const myPub = this.myKeyPair.pub;
        const sharedSecret = x25519.getSharedSecret(myPriv, theirPub);
        return { myPub, sharedSecret };
    }

    /**
     * Import a raw key into the crypto.subtle API for use in encryption and decryption.
     * See https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey.
     * @param {ArrayBuffer} rawKey - raw key to import
     * @returns {Promise<CryptoKey>} CryptoKey
     */
    private importSecretKey(rawKey: ArrayBuffer): Promise<CryptoKey> {
        return crypto.subtle.importKey("raw", rawKey, "AES-GCM", true, ["encrypt", "decrypt"]);
    }

    /**
     * Generate X25519 key pair, in the event the invoking client has not provided a key pair.
     * @returns {X25519Pair} X25519Pair
     */
    private static generateX25KeyPair(): X25519Pair {
        const priv = x25519.utils.randomPrivateKey();
        const pub = x25519.getPublicKey(priv);
        return { pub, priv };
    }

    /**
     * Encrypt a message with AES-GCM, using ECDH derived shared secret as the key.
     * See https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt.
     * Authentication tag is appended to the cipher text for ensuring confidentiality and integrity.
     * @param {string} plainText - plain text to encrypt
     * @param {Uint8Array} secret - secret to encrypt with
     * @returns {EncryptedMessage} EncryptedMessage
     */
    private async encryptMessage(plainText: string, secret: Uint8Array): Promise<EncryptedMessage> {
        const enc = new TextEncoder();
        const encoded = enc.encode(plainText);
        const secretKey = await this.importSecretKey(secret.buffer);
        // iv will be needed for decryption
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const cipherText = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, secretKey, encoded);
        return { cipherText, iv };
    }

    /**
     * Encrypt an unencrypted payload with AES-GCM, using ECDH derived shared secret as the key.
     * @param {UnencryptedPayload} unencryptedPayload - unencrypted payload to encrypt
     * @returns {Promise<EncryptedPayload>} EncryptedPayload
     */
    async encrypt(unencryptedPayload: UnencryptedPayload): Promise<EncryptedPayload> {
        // Derive ECDHSharedSecret
        const theirPub = unencryptedPayload.senderPublicKey;
        const echdPair: ECDHPair = this.generateSharedSecret(theirPub);
        const json = unencryptedPayload.unencryptedData;
        const jsonString: string = JSON.stringify(json);
        const cipherTextIVJSON: EncryptedMessage = await this.encryptMessage(jsonString, echdPair.sharedSecret);
        const encryptedPayload: EncryptedPayload = {
            iv: cipherTextIVJSON.iv,
            encryptedData: cipherTextIVJSON.cipherText,
            senderPublicKey: unencryptedPayload.senderPublicKey,
        };
        return encryptedPayload;
    }

    /**
     * Decrypt cipherText with AES-GCM, with the secret and iv.
     * See https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/decrypt.
     * Authentication tag is appended to the cipher text, and used for ensuring confidentiality and integrity.
     * @param {ArrayBuffer} cipherText - encrypted text
     * @param {Uint8Array} iv - initialization vector
     * @param {Uint8Array} secret - secret to decrypt with
     * @returns {Promise<string>} - decrypted text
     */
    private async decryptMessage(cipherText: ArrayBuffer, iv: Uint8Array, secret: Uint8Array): Promise<string> {
        const secretKey = await this.importSecretKey(secret.buffer);
        const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, secretKey, cipherText);
        const dec = new TextDecoder();
        return dec.decode(decrypted);
    }

    /**
     * Decrypt an encrypted payload with AES-GCM, using ECDH derived shared secret as the key.
     * @param {EncryptedPayload} encryptedPayload - encrypted payload to decrypt
     * @returns {Promise<UnencryptedPayload>} UnencryptedPayload
     */
    async decrypt(encryptedPayload: EncryptedPayload): Promise<UnencryptedPayload> {
        // Derive ECDHSharedSecret
        const echdPair: ECDHPair = this.generateSharedSecret(encryptedPayload.senderPublicKey);
        const cipherText: ArrayBuffer = encryptedPayload.encryptedData;
        const iv: Uint8Array = encryptedPayload.iv;
        const decrypted: string = await this.decryptMessage(cipherText, iv, echdPair.sharedSecret);
        const decryptedJSON: any = JSON.parse(decrypted);
        return { unencryptedData: decryptedJSON, senderPublicKey: encryptedPayload.senderPublicKey };
    }

    /**
     * Get my public key.
     * @returns {Uint8Array} - my public key
     */
    getMyPub(): Uint8Array {
        return this.myKeyPair.pub;
    }
}
