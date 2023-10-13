export interface Subscription {
    [eventName: string]: ((data: any) => void)[];
}

export interface EncryptedPayload {
    encryptedData: ArrayBuffer;
    iv: Uint8Array;
    senderPublicKey: Uint8Array;
}
export interface UnencryptedPayload {
    unencryptedData: any;
    senderPublicKey: Uint8Array;
}

export type ECDHPair = {
    myPub: Uint8Array;
    sharedSecret: Uint8Array;
};

export type EncryptedMessage = {
    cipherText: ArrayBuffer;
    iv: Uint8Array;
};

export type X25519Pair = {
    pub: Uint8Array;
    priv: Uint8Array;
};
