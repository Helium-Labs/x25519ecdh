import { x25519 } from "@noble/curves/ed25519";
import { X25519Pair } from "./types";

export function generateX25519KeyPair(): X25519Pair {
    const priv = x25519.utils.randomPrivateKey();
    const pub = x25519.getPublicKey(priv);
    return { pub, priv };
}
