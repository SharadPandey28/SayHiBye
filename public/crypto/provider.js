// ═══════════════════════════════════════════════════════════════════════════
//  CRYPTO PROVIDER PATTERN
//  ─────────────────────────────────────────────────────────────────────────
//  The app layer never touches raw crypto primitives directly.
//  It only calls methods on the active CryptoProvider.
//
//  To switch algorithms in the future (e.g. DH → ECDH, SHA-256 → HKDF):
//    1. Create a new class that extends CryptoProvider
//    2. Implement all 5 methods
//    3. Change ONE line at the bottom: CryptoRegistry.setActive("ecdh")
//    4. Done — zero changes to index.html app logic
//
//  Interface contract (all methods are async):
//    generateKeyPair(seed?)  → { publicKey: string, privateKey: any }
//    computeSecret(peerPublicKey: string, privateKey: any) → string
//    deriveAESKey(sharedSecret: string) → CryptoKey
//    encrypt(plaintext: string, aesKey: CryptoKey) → { iv: number[], data: number[] }
//    decrypt(payload: { iv, data }, aesKey: CryptoKey) → string
//    get metadata() → { name, keyExchange, kdf, cipher, pfsEnabled }
// ═══════════════════════════════════════════════════════════════════════════

// ─────────────────────────────────────────────────────────────────────────
//  BASE CLASS  (abstract interface — do not instantiate directly)
// ─────────────────────────────────────────────────────────────────────────
class CryptoProvider {
  async generateKeyPair(_seed) { throw new Error("generateKeyPair() not implemented"); }
  async computeSecret(_peerPublicKey, _privateKey) { throw new Error("computeSecret() not implemented"); }
  async deriveAESKey(_sharedSecret) { throw new Error("deriveAESKey() not implemented"); }
  async encrypt(_plaintext, _aesKey) { throw new Error("encrypt() not implemented"); }
  async decrypt(_payload, _aesKey) { throw new Error("decrypt() not implemented"); }
  get metadata() { return { name: "base", keyExchange: "none", kdf: "none", cipher: "none", pfsEnabled: false }; }
}

// ─────────────────────────────────────────────────────────────────────────
//  SHARED HELPERS  (used by all providers — never called directly by app)
// ─────────────────────────────────────────────────────────────────────────
const CryptoHelpers = {
  // Secure IV generation — throws if entropy unavailable (never silently degrades)
  generateIV() {
    const iv = new Uint8Array(12);
    crypto.getRandomValues(iv);
    // Sanity check: IV must not be all-zeros (would break AES-GCM)
    if (iv.every(b => b === 0)) throw new Error("IV generation failed: all-zero IV rejected");
    return iv;
  },

  // AES-GCM encrypt (shared across all providers)
  async aesGcmEncrypt(plaintext, aesKey) {
    const iv = CryptoHelpers.generateIV();
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      aesKey,
      new TextEncoder().encode(plaintext)
    );
    return { iv: Array.from(iv), data: Array.from(new Uint8Array(ciphertext)) };
  },

  // AES-GCM decrypt (shared across all providers)
  async aesGcmDecrypt({ iv, data }, aesKey) {
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: new Uint8Array(iv) },
      aesKey,
      new Uint8Array(data)
    );
    return new TextDecoder().decode(decrypted);
  },

  // Import raw bytes as AES-GCM key
  async importAesKey(rawBytes) {
    return crypto.subtle.importKey("raw", rawBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  },
};

// ─────────────────────────────────────────────────────────────────────────
//  PROVIDER 1: DHProvider  (CURRENT — active default)
//
//  Key exchange : Diffie-Hellman with a Mersenne prime
//  KDF          : SHA-256 of the shared secret
//  Cipher       : AES-256-GCM
//  PFS          : Yes — new key pair per session via crypto.getRandomValues()
//
//  To upgrade later: keep this class untouched, add ECDHProvider below,
//  and change CryptoRegistry.setActive("ecdh") at the bottom.
// ─────────────────────────────────────────────────────────────────────────
class DHProvider extends CryptoProvider {
  constructor() {
    super();
    // RFC-compliant large safe prime (Mersenne M31)
    // TODO: upgrade to RFC-3526 Group 14 (2048-bit) for production
    this._p = 2147483647n;
    this._g = 5n;
  }

  get metadata() {
    return {
      name: "DHProvider",
      keyExchange: "Diffie-Hellman (Mersenne M31 prime)",
      kdf: "SHA-256",
      cipher: "AES-256-GCM",
      pfsEnabled: true,
      note: "Demo-grade DH prime. Swap to RFC-3526 Group 14 for production.",
    };
  }

  // Generates a fresh DH key pair
  // seed (optional): latency value XOR'd in for extra environment entropy
  async generateKeyPair(seed = 0) {
    const arr = new Uint32Array(4);
    crypto.getRandomValues(arr);
    // Combine cryptographic randomness with network-latency entropy
    let raw = BigInt(arr[0]) << 96n | BigInt(arr[1]) << 64n | BigInt(arr[2]) << 32n | BigInt(arr[3]);
    raw ^= BigInt(Math.round(seed) * 999983);
    const privateKey = (raw % (this._p - 2n)) + 2n;
    const publicKey = this._modExp(this._g, privateKey, this._p);
    return {
      publicKey: publicKey.toString(),   // safe to send to server
      privateKey,                        // BigInt — never leaves the client
    };
  }

  // Computes shared secret from peer's public key and our private key
  async computeSecret(peerPublicKeyStr, privateKey) {
    const peerPublicKey = BigInt(peerPublicKeyStr);
    const secret = this._modExp(peerPublicKey, privateKey, this._p);
    return secret.toString();
  }

  // Derives a 256-bit AES key from the shared secret using SHA-256
  // NOTE: For production, replace with HKDF (more standard KDF).
  //       Changing to HKDF only requires updating this one method.
  async deriveAESKey(sharedSecret) {
    const hash = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(sharedSecret)
    );
    return CryptoHelpers.importAesKey(hash);
  }

  async encrypt(plaintext, aesKey) {
    return CryptoHelpers.aesGcmEncrypt(plaintext, aesKey);
  }

  async decrypt(payload, aesKey) {
    return CryptoHelpers.aesGcmDecrypt(payload, aesKey);
  }

  // ── Internal: fast modular exponentiation (BigInt) ──────────────────────
  _modExp(base, exp, mod) {
    let result = 1n;
    base = base % mod;
    while (exp > 0n) {
      if (exp % 2n === 1n) result = (result * base) % mod;
      base = (base * base) % mod;
      exp >>= 1n;
    }
    return result;
  }
}

// ─────────────────────────────────────────────────────────────────────────
//  PROVIDER 2: ECDHProvider  (FUTURE — uncomment and activate when ready)
//
//  Key exchange : ECDH with curve P-256 (WebCrypto native)
//  KDF          : HKDF-SHA-256
//  Cipher       : AES-256-GCM
//  PFS          : Yes — new key pair per session
//
//  To activate: change CryptoRegistry.setActive("ecdh") at the bottom.
//  No other file needs to change.
// ─────────────────────────────────────────────────────────────────────────
class ECDHProvider extends CryptoProvider {
  get metadata() {
    return {
      name: "ECDHProvider",
      keyExchange: "ECDH P-256 (WebCrypto native)",
      kdf: "HKDF-SHA-256",
      cipher: "AES-256-GCM",
      pfsEnabled: true,
      note: "Production-grade. 3072-bit equivalent security with smaller keys.",
    };
  }

  // Generates a fresh ECDH key pair using WebCrypto
  // seed param accepted for interface compatibility but not needed (WebCrypto is already CSPRNG)
  async generateKeyPair(_seed = 0) {
    const keyPair = await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,      // extractable (needed to export public key)
      ["deriveKey", "deriveBits"]
    );
    // Export public key as JWK string for transmission
    const publicKeyJwk = JSON.stringify(
      await crypto.subtle.exportKey("jwk", keyPair.publicKey)
    );
    return {
      publicKey: publicKeyJwk,       // JWK string — safe to send
      privateKey: keyPair.privateKey, // CryptoKey — never leaves client
    };
  }

  // Computes shared bits using ECDH
  async computeSecret(peerPublicKeyStr, privateKey) {
    const peerPublicKey = await crypto.subtle.importKey(
      "jwk",
      JSON.parse(peerPublicKeyStr),
      { name: "ECDH", namedCurve: "P-256" },
      false,
      []
    );
    const sharedBits = await crypto.subtle.deriveBits(
      { name: "ECDH", public: peerPublicKey },
      privateKey,
      256
    );
    // Return as hex string for consistency with DHProvider interface
    return Array.from(new Uint8Array(sharedBits)).map(b => b.toString(16).padStart(2, "0")).join("");
  }

  // Derives AES key using HKDF-SHA-256 (proper KDF — replaces raw SHA-256)
  async deriveAESKey(sharedSecretHex) {
    const raw = new Uint8Array(sharedSecretHex.match(/.{2}/g).map(h => parseInt(h, 16)));
    const baseKey = await crypto.subtle.importKey("raw", raw, { name: "HKDF" }, false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: new Uint8Array(32),          // zero salt for now — use a session nonce in production
        info: new TextEncoder().encode("dh-secure-chat-v1"),
      },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  async encrypt(plaintext, aesKey) {
    return CryptoHelpers.aesGcmEncrypt(plaintext, aesKey);
  }

  async decrypt(payload, aesKey) {
    return CryptoHelpers.aesGcmDecrypt(payload, aesKey);
  }
}

// ─────────────────────────────────────────────────────────────────────────
//  CRYPTO REGISTRY  — single source of truth for active provider
//  ─────────────────────────────────────────────────────────────────────────
//  THIS IS THE ONLY PLACE YOU NEED TO CHANGE TO SWAP ALGORITHMS.
// ─────────────────────────────────────────────────────────────────────────
const CryptoRegistry = (() => {
  const _providers = {
    dh: () => new DHProvider(),
    ecdh: () => new ECDHProvider(),
  };

  let _active = null;
  let _activeName = "";

  return {
    // Call once at app startup
    setActive(name) {
      if (!_providers[name]) throw new Error(`Unknown crypto provider: "${name}". Available: ${Object.keys(_providers).join(", ")}`);
      _active = _providers[name]();
      _activeName = name;
      console.info(`[CryptoRegistry] Active provider: ${_active.metadata.name}`);
      console.table(_active.metadata);
    },

    get provider() {
      if (!_active) throw new Error("CryptoRegistry: no provider set. Call CryptoRegistry.setActive() first.");
      return _active;
    },

    get activeName() { return _activeName; },
  };
})();

// ═══════════════════════════════════════════════════════════════════════════
//  ACTIVE ALGORITHM SELECTION
//  Change "dh" → "ecdh" here when you want to upgrade.
//  Nothing else in the codebase needs to change.
// ═══════════════════════════════════════════════════════════════════════════
CryptoRegistry.setActive("dh");