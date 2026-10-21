//! Keypair generation, storage, and signing.
//!
//! A gitlawb identity is an Ed25519 keypair. The public key encodes into a
//! `did:key` DID. The private key is stored as PKCS#8 PEM on disk.
//!
//! A keypair can carry a public-DID override ([`Keypair::with_public_did`]):
//! the identity it PRESENTS (`did()`, signature `keyid`s, signer fields) then
//! differs from the DID its local key derives. Proxy deployments use this so a
//! coding box can hold a local, disposable key while a trusted proxy re-signs
//! each request with the real private key, which never leaves the proxy.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::did::Did;
use crate::{Error, Result};

/// Environment variable that, when set, names the DID a box's identity should
/// present in place of the one derived from its local PEM. Read by
/// [`apply_proxy_did_from_env`]; a proxy deployment sets it to the agent's real
/// DID, and the trusted proxy re-signs requests with the matching private key.
pub const PROXY_DID_ENV: &str = "GITLAWB_PROXY_DID";

/// An Ed25519 keypair that is the root identity for a gitlawb actor.
#[derive(Clone)]
pub struct Keypair {
    signing_key: SigningKey,
    /// When set, `did()` reports this DID instead of the one derived from the
    /// local signing key. Signatures are still made by the local key.
    public_did: Option<Did>,
}

impl Keypair {
    /// Generate a new random keypair using the OS CSPRNG.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self {
            signing_key,
            public_did: None,
        }
    }

    /// Load a keypair from raw 32-byte seed bytes (zeroized after use).
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self> {
        let signing_key = SigningKey::from_bytes(seed);
        Ok(Self {
            signing_key,
            public_did: None,
        })
    }

    /// The Ed25519 verifying (public) key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// The DID this identity presents: the attached public-DID override when
    /// one is set, otherwise the `did:key` derived from the local public key.
    pub fn did(&self) -> Did {
        match &self.public_did {
            Some(did) => did.clone(),
            None => Did::from_verifying_key(&self.verifying_key()),
        }
    }

    /// The `did:key` derived from the local signing key, ignoring any
    /// public-DID override.
    pub fn local_did(&self) -> Did {
        Did::from_verifying_key(&self.verifying_key())
    }

    /// Attach a public-DID override, replacing any previous one. See [`PROXY_DID_ENV`].
    pub fn with_public_did(mut self, did: Did) -> Self {
        self.public_did = Some(did);
        self
    }

    /// The attached public-DID override, if any.
    pub fn public_did_override(&self) -> Option<&Did> {
        self.public_did.as_ref()
    }

    /// Sign arbitrary bytes. Returns a 64-byte Ed25519 signature.
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.signing_key.sign(msg)
    }

    /// Sign and return base64url-encoded signature string.
    pub fn sign_b64(&self, msg: &[u8]) -> String {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let sig = self.sign(msg);
        URL_SAFE_NO_PAD.encode(sig.to_bytes())
    }

    /// The raw 32-byte Ed25519 seed, wrapped in `Zeroizing` so the copy is
    /// scrubbed on drop. This is the only seed accessor; it is used to derive
    /// the X25519 secret for envelope decryption (see `crate::encrypt`).
    pub fn to_seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.signing_key.to_bytes())
    }

    /// Export to PEM-encoded PKCS#8 private key string.
    pub fn to_pem(&self) -> Result<Zeroizing<String>> {
        use pkcs8::EncodePrivateKey;
        self.signing_key
            .to_pkcs8_pem(pkcs8::LineEnding::LF)
            .map(|pem| Zeroizing::new(pem.to_string()))
            .map_err(|e| Error::Key(e.to_string()))
    }

    /// Load from PEM-encoded PKCS#8 private key string.
    pub fn from_pem(pem: &str) -> Result<Self> {
        use pkcs8::DecodePrivateKey;
        let signing_key = SigningKey::from_pkcs8_pem(pem).map_err(|e| Error::Key(e.to_string()))?;
        Ok(Self {
            signing_key,
            public_did: None,
        })
    }
}

/// Apply the [`PROXY_DID_ENV`] override to `kp`: when the variable is set to a
/// well-formed DID, `kp` presents it instead of the DID its local key derives.
/// Absent or empty, `kp` is returned unchanged. An invalid value is an error,
/// never a silent fallback: a box that believes it presents one identity while
/// the proxy signs as another produces rejections that are hard to diagnose.
pub fn apply_proxy_did_from_env(kp: Keypair) -> Result<Keypair> {
    let raw = match std::env::var(PROXY_DID_ENV) {
        Ok(v) if !v.trim().is_empty() => v,
        _ => return Ok(kp),
    };
    let did: Did = raw.trim().parse().map_err(|e: Error| {
        Error::InvalidDid(format!("{PROXY_DID_ENV} is not a valid DID: {e}"))
    })?;
    Ok(kp.with_public_did(did))
}

/// Verify an Ed25519 signature.
pub fn verify(verifying_key: &VerifyingKey, msg: &[u8], sig_bytes: &[u8; 64]) -> Result<()> {
    let sig = Signature::from_bytes(sig_bytes);
    verifying_key
        .verify_strict(msg, &sig)
        .map_err(|_| Error::SignatureInvalid)
}

/// A signed payload: the data plus the DID of the signer and the signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signed<T> {
    pub payload: T,
    pub signer: Did,
    #[serde(with = "sig_b64")]
    pub signature: [u8; 64],
}

impl<T: Serialize> Signed<T> {
    pub fn new(payload: T, keypair: &Keypair) -> Result<Self> {
        let bytes = serde_json::to_vec(&payload)?;
        let sig = keypair.sign(&bytes);
        Ok(Self {
            payload,
            signer: keypair.did(),
            signature: sig.to_bytes(),
        })
    }
}

impl<T: Serialize> Signed<T> {
    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<()> {
        let bytes = serde_json::to_vec(&self.payload)?;
        verify(verifying_key, &bytes, &self.signature)
    }
}

mod sig_b64 {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let s = String::deserialize(d)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(&s)
            .map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 64 bytes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_pem() {
        let kp = Keypair::generate();
        let pem = kp.to_pem().unwrap();
        let kp2 = Keypair::from_pem(&pem).unwrap();
        assert_eq!(kp.verifying_key(), kp2.verifying_key());
    }

    #[test]
    fn sign_and_verify() {
        let kp = Keypair::generate();
        let msg = b"gitlawb test message";
        let sig = kp.sign(msg);
        let sig_bytes = sig.to_bytes();
        verify(&kp.verifying_key(), msg, &sig_bytes).unwrap();
    }

    #[test]
    fn did_from_keypair() {
        let kp = Keypair::generate();
        let did = kp.did();
        assert!(did.to_string().starts_with("did:key:z6Mk"));
    }

    #[test]
    fn from_seed_round_trip() {
        let kp = Keypair::generate();
        let seed = kp.to_seed();
        let kp2 = Keypair::from_seed(&seed).unwrap();
        assert_eq!(kp.verifying_key(), kp2.verifying_key());
    }

    // `to_seed()` is the only seed accessor on `Keypair` (the raw, unzeroized
    // `seed_bytes()` was removed in #41). Pin its return type so a bare-array
    // accessor can't slip back in, and confirm it is deterministic. The
    // from_seed -> verifying_key round-trip is already covered by
    // `from_seed_round_trip`.
    #[test]
    fn to_seed_returns_zeroizing_and_is_deterministic() {
        let kp = Keypair::generate();
        // The type annotation is the regression guard: the seed must be handed
        // out wrapped in `Zeroizing`, never as a bare `[u8; 32]`.
        let seed: Zeroizing<[u8; 32]> = kp.to_seed();
        assert_eq!(*kp.to_seed(), *seed); // stable across calls
    }

    #[test]
    fn sign_b64_decodes_to_valid_signature() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let kp = Keypair::generate();
        let msg = b"test payload for b64 signing";
        let b64 = kp.sign_b64(msg);
        let sig_bytes: [u8; 64] = URL_SAFE_NO_PAD
            .decode(&b64)
            .expect("sign_b64 must produce valid base64url")
            .try_into()
            .expect("Ed25519 signature must be 64 bytes");
        verify(&kp.verifying_key(), msg, &sig_bytes).unwrap();
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let kp1 = Keypair::generate();
        let kp2 = Keypair::generate();
        let msg = b"some message";
        let sig = kp1.sign(msg);
        let result = verify(&kp2.verifying_key(), msg, &sig.to_bytes());
        assert!(
            result.is_err(),
            "signature from kp1 must not verify under kp2"
        );
    }

    #[test]
    fn verify_rejects_weak_key_signature() {
        // Regression guard for strict verification: a signature forged under a
        // weak (small-order) public key satisfies the verification equation
        // but must be rejected. The identity point is such a key: with R the
        // identity and S = 0, [S]B - [k]A is the identity for any message.
        let mut weak_key_bytes = [0u8; 32];
        weak_key_bytes[0] = 1; // compressed identity point (y = 1, x = 0)
        let weak_vk = VerifyingKey::from_bytes(&weak_key_bytes).unwrap();
        assert!(weak_vk.is_weak(), "identity point must be a weak key");

        let msg = b"forged message";
        let mut forged = [0u8; 64];
        forged[0] = 1; // R = identity point, S = 0

        let result = verify(&weak_vk, msg, &forged);
        assert!(
            result.is_err(),
            "signature under a weak (small-order) public key must be rejected"
        );
    }

    #[test]
    fn signed_payload_round_trip() {
        let kp = Keypair::generate();
        let payload = serde_json::json!({"action": "push", "repo": "my-repo"});
        let signed = Signed::new(payload, &kp).unwrap();
        signed.verify(&kp.verifying_key()).unwrap();
    }

    #[test]
    fn signed_payload_wrong_key_fails() {
        let kp1 = Keypair::generate();
        let kp2 = Keypair::generate();
        let payload = serde_json::json!({"action": "push"});
        let signed = Signed::new(payload, &kp1).unwrap();
        let result = signed.verify(&kp2.verifying_key());
        assert!(
            result.is_err(),
            "Signed payload must not verify under a different key"
        );
    }

    #[test]
    fn from_pem_invalid_input_fails() {
        let result = Keypair::from_pem("this is not valid PEM at all");
        assert!(result.is_err());
    }

    // ── public-DID override (proxy mode) ─────────────────────────────────

    #[test]
    fn public_did_override_changes_presented_did_only() {
        let kp = Keypair::generate();
        let local = kp.did();
        let real: Did = "did:key:z6MkgKE7i43aWhq2ntFx5o7e2tXrSZFay1nY4KZAuyj5WofL"
            .parse()
            .unwrap();

        let overridden = kp.clone().with_public_did(real.clone());
        assert_eq!(overridden.did(), real);
        assert_eq!(overridden.public_did_override(), Some(&real));
        assert_eq!(overridden.local_did(), local, "local DID must not move");
        assert_eq!(
            overridden.verifying_key(),
            kp.verifying_key(),
            "the signing key must not move"
        );
        assert_eq!(kp.public_did_override(), None);
    }

    #[test]
    fn sign_request_keyid_uses_the_override() {
        let kp = Keypair::generate();
        let real: Did = "did:key:z6MkgKE7i43aWhq2ntFx5o7e2tXrSZFay1nY4KZAuyj5WofL"
            .parse()
            .unwrap();
        let overridden = kp.with_public_did(real.clone());

        let headers = crate::http_sig::sign_request(&overridden, "POST", "/api/x", b"{}");
        let sig =
            crate::http_sig::HttpSignature::parse(&headers.signature_input, &headers.signature)
                .unwrap();
        assert_eq!(
            sig.key_id, real,
            "the signature's keyid must name the presented (real) DID"
        );
    }

    /// Serializes the `apply_proxy_did_from_env` tests: they read and write the
    /// process-global `GITLAWB_PROXY_DID` variable and must not race.
    static PROXY_DID_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Set `GITLAWB_PROXY_DID` for the guard's lifetime, restoring the previous
    /// value (or its absence) on drop.
    struct ProxyDidEnv(Option<std::ffi::OsString>);

    impl ProxyDidEnv {
        fn set(value: &str) -> Self {
            let _lock = PROXY_DID_ENV_LOCK.lock().unwrap();
            let prev = std::env::var_os(PROXY_DID_ENV);
            std::env::set_var(PROXY_DID_ENV, value);
            ProxyDidEnv(prev)
        }
        fn unset() -> Self {
            let _lock = PROXY_DID_ENV_LOCK.lock().unwrap();
            let prev = std::env::var_os(PROXY_DID_ENV);
            std::env::remove_var(PROXY_DID_ENV);
            ProxyDidEnv(prev)
        }
    }

    impl Drop for ProxyDidEnv {
        fn drop(&mut self) {
            let _lock = PROXY_DID_ENV_LOCK.lock().unwrap();
            match self.0.take() {
                Some(v) => std::env::set_var(PROXY_DID_ENV, v),
                None => std::env::remove_var(PROXY_DID_ENV),
            }
        }
    }

    #[test]
    fn env_override_applied_when_set() {
        let _env = ProxyDidEnv::set("did:key:z6MkgKE7i43aWhq2ntFx5o7e2tXrSZFay1nY4KZAuyj5WofL");
        let kp = apply_proxy_did_from_env(Keypair::generate()).unwrap();
        assert_eq!(
            kp.did().to_string(),
            "did:key:z6MkgKE7i43aWhq2ntFx5o7e2tXrSZFay1nY4KZAuyj5WofL"
        );
    }

    #[test]
    fn env_override_ignored_when_unset_or_empty() {
        {
            let _env = ProxyDidEnv::unset();
            let kp = apply_proxy_did_from_env(Keypair::generate()).unwrap();
            assert_eq!(kp.public_did_override(), None);
        }
        let _env = ProxyDidEnv::set("   ");
        let kp = apply_proxy_did_from_env(Keypair::generate()).unwrap();
        assert_eq!(kp.public_did_override(), None);
    }

    #[test]
    fn env_override_invalid_value_is_an_error() {
        let _env = ProxyDidEnv::set("not-a-did");
        let err = apply_proxy_did_from_env(Keypair::generate())
            .err()
            .expect("expected the invalid GITLAWB_PROXY_DID to be rejected");
        assert!(err.to_string().contains(PROXY_DID_ENV));
    }
}
