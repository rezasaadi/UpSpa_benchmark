use crate::crypto;
use crate::crypto_tspa;
use crate::protocols::tspa as tspa_proto;
use crate::protocols::upspa as upspa_proto;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::collections::HashMap;

/// Compressed Ristretto point size in bytes.
pub const RISTRETTO_BYTES: usize = 32;

/// Network payload sizes (compact constants used by benchmarks).
pub const NET_UPSPA_SETUP_REQ_BYTES: usize = 32 + 32 + 136 + 32 + 4;
/// 1-byte status response for setup.
pub const NET_UPSPA_SETUP_RESP_BYTES: usize = 1;

/// TSPA registration upload payload: stor_uid(32) || k_i(32) || c_i(48).
pub const NET_TSPA_REG_REQ_BYTES: usize = 32 + 32 + 48;
/// 1-byte status response.
pub const NET_TSPA_REG_RESP_BYTES: usize = 1;

/// TSPA auth request: stor_uid(32) || blinded(32).
pub const NET_TSPA_AUTH_REQ_BYTES: usize = 32 + RISTRETTO_BYTES;
/// TSPA auth response: z(32) || ciphertext(48).
pub const NET_TSPA_AUTH_RESP_BYTES: usize = RISTRETTO_BYTES + 48;

/// UpSPA TOPRF request: uid_hash(32) || blinded(32).
pub const NET_UPSPA_TOPRF_REQ_BYTES: usize = 32 + RISTRETTO_BYTES;
/// UpSPA TOPRF response: partial(32).
pub const NET_UPSPA_TOPRF_RESP_BYTES: usize = RISTRETTO_BYTES;

/// UpSPA fetch ciphersp request: suid(32).
pub const NET_UPSPA_GET_CSP_REQ_BYTES: usize = 32;
/// UpSPA fetch ciphersp response: nonce || ct || tag (CtBlob).
pub const NET_UPSPA_GET_CSP_RESP_BYTES: usize =
    crypto::NONCE_LEN + upspa_proto::CIPHERSP_PT_LEN + crypto::TAG_LEN;

/// UpSPA store ciphersp request: suid(32) || CtBlob.
pub const NET_UPSPA_PUT_CSP_REQ_BYTES: usize = 32 + NET_UPSPA_GET_CSP_RESP_BYTES;
/// 1-byte status response for put ciphersp.
pub const NET_UPSPA_PUT_CSP_RESP_BYTES: usize = 1;

/// UpSPA password update request total size (uid_hash + msg + sig).
/// msg layout: cipherid_blob || share || timestamp || idx
pub const NET_UPSPA_PWDUPD_REQ_BYTES: usize = 32
    + (crypto::NONCE_LEN
        + upspa_proto::CIPHERID_PT_LEN
        + crypto::TAG_LEN
        + 32
        + 8
        + 4)
    + 64;
/// 1-byte status response for password update.
pub const NET_UPSPA_PWDUPD_RESP_BYTES: usize = 1;

/// Minimal in-memory UpSPA storage provider used by benchmarks.
///
/// Note: this is a simple, not thread-safe model intended for testing and
/// benchmarking. It stores the provider's TOPRF share, a signing key used
/// for password-update verification, and an in-memory map of stored ciphertexts.
#[derive(Clone)]
pub struct UpSpaProvider {
    pub sp_id: u32,
    /// TOPRF share `k_i`.
    pub share: Scalar,
    /// Verifying key `σ` stored at the provider for password updates.
    pub sig_pk: VerifyingKey,
    /// Per-login-server records keyed by `SUid`.
    pub ciphersp_db: HashMap<[u8; 32], crypto::CtBlob<{ upspa_proto::CIPHERSP_PT_LEN }>>,
    /// Optional cached latest cipherid blob (not strictly required for the scheme,
    /// but convenient for benchmarking an "apply update" write path).
    pub last_cipherid: crypto::CtBlob<{ upspa_proto::CIPHERID_PT_LEN }>,
    /// Monotonic timestamp guard for password updates.
    pub last_pwdupd_ts: u64,
}

impl UpSpaProvider {
    pub fn new(
        sp_id: u32,
        share: Scalar,
        sig_pk_bytes: [u8; 32],
        initial_cipherid: crypto::CtBlob<{ upspa_proto::CIPHERID_PT_LEN }>,
    ) -> Self {
        let sig_pk = VerifyingKey::from_bytes(&sig_pk_bytes).expect("valid verifying key bytes");
        Self {
            sp_id,
            share,
            sig_pk,
            ciphersp_db: HashMap::new(),
            last_cipherid: initial_cipherid,
            last_pwdupd_ts: 0,
        }
    }

    /// TOPRF sender evaluation: given `blinded = H(pwd) * r` (compressed), return
    /// `partial = blinded * k_i` (compressed).
    #[inline]
    pub fn toprf_send_eval(&self, blinded_bytes: &[u8; 32]) -> [u8; 32] {
        let blinded = CompressedRistretto(*blinded_bytes)
            .decompress()
            .expect("valid compressed Ristretto");
        let y = blinded * self.share;
        y.compress().to_bytes()
    }

    #[inline]
    pub fn get_ciphersp(
        &self,
        suid: &[u8; 32],
    ) -> Option<crypto::CtBlob<{ upspa_proto::CIPHERSP_PT_LEN }>> {
        self.ciphersp_db.get(suid).cloned()
    }

    #[inline]
    pub fn put_ciphersp(&mut self, suid: [u8; 32], blob: crypto::CtBlob<{ upspa_proto::CIPHERSP_PT_LEN }>) {
        // Replace existing entry (benchmark-friendly: avoids map growth).
        self.ciphersp_db.insert(suid, blob);
    }

    /// Verify and apply a password update payload.
    ///
    ///
    /// Expected `msg` layout (client benchmark):
    ///   cipherid_blob (nonce||ct||tag) || share (32) || timestamp (8) || idx (4)
    ///
    /// The function performs lightweight validation in this order:
    /// 1. quick length check, 2. monotonic timestamp check, 3. signature verify,
    /// then parses and applies the new cipherid and TOPRF share.
    /// Returns `true` on success.
    #[inline]
    pub fn apply_password_update(&mut self, msg: &[u8], sig: &Signature) -> bool {
        // Fast reject on timestamp (assumes msg is well-formed).
        const MIN_MSG: usize = crypto::NONCE_LEN
            + upspa_proto::CIPHERID_PT_LEN
            + crypto::TAG_LEN
            + 32
            + 8
            + 4;
        if msg.len() < MIN_MSG {
            return false;
        }
        let ts_off = crypto::NONCE_LEN + upspa_proto::CIPHERID_PT_LEN + crypto::TAG_LEN + 32;
        let mut ts_bytes = [0u8; 8];
        ts_bytes.copy_from_slice(&msg[ts_off..ts_off + 8]);
        let ts = u64::from_le_bytes(ts_bytes);
        if ts < self.last_pwdupd_ts {
            return false;
        }

        if self.sig_pk.verify(msg, sig).is_err() {
            // Signature mismatch: reject update.
            return false;
        }

        // Parse and apply: update cached cipherid and provider share.
        // Parse cipherid blob (nonce || ct || tag)
        let mut nonce = [0u8; crypto::NONCE_LEN];
        nonce.copy_from_slice(&msg[0..crypto::NONCE_LEN]);
        let mut ct = [0u8; upspa_proto::CIPHERID_PT_LEN];
        ct.copy_from_slice(&msg[crypto::NONCE_LEN..crypto::NONCE_LEN + upspa_proto::CIPHERID_PT_LEN]);
        let mut tag = [0u8; crypto::TAG_LEN];
        tag.copy_from_slice(
            &msg[crypto::NONCE_LEN + upspa_proto::CIPHERID_PT_LEN
                ..crypto::NONCE_LEN + upspa_proto::CIPHERID_PT_LEN + crypto::TAG_LEN],
        );
        self.last_cipherid = crypto::CtBlob { nonce, ct, tag };

        // share bytes (32) follow the cipherid blob + tag
        let share_off = crypto::NONCE_LEN + upspa_proto::CIPHERID_PT_LEN + crypto::TAG_LEN;
        let mut share_bytes = [0u8; 32];
        share_bytes.copy_from_slice(&msg[share_off..share_off + 32]);
        self.share = Scalar::from_bytes_mod_order(share_bytes);

        self.last_pwdupd_ts = ts;
        true
    }
}

/// Minimal in-memory TSPA provider storing an OPRF key and ciphertext records.
#[derive(Clone)]
pub struct TspaProvider {
    pub sp_id: u32,
    /// OPRF key `k_i` stored at the provider.
    pub oprf_key: Scalar,
    /// Stored record keyed by stor_uid.
    pub record_db: HashMap<[u8; 32], tspa_proto::Ciphertext>,
}

impl TspaProvider {
    pub fn new(sp_id: u32, oprf_key: Scalar) -> Self {
        Self { sp_id, oprf_key, record_db: HashMap::new() }
    }

    /// OPRF sender evaluation: given `blinded = H(pwd) * r` (compressed), return
    /// `z = blinded * k_i` (compressed).
    #[inline]
    pub fn oprf_send_eval(&self, blinded_bytes: &[u8; 32]) -> [u8; 32] {
        let blinded = CompressedRistretto(*blinded_bytes)
            .decompress()
            .expect("valid compressed Ristretto");
        let z = blinded * self.oprf_key;
        z.compress().to_bytes()
    }

    #[inline]
    pub fn put_record(&mut self, stor_uid: [u8; 32], c: tspa_proto::Ciphertext) {
        self.record_db.insert(stor_uid, c);
    }

    #[inline]
    pub fn get_record(&self, stor_uid: &[u8; 32]) -> Option<tspa_proto::Ciphertext> {
        self.record_db.get(stor_uid).copied()
    }
}

// Helpers

/// Compress a `RistrettoPoint` to 32 bytes (convenience wrapper).
#[inline]
pub fn compress_point(p: &RistrettoPoint) -> [u8; 32] {
    p.compress().to_bytes()
}

/// Derive a fixed-size uid hash used in network payloads.
///
/// In a real deployment this should be a domain-separated hash of the user id
/// and any context/salt. Here it is used for deterministic benchmarking.
#[inline]
pub fn uid_hash(uid: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"uptspa/uid_hash/v1");
    h.update(uid);
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(out.as_bytes());
    r
}

/// Compute the storage identifier used by TSPA providers.
#[inline]
pub fn tspa_stor_uid(uid: &[u8], lsj: &[u8]) -> [u8; 32] {
    crypto_tspa::hash_storuid(uid, lsj)
}
