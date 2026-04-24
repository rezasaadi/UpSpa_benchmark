use aes::Aes256;
use blake3;
use ctr::cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use rand_core::RngCore;

pub const AES_KEY_LEN: usize = 32;
pub const AES_IV_LEN: usize = 16;

// AES-256-CTR (no auth), as used in many TSPA-style benchmarks
type Aes256Ctr = Ctr128BE<Aes256>;

// Domain separation
const DST_H2P: &[u8] = b"tspa/h2p/v1";
const DST_OPRF_OUT: &[u8] = b"tspa/oprf_out/v1";
const DST_STORUID: &[u8] = b"tspa/storuid/v1";
const DST_VINFO: &[u8] = b"tspa/vinfo/v1";

pub fn hash_to_point(msg: &[u8]) -> RistrettoPoint {
    let mut h = blake3::Hasher::new();
    h.update(DST_H2P);
    h.update(msg);

    let mut wide = [0u8; 64];
    h.finalize_xof().fill(&mut wide);
    RistrettoPoint::from_uniform_bytes(&wide)
}

pub fn random_scalar(rng: &mut impl RngCore) -> Scalar {
    loop {
        let mut wide = [0u8; 64];
        rng.fill_bytes(&mut wide);
        let s = Scalar::from_bytes_mod_order_wide(&wide);
        if s != Scalar::ZERO {
            return s;
        }
    }
}

/// OPRF finalize => 32-byte key material from (pwd, Y)
pub fn oprf_finalize(password: &[u8], y: &RistrettoPoint) -> [u8; 32] {
    let y_bytes = y.compress().to_bytes();

    let mut h = blake3::Hasher::new();
    h.update(DST_OPRF_OUT);
    h.update(password);
    h.update(&y_bytes);

    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(out.as_bytes());
    r
}

pub fn hash_storuid(uid: &[u8], lsj: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(DST_STORUID);
    h.update(uid);
    h.update(lsj);

    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(out.as_bytes());
    r
}

pub fn hash_vinfo(rnd32: &[u8; 32], lsj: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(DST_VINFO);
    h.update(rnd32);
    h.update(lsj);

    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(out.as_bytes());
    r
}

/// AES-CTR XOR for exactly 32 bytes
pub fn aes256ctr_xor_32(key: [u8; 32], iv: [u8; 16], mut block: [u8; 32]) -> [u8; 32] {
    let mut cipher = Aes256Ctr::new(&key.into(), &iv.into());
    cipher.apply_keystream(&mut block);
    block
}

pub fn rand_bytes<const N: usize>(rng: &mut impl RngCore) -> [u8; N] {
    let mut out = [0u8; N];
    rng.fill_bytes(&mut out);
    out
}

/// Horner polynomial evaluation
pub fn eval_poly(coeffs: &[Scalar], x: Scalar) -> Scalar {
    let mut acc = Scalar::ZERO;
    for c in coeffs.iter().rev() {
        acc = acc * x + c;
    }
    acc
}

/// Lagrange coefficients for interpolation at x=0
pub fn lagrange_lambdas_at_zero(xs: &[Scalar]) -> Vec<Scalar> {
    let k = xs.len();
    let mut lambdas = Vec::with_capacity(k);

    for j in 0..k {
        let xj = xs[j];
        let mut num = Scalar::ONE;
        let mut den = Scalar::ONE;

        for m in 0..k {
            if m == j {
                continue;
            }
            let xm = xs[m];
            num *= -xm;
            den *= xj - xm;
        }

        lambdas.push(num * den.invert());
    }
    lambdas
}
