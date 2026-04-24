use crate::crypto_tspa as crypto;
use crate::crypto_tspa::{AES_IV_LEN};
use blake3;
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use std::hint::black_box;

/// Ciphertext layout: iv(16) || ct(32) = 48 bytes
pub type Ciphertext = [u8; 48];

#[derive(Clone)]
pub struct Fixture {
    pub nsp: usize,
    pub tsp: usize,

    pub uid: Vec<u8>,
    pub lsj: Vec<u8>,
    pub password: Vec<u8>,
    pub pwd_point: RistrettoPoint,

    // x coords 1..=nsp, and lambdas for 1..=tsp at zero
    pub x_all: Vec<Scalar>,
    pub lambdas_sel: Vec<Scalar>,

    // Stored LS value (verification info)
    pub vinfo_db: [u8; 32],

    // Stored SP records (what client would fetch during auth) for first tsp providers
    pub auth_ciphertexts_sel: Vec<Ciphertext>, // length tsp
    pub auth_oprf_keys_sel: Vec<Scalar>,       // length tsp (only for generating Z outside timing)
}

pub struct IterData<'a> {
    // Registration randomness (prepared outside timing)
    pub reg_coeffs: Vec<Scalar>,    // degree t-1, coeffs[0] = rnd
    pub reg_oprf_keys: Vec<Scalar>, // length nsp
    pub reg_ivs: Vec<[u8; AES_IV_LEN]>, // length nsp

    // Authentication randomness + “server replies” (prepared outside timing)
    pub auth_r: Scalar,
    pub auth_z_sel: Vec<RistrettoPoint>, // length tsp

    // Borrowed from fixture
    pub auth_ciphertexts_sel: &'a [Ciphertext],
}

fn seed_bytes(tag: &[u8], nsp: usize, tsp: usize) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(tag);
    h.update(&nsp.to_le_bytes());
    h.update(&tsp.to_le_bytes());
    *h.finalize().as_bytes()
}

fn pack_ciphertext(iv: [u8; 16], ct: [u8; 32]) -> Ciphertext {
    let mut out = [0u8; 48];
    out[..16].copy_from_slice(&iv);
    out[16..].copy_from_slice(&ct);
    out
}
fn unpack_ciphertext(c: Ciphertext) -> ([u8; 16], [u8; 32]) {
    let mut iv = [0u8; 16];
    let mut ct = [0u8; 32];
    iv.copy_from_slice(&c[..16]);
    ct.copy_from_slice(&c[16..]);
    (iv, ct)
}

pub fn make_fixture(nsp: usize, tsp: usize) -> Fixture {
    assert!(tsp >= 1 && tsp <= nsp);

    let seed = seed_bytes(b"tspa/fixture_seed/v1", nsp, tsp);
    let mut rng = ChaCha20Rng::from_seed(seed);

    let uid = b"user123".to_vec();
    let lsj = b"LS1".to_vec();
    let password = b"benchmark password".to_vec();
    let pwd_point = crypto::hash_to_point(&password);

    // x coordinates 1..=nsp
    let mut x_all = Vec::with_capacity(nsp);
    for i in 1..=nsp {
        x_all.push(Scalar::from(i as u64));
    }

    // selected x 1..=tsp
    let mut x_sel = Vec::with_capacity(tsp);
    for i in 1..=tsp {
        x_sel.push(Scalar::from(i as u64));
    }
    let lambdas_sel = crypto::lagrange_lambdas_at_zero(&x_sel);

    // Create a “stored record” for auth: choose rnd, share it, choose per-SP keys, encrypt shares.
    let secret_rnd = crypto::random_scalar(&mut rng);

    let mut coeffs = Vec::with_capacity(tsp);
    coeffs.push(secret_rnd);
    for _ in 1..tsp {
        coeffs.push(crypto::random_scalar(&mut rng));
    }

    let mut oprf_keys_all = Vec::with_capacity(nsp);
    for _ in 0..nsp {
        oprf_keys_all.push(crypto::random_scalar(&mut rng));
    }

    // build ciphertexts for the first tsp providers
    let mut auth_ciphertexts_sel = Vec::with_capacity(tsp);
    for j in 0..tsp {
        let k = oprf_keys_all[j];

        // unblinded OPRF output: Y = P*k
        let y = pwd_point * k;
        let key = crypto::oprf_finalize(&password, &y);

        // share at x=j+1
        let share = crypto::eval_poly(&coeffs, x_all[j]);
        let share_bytes = share.to_bytes();

        let iv = crypto::rand_bytes::<16>(&mut rng);
        let ct = crypto::aes256ctr_xor_32(key, iv, share_bytes);
        auth_ciphertexts_sel.push(pack_ciphertext(iv, ct));
    }

    let auth_oprf_keys_sel = oprf_keys_all[..tsp].to_vec();

    // stored LS verification info
    let vinfo_db = crypto::hash_vinfo(&secret_rnd.to_bytes(), &lsj);

    Fixture {
        nsp,
        tsp,
        uid,
        lsj,
        password,
        pwd_point,
        x_all,
        lambdas_sel,
        vinfo_db,
        auth_ciphertexts_sel,
        auth_oprf_keys_sel,
    }
}

/// Prepare per-iteration randomness (NOT timed by the benchmark binary).
pub fn make_iter_data<'a>(fx: &'a Fixture, rng: &mut impl RngCore) -> IterData<'a> {
    // Registration randomness
    let mut reg_coeffs = Vec::with_capacity(fx.tsp);
    reg_coeffs.push(crypto::random_scalar(rng)); // rnd
    for _ in 1..fx.tsp {
        reg_coeffs.push(crypto::random_scalar(rng));
    }

    let mut reg_oprf_keys = Vec::with_capacity(fx.nsp);
    for _ in 0..fx.nsp {
        reg_oprf_keys.push(crypto::random_scalar(rng));
    }

    let mut reg_ivs = Vec::with_capacity(fx.nsp);
    for _ in 0..fx.nsp {
        reg_ivs.push(crypto::rand_bytes::<16>(rng));
    }

    // Authentication “server replies”
    let auth_r = crypto::random_scalar(rng);
    let blinded = fx.pwd_point * auth_r;

    let mut auth_z_sel = Vec::with_capacity(fx.tsp);
    for j in 0..fx.tsp {
        // Z_j = (P*r) * k_j  (server-side), prepared outside timing
        auth_z_sel.push(blinded * fx.auth_oprf_keys_sel[j]);
    }

    IterData {
        reg_coeffs,
        reg_oprf_keys,
        reg_ivs,
        auth_r,
        auth_z_sel,
        auth_ciphertexts_sel: &fx.auth_ciphertexts_sel,
    }
}

/// Registration (client-side only), timed by bench.
/// Uses pre-generated randomness from IterData.
pub fn registration_user_side(fx: &Fixture, it: &IterData<'_>) -> [u8; 32] {
    let stor_uid = crypto::hash_storuid(&fx.uid, &fx.lsj);

    let rnd_bytes = it.reg_coeffs[0].to_bytes();
    let vinfo = crypto::hash_vinfo(&rnd_bytes, &fx.lsj);

    let mut acc = blake3::Hasher::new();
    acc.update(b"tspa/registration/acc/v1");
    acc.update(&stor_uid);
    acc.update(&vinfo);

    for i in 0..fx.nsp {
        let k_i = it.reg_oprf_keys[i];

        // registration-time: client can compute unblinded OPRF output directly
        let y = fx.pwd_point * k_i;
        let key = crypto::oprf_finalize(&fx.password, &y);

        let share = crypto::eval_poly(&it.reg_coeffs, fx.x_all[i]);
        let share_bytes = share.to_bytes();

        let iv = it.reg_ivs[i];
        let ct = crypto::aes256ctr_xor_32(key, iv, share_bytes);
        let c = pack_ciphertext(iv, ct);

        acc.update(&c);
    }

    let out = acc.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(out.as_bytes());
    r
}

/// Authentication (client-side only), timed by bench.
/// Uses pre-fetched ciphertexts and pre-generated server replies Z_j from IterData.
pub fn authentication_user_side(fx: &Fixture, it: &IterData<'_>) -> [u8; 32] {
    let stor_uid = crypto::hash_storuid(&fx.uid, &fx.lsj);

    // include “blind” structure parity in timed region
    let b = fx.pwd_point * it.auth_r;
    black_box(b);

    let r_inv = it.auth_r.invert();

    let mut acc_rnd = Scalar::ZERO;

    for j in 0..fx.tsp {
        // unblind: Y = Z * r^{-1} = P*k
        let y = it.auth_z_sel[j] * r_inv;
        let key = crypto::oprf_finalize(&fx.password, &y);

        // decrypt share
        let c = it.auth_ciphertexts_sel[j];
        let (iv, ct) = unpack_ciphertext(c);
        let pt = crypto::aes256ctr_xor_32(key, iv, ct);

        let share = Scalar::from_bytes_mod_order(pt);
        acc_rnd += share * fx.lambdas_sel[j];
    }

    let recovered_rnd = acc_rnd.to_bytes();
    let vinfo = crypto::hash_vinfo(&recovered_rnd, &fx.lsj);
    let ok = vinfo == fx.vinfo_db;

    let mut h = blake3::Hasher::new();
    h.update(b"tspa/auth/acc/v1");
    h.update(&stor_uid);
    h.update(&recovered_rnd);
    h.update(&vinfo);
    h.update(&[ok as u8]);

    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(out.as_bytes());
    r
}

