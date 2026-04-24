## Primitive op names

These are the `op` names you will see in the output for `kind=prim` and `kind=sp`.

### Client primitives (`kind=prim`)

**UpSPA (`scheme=upspa`):**
- `TOPRF_recv_eval_tsp`
- `AEAD_DEC_cipherid`
- `AEAD_DEC_ciphersp`
- `AEAD_ENC_ciphersp_with_rng`
- `AEAD_ENC_ciphersp_fixed_nonce`
- `HASH_suid`
- `HASH_vinfo`

**TSPA (`scheme=tspa`):**
- `HASH_storuid`
- `HASH_vinfo`
- `OPRF_finalize`
- `OPRF_eval_full` (MulP + finalize)
- `OPRF_recv_eval_tsp`
- `MulP_point_scalar`
- `InvS_scalar_invert`
- `FieldOp_mul_add`
- `AES256CTR_xor_32`
- `PolyEval_degree_t_minus_1`

### Server/storage-provider primitives (`kind=sp`)

**UpSPA (`scheme=upspa`):**
- `srv_TOPRF_send_eval_one`
- `srv_DB_get_ciphersp_one`
- `srv_DB_put_ciphersp_one`
- `srv_Ed25519_verify_pwdupd_v1_one`
- `srv_PWDUPD_v1_apply_one`
- `srv_Ed25519_verify_pwdupd_v2_one`
- `srv_PWDUPD_v2_verify_only_one`

**TSPA (`scheme=tspa`):**
- `srv_OPRF_send_eval_one`
- `srv_DB_get_record_one`
- `srv_DB_put_record_one`

---

## Measurement methodology

For each `(nsp, tsp)` point and each operation:

1) **Warmup**: run the operation `--warmup-iters` times (default 300).
2) **Sampling**: run the operation `--sample-size` times (default 2000), recording elapsed nanoseconds.
3) Compute summary stats:
   - min, p50 (median), p95, max, mean, stddev

Timing uses `std::time::Instant` and `black_box()` to limit compiler elimination.

Deterministic seeding:
- a BLAKE3 hash of (tag, nsp, tsp) seeds ChaCha20Rng.
- repeated runs on the same machine produce identical fixtures and RNG streams (modulo OS scheduling noise).

`--rng-in-timed`:
- affects only some client benches where RNG can be hoisted out (e.g., fixed nonce AEAD).
- the flag is still recorded in the output row for filtering/plotting consistency.

---

## Network model (LAN/WAN)

The simulator models a “fan-out” phase:
- client sends `k` requests (serialized on the uplink),
- each provider “processes” for `proc_ns` (injected),
- providers respond, and responses are serialized on the downlink.

For each message:
- **propagation delay**: `one_way_ns = (rtt_ms / 2)`
- **jitter**: sampled uniformly in `[-jitter_ns, +jitter_ns]` independently per direction
- **bandwidth serialization**:
  - `tx_ns = ceil(bits * 1e9 / bw_bps)`
  - the simulator adds `overhead_bytes` to both req/resp sizes before computing `tx_ns`

Default profiles (can be overridden by flags):
- **LAN**: RTT=0.5ms, jitter=0.05ms, bandwidth=1000 Mbps, overhead=64 bytes
- **WAN**: RTT=60ms, jitter=5ms, bandwidth=50 Mbps, overhead=64 bytes