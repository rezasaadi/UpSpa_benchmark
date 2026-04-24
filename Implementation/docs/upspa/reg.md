# UpSPA — Registration (step-by-step)

## Goal
Store per-provider encrypted state `cipherspᵢ` indexed by `suidᵢ`.

## Inputs
- From setup: `cipherid` decrypts to `(Sid || Rsp || FK)` under `TOPRF(pwd)`
- Providers store `ciphersp` blobs under `suid`

## Steps

### 1) Existence checks (optional in modeling)
- U → SPᵢ: `uid`
- SPᵢ checks `DBᵢ` and returns `initok` or fail

### 2) Recover `(Sid || Rsp || FK)`
- Run TOPRF(pwd) with `t` providers to derive `K_state`
- Decrypt: `(Sid || Rsp || FK) = AEAD_Dec(K_state, aad_id, cipherid)`

### 3) Compute `suidᵢ` and build `cipherspᵢ`
For each provider i = 1..n:
1. `suidᵢ = H_suid(Rsp, lsj, i)`
2. Create plaintext `pt_sp = rlsj || ctr` (ctr starts at 0)
3. `cipherspᵢ = AEAD_Enc(FK, aad_sp, pt_sp)`

### 4) Store at providers
- U → SPᵢ: `(suidᵢ, cipherspᵢ)`
- SPᵢ stores: `DBᵢ[suidᵢ] ← cipherspᵢ`

## Output
- Providers store `cipherspᵢ` indexed by `suidᵢ`.
