# UpSPA — Authentication (step-by-step)

This matches the benchmark’s “2-decrypt” model:
- decrypt `cipherid` once
- decrypt **one** `ciphersp` once (in a full deployment you may decrypt more)

## Inputs
- `pwd`, `uid`, `lsj`, `cipherid`
- Providers store `ciphersp` under `suidᵢ`

## Steps

### 1) Recover `(Rsp, FK)`
- TOPRF(pwd) → `K_state`
- Decrypt `cipherid` → `(Sid || Rsp || FK)`

### 2) Compute `suid` for contacted providers
- For contacted IDs `i` (size `t` in fixtures):
  - `suidᵢ = H_suid(Rsp, lsj, i)`

### 3) Fetch and decrypt one `ciphersp`
- U → SPᵢ: `suidᵢ`
- SPᵢ → U: `cipherspᵢ`
- Decrypt: `pt_sp = AEAD_Dec(FK, aad_sp, cipherspᵢ)` → parse `(rlsj, ctr)`
- Compute: `vinfo = H_vinfo(rlsj, lsj)`

## Output
- Authentication output is derived from `(ctr, vinfo)` and consistency checks (scheme-specific).
