# UpSPA — Password Update (step-by-step)

Includes both password update variants used in benchmarks.

## Common input
- Current password `pwd`, new password `newpwd`
- `cipherid` decrypts to `(Sid || Rsp || FK)` under `TOPRF(pwd)`

---

## v1 (re-key + per-provider signatures) — `op=pwdupd`

### 1) Recover state
- TOPRF(pwd) → decrypt `cipherid` → `(Sid || Rsp || FK)`

### 2) Re-key TOPRF shares
- Client samples a fresh master secret and generates new shares for all providers
- Derive new state key from `newpwd` and the new master secret
- Re-encrypt `cipherid_pt` under new key → `newcipherid`

### 3) Per-provider signed updates
For each provider i:
- Build `msg_i = newcipherid || share_i || timestamp || spid_i`
- Sign with `Sid`: `sig_i = Sign(Sid, msg_i)`
- Send to SPᵢ; SPᵢ verifies and updates state

This is heavy because signatures scale with `nsp`.

---

## v2 (keep shares + sign once) — `op=pwdupd_v2`

Matches your provided v2 protocol.

### 1) Existence check
- U → SPᵢ: `uid`
- SPᵢ returns `initok` or fail
- Abort unless all `nsp` return `initok`

### 2) Recover old ciphertext
- `K_state = TOPRF(pwd, {key_j}_{j∈[t]})`
- Decrypt `cipherid` → `(Sid || Rsp || FK)`

### 3) Derive new key (shares unchanged)
- `K_state' = TOPRF(newpwd, {key_j}_{j∈[t]})`

### 4) Re-encrypt + sign once
- `newcipherid = Enc_{K_state'}(Sid || Rsp || FK)`
- `sig = Sign(Sid, newcipherid || timestamp)`

### 5) Update providers
- U → SPᵢ: `<sig, newcipherid>`
- SPᵢ verifies and stores: `DBᵢ[uid] ← newcipherid`
