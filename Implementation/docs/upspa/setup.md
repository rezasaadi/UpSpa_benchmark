# UpSPA — Setup (step-by-step)

Setup initializes provider-side TOPRF shares and creates the user's `cipherid`.

## Actors / parameters
- U: user/client
- SPᵢ: providers (nsp = n)
- tsp = t: threshold used for TOPRF evaluations

## Goal
- Providers hold TOPRF shares `{keyᵢ}`.
- Client creates `cipherid = AEAD_Enc(K_state, (Sid || Rsp || FK))` where `K_state = TOPRF(pwd)`.

## Steps

### 1) Providers hold TOPRF shares
- Each SPᵢ has a TOPRF share `keyᵢ` (e.g., Shamir share of a master scalar).

### 2) Client derives `K_state = TOPRF(pwd)`
1. `P = H_to_point(pwd)`
2. choose random `r`, blind: `B = r · P`
3. Query `t` providers: SPⱼ returns `Zⱼ = keyⱼ · B`
4. Combine + unblind: `Y = Combine({Zⱼ}, r)`
5. Finalize: `K_state = TOPRF_finalize(pwd, Y)`

### 3) Client creates `cipherid`
1. Sample/derive `Sid` (signing key bytes), `Rsp` (random string), `FK` (fairness AEAD key)
2. Encode `pt_id = Sid || Rsp || FK`
3. Encrypt: `cipherid = AEAD_Enc(K_state, aad_id, pt_id)`

## Output
- Client stores `cipherid`.
- Providers already hold TOPRF shares.
