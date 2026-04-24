# UpSPA — Secret Update (step-by-step)

## Goal
Update the per-provider encrypted state (`ciphersp`) without changing the password.

## Steps

### 1) Recover `(Rsp, FK)`
- TOPRF(pwd) → decrypt `cipherid` → `(Sid || Rsp || FK)`

### 2) Fetch enough `ciphersp` to find the latest counter
- Fetch a set of `ciphersp` blobs (bench fixture uses `t` IDs)
- Decrypt each: `(rlsj, ctr)`
- Select the entry with maximum `ctr`

### 3) Re-encrypt with incremented counter
- Set `ctr' = ctr + 1`
- Sample new `rlsj'`
- Encrypt: `ciphersp' = AEAD_Enc(FK, aad_sp, (rlsj' || ctr'))`

### 4) Store updated blob(s)
- Send/store `ciphersp'` back to providers under the same `suid` keys

## Output
- Providers store the updated `(rlsj', ctr')` state encrypted under `FK`.
