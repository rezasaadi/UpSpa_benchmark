# TSPA — Authentication (step-by-step)

High-level flow matching the benchmark implementation.

## Actors and parameters
- U: user/client
- SPᵢ: providers
- nsp = n, tsp = t
- Authentication contacts **t** providers (a selected subset).

## Inputs
- `uid`, `pwd`, `lsj`
- Providers have `DBᵢ[storuid] = ctᵢ`
- Each provider has an OPRF secret key `kᵢ`

## Authentication steps

### 1) U computes `storuid`
- `storuid = H(uid || lsj)`

### 2) U selects `t` providers and runs OPRF with them
For each selected provider SPⱼ (j in selected set of size t):
1. `P = H_to_point(pwd)`
2. Choose random `r`, blind: `B = r · P`
3. U → SPⱼ: `B`
4. SPⱼ → U: `Zⱼ = kⱼ · B`
5. U computes:
   - `Yⱼ = r^{-1} · Zⱼ`
   - `Kⱼ = OPRF_finalize(pwd, Yⱼ)`

### 3) U fetches ciphertext records from those `t` providers
- U → SPⱼ: request `ctⱼ = DBⱼ[storuid]`
- SPⱼ → U: `ctⱼ`

### 4) U decrypts and reconstructs/authenticates
- Decrypt each `ctⱼ` using `Kⱼ` to obtain partial data
- Combine partials via threshold reconstruction / consistency checks (scheme-specific)
- Authentication succeeds if outputs verify correctly

## Output
- Success/failure + derived session/authentication material (scheme-specific).
