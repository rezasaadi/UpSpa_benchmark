# TSPA — Registration (step-by-step)

This describes the **client-side** and **provider-side** steps at a high level (aligned with the benchmark code structure).

## Actors and notation
- **U**: user/client
- **LS**: login server context (modeled via `lsj` / salts / identifiers)
- **SPᵢ**: storage provider i
- **nsp = n**: number of providers
- **tsp = t**: threshold used in authentication selection (registration typically writes to all `n`)

## Inputs
- `uid`: user identifier
- `pwd`: password
- `lsj`: server context / salt
- Provider database: `DBᵢ` (maps a storage key to a record ciphertext)

## Registration steps

### 1) U computes the storage key
- `storuid = H(uid || lsj)`  
This is the provider DB key.

### 2) U runs OPRF with each provider (per-provider key derivation)
For each provider SPᵢ (i = 1..n):
1. `P = H_to_point(pwd)`
2. Choose random `rᵢ`, compute blinded: `Bᵢ = rᵢ · P`
3. U → SPᵢ: `Bᵢ`
4. SPᵢ computes: `Zᵢ = kᵢ · Bᵢ` and returns `Zᵢ`
5. U unblinds and finalizes:
   - `Yᵢ = rᵢ^{-1} · Zᵢ`
   - `Kᵢ = OPRF_finalize(pwd, Yᵢ)`

### 3) U encrypts and stores a record at SPᵢ
1. U forms a fixed-size record plaintext (scheme-specific)
2. Encrypt under `Kᵢ`: `ctᵢ = Enc_{Kᵢ}(record_plaintext)` (AES-CTR XOR in this repo)
3. U → SPᵢ: `(storuid, ctᵢ)`
4. SPᵢ stores: `DBᵢ[storuid] ← ctᵢ`

## Output
- Providers store `ctᵢ` under `storuid`.
- Client keeps local state needed for authentication (bench fixtures model this).
