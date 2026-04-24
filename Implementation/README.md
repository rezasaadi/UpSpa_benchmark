# UpSPA vs TSPA Benchmarks 

This repository contains a small Rust crate (`(Up/T)SPA`) plus a **single, unified benchmark binary** that can measure:

- **Client protocol phases** (`kind=proto`)
- **Client cryptographic primitives** (`kind=prim`)
- **Server/storage-provider primitives** (`kind=sp`)
- **Network-only simulation** for LAN/WAN (`kind=net`)
- **Modeled end-to-end totals** = client(measured) + network(simulated) + server(p50 injected) (`kind=full`)

The benchmark suite is **manual and reproducible**:
- fixed warmup + sample counts,
- deterministic seeding (BLAKE3 → ChaCha20Rng),
- explicit CLI flags,
- results written to a single whitespace-separated `.dat` file.


---

## Repository layout

```
UpSpa_benchmark/
├── Cargo.toml
├── README.md
├── docs/
│   ├── tspa/
│   │   ├── auth.md
│   │   └── reg.md
│   └── upspa/
│       ├── setup.md
│       ├── reg.md
│       ├── auth.md
│       ├── secret_update.md
│       └── pwd_update.md
└── src/
    ├── lib.rs
    ├── crypto.rs
    ├── crypto_tspa.rs
    ├── protocols/
    │   ├── sp.rs
    │   ├── upspa.rs
    │   └── tspa.rs
    └── bin/
        └── bench_unified.rs
```

`src/bin/bench_unified.rs` is the **single** benchmark binary.

---

## Output format

`bench_unified` writes one output file (default: `unified_bench.dat`) with header:

```
scheme kind op rng_in_timed nsp tsp samples warmup min_ns p50_ns p95_ns max_ns mean_ns stddev_ns
```

- times are in **nanoseconds**
- fields are **whitespace-separated** (easy to parse as CSV by splitting on spaces)
- `scheme ∈ {upspa, tspa}`
- `kind ∈ {proto, prim, sp, net, full}`
- `op` identifies the measured operation (see lists below)

`rng_in_timed` is `1` if `--rng-in-timed` was passed, else `0`.

---

## What each benchmark kind measures

### `--kind proto` (client protocol phases)

Measures **client-side computation only** for protocol phases.

**UpSPA (`scheme=upspa`):**
- `setup`
- `reg`
- `auth` (uses the “2-decrypt” variant: decrypt `cipherid` once + decrypt **one** `ciphersp` once)
- `secupd`
- `pwdupd` (v1) and/or `pwdupd_v2` (v2), controlled by `--pwdupd`

**TSPA (`scheme=tspa`):**
- `setup` (client-side placeholder only; real server init is in `sp`/`full`)
- `reg`
- `auth`

### `--kind prim` (client cryptographic primitives)

Measures **microbenchmarks** of individual client primitives (hash, AEAD, (T)OPRF steps, etc.).
See “Primitive op names” below.

### `--kind sp` (server/storage-provider primitives)

Measures **server-side** primitive costs for a *single* provider instance (no networking):
- TOPRF/OPRF server evaluation
- DB get/put operations (modeled as provider map ops)
- password-update verification/apply (v1 and v2 separated)

See “Primitive op names” below.

### `--kind net` (network-only simulation)

Measures **simulated network time only** (LAN/WAN), with **server processing set to 0**.
This is useful to isolate communication overhead from computation.

Output ops look like:
- `lan_reg_net`, `wan_auth_net`, …

### `--kind full` (modeled end-to-end)

Measures a modeled end-to-end time per phase:


T_full = T_{client,measured} + T_{net,simulated,serverside}(LAN/WAN,bytes,jitter,bw,overhead,proc_{p50})


Where:
- `T_client,measured` is real local timing of the client phase implementation.
- `T_net,simulated` is the network simulator (same model as `bench_net.rs`).
- `proc_p50` is injected per-provider processing time, measured **on this machine** via server primitive microbench medians (p50).

Output ops look like:
- `lan_reg_total`, `wan_auth_total`, …

---

## Password update variants (UpSPA)

Select with `--pwdupd`:

- **v1** (`pwdupd`): re-key/update shares + **per-provider signature(s)** (heavier)
- **v2** (`pwdupd_v2`): keep existing TOPRF shares, re-encrypt `cipherid` under TOPRF(newpwd), **sign once** (lighter)

`--pwdupd both` outputs both v1 and v2 rows for pwdupd-related ops (proto/sp/net/full). Other phases are output once.


---

### Phase message patterns (high level)

**UpSPA:**
- `setup`: `nsp` parallel messages
- `reg`: TOPRF to `tsp` + PUT to `nsp`
- `auth`: TOPRF to `tsp` + GET to `two sp`
- `secupd`: TOPRF to `tsp` + GET to `two sp` + PUT to `nsp`
- `pwdupd`: TOPRF to `tsp` + password-update to `nsp`
  - v2 uses a smaller request payload size than v1 (see `upspa_pwdupd_req_bytes()` in the bench)

**TSPA:**
- `setup`: modeled as server init only (no client↔provider messages)
- `reg`: `nsp` parallel messages
- `auth`: `tsp` parallel messages

Message sizes are taken from constants in `protocols/sp.rs` (and for UpSPA pwdupd v2, computed in the bench).


---

## Building

Use release mode for meaningful crypto timings:

```bash
cargo build --release
```

---

## CLI flags (complete)

Run `cargo run --release --bin bench_unified -- --help` for the built-in help text.
These flags are supported:

### Core
- `--scheme all|upspa|tspa` (default: `all`)
- `--kind proto,prim,sp,net,full` (comma-separated; default: `proto,prim`)
  - `--kind all` runs everything.
- `--pwdupd 1|2|both|v1|v2` (default: `1`)
  - alias: `--pwdupd-v2` sets v2
- `--out FILE` (default: `unified_bench.dat`)
- `--help` / `-h`

### Grid
- `--nsp 20,40,60,80,100` (default shown)
- `--tsp 5,10,20` absolute thresholds (overrides `--tsp-pct`)
- `--tsp-pct 20,40,60,80,100` percentage of nsp (rounded up; clamped to `[1,nsp]`)

### Timing
- `--sample-size N` (default: 2000)
- `--warmup-iters N` (default: 300)
- `--rng-in-timed` (alias `--rng`)

### Network (used by `--kind net` and/or `--kind full`)
- `--net lan|wan|all` (default: `all`)
- `--lan-rtt-ms X`
- `--lan-jitter-ms Y`
- `--lan-bw-mbps Z`
- `--wan-rtt-ms X`
- `--wan-jitter-ms Y`
- `--wan-bw-mbps Z`
- `--overhead-bytes N` (default: 64)

### Server p50 calibration (only used by `--kind full`)
- `--proc-warmup N` (default: 200)
- `--proc-samples N` (default: 1000)

### Compatibility
- `--bench` is tolerated/ignored (to survive Cargo/libtest noise).

---

## Common runs

### 1) Client-only protocol phases (UpSPA + TSPA)
```bash
cargo run --release --bin bench_unified -- \
  --scheme all \
  --kind proto \
  --out proto_only.dat
```

### 2) Client primitives only
```bash
cargo run --release --bin bench_unified -- \
  --scheme all \
  --kind prim \
  --out prim_only.dat
```

### 3) Server primitives only
```bash
cargo run --release --bin bench_unified -- \
  --scheme all \
  --kind sp \
  --pwdupd both \
  --out sp_only.dat
```

### 4) Net-only simulation (LAN + WAN)
```bash
cargo run --release --bin bench_unified -- \
  --scheme all \
  --kind net \
  --net all \
  --out net_only.dat
```

### 5) End-to-end modeled totals (WAN only)
```bash
cargo run --release --bin bench_unified -- \
  --scheme all \
  --kind full \
  --net wan \
  --out full_wan.dat
```

### 6) Compare pwdupd v1 vs v2 everywhere (UpSPA)
```bash
cargo run --release --bin bench_unified -- \
  --scheme upspa \
  --kind proto,sp,net,full \
  --pwdupd both \
  --net all \
  --out upspa_pwdupd_both.dat
```

---
## Running Benchmarks with Docker

###  Build the Docker Image

From the root of the repository:

```bash
docker build -t upspa-bench .
```

This builds the image and compiles `bench_unified` in release mode inside the container.

---

## Basic Usage Pattern

All benchmark flags are passed **after the image name**:

```bash
docker run --rm -v $(pwd)/out:/out upspa-bench [FLAGS...]
```

* `--rm` → removes container after exit
* `-v $(pwd)/out:/out` → mounts a local `out/` directory for results
* `/out` is the working directory inside the container
* Output files will appear in `./out`

---

# Example Runs

---

## Client-only protocol phases

```bash
docker run --rm -v $(pwd)/out:/out upspa-bench \
  --scheme all \
  --kind proto \
  --out proto.dat
```

---

## Client primitives only

```bash
docker run --rm -v $(pwd)/out:/out upspa-bench \
  --scheme all \
  --kind prim \
  --out prim.dat
```

---

## Server-side primitives only

```bash
docker run --rm -v $(pwd)/out:/out upspa-bench \
  --scheme all \
  --kind sp \
  --pwdupd both \
  --out sp.dat
```

---

## Network-only simulation (LAN + WAN)

```bash
docker run --rm -v $(pwd)/out:/out upspa-bench \
  --scheme all \
  --kind net \
  --net all \
  --out net.dat
```

---

## End-to-End modeled (client + net + server), WAN only

```bash
docker run --rm -v $(pwd)/out:/out upspa-bench \
  --scheme all \
  --kind full \
  --net wan \
  --out full_wan.dat
```

---

## Compare pwdupd v1 vs v2 (UpSPA only)

```bash
docker run --rm -v $(pwd)/out:/out upspa-bench \
  --scheme upspa \
  --kind proto,sp,net,full \
  --pwdupd both \
  --net all \
  --out upspa_pwdupd_compare.dat
```

---

## Custom Grid Example

```bash
docker run --rm -v $(pwd)/out:/out upspa-bench \
  --scheme all \
  --kind full \
  --nsp 20,40 \
  --tsp-pct 20,50 \
  --sample-size 500 \
  --warmup-iters 100 \
  --net lan \
  --out custom_run.dat
```

# Override Network Parameters (Example)

```bash
docker run --rm -v $(pwd)/out:/out upspa-bench \
  --kind full \
  --net wan \
  --wan-rtt-ms 100 \
  --wan-bw-mbps 20 \
  --wan-jitter-ms 10 \
  --out slow_wan.dat
```




