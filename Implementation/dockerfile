FROM rustlang/rust:nightly AS builder
WORKDIR /app

# Copy manifests first for better layer caching
COPY Cargo.toml ./

# Dummy build to cache dependencies
RUN mkdir -p src && echo "fn main(){}" > src/main.rs
RUN cargo build --release --bins || true
RUN rm -rf src

# Copy actual sources
COPY src ./src

# Build release binaries (includes bench_unified)
RUN cargo build --release --bins

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy the unified benchmark binary
COPY --from=builder /app/target/release/bench_unified /usr/local/bin/bench_unified

WORKDIR /out

# Run bench_unified directly; pass flags after the image name
ENTRYPOINT ["/usr/local/bin/bench_unified"]
