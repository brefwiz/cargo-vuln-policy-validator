# syntax=docker/dockerfile:1
#
# Scratch image whose only file is the validator binary. ci-internal COPYs
# it; this image is not a job container.

ARG CI_RUST_IMAGE=registry.brefwiz.com/brefwiz/ci-rust
ARG CI_RUST_TAG=1.94.1-n20260805

FROM ${CI_RUST_IMAGE}:${CI_RUST_TAG} AS build

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gcc \
        libc6-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked \
    && strip target/release/cargo-vuln-policy-validator

FROM scratch
COPY --from=build /src/target/release/cargo-vuln-policy-validator /cargo-vuln-policy-validator
