# syntax=docker/dockerfile:1.7
FROM rust:1.92-slim-bookworm AS builder
WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY crates/releasy-core/Cargo.toml crates/releasy-core/Cargo.toml
COPY crates/releasy-server/Cargo.toml crates/releasy-server/Cargo.toml

# Minimal sources so cargo can load workspace manifests during fetch.
RUN mkdir -p crates/releasy-core/src crates/releasy-server/src \
    && printf 'pub fn placeholder() {}\n' > crates/releasy-core/src/lib.rs \
    && printf 'fn main() {}\n' > crates/releasy-server/src/main.rs \
    && printf 'pub fn placeholder() {}\n' > crates/releasy-server/src/lib.rs

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo fetch --locked

COPY crates crates
COPY migrations migrations

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release --locked -p releasy-server --bin releasy-server \
    && cp /app/target/release/releasy-server /app/releasy-server

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin releasy
WORKDIR /app
COPY --from=builder /app/releasy-server /usr/local/bin/releasy-server
ARG RELEASY_VERSION=unknown
ARG RELEASY_BUILD=unknown
ENV RELEASY_VERSION=${RELEASY_VERSION} \
    RELEASY_BUILD=${RELEASY_BUILD}
USER 10001
ARG RELEASY_CONTAINER_PORT=8080
EXPOSE ${RELEASY_CONTAINER_PORT}
ENTRYPOINT ["/usr/local/bin/releasy-server"]
