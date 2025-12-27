FROM rust:1.92-slim-bookworm AS builder
WORKDIR /app
COPY . .
RUN cargo build --release --locked -p releasy-server

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin releasy
WORKDIR /app
COPY --from=builder /app/target/release/releasy-server /usr/local/bin/releasy-server
ARG RELEASY_VERSION=unknown
ARG RELEASY_BUILD=unknown
ENV RELEASY_VERSION=${RELEASY_VERSION} \
    RELEASY_BUILD=${RELEASY_BUILD}
USER 10001
ARG RELEASY_CONTAINER_PORT=8080
EXPOSE ${RELEASY_CONTAINER_PORT}
ENTRYPOINT ["/usr/local/bin/releasy-server"]
