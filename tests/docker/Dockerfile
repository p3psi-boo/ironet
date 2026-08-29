FROM rust:1.95-trixie AS builder

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --locked --release \
    && cp /src/target/release/ironet /tmp/ironet \
    && cp /src/target/release/ironetd /tmp/ironetd

FROM golang:1.26.5-alpine AS derper-builder

ARG TAILSCALE_VERSION=v1.102.2
RUN CGO_ENABLED=0 go install tailscale.com/cmd/derper@${TAILSCALE_VERSION}

FROM rust:1.95-trixie AS iroh-relay-builder

ARG IROH_RELAY_VERSION=1.0.3
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/tmp/iroh-relay-target \
    CARGO_TARGET_DIR=/tmp/iroh-relay-target \
    cargo install --locked --root /tmp/iroh-relay \
      --version ${IROH_RELAY_VERSION} --features server iroh-relay

FROM debian:trixie-slim

RUN DEBIAN_FRONTEND=noninteractive apt-get update \
    && apt-get install -y --no-install-recommends \
       bind9-dnsutils ca-certificates conntrack iperf3 iproute2 iptables iputils-ping jq netcat-openbsd passwd procps python3 systemd \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /tmp/ironet /usr/local/bin/ironet
COPY --from=builder /tmp/ironetd /usr/local/bin/ironetd
COPY --from=derper-builder /go/bin/derper /usr/local/bin/derper
COPY --from=iroh-relay-builder /tmp/iroh-relay/bin/iroh-relay /usr/local/bin/iroh-relay

ENTRYPOINT ["/usr/local/bin/ironet"]
CMD ["--help"]
