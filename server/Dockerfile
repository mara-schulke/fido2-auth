# syntax=docker/dockerfile:experimental

FROM rust:1.60-alpine AS BUILD

RUN apk update
RUN apk add musl-dev openssl-dev

WORKDIR /server

ENV SODIUM_USE_PKG_CONFIG=1
ENV RUSTFLAGS="-C target-feature=-crt-static"

COPY Cargo.toml Cargo.lock .
RUN mkdir src && touch src/lib.rs
RUN \
  --mount=type=cache,target=/opt/target \
  --mount=type=cache,target=/usr/local/cargo/registry \
  cargo build --release

COPY . .
RUN \
  --mount=type=cache,target=/opt/target \
  --mount=type=cache,target=/usr/local/cargo/registry \
  cargo clean -r -p auth-server && \
  cargo build --release && \
  cp ./target/release/auth-server .

FROM alpine:3.15 as RUN

WORKDIR /server

RUN apk update
RUN apk add openssl libgcc

COPY --from=BUILD /server/auth-server ./auth-server

CMD [ "./auth-server" ]
