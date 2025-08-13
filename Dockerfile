FROM rust:1-slim-bookworm as builder

WORKDIR /build

COPY . .

RUN cargo build --release

FROM debian:bookworm-slim as client

COPY --from=builder /build/target/release/asport-client /usr/bin/asport-client

ENTRYPOINT ["asport-client"]

CMD ["--config", "/etc/asport/client.toml"]

FROM debian:bookworm-slim as server

COPY --from=builder /build/target/release/asport-server /usr/bin/asport-server

ENTRYPOINT ["asport-server"]

CMD ["run", "--config", "/etc/asport/server.toml"]