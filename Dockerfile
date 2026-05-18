FROM rust:bookworm AS builder
WORKDIR /app

COPY Cargo.toml Cargo.toml
COPY Cargo.lock Cargo.lock
COPY crates crates
RUN cargo build --release --locked -p skill-issue-server

FROM debian:bookworm-slim AS runtime
WORKDIR /app

RUN apt-get update \
	&& apt-get install -y --no-install-recommends ca-certificates git \
	&& rm -rf /var/lib/apt/lists/*
RUN useradd --create-home --shell /usr/sbin/nologin skillissue
COPY --from=builder /app/target/release/skill-issue-server /usr/local/bin/skill-issue-server
COPY models /app/models

ENV BIND_ADDRESS=0.0.0.0:3000
USER skillissue
EXPOSE 3000
CMD ["skill-issue-server"]
