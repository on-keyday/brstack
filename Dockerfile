FROM rust:1.86-slim

WORKDIR /app

# Install build dependencies and network tools
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    iproute2 \
    net-tools \
    iputils-ping \
    nftables \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

COPY ./app/ /app/app/
COPY ./protocol/ /app/protocol/
COPY ./Cargo.toml /app/Cargo.toml
COPY ./Cargo.lock /app/Cargo.lock
RUN  cargo build

RUN cp /app/target/debug/brstack /app/brstack
COPY ./ruleset.txt /app/ruleset.txt
COPY ./run.sh /app/run.sh
ENV RUST_LOG=debug
ENV RUST_BACKTRACE=1
CMD ["/app/run.sh"]
