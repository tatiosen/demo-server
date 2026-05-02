FROM rust:1.87-slim AS rust-builder

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY src/bin ./src/bin
RUN cargo build --release --bin nsm_attestor

FROM debian:bookworm-slim@sha256:5a2a80d11944804c01b8619bc967e31801ec39bf3257ab80b91070eb23625644

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      ca-certificates \
      python3 \
      python3-pip \
      python3-venv \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./requirements.txt
RUN python3 -m venv /opt/micrus-venv \
    && /opt/micrus-venv/bin/pip install --no-cache-dir -r requirements.txt

COPY src ./src
COPY --from=rust-builder /build/target/release/nsm_attestor /usr/local/bin/nsm-attestor

EXPOSE 5005

ENV PORT=5005
ENV PATH="/opt/micrus-venv/bin:${PATH}"
ENV PYTHONUNBUFFERED=1

CMD ["python", "src/server.py"]
