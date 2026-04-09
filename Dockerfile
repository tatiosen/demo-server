FROM rust:1.87-slim AS rust-builder

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY src/bin ./src/bin
RUN cargo build --release --bin nsm_attestor

FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY src ./src
COPY --from=rust-builder /build/target/release/nsm_attestor /usr/local/bin/nsm-attestor

EXPOSE 5005

ENV PORT=5005

CMD ["python", "src/server.py"]
