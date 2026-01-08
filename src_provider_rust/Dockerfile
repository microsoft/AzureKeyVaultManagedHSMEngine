# Multi-stage build for Azure Managed HSM OpenSSL Provider
FROM ubuntu:22.04 AS builder

# Avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    openssl \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Set working directory
WORKDIR /build

# Copy source code
COPY Cargo.toml Cargo.lock* ./
COPY build.rs ./
COPY src/ ./src/

# Build the provider
RUN cargo build --release

# Runtime stage
FROM ubuntu:22.04

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    openssl \
    libssl3 \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Azure CLI (for authentication)
RUN curl -sL https://aka.ms/InstallAzureCLIDeb | bash

# Create OpenSSL modules directory
RUN mkdir -p /usr/lib/x86_64-linux-gnu/ossl-modules

# Copy the provider from builder
COPY --from=builder /build/target/release/libakv_provider.so /usr/lib/x86_64-linux-gnu/ossl-modules/libakv_provider.so

# Copy test configuration
COPY testOpenssl.cnf /app/testOpenssl.cnf
COPY runtest.sh /app/runtest.sh

# Set working directory
WORKDIR /app

# Make test script executable
RUN chmod +x runtest.sh

# Verify provider is loadable
RUN openssl list -providers -provider libakv_provider -provider default || \
    (echo "ERROR: Provider not loadable" && exit 1)

# Set environment variables
ENV OPENSSL_MODULES=/usr/lib/x86_64-linux-gnu/ossl-modules
ENV AKV_LOG_LEVEL=3

CMD ["/bin/bash"]
