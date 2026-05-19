FROM debian:trixie-slim AS builder

# Download and install Zig 0.16
ARG ZIG_VERSION=0.16.0
ARG TARGETARCH=amd64

# Install build dependencies and OpenSSL development headers
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    xz-utils \
    ca-certificates \
    libc6-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN case "${TARGETARCH}" in \
      "amd64") ZIG_ARCH="x86_64"  ;; \
      "arm64") ZIG_ARCH="aarch64" ;; \
      *) echo "Unsupported arch: ${TARGETARCH}" && exit 1 ;; \
    esac && \
    curl -fsSL \
      "https://ziglang.org/download/${ZIG_VERSION}/zig-${ZIG_ARCH}-linux-${ZIG_VERSION}.tar.xz" \
      -o /tmp/zig.tar.xz && \
    mkdir -p /opt/zig && \
    tar -xJf /tmp/zig.tar.xz -C /opt/zig --strip-components=1 && \
    rm /tmp/zig.tar.xz

ENV PATH="/opt/zig:${PATH}"

# Set up the working directory
WORKDIR /app

# Copy your source code and build script into the container
COPY build.zig build.zig.zon ./
COPY src/ src/

# Build the binary. We link OpenSSL dynamically against the Debian system libraries.
# Lib path is arch-dependent on Debian.
RUN case "${TARGETARCH}" in \
      "amd64") OPENSSL_LIB="/usr/lib/x86_64-linux-gnu"  ;; \
      "arm64") OPENSSL_LIB="/usr/lib/aarch64-linux-gnu"  ;; \
    esac && \
    zig build -Doptimize=ReleaseSafe \
      -Dcpu=baseline \
      -Dopenssl-include=/usr/include \
      -Dopenssl-lib="${OPENSSL_LIB}"

FROM debian:trixie-slim

# Install CA certificates and OpenSSL runtime library
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    tzdata \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user for Kubernetes security context compliance
RUN groupadd -r webhook && useradd -r -g webhook webhook

WORKDIR /app

# Copy the compiled binary from the builder stage
COPY --from=builder /app/zig-out/bin/acme-dns-aliyun /app/webhook
RUN chown webhook:webhook /app/webhook && chmod +x /app/webhook

# Drop root privileges
USER webhook:webhook

# Expose the default port your server listens on
EXPOSE 8080

# Run the webhook server
ENTRYPOINT ["/app/webhook"]
