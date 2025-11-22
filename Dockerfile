# Multi-stage Dockerfile for Security Scanner

ARG ALPINE_VERSION=3.19
ARG PYTHON_VERSION=3.12

# ============================================
# STAGE 1: Security Tools Downloader
# ============================================
FROM alpine:${ALPINE_VERSION} AS downloader

ARG GITLEAKS_VERSION=v8.28.0
ARG TRIVY_VERSION=v0.65.0
ARG OSV_SCANNER_VERSION=v2.2.1
ARG HELM_VERSION=v3.18.6

ARG GITLEAKS_SHA256_AMD64=a65b5253807a68ac0cafa4414031fd740aeb55f54fb7e55f386acb52e6a840eb
ARG GITLEAKS_SHA256_ARM64=eff65261156100e5d94a6b3dec313d532fddfe19ae1590bf7a2b4f2699128356

ARG TRIVY_SHA256_AMD64=f0c5e3c912e7f5194a0efc85dfd34c94c63c4a4184b2d7b97ec7718661f5ead2
ARG TRIVY_SHA256_ARM64=013c67e6aff35429cbbc9f38ea030f5a929d128df08f16188af35ca70517330b

ARG OSV_SCANNER_SHA256_AMD64=59e3bbd49f964265efc495b7ff896bff3c725b14c9fcce2e82088e053af98e7b
ARG OSV_SCANNER_SHA256_ARM64=cd62c3f13d73fe454ba0518e9c738fdedc8e5e37203bdb4f6b7eaefc7d137878

ARG HELM_SHA256_AMD64=3f43c0aa57243852dd542493a0f54f1396c0bc8ec7296bbb2c01e802010819ce
ARG HELM_SHA256_ARM64=5b8e00b6709caab466cbbb0bc29ee09059b8dc9417991dd04b497530e49b1737

# Install download dependencies
RUN apk add --no-cache \
    curl \
    wget \
    unzip \
    ca-certificates \
    && update-ca-certificates

WORKDIR /downloads

RUN ARCH=$(uname -m | sed 's/x86_64/x64/; s/aarch64/arm64/') && \
    if [ "$(uname -m)" = "x86_64" ]; then CHECKSUM=${GITLEAKS_SHA256_AMD64}; else CHECKSUM=${GITLEAKS_SHA256_ARM64}; fi && \
    curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION:1}_linux_${ARCH}.tar.gz" \
    -o gitleaks.tar.gz && \
    echo "${CHECKSUM}  gitleaks.tar.gz" | sha256sum -c - && \
    tar -xzf gitleaks.tar.gz gitleaks && \
    chmod +x gitleaks

# Download and verify Trivy
RUN ARCH=$(uname -m | sed 's/x86_64/64bit/; s/aarch64/ARM64/') && \
    if [ "$(uname -m)" = "x86_64" ]; then CHECKSUM=${TRIVY_SHA256_AMD64}; else CHECKSUM=${TRIVY_SHA256_ARM64}; fi && \
    curl -sSfL "https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VERSION}/trivy_${TRIVY_VERSION:1}_Linux-${ARCH}.tar.gz" \
    -o trivy.tar.gz && \
    echo "${CHECKSUM}  trivy.tar.gz" | sha256sum -c - && \
    tar -xzf trivy.tar.gz trivy && \
    chmod +x trivy

# Download and verify OSV-Scanner
RUN ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/') && \
    if [ "$(uname -m)" = "x86_64" ]; then CHECKSUM=${OSV_SCANNER_SHA256_AMD64}; else CHECKSUM=${OSV_SCANNER_SHA256_ARM64}; fi && \
    curl -sSfL "https://github.com/google/osv-scanner/releases/download/${OSV_SCANNER_VERSION}/osv-scanner_linux_${ARCH}" \
    -o osv-scanner && \
    echo "${CHECKSUM}  osv-scanner" | sha256sum -c - && \
    chmod +x osv-scanner

# Download and verify Helm (for Kubernetes manifest scanning)
RUN ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/') && \
    if [ "$(uname -m)" = "x86_64" ]; then CHECKSUM=${HELM_SHA256_AMD64}; else CHECKSUM=${HELM_SHA256_ARM64}; fi && \
    curl -sSfL "https://get.helm.sh/helm-${HELM_VERSION}-linux-${ARCH}.tar.gz" \
    -o helm.tar.gz && \
    echo "${CHECKSUM}  helm.tar.gz" | sha256sum -c - && \
    tar -xzf helm.tar.gz linux-${ARCH}/helm && \
    mv linux-${ARCH}/helm helm && \
    chmod +x helm

# Verify downloads
RUN ls -la /downloads/ && \
    ./gitleaks version && \
    ./trivy version && \
    ./osv-scanner --version && \
    ./helm version --client

# ============================================
# STAGE 2: Final Runtime Image
# ============================================
# Note: Python builder stage removed to reduce build complexity
FROM alpine:${ALPINE_VERSION}

# Metadata labels following OCI specification
LABEL org.opencontainers.image.title="Git Security Scanner" \
    org.opencontainers.image.description="Containerized security scanning tool with Gitleaks, Trivy, and OSV-Scanner" \
    org.opencontainers.image.vendor="CloudOn-One Security Team" \
    org.opencontainers.image.version="2.0.0" \
    org.opencontainers.image.url="https://github.com/cloudon-one/git-security-scanner-public" \
    org.opencontainers.image.documentation="https://github.com/cloudon-one/git-security-scanner-public/blob/main/README.md" \
    org.opencontainers.image.source="https://github.com/cloudon-one/git-security-scanner-public" \
    org.opencontainers.image.licenses="MIT"

# Install runtime dependencies
RUN apk add --no-cache \
    python3 \
    py3-pip \
    py3-requests \
    git \
    bash \
    jq \
    curl \
    ca-certificates \
    tzdata \
    openssl \
    && update-ca-certificates

# Create non-root user for security
RUN addgroup -g 1000 scanner && \
    adduser -u 1000 -G scanner -D -s /bin/bash scanner

# Create application directories with common mount points
RUN mkdir -p /app/{bin,configs,templates,cache} && \
    mkdir -p /scan /scan_target /reports /tmp/scanner && \
    chown -R scanner:scanner /app /scan /scan_target /reports /tmp/scanner

# Copy security tools from downloader stage
COPY --from=downloader --chown=scanner:scanner /downloads/gitleaks /app/bin/
COPY --from=downloader --chown=scanner:scanner /downloads/trivy /app/bin/
COPY --from=downloader --chown=scanner:scanner /downloads/osv-scanner /app/bin/
COPY --from=downloader --chown=scanner:scanner /downloads/helm /app/bin/

# Security tools configured for reliable scanning

# Environment variables with smart defaults
ENV PATH="/app/bin:${PATH}" \
    SCANNER_HOME="/app" \
    SCANNER_USER="scanner" \
    SCANNER_GROUP="scanner" \
    # Scanner configuration with CI/CD-friendly defaults
    REPO_PATH="/scan" \
    REPORTS_DIR="/reports" \
    GITLEAKS_CONFIG_PATH="/app/gitleaks.toml" \
    PYTHON_SCRIPT_PATH="/app/git-audit-script.py" \
    # Output and behavior defaults
    DEFAULT_SCAN_TYPE="comprehensive" \
    DEFAULT_OUTPUT_FORMATS="json,sarif,html" \
    DEFAULT_FAIL_ON_CRITICAL="true" \
    # GitHub Actions auto-detection
    CI_MODE="auto" \
    MAX_REPOS="50"

# Copy main Python script and shell wrapper
COPY --chown=scanner:scanner run_scans.sh /app/
COPY --chown=scanner:scanner git-audit-script.py /app/
COPY --chown=scanner:scanner gitleaks.toml /app/

# Set executable permissions
RUN chmod +x /app/run_scans.sh

# Create cache directories for scanners
RUN mkdir -p /home/scanner/.cache/{trivy,osv} && \
    chown -R scanner:scanner /home/scanner/.cache


# Switch to non-root user
USER scanner
WORKDIR /scan

# Validate tools are working
RUN gitleaks version && \
    trivy version && \
    osv-scanner --version && \
    helm version --client

# Health check - simple check for required tools
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD gitleaks version && trivy version || exit 1

# Set entrypoint to the shell script
ENTRYPOINT ["/app/run_scans.sh"]

# Default command runs all scans
CMD ["all"]