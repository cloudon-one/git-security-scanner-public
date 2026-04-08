# Multi-stage Dockerfile for Security Scanner

ARG ALPINE_VERSION=3.23
ARG PYTHON_VERSION=3.12

# ============================================
# STAGE 1: Security Tools Downloader
# ============================================
FROM alpine:${ALPINE_VERSION} AS downloader

ARG GITLEAKS_VERSION=v8.30.1
ARG TRIVY_VERSION=v0.69.3
ARG OSV_SCANNER_VERSION=v2.2.1
ARG HELM_VERSION=v3.20.1

ARG GITLEAKS_SHA256_AMD64=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
ARG GITLEAKS_SHA256_ARM64=e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080

ARG TRIVY_SHA256_AMD64=1816b632dfe529869c740c0913e36bd1629cb7688bd5634f4a858c1d57c88b75
ARG TRIVY_SHA256_ARM64=7e3924a974e912e57b4a99f65ece7931f8079584dae12eb7845024f97087bdfd

ARG OSV_SCANNER_SHA256_AMD64=59e3bbd49f964265efc495b7ff896bff3c725b14c9fcce2e82088e053af98e7b
ARG OSV_SCANNER_SHA256_ARM64=cd62c3f13d73fe454ba0518e9c738fdedc8e5e37203bdb4f6b7eaefc7d137878

ARG HELM_SHA256_AMD64=0165ee4a2db012cc657381001e593e981f42aa5707acdd50658326790c9d0dc3
ARG HELM_SHA256_ARM64=56b9d1b0e0efbb739be6e68a37860ace8ec9c7d3e6424e3b55d4c459bc3a0401

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
    org.opencontainers.image.version="2.1.0" \
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