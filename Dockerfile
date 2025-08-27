# Multi-stage Dockerfile for Security Scanner
# Optimized for security, performance, and minimal attack surface

ARG ALPINE_VERSION=3.19
ARG PYTHON_VERSION=3.12

# ============================================
# STAGE 1: Security Tools Downloader
# ============================================
FROM alpine:${ALPINE_VERSION} AS downloader

# Tool versions (can be overridden at build time)
ARG GITLEAKS_VERSION=v8.28.0
ARG TRIVY_VERSION=v0.65.0
ARG OSV_SCANNER_VERSION=v2.2.1
ARG HELM_VERSION=v3.18.6

# Install download dependencies
RUN apk add --no-cache \
    curl \
    wget \
    unzip \
    ca-certificates \
    && update-ca-certificates

WORKDIR /downloads

# Download Gitleaks
RUN ARCH=$(uname -m | sed 's/x86_64/x64/; s/aarch64/arm64/') && \
    curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION:1}_linux_${ARCH}.tar.gz" \
    -o gitleaks.tar.gz && \
    tar -xzf gitleaks.tar.gz gitleaks && \
    chmod +x gitleaks

# Download Trivy
RUN ARCH=$(uname -m | sed 's/x86_64/64bit/; s/aarch64/ARM64/') && \
    curl -sSfL "https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VERSION}/trivy_${TRIVY_VERSION:1}_Linux-${ARCH}.tar.gz" \
    -o trivy.tar.gz && \
    tar -xzf trivy.tar.gz trivy && \
    chmod +x trivy

# Download OSV-Scanner
RUN ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/') && \
    curl -sSfL "https://github.com/google/osv-scanner/releases/download/${OSV_SCANNER_VERSION}/osv-scanner_linux_${ARCH}" \
    -o osv-scanner && \
    chmod +x osv-scanner

# Download Helm (for Kubernetes manifest scanning)
RUN ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/') && \
    curl -sSfL "https://get.helm.sh/helm-${HELM_VERSION}-linux-${ARCH}.tar.gz" \
    -o helm.tar.gz && \
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
LABEL org.opencontainers.image.title="Security Scanner" \
      org.opencontainers.image.description="Containerized security scanning tool with Gitleaks, Trivy, and OSV-Scanner" \
      org.opencontainers.image.vendor="Security Scanner Team" \
      org.opencontainers.image.version="2.1.0" \
      org.opencontainers.image.url="https://github.com/cloudon-one/security-scanner" \
      org.opencontainers.image.documentation="https://github.com/cloudon-one/security-scanner/blob/main/README.md" \
      org.opencontainers.image.source="https://github.com/cloudon-one/security-scanner" \
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

# Security and performance optimizations
# - Use multi-stage builds to reduce image size
# - Run as non-root user
# - Pin dependency versions
# - Validate downloaded binaries
# - Set proper file permissions
# - Use health checks
# - Minimize installed packages