# ══════════════════════════════════════════════════════════════
#  VoIP OSINT APEX v3.0 — Production Dockerfile
#  Base: Python 3.11-slim (Debian Bookworm)
#  Includes: nmap, masscan, tshark, whois, scapy dependencies
# ══════════════════════════════════════════════════════════════

FROM python:3.11-slim-bookworm AS base

# ── Labels ──────────────────────────────────────────────────
LABEL maintainer="VoIP OSINT APEX" \
      version="3.0" \
      description="Enterprise VoIP Forensic Intelligence Platform"

# ── System dependencies ──────────────────────────────────────
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Network tools
    nmap \
    masscan \
    tshark \
    tcpdump \
    traceroute \
    iputils-ping \
    netcat-openbsd \
    whois \
    net-tools \
    curl \
    wget \
    # Build tools (for scapy, cryptodome)
    gcc \
    g++ \
    libpcap-dev \
    libssl-dev \
    libffi-dev \
    # Misc
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ── App user (non-root for security, but with net_raw cap for scapy) ──
RUN groupadd -r apexuser && useradd -r -g apexuser -d /app -s /bin/bash apexuser

# ── Working directory ────────────────────────────────────────
WORKDIR /app

# ── Python dependencies (cached layer) ─────────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir sipvicious python-telegram-bot>=20.0

# ── Copy source code ─────────────────────────────────────────
COPY . .

# ── Output directories ───────────────────────────────────────
RUN mkdir -p outputs/reports outputs/logs outputs/pcaps \
             outputs/subpoenas outputs/feed_cache && \
    chown -R apexuser:apexuser /app

# ── Environment defaults ─────────────────────────────────────
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    VOIP_OUTPUT_DIR=/app/outputs

# ── Drop to non-root (set net_raw in docker-compose for scapy) ──
USER apexuser

# ── Healthcheck ──────────────────────────────────────────────
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python main.py --help > /dev/null 2>&1 || exit 1

# ── Entry point ──────────────────────────────────────────────
ENTRYPOINT ["python", "main.py"]
CMD ["--help"]
