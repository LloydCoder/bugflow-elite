# ============================================================
# BugFlow Elite v6 — Dockerfile
# Based on Ubuntu 24.04 with all Go tools pre-installed
# Tinlance Limited | LloydCoder
# ============================================================

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV GOPATH=/root/go
ENV PATH="${GOPATH}/bin:/usr/local/go/bin:${PATH}"
ENV GO_VERSION=1.22.4

WORKDIR /app

# ── System dependencies ────────────────────────────────────
RUN apt-get update && apt-get install -y \
    python3.12 python3.12-venv python3-pip \
    curl wget git nmap dnsutils \
    libpcap-dev build-essential pkg-config \
    chromium-browser chromium-driver \
    ca-certificates gnupg \
    && rm -rf /var/lib/apt/lists/*

# ── Install Go ─────────────────────────────────────────────
RUN curl -sSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" \
    | tar -C /usr/local -xzf -

# ── Install Go-based security tools ────────────────────────
RUN go install github.com/hahwul/dalfox/v2@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install github.com/projectdiscovery/alterx/cmd/alterx@latest && \
    go install github.com/lc/gau/v2/cmd/gau@latest && \
    go install github.com/lc/subjs@latest && \
    go install github.com/003random/getJS/v2@latest && \
    go install github.com/tomnomnom/anew@latest && \
    go install github.com/tomnomnom/waybackurls@latest && \
    go install github.com/hakluke/hakrawler@latest && \
    go install github.com/ffuf/ffuf/v2@latest && \
    go install github.com/sensepost/gowitness@latest && \
    go install github.com/BishopFox/jsluice/cmd/jsluice@latest && \
    go install github.com/edoardottt/cariddi/cmd/cariddi@latest

# ── Install Python dependencies ────────────────────────────
COPY requirements.txt .
RUN python3 -m pip install --no-cache-dir -r requirements.txt

# ── Install Playwright browsers ────────────────────────────
RUN python3 -m playwright install chromium --with-deps

# ── Install nuclei templates ────────────────────────────────
RUN nuclei -update-templates -silent || true

# ── Copy application ────────────────────────────────────────
COPY . .

# ── Create output directories ──────────────────────────────
RUN mkdir -p output/bbot output/js_intel output/cloud output/takeovers \
    output/nuclei output/screenshots db

# ── Healthcheck ────────────────────────────────────────────
HEALTHCHECK --interval=60s --timeout=10s --start-period=30s --retries=3 \
    CMD python3 -c "from db.models import get_conn; get_conn('./db/bugflow.db')" \
    || exit 1

CMD ["python3", "scheduler/tasks.py"]
