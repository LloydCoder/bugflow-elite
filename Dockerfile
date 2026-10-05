# BugFlow Elite — reproducible runtime image
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    GOPATH=/root/go \
    PATH=/root/go/bin:/usr/local/go/bin:$PATH \
    GO_VERSION=1.22.4

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3.12 python3.12-venv python3-pip \
    curl wget git nmap dnsutils \
    libpcap-dev build-essential pkg-config \
    ca-certificates gnupg \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" \
    | tar -C /usr/local -xzf -

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

COPY requirements.txt .
RUN python3 -m pip install --no-cache-dir --break-system-packages -r requirements.txt
RUN python3 -m playwright install --with-deps chromium

COPY . .

RUN mkdir -p output/bbot output/js_intel output/cloud output/takeovers \
    output/nuclei output/screenshots db

HEALTHCHECK --interval=60s --timeout=10s --start-period=30s --retries=3 \
    CMD python3 -c "from db.models import get_conn; get_conn('./db/bugflow.db')" || exit 1

CMD ["python3", "scheduler/tasks.py"]
