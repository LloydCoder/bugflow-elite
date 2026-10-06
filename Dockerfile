# BugFlow Elite — reproducible runtime image
FROM mcr.microsoft.com/playwright/python:v1.63.0-noble

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    GOPATH=/root/go \
    PATH=/root/go/bin:/usr/local/go/bin:$PATH \
    GO_VERSION=1.27.1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3.12 python3.12-venv python3-pip \
    curl wget git nmap dnsutils \
    libpcap-dev build-essential pkg-config \
    ca-certificates gnupg \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tar.gz \
    && echo "63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445  /tmp/go.tar.gz" | sha256sum -c - \
    && tar -C /usr/local -xzf /tmp/go.tar.gz \
    && rm -f /tmp/go.tar.gz

RUN go install github.com/hahwul/dalfox/v2@v3.2.3 && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@v1.12.0 && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.11.1 && \
    go install github.com/projectdiscovery/katana/cmd/katana@v1.8.0 && \
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.6.1 && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@v1.3.1 && \
    go install github.com/projectdiscovery/alterx/cmd/alterx@v0.1.0 && \
    go install github.com/lc/gau/v2/cmd/gau@v2.2.4 && \
    go install github.com/lc/subjs@v1.0.1 && \
    go install github.com/003random/getJS/v2@v2.0.0 && \
    go install github.com/tomnomnom/anew@v0.1.1 && \
    go install github.com/tomnomnom/waybackurls@v0.1.0 && \
    go install github.com/hakluke/hakrawler@2.1 && \
    go install github.com/ffuf/ffuf/v2@v2.3.0 && \
    go install github.com/sensepost/gowitness@v3.2.0 && \
    go install github.com/BishopFox/jsluice/cmd/jsluice@0ddfab153e060a9eeaded4d8669233f7c071e7e4 && \
    go install github.com/edoardottt/cariddi/cmd/cariddi@v1.4.6

COPY requirements.txt .
RUN python3 -m pip install --no-cache-dir --break-system-packages -r requirements.txt

COPY . .

RUN mkdir -p output/bbot output/js_intel output/cloud output/takeovers \
    output/nuclei output/screenshots db

HEALTHCHECK --interval=60s --timeout=10s --start-period=30s --retries=3 \
    CMD python3 -c "from db.models import get_conn; get_conn('./db/bugflow.db')" || exit 1

CMD ["python3", "scheduler/tasks.py"]
