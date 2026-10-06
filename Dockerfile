# BugFlow Elite — production runtime image
# Playwright's maintained Noble image supplies the browser runtime and system
# libraries required by the browser-based research adapters.
FROM mcr.microsoft.com/playwright/python:v1.63.0-noble

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH=/usr/local/bin:$PATH

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap dnsutils git libpcap-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN python -m pip install --no-cache-dir --break-system-packages -r requirements.txt

COPY . .

RUN mkdir -p output/bbot output/js_intel output/cloud output/takeovers \
    output/nuclei output/screenshots db \
    && useradd --create-home --shell /usr/sbin/nologin bugflow \
    && chown -R bugflow:bugflow /app

USER bugflow

HEALTHCHECK --interval=60s --timeout=10s --start-period=30s --retries=3 \
    CMD python -c "from db.models import get_conn; get_conn('./db/bugflow.db')" || exit 1

CMD ["python", "scheduler/tasks.py"]
