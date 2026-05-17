# ReconX - Dockerfile
# Build:  docker build -t reconx .
# Run:    docker run --rm -v $(pwd)/output:/app/output reconx -t example.com --html-report

FROM python:3.11-slim

LABEL maintainer="ReconX Security Tool"
LABEL description="Automated Reconnaissance & Vulnerability Scanner"
LABEL version="1.0.0"

# Install system dependencies + Nikto + Nuclei
RUN apt-get update && apt-get install -y \
    nikto \
    curl \
    dnsutils \
    nmap \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Nuclei
RUN ARCH=$(dpkg --print-architecture) && \
    case "$ARCH" in \
        amd64)  NUCLEI_ARCH="linux_amd64" ;; \
        arm64)  NUCLEI_ARCH="linux_arm64" ;; \
        *)      NUCLEI_ARCH="linux_amd64" ;; \
    esac && \
    NUCLEI_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
        | grep '"tag_name"' | cut -d'"' -f4) && \
    curl -sL "https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION#v}_${NUCLEI_ARCH}.zip" \
        -o /tmp/nuclei.zip && \
    unzip /tmp/nuclei.zip -d /usr/local/bin/ && \
    rm /tmp/nuclei.zip && \
    chmod +x /usr/local/bin/nuclei && \
    nuclei -update-templates -silent || true

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/output

# Update Nuclei templates on first run
RUN nuclei -update-templates -silent 2>/dev/null || true

VOLUME ["/app/output"]

ENTRYPOINT ["python", "main.py"]
CMD ["--help"]
