FROM zeek/zeek:latest

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/usr/local/zeek/bin:${PATH}"

# Install utilities, python libraries, and networking tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    iproute2 \
    procps \
    python3-flask \
    python3-requests \
    awscli \
    jq \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /demo

# Copy demo code
COPY vuln_app.py .
COPY fake_metadata.py .
COPY ssrf_detect.zeek .
COPY run_simulation.sh .

RUN chmod +x run_simulation.sh

CMD ["/bin/bash"]
