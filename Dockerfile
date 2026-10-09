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
COPY services/ services/
COPY zeek/ zeek/
COPY canary/ canary/
COPY run_simulation.sh .
COPY run_interactive_demo.py .

RUN chmod +x run_simulation.sh run_interactive_demo.py canary/*.sh


CMD ["/bin/bash"]
