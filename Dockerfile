FROM kalilinux/kali-rolling

ENV GOPATH=/root/go
ENV PATH=$PATH:/usr/local/go/bin:$GOPATH/bin


# ---------------------------------------------------
# Install all system packages
# ---------------------------------------------------
RUN apt -y update --fix-missing && apt -y upgrade && apt -y autoremove && apt clean
RUN apt install -y \
    python3 python3-pip golang \
    curl wget unzip git jq dnsutils \
    pkg-config libpostal-dev \
    build-essential libssl-dev \
    docker.io seclists httpx-toolkit amass subfinder dnsx gobuster assetfinder \
    && rm -rf /var/lib/apt/lists/*


# ---------------------------------------------------
# Install Recon Tools
# ---------------------------------------------------
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install github.com/OJ/gobuster/v3@latest && \
    go install github.com/tomnomnom/assetfinder@latest
    


# ---------------------------------------------------
# App
# ---------------------------------------------------
WORKDIR /subenum
COPY subenum.py /subenum/subenum.py

ENTRYPOINT ["python3", "/subenum/subenum.py"]
