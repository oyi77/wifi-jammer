FROM python:3.12-slim

WORKDIR /app

# Install system dependencies for scapy
RUN apt-get update && apt-get install -y --no-install-recommends \
    wireless-tools \
    iw \
    ethtool \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN pip install --no-cache-dir -e .

ENTRYPOINT ["wifi-jammer"]
