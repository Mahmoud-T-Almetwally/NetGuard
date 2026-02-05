FROM golang:1.25-bookworm

# 1. Install System Dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    iptables \
    libnetfilter-queue-dev \
    libpcap-dev \
    wget \
    tar \
    && rm -rf /var/lib/apt/lists/*

# 2. Install Python Deps
RUN pip3 install requests --break-system-packages

# 3. Install ONNX Runtime
WORKDIR /tmp
RUN wget https://github.com/microsoft/onnxruntime/releases/download/v1.23.2/onnxruntime-linux-x64-1.23.2.tgz \
    && tar -zxvf onnxruntime-linux-x64-1.23.2.tgz \
    && cp -r onnxruntime-linux-x64-1.23.2/include/* /usr/local/include/ \
    && cp onnxruntime-linux-x64-1.23.2/lib/libonnxruntime.so.1.23.2 /usr/lib/libonnxruntime.so \
    && ln -s /usr/lib/libonnxruntime.so /usr/lib/libonnxruntime.so.1

# 4. Create a user for the TRAFFIC GENERATOR (Not NetGuard)
RUN useradd -m -u 1001 stressuser

WORKDIR /app

# 5. Copy Source Code
COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ cmd/
COPY internal/ internal/
COPY data/ data/
COPY configs/ configs/

# 6. Build the Binary
RUN CGO_ENABLED=1 go build -o netguard cmd/netguard/main.go

# 7. Copy Test Scripts & Data
COPY scripts/stress_test/entrypoint.sh .
COPY scripts/stress_test/traffic_gen.py .
COPY scripts/stress_test/traffic_urls.csv .

# 8. Permissions
RUN chmod +x entrypoint.sh

# Grant the stressuser permissions to read the python script and csv
RUN chown -R stressuser:stressuser /app

CMD ["./entrypoint.sh"]