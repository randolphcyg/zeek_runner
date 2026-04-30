# ===========================
# Global Arguments
# ===========================
ARG ZEEK_VER=8.1.2
ARG GO_VER=1.26.2-alpine
ARG ZEEK_KAFKA_VER=2.2
ARG APT_MIRROR

ARG VERSION=dev
ARG BUILD_TIME
ARG GIT_COMMIT

# ==========================================
# Stage 1: Build Zeek Plugin (zeek-kafka)
# ==========================================
FROM zeek/zeek:${ZEEK_VER} AS zeek-builder
ARG ZEEK_KAFKA_VER
ARG APT_MIRROR

ENV DEBIAN_FRONTEND=noninteractive

RUN \
    if [ -n "$APT_MIRROR" ]; then \
        sed -i "s|deb.debian.org|$APT_MIRROR|g" /etc/apt/sources.list && \
        sed -i "s|security.debian.org|$APT_MIRROR|g" /etc/apt/sources.list; \
    fi && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        wget cmake make curl build-essential \
        libpcap-dev libssl-dev librdkafka-dev \
        libzmq5 libzmq3-dev cppzmq-dev && \
    curl -L -o /zeek-kafka.tar.gz https://github.com/randolphcyg/zeek-kafka/archive/refs/tags/v${ZEEK_KAFKA_VER}.tar.gz && \
    tar -xzf /zeek-kafka.tar.gz -C / && \
    mv /zeek-kafka-${ZEEK_KAFKA_VER} /zeek-kafka && \
    cd /zeek-kafka && \
    export PATH="/usr/local/zeek/bin:$PATH" && \
    ./configure && \
    make && \
    make install && \
    cd / && rm -rf /zeek-kafka* /zeek-kafka.tar.gz && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# ==========================================
# Stage 2: Build Go Server
# ==========================================
FROM golang:${GO_VER} AS go-builder
ARG VERSION
ARG BUILD_TIME
ARG GIT_COMMIT

WORKDIR /app

ENV GOPROXY=https://mirrors.aliyun.com/goproxy/,direct
ENV GOSUMDB=off
ENV GOMODCACHE=/go/pkg/mod

COPY go.mod go.sum ./
RUN go mod download || go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME} -X main.GitCommit=${GIT_COMMIT}" -o zeek_runner .

# ==========================================
# Stage 3: Runtime
# ==========================================
FROM zeek/zeek:${ZEEK_VER}
ENV TZ=Asia/Shanghai
ARG APT_MIRROR

RUN \
    if [ -n "$APT_MIRROR" ]; then \
        sed -i "s|deb.debian.org|$APT_MIRROR|g" /etc/apt/sources.list && \
        sed -i "s|security.debian.org|$APT_MIRROR|g" /etc/apt/sources.list; \
    fi && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        libpcap0.8 \
        librdkafka++1 \
        openssl \
        libzmq5 \
        tzdata \
        git && \
    ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /usr/share/doc/* /usr/share/man/* /tmp/* /var/tmp/*

COPY --from=zeek-builder /usr/local/zeek /usr/local/zeek
COPY --from=go-builder /app/zeek_runner /app/

RUN mkdir -p /usr/local/zeek/share/zeek/base/custom
COPY ./custom/ /usr/local/zeek/share/zeek/base/custom/

# Zeek-Intelligence-Feeds
RUN cd /usr/local/zeek/share/zeek/site && \
    git clone https://github.com/CriticalPathSecurity/Zeek-Intelligence-Feeds.git && \
    sed -i "/abuse-ja3-fingerprints\\.intel/d" /usr/local/zeek/share/zeek/site/Zeek-Intelligence-Feeds/main.zeek && \
    sed -i "/salesforce-ja3-fingerprints\\.intel/d" /usr/local/zeek/share/zeek/site/Zeek-Intelligence-Feeds/main.zeek && \
    sed -i "s|lockbit\\.intel|lockbit_ip.intel|g" /usr/local/zeek/share/zeek/site/Zeek-Intelligence-Feeds/main.zeek

RUN echo "@load base/custom" >> /usr/local/zeek/share/zeek/base/init-default.zeek

WORKDIR /app
EXPOSE 8000
EXPOSE 50051
CMD ["./zeek_runner"]
