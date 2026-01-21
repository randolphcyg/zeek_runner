# ===========================
# Global Arguments
# ===========================
ARG ZEEK_VER=8.1.0
ARG GO_VER=1.25-alpine
ARG ZEEK_KAFKA_VER=2.2
ARG APT_MIRROR

# ==========================================
# Stage 1: Build Zeek Plugin (zeek-kafka)
# ==========================================
FROM zeek/zeek:${ZEEK_VER} AS zeek-builder
ARG ZEEK_KAFKA_VER
ARG APT_MIRROR

ENV DEBIAN_FRONTEND=noninteractive

RUN \
    # 1. 自动配置国内源
    if [ -n "$APT_MIRROR" ]; then \
        sed -i "s|deb.debian.org|$APT_MIRROR|g" /etc/apt/sources.list && \
        sed -i "s|security.debian.org|$APT_MIRROR|g" /etc/apt/sources.list; \
    fi && \
    # 2. 安装编译依赖
    apt-get update && \
    apt-get install -y --no-install-recommends \
        wget cmake make curl build-essential \
        libpcap-dev libssl-dev librdkafka-dev \
        libzmq5 libzmq3-dev cppzmq-dev && \
    # 3. 下载并编译 zeek-kafka
    curl -L -o /zeek-kafka.tar.gz https://github.com/randolphcyg/zeek-kafka/archive/refs/tags/v${ZEEK_KAFKA_VER}.tar.gz && \
    tar -xzf /zeek-kafka.tar.gz -C / && \
    mv /zeek-kafka-${ZEEK_KAFKA_VER} /zeek-kafka && \
    cd /zeek-kafka && \
    export PATH="/usr/local/zeek/bin:$PATH" && \
    ./configure && \
    make && \
    make install && \
    # 4. 清理编译垃圾
    cd / && rm -rf /zeek-kafka* /zeek-kafka.tar.gz && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# ==========================================
# Stage 2: Build Go Server
# ==========================================
FROM golang:${GO_VER} AS go-builder
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o zeek_runner .

# ==========================================
# Stage 3: Runtime (Final)
# ==========================================
FROM zeek/zeek:${ZEEK_VER}
ENV TZ=Asia/Shanghai
ARG APT_MIRROR

RUN \
    # 1. 配置源
    if [ -n "$APT_MIRROR" ]; then \
        sed -i "s|deb.debian.org|$APT_MIRROR|g" /etc/apt/sources.list && \
        sed -i "s|security.debian.org|$APT_MIRROR|g" /etc/apt/sources.list; \
    fi && \
    # ... (后续保持不变) ...
    apt-get update && \
    apt-get install -y --no-install-recommends \
        libpcap0.8 \
        librdkafka++1 \
        openssl \
        libzmq5 \
        tzdata && \
    ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /usr/share/doc/* /usr/share/man/* /tmp/* /var/tmp/*

COPY --from=zeek-builder /usr/local/zeek /usr/local/zeek
COPY --from=go-builder /app/zeek_runner /app/

RUN mkdir -p /usr/local/zeek/share/zeek/base/custom
COPY ./custom/config.zeek /usr/local/zeek/share/zeek/base/custom/
COPY ./custom/__load__.zeek /usr/local/zeek/share/zeek/base/custom/

RUN echo "@load base/custom" >> /usr/local/zeek/share/zeek/base/init-default.zeek

WORKDIR /app
EXPOSE 8000
CMD ["./zeek_runner"]