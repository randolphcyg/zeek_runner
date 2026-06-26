# ===========================
# Global Arguments
# ===========================
ARG ZEEK_VER=8.0.8
ARG GO_VER=1.26.4-alpine
ARG APT_MIRROR

ARG VERSION=dev
ARG BUILD_TIME
ARG GIT_COMMIT

# ==========================================
# Stage 1: Build Go Server
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
# Stage 2: Runtime
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
        openssl \
        tzdata \
        git \
        wget && \
    ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /usr/share/doc/* /usr/share/man/* /tmp/* /var/tmp/*

COPY --from=go-builder /app/zeek_runner /app/

RUN mkdir -p /usr/local/zeek/share/zeek/base/custom
COPY ./custom/ /usr/local/zeek/share/zeek/base/custom/
COPY ./scripts/sanitize_zeek_intel_feeds.sh /usr/local/bin/sanitize_zeek_intel_feeds.sh

# Zeek-Intelligence-Feeds
RUN cd /usr/local/zeek/share/zeek/site && \
    git clone https://github.com/CriticalPathSecurity/Zeek-Intelligence-Feeds.git && \
    sed -i "/abuse-ja3-fingerprints\\.intel/d" /usr/local/zeek/share/zeek/site/Zeek-Intelligence-Feeds/main.zeek && \
    sed -i "/salesforce-ja3-fingerprints\\.intel/d" /usr/local/zeek/share/zeek/site/Zeek-Intelligence-Feeds/main.zeek && \
    sed -i "s|lockbit\\.intel|lockbit_ip.intel|g" /usr/local/zeek/share/zeek/site/Zeek-Intelligence-Feeds/main.zeek && \
    chmod +x /usr/local/bin/sanitize_zeek_intel_feeds.sh && \
    /usr/local/bin/sanitize_zeek_intel_feeds.sh /usr/local/zeek/share/zeek/site/Zeek-Intelligence-Feeds

RUN echo "@load base/custom" >> /usr/local/zeek/share/zeek/base/init-default.zeek

WORKDIR /app
EXPOSE 8000
EXPOSE 50051
CMD ["./zeek_runner"]
