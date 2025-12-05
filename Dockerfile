# build zeek
FROM zeek/zeek:8.0.4 AS zeek-builder
ENV DEBIAN_FRONTEND=noninteractive

# Optionally use a mirror
ARG APT_MIRROR=
RUN if [ -n "$APT_MIRROR" ]; then \
        echo "deb $APT_MIRROR/debian bookworm main" > /etc/apt/sources.list && \
        echo "deb $APT_MIRROR/debian-security bookworm-security main" >> /etc/apt/sources.list && \
        echo "deb $APT_MIRROR/debian bookworm-updates main" >> /etc/apt/sources.list; \
    else \
        echo "deb http://deb.debian.org/debian bookworm main" > /etc/apt/sources.list && \
        echo "deb http://deb.debian.org/debian-security bookworm-security main" >> /etc/apt/sources.list && \
        echo "deb http://deb.debian.org/debian bookworm-updates main" >> /etc/apt/sources.list; \
    fi && \
    for i in 1 2 3; do \
        apt-get update && \
        apt-get install -y --no-install-recommends \
            wget \
            cmake \
            make \
            curl \
            build-essential \
            libpcap-dev \
            libssl-dev \
            librdkafka-dev \
            libzmq5 \
            libzmq3-dev \
            cppzmq-dev \
        && break || (sleep 5 && echo "Attempt $i failed"); \
    done && \
    apt-get clean

# zeek-kafka
RUN for i in 1 2 3; do \
        apt-get update && \
        apt-get install -y --no-install-recommends curl && \
        curl -L -o /zeek-kafka.tar.gz https://github.com/randolphcyg/zeek-kafka/archive/refs/tags/v2.2.tar.gz \
        && tar -xzf /zeek-kafka.tar.gz -C / \
        && mv /zeek-kafka-2.2 /zeek-kafka \
        && rm /zeek-kafka.tar.gz \
        && cd /zeek-kafka \
        && ./configure \
        && make \
        && make install \
        && cd / \
        && rm -rf /zeek-kafka* && \
        apt-get clean && \
        rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* && \
        break || (sleep 5 && echo "Attempt $i failed"); \
    done

# build server
FROM golang:1.25-alpine AS go-builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o zeek_runner .

# runtime
FROM zeek/zeek:8.0.4
ENV TZ=Asia/Shanghai

# Optionally use a mirror
ARG APT_MIRROR=
RUN if [ -n "$APT_MIRROR" ]; then \
        echo "deb $APT_MIRROR/debian bookworm main" > /etc/apt/sources.list && \
        echo "deb $APT_MIRROR/debian-security bookworm-security main" >> /etc/apt/sources.list && \
        echo "deb $APT_MIRROR/debian bookworm-updates main" >> /etc/apt/sources.list; \
    else \
        echo "deb http://deb.debian.org/debian bookworm main" > /etc/apt/sources.list && \
        echo "deb http://deb.debian.org/debian-security bookworm-security main" >> /etc/apt/sources.list && \
        echo "deb http://deb.debian.org/debian bookworm-updates main" >> /etc/apt/sources.list; \
    fi && \
    for i in 1 2 3; do \
        apt-get update && \
        apt-get install -y --no-install-recommends \
            libpcap0.8 \
            librdkafka++1 \
            openssl \
            libzmq5 \
            tzdata \
        && break || (sleep 5 && echo "Attempt $i failed"); \
    done && \
    ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && \
    apt-get clean && \
    rm -rf \
        /var/lib/apt/lists/* \
        /usr/share/doc/* \
        /usr/share/man/* \
        /tmp/* \
        /var/tmp/*

COPY --from=zeek-builder /usr/local/zeek /usr/local/zeek
COPY --from=go-builder /app/zeek_runner /app/

# load custom config
RUN mkdir -p /usr/local/zeek/share/zeek/base/custom
COPY ./custom/config.zeek /usr/local/zeek/share/zeek/base/custom
COPY ./custom/__load__.zeek /usr/local/zeek/share/zeek/base/custom
RUN echo "@load base/custom" >> /usr/local/zeek/share/zeek/base/init-default.zeek

WORKDIR /app
EXPOSE 8000
CMD ["./zeek_runner"]