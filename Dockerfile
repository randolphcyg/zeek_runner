# build zeek
FROM zeek/zeek:7.2.1 AS zeek-builder
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    cmake \
    make \
    curl \
    build-essential \
    libpcap-dev \
    libssl-dev \
    librdkafka-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# zeek-kafka
RUN curl -L -o /zeek-kafka.tar.gz https://github.com/randolphcyg/zeek-kafka/archive/refs/tags/v2.1.tar.gz \
    && tar -xzf /zeek-kafka.tar.gz -C / \
    && mv /zeek-kafka-2.1 /zeek-kafka \
    && rm /zeek-kafka.tar.gz \
    && cd /zeek-kafka \
    && ./configure \
    && make \
    && make install \
    && cd / \
    && rm -rf /zeek-kafka* /var/lib/apt/lists/*

# build server
FROM golang:1.24-alpine AS go-builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o zeek_runner .

# runtime
FROM zeek/zeek:7.2.1
ENV TZ=Asia/Shanghai

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    librdkafka++1 \
    openssl \
    tzdata && \
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