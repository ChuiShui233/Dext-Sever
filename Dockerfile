# syntax=docker/dockerfile:1.6

FROM golang:1.24-alpine AS builder

ENV GOPROXY=https://goproxy.cn,direct \
    GOSUMDB=off

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/dext .

FROM alpine:3.20 AS runtime

RUN apk add --no-cache \
        ca-certificates \
        tzdata \
        python3 \
        wget \
    && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime \
    && echo "Asia/Shanghai" > /etc/timezone

WORKDIR /app

COPY --from=builder /out/dext /app/dext
COPY env_secret.py /app/env_secret.py
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

RUN mkdir -p /app/assets_storage /app/uploads /app/SSL /app/keys /app/bin /app/static \
    && chmod +x /usr/local/bin/docker-entrypoint.sh \
    && adduser -D -u 1000 appuser \
    && chown -R 1000:1000 /app

# HuggingFace Space 适配:
# - 必须 listen 7860
# - 必须以非 root (uid 1000) 运行
# - HF 在前端终止 TLS, 后端只用 HTTP
ENV PORT=7860 \
    HTTPS_ENABLED=false \
    TZ=Asia/Shanghai

USER 1000

EXPOSE 7860

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget --spider -q http://127.0.0.1:7860/ || exit 1

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["/app/dext"]
