FROM golang:1.27.1-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /anquan-master ./cmd/anquan-master

FROM alpine:3.23
RUN apk add --no-cache ca-certificates su-exec && addgroup -S anquan && adduser -S -G anquan anquan \
    && mkdir -p /app /data/anquan && chown anquan:anquan /data/anquan
COPY --from=build /anquan-master /app/anquan-master
COPY deploy/reset-admin-password.sh /app/reset-admin-password.sh
COPY deploy/docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod 0755 /app/reset-admin-password.sh /app/docker-entrypoint.sh
ENV ANQUAN_BIN=/app/anquan-master ANQUAN_DATA_DIR=/data/anquan
VOLUME /data/anquan
EXPOSE 10110/tcp 55555/udp
ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["/app/anquan-master"]
