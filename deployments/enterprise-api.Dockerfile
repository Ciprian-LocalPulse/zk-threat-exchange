# zk-threat-exchange :: enterprise-api image
# Author: Ciprian Ștefan Pleșca
FROM golang:1.22-alpine AS builder
WORKDIR /build
COPY enterprise-api/go.mod ./go.mod
COPY enterprise-api/go.sum ./go.sum
COPY enterprise-api/cmd ./cmd
COPY enterprise-api/internal ./internal
RUN go build -o /build/server ./cmd/server

FROM alpine:3.19
LABEL maintainer="Ciprian Ștefan Pleșca"
COPY --from=builder /build/server /usr/local/bin/server
ENV ZKT_ENV=development
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/server"]
