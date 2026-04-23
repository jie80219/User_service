FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /spiffe-sidecar ./cmd/spiffe-sidecar

FROM alpine:3.20

RUN apk add --no-cache ca-certificates

COPY --from=builder /spiffe-sidecar /usr/local/bin/spiffe-sidecar

ENTRYPOINT ["/usr/local/bin/spiffe-sidecar"]
