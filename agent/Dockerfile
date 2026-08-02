FROM golang:1.25-alpine AS builder
RUN apk add --no-cache clang
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
    -I internal/procexec/bpf/include \
    -c internal/procexec/bpf/execve.bpf.c \
    -o internal/procexec/bpf/execve.bpf.o
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /agent ./cmd/agent/

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /agent /app/agent
COPY config.yaml /app/config.yaml
CMD ["/app/agent"]
