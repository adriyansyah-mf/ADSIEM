# Linux agent for the evidence fault harness (tests/evidence/run.py): the
# production build of agent/Dockerfile without the demo victim userland.
# Build context: agent/.
FROM golang:1.25-alpine AS builder
RUN apk add --no-cache clang
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I internal/procexec/bpf/include \
        -c internal/procexec/bpf/execve.bpf.c -o internal/procexec/bpf/execve.bpf.o \
 && clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I internal \
        -c internal/netwatch/bpf/netwatch.bpf.c -o internal/netwatch/bpf/netwatch.bpf.o
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /agent ./cmd/agent/

FROM alpine:3.20
COPY --from=builder /agent /usr/local/bin/siem-agent
# The harness copies its config in before the first start (docker compose cp).
VOLUME ["/etc/siem-agent", "/var/lib/siem-agent", "/data"]
ENTRYPOINT ["/usr/local/bin/siem-agent", "-config", "/etc/siem-agent/config.yaml"]
