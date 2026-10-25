VERSION ?= 1.0.0
ARCH    ?= $(shell dpkg --print-architecture 2>/dev/null || uname -m)

BPF_ARCH_x86_64 := x86
BPF_ARCH_amd64  := x86
BPF_ARCH_aarch64 := arm64
BPF_ARCH_arm64  := arm64
BPF_ARCH := $(or $(BPF_ARCH_$(uname -m)),$(BPF_ARCH_$(ARCH)),x86)
BPF_OBJ := internal/procexec/bpf/execve.bpf.o
NETWATCH_OBJ := internal/netwatch/bpf/netwatch.bpf.o
LINSENSOR_OBJ := internal/linsensor/bpf/linsensor.bpf.o

.PHONY: build bpf package-deb package-rpm package clean

bpf: $(BPF_OBJ) $(NETWATCH_OBJ) $(LINSENSOR_OBJ)

$(BPF_OBJ): internal/procexec/bpf/execve.bpf.c
	@command -v clang >/dev/null 2>&1 || { \
		echo "error: clang is required to build $(BPF_OBJ)." >&2; \
		echo "       install clang, or build via Docker (docker build -f Dockerfile .)." >&2; \
		exit 1; }
	clang -O2 -g -target bpf -D__TARGET_ARCH_$(BPF_ARCH) \
		-I internal/procexec/bpf/include \
		-c internal/procexec/bpf/execve.bpf.c \
		-o $(BPF_OBJ)

$(NETWATCH_OBJ): internal/netwatch/bpf/netwatch.bpf.c
	clang -O2 -g -target bpf -D__TARGET_ARCH_$(BPF_ARCH) \
		-I internal \
		-c internal/netwatch/bpf/netwatch.bpf.c \
		-o $(NETWATCH_OBJ)

$(LINSENSOR_OBJ): internal/linsensor/bpf/linsensor.bpf.c
	clang -O2 -g -target bpf -D__TARGET_ARCH_$(BPF_ARCH) \
		-I internal \
		-c internal/linsensor/bpf/linsensor.bpf.c \
		-o $(LINSENSOR_OBJ)

build: bpf
	CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X main.Version=$(VERSION)" \
		-o bin/siem-agent ./cmd/agent/

package-deb: bpf
	@mkdir -p dist
	VERSION=$(VERSION) ARCH=$(ARCH) bash packaging/build-deb.sh

package-rpm: bpf
	@mkdir -p dist
	VERSION=$(VERSION) bash packaging/build-rpm.sh

package: package-deb package-rpm

clean:
	rm -rf dist bin $(BPF_OBJ) $(NETWATCH_OBJ) $(LINSENSOR_OBJ)
