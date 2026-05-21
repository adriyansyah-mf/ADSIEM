VERSION ?= 1.0.0
ARCH    ?= $(shell dpkg --print-architecture 2>/dev/null || uname -m)

.PHONY: build package-deb package-rpm package clean

build:
	CGO_ENABLED=0 go build -ldflags="-s -w -X main.Version=$(VERSION)" \
		-o bin/siem-agent ./cmd/agent/

package-deb:
	@mkdir -p dist
	VERSION=$(VERSION) ARCH=$(ARCH) bash packaging/build-deb.sh

package-rpm:
	@mkdir -p dist
	VERSION=$(VERSION) bash packaging/build-rpm.sh

package: package-deb package-rpm

clean:
	rm -rf dist bin
