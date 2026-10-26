# agent-demo VM image: the SIEM agent plus the vulnerable company-profile app
# it is meant to protect. Same Debian userland as the old victim container
# (Apache + PHP-FPM + MySQL + sshd), with the agent binary added on top.
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
RUN clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
    -I internal \
    -c internal/netwatch/bpf/netwatch.bpf.c \
    -o internal/netwatch/bpf/netwatch.bpf.o
RUN clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
    -I internal \
    -c internal/linsensor/bpf/linsensor.bpf.c \
    -o internal/linsensor/bpf/linsensor.bpf.o
RUN clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
    -c internal/prevent/bpf/prevent.bpf.c \
    -o internal/prevent/bpf/prevent.bpf.o
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /agent ./cmd/agent/

FROM php:8.3-fpm

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        apache2 \
        libapache2-mod-fcgid \
        default-mysql-server \
        default-mysql-client \
        rsyslog \
        openssh-server \
        nftables \
        iproute2 \
        procps \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN docker-php-ext-install mysqli pdo pdo_mysql \
    && a2enmod proxy proxy_fcgi rewrite \
    && rm -f /etc/apache2/sites-enabled/000-default.conf \
    && mkdir -p /var/log/apache2 /run/php \
    && rm -f /var/log/apache2/access.log /var/log/apache2/error.log \
    && touch /var/log/apache2/access.log /var/log/apache2/error.log

COPY demo/apache-lab.conf /etc/apache2/conf-available/zz-lab.conf
COPY demo/apache-vhost.conf /etc/apache2/sites-available/000-lab.conf
COPY demo/ports.conf /etc/apache2/ports.conf
COPY demo/php-fpm-lab.conf /usr/local/etc/php-fpm.d/zz-lab-socket.conf
RUN a2enconf zz-lab && a2ensite 000-lab

COPY --from=builder /agent /app/agent
COPY config.yaml /app/config.yaml
COPY demo/www/ /var/www/html/
COPY demo/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

EXPOSE 1337 22
CMD ["/app/entrypoint.sh"]
