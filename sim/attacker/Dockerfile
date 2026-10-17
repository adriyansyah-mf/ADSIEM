# sim/attacker/Dockerfile
# Real attacker against the victim stack. It only speaks sshd/Apache/MySQL
# protocols — it never touches the SIEM API.
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        hydra \
        nmap \
        curl \
        netcat-openbsd \
        iproute2 \
        openssh-client \
        jq \
    && rm -rf /var/lib/apt/lists/*

COPY run_attack.sh /run_attack.sh
COPY loop.sh /run_attack_loop.sh
RUN chmod +x /run_attack.sh /run_attack_loop.sh

ENTRYPOINT ["/run_attack_loop.sh"]
