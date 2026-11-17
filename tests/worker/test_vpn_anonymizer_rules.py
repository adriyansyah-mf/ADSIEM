# tests/worker/test_vpn_anonymizer_rules.py
"""VPN, Tor and proxy clients, SSH SOCKS proxies and VPN tunnel drivers, from
the lines Linux and Windows agents send, through the shipped decoders and
rules (rules/*vpn*, rules/*ssh_socks*)."""
import asyncio
import glob
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import pytest  # noqa: E402
import yaml  # noqa: E402

from worker.decoder_engine import DecoderEngine  # noqa: E402
from worker.sigma_engine import SigmaEngine  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "../..")
LIN_CLIENT = "VPN, Tor Or Proxy Client Started On Linux"
WIN_CLIENT = "VPN, Tor Or Proxy Client Started On Windows"
LIN_SSH = "SSH Started As A SOCKS Proxy Or Tunnel On Linux"
WIN_SSH = "SSH Started As A SOCKS Proxy On Windows"
LIN_MODULE = "VPN Tunnel Kernel Module Loaded On Linux"
WIN_DRIVER = "VPN Tunnel Driver Or Service Installed On Windows"


@pytest.fixture(scope="module")
def engines():
    load = lambda p: [open(f).read() for f in sorted(glob.glob(os.path.join(ROOT, p)))]  # noqa: E731
    dec = DecoderEngine()
    dec.load_from_yaml_list(sorted(load("decoders/*.yaml"), key=lambda c: yaml.safe_load(c).get("priority", 100)))
    sig = SigmaEngine()
    sig.load_from_yaml_list(load("rules/*.yaml"))
    assert not sig.load_errors, sig.load_errors
    return dec, sig


def titles(engines, log_type, raw):
    dec, sig = engines
    decoded, _ = dec.decode_named(log_type, raw)
    return {m["title"] for m in asyncio.run(sig.evaluate(dict(decoded, raw_message=raw, log_type=log_type)))}


def q(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def lin(image, cmd, parent="/bin/bash"):
    return f'pid=4242 ppid=1 uid=1000 comm={os.path.basename(image)[:15]} Image={q(image)} CommandLine={q(cmd)} ' \
           f'ParentImage={q(parent)}'


def win(image, cmd, parent="C:\\Windows\\explorer.exe"):
    return (f'EventID=1 Channel="ETW" Provider="Microsoft-Windows-Kernel-Process" ProcessId="4321" '
            f'Image={q(image)} CommandLine={q(cmd)} User="WIN01\\alice" IntegrityLevel="Medium" '
            f'ParentProcessId="1000" ParentImage={q(parent)}')


@pytest.mark.parametrize("image,cmd", [
    ("/usr/sbin/openvpn", "openvpn --config client.ovpn"),
    ("/usr/bin/wg-quick", "wg-quick up wg0"),
    ("/usr/bin/tor", "tor"),
    ("/home/bob/tor-browser/Browser/firefox.real", "firefox.real"),
    ("/opt/sing-box/sing-box", "sing-box run -c config.json"),
    ("/usr/local/bin/sslocal", "sslocal -c ss.json"),
    ("/usr/bin/warp-svc", "warp-svc"),
])
def test_linux_clients_alert(engines, image, cmd):
    assert LIN_CLIENT in titles(engines, "linux_process_exec", lin(image, cmd))


@pytest.mark.parametrize("image", ["/usr/bin/curl", "/usr/bin/pastor", "/usr/bin/ls", "/usr/bin/torsocks-not"])
def test_linux_other_programs_do_not(engines, image):
    assert LIN_CLIENT not in titles(engines, "linux_process_exec", lin(image, image))


@pytest.mark.parametrize("image,cmd", [
    ("C:\\Program Files\\OpenVPN\\bin\\openvpn-gui.exe", "openvpn-gui.exe"),
    ("C:\\Program Files\\WireGuard\\wireguard.exe", "wireguard.exe /installtunnelservice x.conf"),
    ("C:\\Program Files\\Cloudflare\\Cloudflare WARP\\Cloudflare WARP.exe", "Cloudflare WARP.exe"),
    ("C:\\Users\\bob\\Desktop\\Tor Browser\\Browser\\firefox.exe", "firefox.exe"),
    ("C:\\Users\\bob\\Downloads\\psiphon3.exe", "psiphon3.exe"),
    ("C:\\Users\\bob\\AppData\\Local\\v2rayN\\v2rayN.exe", "v2rayN.exe"),
])
def test_windows_clients_alert(engines, image, cmd):
    assert WIN_CLIENT in titles(engines, "windows_etw_process", win(image, cmd))


def test_windows_browser_does_not(engines):
    assert WIN_CLIENT not in titles(
        engines, "windows_etw_process", win("C:\\Program Files\\Mozilla Firefox\\firefox.exe", "firefox.exe"))


@pytest.mark.parametrize("cmd,want", [
    ("ssh -D 1080 user@vps", True),
    ("ssh -fND 127.0.0.1:1080 user@vps", True),
    ("ssh -D1080 vps", True),
    ("ssh -w 0:0 root@vps", True),
    ("ssh -L 8080:localhost:80 user@db", False),
    ("ssh user@host uptime", False),
    ("ssh -o ServerAliveInterval=30 user@host", False),
])
def test_linux_ssh_socks(engines, cmd, want):
    assert (LIN_SSH in titles(engines, "linux_process_exec", lin("/usr/bin/ssh", cmd))) == want


def test_windows_ssh_socks(engines):
    ssh = "C:\\Windows\\System32\\OpenSSH\\ssh.exe"
    assert WIN_SSH in titles(engines, "windows_etw_process", win(ssh, "ssh.exe -D 1080 user@vps"))
    assert WIN_SSH not in titles(engines, "windows_etw_process", win(ssh, "ssh.exe user@vps"))


def test_linux_tunnel_module(engines):
    line = ('action=load Module="/lib/modules/6.8.0/kernel/drivers/net/wireguard/wireguard.ko.zst" Params="" '
            'Image="/usr/bin/kmod" Comm="modprobe" PID=7001 PPID=7000 User=0 EUID=0')
    assert LIN_MODULE in titles(engines, "linux_kernel_module", line)
    other = line.replace("drivers/net/wireguard/wireguard.ko.zst", "fs/btrfs/btrfs.ko.zst")
    assert LIN_MODULE not in titles(engines, "linux_kernel_module", other)


def test_windows_vpn_driver_installed(engines):
    line = ('EventID=7045 Channel="System" Provider="Service Control Manager" Computer="WIN01" '
            'AccountName="LocalSystem" ImagePath="\\SystemRoot\\System32\\drivers\\wintun.sys" '
            'ServiceName="wintun" StartType="demand start"')
    assert WIN_DRIVER in titles(engines, "windows_system", line)
    psexec = ('EventID=7045 Channel="System" Provider="Service Control Manager" Computer="WIN01" '
              'AccountName="LocalSystem" ImagePath="%SystemRoot%\\PSEXESVC.exe" ServiceName="PSEXESVC" '
              'StartType="demand start"')
    assert WIN_DRIVER not in titles(engines, "windows_system", psexec)
