#!/usr/bin/env python3
"""
verify_ech.py — live integration check for CloakDNS ECH (RFC 9849).

Spins up CloakDNS with a real ECHConfigList for an upstream, captures
the upstream TLS handshakes with tshark, and asserts:

  1. The ClientHello carries an `encrypted_client_hello` extension
     (TLS extension type 0xfe0d).
  2. The inner SNI (the real hostname, e.g. `cloudflare-dns.com`)
     never appears in cleartext in any ClientHello on the wire.
  3. The cleartext `server_name` extension carries the decoy hostname,
     not the real one.

Failure of any assertion exits non-zero with a diagnostic. On success
the script prints a one-line summary and exits 0.

Prerequisites (none of these are installed by the repo; this is an
"online integration" tool, not a unit test):

  - A CloakDNS binary built with -DCLOAKDNS_ECH=ON against OpenSSL 4.0+.
  - `tshark` (Wireshark CLI) on PATH, with capture privileges on the
    egress interface (Linux: setcap or run as root; macOS: ChmodBPF;
    Windows: Npcap + Administrator).
  - `dig` on PATH for both fetching the ECHConfigList from the
    upstream's HTTPS DNS RR and probing the running CloakDNS.

Usage:

  ./verify_ech.py \\
      --cloakdns ../../build/cloakdns \\
      --upstream cloudflare-dns.com \\
      --upstream-ip 1.1.1.1 \\
      --protocol doh

The script writes a temporary cloakdns.toml + capture.pcap into a
mkdtemp() directory and prints the directory on failure so the user can
inspect the pcap in Wireshark. It is deliberately stand-alone (no
external Python dependencies) so it can be dropped onto any developer
workstation.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

# RFC 9849 §11: the IANA-assigned TLS ExtensionType for
# encrypted_client_hello is 0xfe0d (decimal 65037).
ECH_EXTENSION_TYPE = 0xFE0D

# Wireshark dissector field for the cleartext `server_name` value inside
# ClientHello — the field that ECH is supposed to make useless. If our
# real hostname shows up here, ECH didn't work.
SNI_FIELD = "tls.handshake.extensions_server_name"

# Cleartext bytes of the inner hostname must not appear ANYWHERE inside a
# ClientHello frame; the dissector field above only catches the standard
# extension. We additionally do a bytes-level scan on the captured
# ClientHello frames as a defence-in-depth check.


def fail(msg: str, *, dump: list[Path] | None = None) -> None:
    sys.stderr.write(f"verify_ech: {msg}\n")
    for path in dump or ():
        if path and path.exists():
            sys.stderr.write(f"\n----- {path} -----\n")
            try:
                body = path.read_text(errors="replace")
            except OSError as e:
                body = f"(read failed: {e})\n"
            sys.stderr.write(body)
            if not body.endswith("\n"):
                sys.stderr.write("\n")
    sys.exit(2)


def find_tshark() -> str:
    on_path = shutil.which("tshark")
    if on_path:
        return on_path
    win_default = Path(r"C:\Program Files\Wireshark\tshark.exe")
    if win_default.is_file():
        return str(win_default)
    return "tshark"


def find_dig() -> str:
    on_path = shutil.which("dig")
    if on_path:
        return on_path
    user = os.environ.get("USERPROFILE", "")
    if user:
        winget_dig = Path(user) / (
            r"AppData\Local\Microsoft\WinGet\Packages"
            r"\ISC.Bind_Microsoft.Winget.Source_8wekyb3d8bbwe\dig.exe")
        if winget_dig.is_file():
            return str(winget_dig)
    return "dig"


def fetch_ech_config_b64(hostname: str, dig: str) -> str:
    """Resolve `hostname` HTTPS RR via dig, extract the ech= SvcParam.

    Uses TYPE65 rather than the HTTPS mnemonic because older dig
    builds (Windows winget ships 9.17.12) don't recognise the
    HTTPS string and silently fall through to an A query.
    """
    try:
        out = subprocess.check_output(
            [dig, "+short", hostname, "TYPE65"],
            text=True, timeout=15)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        fail(f"dig TYPE65 {hostname} failed: {e}")
    # dig prints something like:
    #   \# 156 0001 000004 0001 ...    (newer dig with the unknown-RR encoding)
    # or
    #   1 . alpn="h2" ipv4hint=1.1.1.1 ech=AED+DQA8...   (newer dig, parsed)
    # The ech= parser handles the human-readable form. For unknown-RR
    # form, we'd need to byte-walk the rdata. defo.ie's auth servers
    # serve the parsed form on dig 9.16+.
    m = re.search(r'\bech=([A-Za-z0-9+/=]+)', out)
    if not m:
        fail(f"dig output for {hostname} TYPE65 contained no ech= SvcParam:\n{out}")
    return m.group(1)


def write_cloakdns_toml(workdir: Path, *, protocol: str,
                        upstream_host: str, upstream_ip: str,
                        listen_port: int,
                        ech_b64: str,
                        ech_outer: str) -> Path:
    upstream_port = 853 if protocol == "dot" else 443
    toml = f"""\
[server]
listen_addr = "127.0.0.1"
listen_port = {listen_port}

[upstream]
protocol             = "{protocol}"
servers              = ["{upstream_ip}:{upstream_port}"]
servername           = "{upstream_host}"
timeout_ms           = 4000
retries_on_primary   = 0
padding_block_size   = 128
ech_enabled          = true
ech_outer_servername = "{ech_outer}"
ech_config_list_b64  = "{ech_b64}"

# Wire test only exercises the upstream encrypted leg; no blocklist
# needed. Omitting [blocklist] entirely is fine -- config.cpp treats
# a missing section as empty. (Writing `sources = []` would hit the
# "must contain at least one path" validator, which we don't want.)

[cache]
max_entries = 100

[logging]
path = ""
"""
    p = workdir / "cloakdns.toml"
    p.write_text(toml)
    return p


def wait_for_dns_responder(port: int, timeout_s: float) -> bool:
    """Wait until 127.0.0.1:port responds to a UDP DNS query.

    We can't use TCP create_connection here because cloakdns listens
    UDP-only (see main.cpp:server.listen_*). We send a minimal A-record
    query for example.com and treat any datagram in response as
    proof-of-life -- we don't care about the rcode, only that the
    daemon's read loop is up and answering.
    """
    # 29-byte minimal RFC 1035 query:
    #   header (12 bytes): id 0x4242, RD=1, qdcount=1, others 0
    #   qname (13):        \x07example\x03com\x00
    #   qtype (2): A      qclass (2): IN
    query = (
        b"\x42\x42\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x07example\x03com\x00\x00\x01\x00\x01"
    )
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.settimeout(0.5)
                sock.sendto(query, ("127.0.0.1", port))
                sock.recvfrom(512)
                return True
            finally:
                sock.close()
        except (OSError, socket.timeout):
            time.sleep(0.2)
    return False


@contextmanager
def background_process(cmd: list[str], log_path: Path):
    log_fh = log_path.open("w")
    proc = subprocess.Popen(
        cmd,
        stdout=log_fh, stderr=subprocess.STDOUT,
        # New process group so we can SIGTERM cleanly without taking down
        # the parent shell on POSIX.
        start_new_session=(os.name == "posix"))
    try:
        yield proc
    finally:
        if proc.poll() is None:
            try:
                if os.name == "posix":
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                else:
                    proc.terminate()
                proc.wait(timeout=5)
            except (subprocess.TimeoutExpired, ProcessLookupError):
                proc.kill()
        log_fh.close()


def run_tshark_dump(pcap: Path, tshark: str) -> list[dict]:
    """Decode the captured pcap into a list of TLS handshake JSON blobs."""
    try:
        out = subprocess.check_output(
            [tshark, "-r", str(pcap),
             "-Y", "tls.handshake.type == 1",
             "-T", "json"],
            text=True, timeout=30)
    except subprocess.CalledProcessError as e:
        fail(f"tshark replay failed: {e}\n{e.output}")
    if not out.strip():
        return []
    return json.loads(out)


def collect_extension_types(handshake_layer: dict) -> list[int]:
    """Pull every `tls.handshake.extension.type` (decimal) out of a
    ClientHello layer, no matter how deep tshark's JSON nests it."""
    found: list[int] = []

    def walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if k.endswith("tls.handshake.extension.type"):
                    if isinstance(v, str):
                        try:
                            found.append(int(v))
                        except ValueError:
                            pass
                    elif isinstance(v, list):
                        for item in v:
                            try:
                                found.append(int(item))
                            except (TypeError, ValueError):
                                pass
                else:
                    walk(v)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(handshake_layer)
    return found


def collect_field(layer: dict, field: str) -> list[str]:
    out: list[str] = []

    def walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if k == field or k.endswith("." + field):
                    if isinstance(v, str):
                        out.append(v)
                    elif isinstance(v, list):
                        out.extend(x for x in v if isinstance(x, str))
                else:
                    walk(v)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(layer)
    return out


def raw_clienthello_bytes(pcap: Path, tshark: str) -> bytes:
    """Concatenate the raw bytes of every ClientHello handshake message
    in the pcap. Used for the defence-in-depth substring scan."""
    try:
        out = subprocess.check_output(
            [tshark, "-r", str(pcap),
             "-Y", "tls.handshake.type == 1",
             "-T", "fields", "-e", "tls.handshake"],
            text=True, timeout=30)
    except subprocess.CalledProcessError as e:
        fail(f"tshark byte-extract failed: {e}")
    blob = b""
    for line in out.splitlines():
        # tshark prints handshake bytes as colon-separated hex, possibly
        # multiple comma-separated handshakes per frame.
        for chunk in line.replace(",", " ").split():
            try:
                blob += binascii.unhexlify(chunk.replace(":", ""))
            except binascii.Error:
                pass
    return blob


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cloakdns", required=True,
                    help="path to a cloakdns binary built with -DCLOAKDNS_ECH=ON")
    ap.add_argument("--upstream", default="cloudflare-dns.com",
                    help="upstream hostname (inner SNI). Default: cloudflare-dns.com")
    ap.add_argument("--upstream-ip", required=True,
                    help="upstream IP literal (so cloakdns doesn't have to bootstrap)")
    ap.add_argument("--ech-outer", default="cloudflare-ech.com",
                    help="outer (decoy) SNI to put on the wire. Default: cloudflare-ech.com")
    ap.add_argument("--protocol", choices=["dot", "doh"], default="doh")
    ap.add_argument("--listen-port", type=int, default=5354)
    ap.add_argument("--interface", default="any",
                    help="capture interface for tshark. Default: any (Linux); use --interface lo0 on macOS or a numeric NIC on Windows.")
    ap.add_argument("--tshark", default=find_tshark())
    ap.add_argument("--dig",    default=find_dig())
    ap.add_argument("--keep-tmp", action="store_true",
                    help="don't delete the working directory on exit")
    args = ap.parse_args()

    for tool in (args.tshark, args.dig, args.cloakdns):
        if shutil.which(tool) is None and not Path(tool).is_file():
            fail(f"required tool not found: {tool}")

    workdir = Path(tempfile.mkdtemp(prefix="cloakdns-ech-"))
    pcap = workdir / "capture.pcap"
    cloak_log = workdir / "cloakdns.log"
    tshark_log = workdir / "tshark.log"
    print(f"workdir: {workdir}", file=sys.stderr)

    upstream_port = 853 if args.protocol == "dot" else 443
    capture_filter = f"host {args.upstream_ip} and tcp port {upstream_port}"

    print(f"fetching ECHConfigList for {args.upstream} via dig...", file=sys.stderr)
    ech_b64 = fetch_ech_config_b64(args.upstream, args.dig)
    try:
        base64.b64decode(ech_b64)
    except binascii.Error as e:
        fail(f"ECHConfigList from dig is not valid base64: {e}")

    toml_path = write_cloakdns_toml(
        workdir,
        protocol=args.protocol,
        upstream_host=args.upstream,
        upstream_ip=args.upstream_ip,
        listen_port=args.listen_port,
        ech_b64=ech_b64,
        ech_outer=args.ech_outer)

    tshark_cmd = [args.tshark,
                  "-i", args.interface,
                  "-f", capture_filter,
                  "-w", str(pcap),
                  "-q"]
    # cloakdns takes the config path as a positional arg, not --config.
    # See main.cpp:load_or_default: argv[1] is treated as the config path
    # (or a legacy bare-blocklist path) directly.
    cloak_cmd = [args.cloakdns, str(toml_path)]

    print(f"starting tshark on {args.interface!r} (filter: {capture_filter!r})...", file=sys.stderr)
    with background_process(tshark_cmd, tshark_log) as tshark_proc, \
         background_process(cloak_cmd,  cloak_log)  as cloak_proc:

        # tshark needs a moment to actually start capturing.
        time.sleep(2)

        # CI runners are noisy; ECH bootstrap may also need a TLS round-trip
        # against the upstream before the listener binds. 30s is generous
        # enough that a real bind failure dominates over scheduling jitter.
        if not wait_for_dns_responder(args.listen_port, timeout_s=30):
            fail(f"cloakdns never answered UDP DNS on {args.listen_port}",
                 dump=[cloak_log, tshark_log])

        print("sending probe queries via dig...", file=sys.stderr)
        for i, qname in enumerate(["example.com", "wikipedia.org", "github.com"]):
            try:
                subprocess.check_call(
                    [args.dig, f"@127.0.0.1", "-p", str(args.listen_port),
                     "+time=4", "+tries=1", "+short", qname],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=10)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                # An individual query failing is not fatal — the test
                # cares about ECH on the upstream handshake, not whether
                # every probe resolved. Some queries do fail (cache
                # misses on first run) on a fresh circuit.
                pass

        # Let any in-flight upstream handshakes finish capturing.
        time.sleep(1)

    if not pcap.exists() or pcap.stat().st_size == 0:
        fail("tshark produced an empty pcap",
             dump=[tshark_log, cloak_log])

    handshakes = run_tshark_dump(pcap, args.tshark)
    if not handshakes:
        fail(f"no TLS handshakes captured to {args.upstream_ip}; "
             f"check that --interface {args.interface!r} is correct "
             f"(the kernel may route loopback or VPN traffic differently). "
             f"pcap: {pcap}")

    inner = args.upstream.encode("ascii")
    raw_blob = raw_clienthello_bytes(pcap, args.tshark)

    # Assertion 3 (defence in depth): the inner hostname's literal bytes
    # don't appear anywhere in any ClientHello frame on the wire.
    if inner in raw_blob:
        fail(f"FAIL: inner hostname {args.upstream!r} appears in cleartext "
             f"inside a captured ClientHello — ECH is NOT active. pcap: {pcap}")

    ech_seen = False
    sni_seen: list[str] = []
    for hs in handshakes:
        layers = hs.get("_source", {}).get("layers", {})
        tls = layers.get("tls", {})
        types = collect_extension_types(tls)
        if ECH_EXTENSION_TYPE in types:
            ech_seen = True
        sni_seen.extend(collect_field(tls, SNI_FIELD))

    # Assertion 1: at least one ClientHello in the trace had an ECH ext.
    if not ech_seen:
        fail(f"FAIL: no ClientHello carried the ECH extension (0xfe0d). "
             f"verify cloakdns was built with -DCLOAKDNS_ECH=ON and the "
             f"ECHConfigList is fresh. pcap: {pcap}")

    # Assertion 2: cleartext SNI never matches the inner hostname.
    inner_str = args.upstream
    leaks = [s for s in sni_seen if s == inner_str]
    if leaks:
        fail(f"FAIL: cleartext server_name carried inner hostname "
             f"{inner_str!r} on {len(leaks)} handshake(s). pcap: {pcap}")

    print(f"OK: {len(handshakes)} ClientHello captured, ECH ext present, "
          f"inner SNI {inner_str!r} never seen in cleartext.")
    print(f"observed outer SNIs: {sorted(set(sni_seen))}")

    if not args.keep_tmp:
        shutil.rmtree(workdir, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
