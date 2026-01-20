import argparse
import base64
import json
import os
import random
import socket
import string
import subprocess
import sys
import tempfile
import time
import urllib.parse
from dataclasses import dataclass
from typing import Optional, Tuple, List

import httpx
import requests
from dotenv import load_dotenv


VLESS_LIST_URL = "https://gist.githubusercontent.com/qwwqe18-cmyk/86b7e28e5afb5b819947d4b02538a275/raw/27ea8e155f8601ac780967bbaf1e113073b78a78/ru_fast.txt"
IP_API_URL = "http://ip-api.com/json/"
IP_API_BATCH_URL = "http://ip-api.com/batch"


def _log(msg: str) -> None:
    print(msg, flush=True)


def _safe_filename(s: str) -> str:
    keep = string.ascii_letters + string.digits + "-_"
    return "".join(c if c in keep else "_" for c in s)[:80]


def download_vless_list(url: str) -> List[str]:
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    lines = []
    for raw in r.text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if not line.startswith("vless://"):
            continue
        lines.append(line)
    return lines


def parse_vless_host_port(link: str) -> Tuple[str, int]:
    """
    vless://uuid@host:port?query#name
    host может быть доменом, ipv4 или ipv6 в [brackets]
    """
    u = urllib.parse.urlsplit(link)
    if u.scheme != "vless":
        raise ValueError("not vless scheme")
    # urlsplit для vless://... кладёт всё после // в netloc
    # netloc выглядит как "uuid@host:port"
    if "@" not in u.netloc:
        raise ValueError("missing '@' in netloc")
    _, hostport = u.netloc.split("@", 1)
    host = None
    port = None
    if hostport.startswith("["):
        # [ipv6]:port
        if "]" not in hostport:
            raise ValueError("bad ipv6 host")
        host = hostport[1 : hostport.index("]")]
        rest = hostport[hostport.index("]") + 1 :]
        if not rest.startswith(":"):
            raise ValueError("missing port for ipv6 host")
        port = int(rest[1:])
    else:
        if ":" not in hostport:
            raise ValueError("missing port")
        host, port_s = hostport.rsplit(":", 1)
        port = int(port_s)
    if not host or not port:
        raise ValueError("bad host/port")
    return host, port


def resolve_to_ip(host: str) -> Optional[str]:
    try:
        # если уже IP — вернётся он же
        socket.inet_pton(socket.AF_INET, host)
        return host
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return host
    except OSError:
        pass
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def ip_api_country_code(client: httpx.Client, ip_or_host: str) -> Optional[str]:
    # ip-api ограничен по частоте — делаем простую паузу между запросами
    try:
        r = client.get(IP_API_URL + urllib.parse.quote(ip_or_host), timeout=10)
        r.raise_for_status()
        data = r.json()
        if data.get("status") != "success":
            return None
        return data.get("countryCode")
    except Exception:
        return None


def ip_api_country_codes_batch(client: httpx.Client, ips_or_hosts: List[str]) -> List[Optional[str]]:
    """
    ip-api поддерживает batch POST. Возвращает список countryCode (или None) той же длины.
    """
    try:
        r = client.post(IP_API_BATCH_URL, json=ips_or_hosts, timeout=20)
        r.raise_for_status()
        data = r.json()
        if not isinstance(data, list):
            return [None] * len(ips_or_hosts)
        out: List[Optional[str]] = []
        for item in data:
            if isinstance(item, dict) and item.get("status") == "success":
                out.append(item.get("countryCode"))
            else:
                out.append(None)
        # иногда ip-api может вернуть меньше элементов — выравниваем
        if len(out) < len(ips_or_hosts):
            out.extend([None] * (len(ips_or_hosts) - len(out)))
        return out[: len(ips_or_hosts)]
    except Exception:
        return [None] * len(ips_or_hosts)


def vless_to_xray_outbound(link: str) -> dict:
    u = urllib.parse.urlsplit(link)
    q = urllib.parse.parse_qs(u.query)
    # uuid@host:port
    if "@" not in u.netloc:
        raise ValueError("missing '@' in netloc")
    userinfo, hostport = u.netloc.split("@", 1)
    uuid = urllib.parse.unquote(userinfo)

    host, port = parse_vless_host_port(link)

    def q1(key: str, default: Optional[str] = None) -> Optional[str]:
        v = q.get(key)
        if not v:
            return default
        return v[0]

    encryption = q1("encryption", "none") or "none"
    flow = q1("flow")
    network = (q1("type", "tcp") or "tcp").lower()
    security = (q1("security", "none") or "none").lower()
    sni = q1("sni") or q1("serverName") or q1("host")
    fp = q1("fp") or q1("fingerprint")
    alpn = q.get("alpn")
    allow_insecure = (q1("allowInsecure") == "1") or (q1("allowinsecure") == "1")

    stream_settings: dict = {"network": network}

    if network == "ws":
        path = q1("path", "/") or "/"
        ws_headers = {}
        ws_host = q1("host")
        if ws_host:
            ws_headers["Host"] = ws_host
        stream_settings["wsSettings"] = {"path": urllib.parse.unquote(path), "headers": ws_headers}
    elif network == "grpc":
        service_name = q1("serviceName") or q1("serviceName".lower())
        if not service_name:
            raise ValueError("grpc without serviceName")
        stream_settings["grpcSettings"] = {"serviceName": service_name}
    elif network == "tcp":
        # часто пусто
        pass
    else:
        # для простоты — поддерживаем только самые распространённые
        raise ValueError(f"unsupported network: {network}")

    if security == "tls":
        tls = {"serverName": sni} if sni else {}
        if fp:
            tls["fingerprint"] = fp
        if alpn:
            tls["alpn"] = alpn
        if allow_insecure:
            tls["allowInsecure"] = True
        stream_settings["security"] = "tls"
        stream_settings["tlsSettings"] = tls
    elif security == "reality":
        pbk = q1("pbk") or q1("publicKey")
        sid = q1("sid") or q1("shortId")
        spx = q1("spx") or q1("spiderX")
        if not (pbk and sid):
            raise ValueError("reality missing pbk/sid")
        reality = {
            "serverName": sni or "",
            "publicKey": pbk,
            "shortId": sid,
        }
        if fp:
            reality["fingerprint"] = fp
        if spx:
            reality["spiderX"] = urllib.parse.unquote(spx)
        stream_settings["security"] = "reality"
        stream_settings["realitySettings"] = reality
    else:
        stream_settings["security"] = "none"

    user = {"id": uuid, "encryption": encryption}
    if flow:
        user["flow"] = flow

    outbound = {
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": host,
                    "port": port,
                    "users": [user],
                }
            ]
        },
        "streamSettings": stream_settings,
        "tag": "proxy",
    }
    return outbound


def make_xray_config(link: str, socks_port: int) -> dict:
    outbound = vless_to_xray_outbound(link)
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"udp": True},
                "tag": "in",
            }
        ],
        "outbounds": [
            outbound,
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "block"},
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {"type": "field", "inboundTag": ["in"], "outboundTag": "proxy"},
            ],
        },
    }


def wait_port_open(port: int, timeout_s: float = 3.0) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return True
        except Exception:
            time.sleep(0.05)
    return False


@dataclass
class CheckResult:
    link: str
    ping_ms: float


def measure_ping_via_xray(xray_path: str, link: str, target_url: str) -> Optional[float]:
    socks_port = random.randint(20000, 40000)
    cfg = make_xray_config(link, socks_port)

    with tempfile.TemporaryDirectory(prefix="xraycfg_") as td:
        cfg_path = os.path.join(td, "config.json")
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False)

        proc = subprocess.Popen(
            [xray_path, "run", "-c", cfg_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            if not wait_port_open(socks_port, timeout_s=3.5):
                return None

            # "пинг" через прокси делаем как время ответа HTTP(S) запроса через SOCKS5
            # используем curl (есть в ubuntu-latest) — это надёжнее чем тянуть socks-зависимости.
            cmd = [
                "curl",
                "--max-time",
                "8",
                "--connect-timeout",
                "5",
                "-L",
                "-o",
                "/dev/null",
                "-s",
                "-w",
                "%{time_total}",
                "--socks5-hostname",
                f"127.0.0.1:{socks_port}",
                target_url,
            ]
            r = subprocess.run(cmd, capture_output=True, text=True)
            if r.returncode != 0:
                return None
            try:
                seconds = float((r.stdout or "").strip())
            except Exception:
                return None
            if seconds <= 0:
                return None
            return seconds * 1000.0
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except Exception:
                proc.kill()


def write_outputs(links: List[str], out_txt: str, out_b64: str) -> None:
    txt = "\n".join(links).strip() + ("\n" if links else "")
    with open(out_txt, "w", encoding="utf-8") as f:
        f.write(txt)
    b64 = base64.b64encode(txt.encode("utf-8")).decode("ascii")
    with open(out_b64, "w", encoding="utf-8") as f:
        f.write(b64 + "\n")


def main() -> int:
    load_dotenv()

    ap = argparse.ArgumentParser()
    ap.add_argument("--xray-path", default=os.environ.get("XRAY_PATH", "./xray"))
    ap.add_argument("--target-url", default=os.environ.get("PING_TARGET_URL", "https://ya.ru/"))
    ap.add_argument("--max-top", type=int, default=int(os.environ.get("TOP_N", "100")))
    ap.add_argument("--out-txt", default="ru_top.txt")
    ap.add_argument("--out-b64", default="ru_top_base64.txt")
    args = ap.parse_args()

    xray_path = args.xray_path
    if not os.path.exists(xray_path):
        _log(f"ERROR: xray not found at {xray_path}")
        return 2

    _log("Downloading VLESS list…")
    links = download_vless_list(VLESS_LIST_URL)
    _log(f"Total links: {len(links)}")

    _log("Filtering by GeoIP (countryCode == RU)…")
    ru_links: List[str] = []
    with httpx.Client(headers={"User-Agent": "vpn-checker/1.0"}) as client:
        # собираем (link, ip_or_host) и шлём batch'ами по 100
        pairs: List[Tuple[str, str]] = []
        for link in links:
            try:
                host, _ = parse_vless_host_port(link)
            except Exception:
                continue
            ip_or_host = resolve_to_ip(host) or host
            pairs.append((link, ip_or_host))

        batch_size = 100
        for start in range(0, len(pairs), batch_size):
            chunk = pairs[start : start + batch_size]
            cc_list = ip_api_country_codes_batch(client, [ip for _, ip in chunk])
            for (link, _), cc in zip(chunk, cc_list):
                if cc == "RU":
                    ru_links.append(link)
            if (start + len(chunk)) % 500 == 0 or (start + len(chunk)) == len(pairs):
                _log(
                    f"GeoIP progress: {start + len(chunk)}/{len(pairs)} (RU kept: {len(ru_links)})"
                )

    _log(f"RU candidates: {len(ru_links)}")
    if not ru_links:
        _log("No RU servers found; writing empty outputs.")
        write_outputs([], args.out_txt, args.out_b64)
        return 0

    _log("Checking speed via Xray (HTTP ping through SOCKS)…")
    results: List[CheckResult] = []
    for i, link in enumerate(ru_links, 1):
        try:
            ping_ms = measure_ping_via_xray(xray_path, link, args.target_url)
        except Exception:
            ping_ms = None
        if ping_ms is not None:
            results.append(CheckResult(link=link, ping_ms=ping_ms))
        if i % 10 == 0:
            _log(f"Speed progress: {i}/{len(ru_links)} (alive: {len(results)})")

    if not results:
        _log("No working RU servers; writing empty outputs.")
        write_outputs([], args.out_txt, args.out_b64)
        return 0

    results.sort(key=lambda r: r.ping_ms)
    top = results[: max(0, args.max_top)]
    top_links = [r.link for r in top]

    _log(f"Writing top-{len(top_links)} results…")
    write_outputs(top_links, args.out_txt, args.out_b64)

    _log("Done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

