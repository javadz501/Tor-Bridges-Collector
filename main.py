import os
import asyncio
import requests
import json
import re
import socket
import concurrent.futures
import ssl
import time
import ipaddress
import zipfile
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from datetime import datetime, timedelta, timezone

TARGETS = [
    {"url": "https://bridges.torproject.org/bridges?transport=obfs4", "file": "obfs4.txt", "type": "obfs4", "ip": "IPv4"},
    {"url": "https://bridges.torproject.org/bridges?transport=webtunnel", "file": "webtunnel.txt", "type": "webtunnel", "ip": "IPv4"},
    {"url": "https://bridges.torproject.org/bridges?transport=vanilla", "file": "vanilla.txt", "type": "vanilla", "ip": "IPv4"},
    {"url": "https://bridges.torproject.org/bridges?transport=obfs4&ipv6=yes", "file": "obfs4_ipv6.txt", "type": "obfs4", "ip": "IPv6"},
    {"url": "https://bridges.torproject.org/bridges?transport=webtunnel&ipv6=yes", "file": "webtunnel_ipv6.txt", "type": "webtunnel", "ip": "IPv6"},
    {"url": "https://bridges.torproject.org/bridges?transport=vanilla&ipv6=yes", "file": "vanilla_ipv6.txt", "type": "vanilla", "ip": "IPv6"},
]

RECENT_HOURS = 72
HISTORY_RETENTION_DAYS = None  # Preserve first-seen timestamps indefinitely.
REPO_URL = "https://raw.githubusercontent.com/javadz501/Tor-Bridges-Collector/refs/heads/main"
MAX_WORKERS = 50
CONNECTION_TIMEOUT = 8
MAX_RETRIES = 2
SSL_TIMEOUT = 5
MAX_TEST_PER_TYPE = 500

IS_GITHUB = os.getenv('GITHUB_ACTIONS') == 'true'
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')
TELEGRAM_UPLOAD = os.getenv('TELEGRAM_UPLOAD', '').lower() == 'true'

BRIDGE_DIR = "bridge"
HISTORY_FILE = os.path.join(BRIDGE_DIR, "bridge_history.json")

if not os.path.exists(BRIDGE_DIR):
    os.makedirs(BRIDGE_DIR)

def utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def write_text_atomic(file_path, content):
    temp_path = file_path + ".tmp"
    with open(temp_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)
    os.replace(temp_path, file_path)


def write_lines_atomic(file_path, lines, preserve_existing_on_empty=False):
    normalized = [str(line).strip() for line in lines if str(line).strip()]
    if preserve_existing_on_empty and not normalized and os.path.exists(file_path):
        return False
    write_text_atomic(file_path, "".join(line + "\n" for line in normalized))
    return True


def merge_archive_bridges(existing, fetched, extra):
    return set(existing).union(fetched).union(extra)


def log(message):
    timestamp = utc_now().strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"[{timestamp}] {message}")

def is_valid_bridge_line(line):
    if "No bridges available" in line:
        return False
    if line.startswith("#"):
        return False
    if len(line) < 10:
        return False
    return bool(re.search(r'\d+\.\d+\.\d+\.\d+|\[.*\]|https?://', line))

def normalize_vanilla_for_history(line):
    if not line.startswith("Bridge "):
        return "Bridge " + line
    return line

def convert_vanilla_for_saving(line):
    if line.startswith("Bridge "):
        return line[7:]
    return line

def convert_existing_file_to_new_format(file_path):
    if not os.path.exists(file_path):
        return
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        
        converted = False
        new_lines = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if line.startswith("Bridge "):
                new_lines.append(line[7:] + "\n")
                converted = True
            else:
                new_lines.append(line + "\n")
        
        if converted:
            with open(file_path, "w", encoding="utf-8") as f:
                f.writelines(new_lines)
            log(f"Converted existing file {file_path} to new format")
    except Exception as e:
        log(f"Error converting {file_path}: {e}")

def convert_all_existing_vanilla_files():
    vanilla_files = [
        os.path.join(BRIDGE_DIR, "vanilla.txt"),
        os.path.join(BRIDGE_DIR, "vanilla_72h.txt"),
        os.path.join(BRIDGE_DIR, "vanilla_tested.txt"),
        os.path.join(BRIDGE_DIR, "vanilla_ipv6.txt"),
        os.path.join(BRIDGE_DIR, "vanilla_ipv6_72h.txt"),
        os.path.join(BRIDGE_DIR, "vanilla_ipv6_tested.txt")
    ]
    
    for file_path in vanilla_files:
        convert_existing_file_to_new_format(file_path)

def extract_connection_info(line, prefer_ipv6=False):
    line = line.strip()
    if not line or len(line) < 5:
        return None, None, None
    
    test_line = line
    if not test_line.startswith("Bridge ") and " " in test_line and ":" in test_line.split()[0]:
        test_line = "Bridge " + test_line
    
    line_lower = test_line.lower()
    if "obfs4" in line_lower:
        transport = "obfs4"
    elif "webtunnel" in line_lower or "https://" in line_lower:
        transport = "webtunnel"
    else:
        transport = "vanilla"
    
    if prefer_ipv6:
        match = re.search(r'\[([0-9a-fA-F:]+)\]:(\d+)', test_line, re.IGNORECASE)
        if match:
            return match.group(1), int(match.group(2)), transport
    
    patterns = [
        (r'https?://\[([0-9a-fA-F:]+)\](?::(\d+))?', "ipv6"),
        (r'https?://([^/:]+)(?::(\d+))?', "domain"),
        (r'\[([0-9a-fA-F:]+)\]:(\d+)', "ipv6"),
        (r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)', "ipv4"),
        (r'([a-zA-Z0-9.-]+):(\d+)', "domain"),
        (r'obfs4\s+([^:]+):(\d+)\s+', "obfs4"),
        (r'(\S+)\s+(\S+)\s+(\S+)', "fingerprint"),
    ]
    
    for pattern, ptype in patterns:
        match = re.search(pattern, test_line, re.IGNORECASE)
        if match:
            if ptype == "fingerprint" and len(match.groups()) >= 3:
                host = match.group(1)
                port = match.group(2)
                return host, int(port), transport
            elif len(match.groups()) >= 2:
                host = match.group(1)
                port = match.group(2) if match.group(2) else "443"
                return host, int(port), transport
            elif ptype in ["domain", "ipv6"]:
                host = match.group(1)
                port = "443" if "https" in line_lower else "80"
                return host, int(port), transport
    
    return None, None, transport

def extract_webtunnel_domain(line):
    match = re.search(r'https?://([^/\s:]+)', line, re.IGNORECASE)
    if match:
        return match.group(1)
    return None

def is_valid_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except:
        return False

def resolve_host(host, ipv6=False):
    hosts = resolve_hosts(host, ipv6=ipv6)
    return hosts[0] if hosts else None

def resolve_hosts(host, ipv6=False):
    family = socket.AF_INET6 if ipv6 else socket.AF_INET
    results = []
    try:
        infos = socket.getaddrinfo(host, None, family, socket.SOCK_STREAM)
        for info in infos:
            addr = info[4][0]
            if addr and addr not in results:
                results.append(addr)
    except:
        pass
    return results

def is_unroutable_ipv6(host):
    try:
        ip = ipaddress.IPv6Address(host)
    except:
        return False
    return not ip.is_global

def test_tcp_socket(host, port, timeout, server_hostname=None):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, "tcp reachable"
    except Exception as e:
        return False, f"tcp {host}:{port} -> {type(e).__name__}: {e}"

def test_ssl_socket(host, port, timeout, server_hostname=None):
    try:
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=server_hostname or host):
                return True, "TLS certificate and hostname verified"
    except Exception as e:
        return False, f"tls {host}:{port} (sni={server_hostname}) -> {type(e).__name__}: {e}"

def advanced_connection_test(bridge_line, ipv6=False):
    host, port, transport = extract_connection_info(bridge_line, prefer_ipv6=ipv6)
    if not host or not port:
        return False, "no host/port extracted"
    sni_domain = extract_webtunnel_domain(bridge_line) if transport == "webtunnel" else None
    if transport == "webtunnel":
        test_func = test_ssl_socket
        timeout = CONNECTION_TIMEOUT
        default_port = 443
    else:
        test_func = test_tcp_socket
        timeout = CONNECTION_TIMEOUT
        default_port = 9001 if transport == "obfs4" else 443
    if port == 0:
        port = default_port
    test_hosts = []
    if transport == "webtunnel" and ipv6:
        if not sni_domain:
            return False, "no url domain found for webtunnel IPv6"
        test_hosts = resolve_hosts(sni_domain, ipv6=True)
        if not test_hosts:
            return False, f"no AAAA records for {sni_domain}"
        last_reason = "unknown"
    else:
        if is_valid_ip(host):
            if not is_unroutable_ipv6(host):
                test_hosts.append(host)
        else:
            resolved = resolve_host(host, ipv6=ipv6)
            if resolved and not is_unroutable_ipv6(resolved):
                test_hosts.append(resolved)
            if not is_unroutable_ipv6(host):
                test_hosts.append(host)
        if not test_hosts:
            return False, "only unroutable/documentation address"
        last_reason = "unknown"
    for test_host in test_hosts:
        for attempt in range(MAX_RETRIES):
            try:
                ok, reason = test_func(test_host, port, timeout, sni_domain)
                last_reason = reason
                if ok:
                    return True, "ok"
            except Exception as e:
                last_reason = f"{type(e).__name__}: {e}"
            if attempt < MAX_RETRIES - 1:
                time.sleep(0.3 * (attempt + 1))
    return False, last_reason

def smart_bridge_filter(bridge_list, transport_type):
    if not bridge_list:
        return []
    if len(bridge_list) > MAX_TEST_PER_TYPE:
        bridge_list = bridge_list[:MAX_TEST_PER_TYPE]
    unique_bridges = []
    seen = set()
    for bridge in bridge_list:
        key = re.sub(r'\s+', ' ', bridge.strip()).lower()
        if key not in seen:
            seen.add(key)
            unique_bridges.append(bridge)
    return unique_bridges

def batch_test_bridges(bridge_list, transport_type, ipv6=False, batch_size=100):
    if not bridge_list:
        return []
    normalized_for_test = []
    for bridge in bridge_list:
        if transport_type == "vanilla" and not bridge.startswith("Bridge "):
            normalized_for_test.append("Bridge " + bridge)
        else:
            normalized_for_test.append(bridge)
    
    filtered_bridges = smart_bridge_filter(normalized_for_test, transport_type)
    if not filtered_bridges:
        return []
    
    working_bridges = []
    total = len(filtered_bridges)
    failure_reasons = {}
    
    for i in range(0, total, batch_size):
        batch = filtered_bridges[i:i + batch_size]
        batch_working = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(batch))) as executor:
            future_to_bridge = {executor.submit(advanced_connection_test, bridge, ipv6): bridge for bridge in batch}
            for future in concurrent.futures.as_completed(future_to_bridge):
                bridge = future_to_bridge[future]
                try:
                    ok, reason = future.result()
                    if ok:
                        batch_working.append(bridge)
                    else:
                        reason = (reason or "unknown")[:200]
                        failure_reasons[reason] = failure_reasons.get(reason, 0) + 1
                except Exception as e:
                    failure_reasons[f"exception: {type(e).__name__}: {e}"[:200]] = failure_reasons.get(f"exception: {type(e).__name__}: {e}"[:200], 0) + 1
        working_bridges.extend(batch_working)
        if len(batch_working) > 0:
            log(f"   Batch {i//batch_size + 1}: {len(batch_working)}/{len(batch)} bridges working")
    
    if failure_reasons:
        top_reasons = sorted(failure_reasons.items(), key=lambda x: -x[1])[:10]
        log(f"   Top failure reasons ({transport_type}{' IPv6' if ipv6 else ''}):")
        for reason, count in top_reasons:
            log(f"     - [{count}] {reason}")
    
    if transport_type == "vanilla":
        working_bridges = [convert_vanilla_for_saving(bridge) for bridge in working_bridges]
    
    return working_bridges

def load_history():
    if not os.path.exists(HISTORY_FILE):
        return {}
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            history = json.load(f)
        if not isinstance(history, dict):
            raise ValueError("History root must be a JSON object")
        return history
    except Exception as e:
        log(f"History file is unreadable; refusing to overwrite it: {e}")
        raise RuntimeError("Cannot continue with an unreadable bridge history file") from e


def save_history(history):
    converted_history = {}
    for bridge, timestamp in history.items():
        key = bridge if bridge.startswith("Bridge ") else "Bridge " + bridge
        converted_history[key] = timestamp
    write_text_atomic(HISTORY_FILE, json.dumps(converted_history, indent=2) + "\n")


def cleanup_history(history):
    retained = {}
    for bridge, timestamp in history.items():
        try:
            datetime.fromisoformat(timestamp)
        except (TypeError, ValueError):
            log(f"Skipping history entry with invalid timestamp: {bridge[:80]}")
            continue
        retained[bridge] = timestamp
    return retained


def update_readme(stats):
    timestamp = utc_now().strftime("%Y-%m-%d %H:%M UTC")
    readme_content = f"""## If you find this helpful, don't forget to ⭐ it

_Last updated: {timestamp}_

This repository automatically collects, checks reachability, and archives Tor bridges. A GitHub Action runs daily at 02:30 UTC to fetch new bridges from the official Tor Project.

### Reachable (Latest Check)
These lists contain bridges that passed a transport-level reachability check. A successful TCP connection or TLS handshake does not guarantee that a Tor circuit can be established.

| Transport | IPv4 (Tested) | Count | IPv6 (Tested) | Count |
| :--- | :--- | :--- | :--- | :--- |
| **obfs4** | [obfs4_tested.txt]({REPO_URL}/bridge/obfs4_tested.txt) | **{stats.get('obfs4_tested.txt', 0)}** | [obfs4_ipv6_tested.txt]({REPO_URL}/bridge/obfs4_ipv6_tested.txt) | **{stats.get('obfs4_ipv6_tested.txt', 0)}** |
| **WebTunnel** | [webtunnel_tested.txt]({REPO_URL}/bridge/webtunnel_tested.txt) | **{stats.get('webtunnel_tested.txt', 0)}** | [webtunnel_ipv6_tested.txt]({REPO_URL}/bridge/webtunnel_ipv6_tested.txt) | **{stats.get('webtunnel_ipv6_tested.txt', 0)}** |
| **Vanilla** | [vanilla_tested.txt]({REPO_URL}/bridge/vanilla_tested.txt) | **{stats.get('vanilla_tested.txt', 0)}** | [vanilla_ipv6_tested.txt]({REPO_URL}/bridge/vanilla_ipv6_tested.txt) | **{stats.get('vanilla_ipv6_tested.txt', 0)}** |

### Fresh Bridges (Last 72 Hours)
Bridges discovered within the last 3 days.

| Transport | IPv4 (72h) | Count | IPv6 (72h) | Count |
| :--- | :--- | :--- | :--- | :--- |
| **obfs4** | [obfs4_72h.txt]({REPO_URL}/bridge/obfs4_72h.txt) | **{stats.get('obfs4_72h.txt', 0)}** | [obfs4_ipv6_72h.txt]({REPO_URL}/bridge/obfs4_ipv6_72h.txt) | **{stats.get('obfs4_ipv6_72h.txt', 0)}** |
| **WebTunnel** | [webtunnel_72h.txt]({REPO_URL}/bridge/webtunnel_72h.txt) | **{stats.get('webtunnel_72h.txt', 0)}** | [webtunnel_ipv6_72h.txt]({REPO_URL}/bridge/webtunnel_ipv6_72h.txt) | **{stats.get('webtunnel_ipv6_72h.txt', 0)}** |
| **Vanilla** | [vanilla_72h.txt]({REPO_URL}/bridge/vanilla_72h.txt) | **{stats.get('vanilla_72h.txt', 0)}** | [vanilla_ipv6_72h.txt]({REPO_URL}/bridge/vanilla_ipv6_72h.txt) | **{stats.get('vanilla_ipv6_72h.txt', 0)}** |

### Full Archive (Since 2026-01-30)
History of all collected bridges. First-seen timestamps are retained indefinitely.

| Transport | IPv4 | Count | IPv6 | Count |
| :--- | :--- | :--- | :--- | :--- |
| **obfs4** | [obfs4.txt]({REPO_URL}/bridge/obfs4.txt) | **{stats.get('obfs4.txt', 0)}** | [obfs4_ipv6.txt]({REPO_URL}/bridge/obfs4_ipv6.txt) | **{stats.get('obfs4_ipv6.txt', 0)}** |
| **WebTunnel** | [webtunnel.txt]({REPO_URL}/bridge/webtunnel.txt) | **{stats.get('webtunnel.txt', 0)}** | [webtunnel_ipv6.txt]({REPO_URL}/bridge/webtunnel_ipv6.txt) | **{stats.get('webtunnel_ipv6.txt', 0)}** |
| **Vanilla** | [vanilla.txt]({REPO_URL}/bridge/vanilla.txt) | **{stats.get('vanilla.txt', 0)}** | [vanilla_ipv6.txt]({REPO_URL}/bridge/vanilla_ipv6.txt) | **{stats.get('vanilla_ipv6.txt', 0)}** |

## Important Notes on IPv6 & WebTunnel

1.  **IPv6 Instability:** IPv6 bridges are significantly fewer in number and are often more susceptible to blocking or connection instability compared to IPv4.
2.  **WebTunnel Overlap:** WebTunnel bridges often use the same endpoint domain for both IPv4 and IPv6. Consequently, the IPv6 list is frequently identical to or a subset of the IPv4 list.
3.  **Recommendation:** For the most reliable connection, **prioritize using IPv4 bridges**. Use IPv6 only if IPv4 is completely inaccessible on your network.
4.  **Reachability Scope:** obfs4 and vanilla checks confirm TCP reachability only. WebTunnel checks validate the TLS certificate and hostname. None of these checks completes a Tor circuit.
5.  **Snapshot Policy:** If a run reports zero reachable bridges for a transport, the previous non-empty tested snapshot is retained to protect against transient network or test failures.

## Keep Delta-Kronecker Going!

### Donate

**USDT BEP20** (BNB Smart Chain):
```
0x2a434FF74737be5B94634040D010a458507b0741
```
> BEP20 network only — send only USDT on BNB Smart Chain.

---

## Disclaimer
This project is for educational and archival purposes. Please use these bridges responsibly.
"""
    write_text_atomic("README.md", readme_content)
    log("README.md updated with latest statistics.")

def create_zip_archive():
    zip_name = "tor_bridges.zip"
    zip_path = os.path.join(BRIDGE_DIR, zip_name)
    temp_path = zip_path + ".tmp"
    archive_root = "Tor Bridges"

    with zipfile.ZipFile(temp_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zipf:
        for root, _, files in os.walk(BRIDGE_DIR):
            for filename in sorted(files):
                if filename in {zip_name, "bridge_history.json"} or not filename.endswith(".txt"):
                    continue

                file_path = os.path.join(root, filename)
                if filename.endswith("_tested.txt"):
                    folder = os.path.join(archive_root, "Tested", "IPv6" if "ipv6" in filename else "IPv4")
                elif filename.endswith(f"_{RECENT_HOURS}h.txt"):
                    folder = os.path.join(archive_root, "Recent 72h")
                else:
                    folder = os.path.join(archive_root, "Full Archive")

                zipf.write(file_path, os.path.join(folder, filename))

    os.replace(temp_path, zip_path)
    log(f"Created ZIP archive: {zip_path}")
    return zip_path


def send_to_telegram(file_path, caption):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        log("Telegram credentials missing.")
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendDocument"
    try:
        with open(file_path, 'rb') as f:
            response = requests.post(url, data={'chat_id': TELEGRAM_CHAT_ID, 'caption': caption, 'parse_mode': 'Markdown'}, files={'document': f})
            if response.status_code == 200:
                log(f"Telegram upload successful: {os.path.basename(file_path)}")
            else:
                log(f"Telegram upload failed: {response.status_code}")
    except Exception as e:
        log(f"Telegram Error: {e}")

def fetch_telegram_bridges():
    # GitHub passes a secret that does not exist as an EMPTY string, not as a missing
    # variable, so int("") used to crash the whole run on a fork without Telegram secrets.
    try:
        api_id = int(os.getenv("TELEGRAM_API_ID") or 0)
    except ValueError:
        api_id = 0
    api_hash = os.getenv("TELEGRAM_API_HASH") or ""
    session = os.getenv("TELEGRAM_SESSION") or ""
    if api_id == 0 or not api_hash or not session:
        log("GetBridgesBot disabled: TELEGRAM_API_ID/API_HASH/SESSION secrets missing.")
        return {}

    try:
        from telethon import TelegramClient
        from telethon.sessions import StringSession
    except ImportError:
        log("GetBridgesBot skipped: telethon is not installed.")
        return {}

    bot_username = os.getenv("GETBRIDGES_BOT", "GetBridgesBot")
    requests_to_bot = [("obfs4", "obfs4 bridges"), ("webtunnel", "webtunnel bridges")]
    result = {}

    async def _fetch():
        client = TelegramClient(StringSession(session), api_id, api_hash)
        try:
            await asyncio.wait_for(client.connect(), timeout=15)
        except asyncio.TimeoutError:
            log("GetBridgesBot: Telethon connect timed out.")
            return result
        if not await client.is_user_authorized():
            log("GetBridgesBot skipped: Telegram session is not authorized.")
            await client.disconnect()
            return result
        for transport, request in requests_to_bot:
            found = []
            try:
                async with client.conversation(bot_username, timeout=30) as conv:
                    await conv.send_message("/start")
                    try:
                        await conv.get_response(timeout=20)
                    except Exception:
                        pass
                    await conv.send_message(request)
                    while True:
                        try:
                            msg = await conv.get_response(timeout=25)
                        except Exception:
                            break
                        text = msg.text or ""
                        for raw_line in text.splitlines():
                            line = raw_line.strip().strip('`')
                            if transport in line.lower() and is_valid_bridge_line(line):
                                if line not in found:
                                    found.append(line)
                        if found:
                            break
            except Exception as e:
                log(f"GetBridgesBot {transport} error: {type(e).__name__}: {e}")
            if found:
                result[transport] = found
                log(f"GetBridgesBot: received {len(found)} {transport} bridge line(s).")
        await client.disconnect()
        return result

    try:
        return asyncio.run(asyncio.wait_for(_fetch(), timeout=120))
    except asyncio.TimeoutError:
        log("GetBridgesBot timed out.")
        return {}
    except Exception as e:
        log(f"GetBridgesBot error: {type(e).__name__}: {e}")
        return {}

def main():
    convert_all_existing_vanilla_files()
    
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    })
    
    history = load_history()
    history = cleanup_history(history)
    
    recent_cutoff_time = utc_now() - timedelta(hours=RECENT_HOURS)
    stats = {}
    
    log("Starting Bridge Scraper Session...")
    
    telegram_bridges = fetch_telegram_bridges()

    for target in TARGETS:
        url = target["url"]
        filename = target["file"]
        bridge_path = os.path.join(BRIDGE_DIR, filename)
        recent_filename = filename.replace(".txt", f"_{RECENT_HOURS}h.txt")
        recent_path = os.path.join(BRIDGE_DIR, recent_filename)
        tested_filename = filename.replace(".txt", "_tested.txt")
        tested_path = os.path.join(BRIDGE_DIR, tested_filename)
        transport_type = target["type"]
        
        existing_bridges = set()
        if os.path.exists(bridge_path):
            try:
                with open(bridge_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if is_valid_bridge_line(line):
                            if transport_type == "vanilla":
                                if not line.startswith("Bridge "):
                                    existing_bridges.add("Bridge " + line)
                                else:
                                    existing_bridges.add(line)
                            else:
                                existing_bridges.add(line)
            except:
                pass

        fetched_bridges = set()
        try:
            response = session.get(url, timeout=30)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, "html.parser")
                bridge_div = soup.find("div", id="bridgelines")
                
                if bridge_div:
                    raw_text = bridge_div.get_text()
                    lines = [line.strip() for line in raw_text.split("\n") if line.strip()]
                    
                    for line in lines:
                        if is_valid_bridge_line(line):
                            history_line = line
                            if transport_type == "vanilla":
                                history_line = normalize_vanilla_for_history(line)
                            fetched_bridges.add(history_line)
                            if history_line not in history:
                                history[history_line] = utc_now().isoformat()
                else:
                    log(f"Warning: No bridge container for {filename}.")
            else:
                log(f"Failed to fetch {url}. Status: {response.status_code}")

        except Exception as e:
            log(f"Connection error for {filename}: {e}")

        extra_bridges = set()
        for transport in ("obfs4", "webtunnel"):
            if filename == f"{transport}.txt":
                for line in telegram_bridges.get(transport, []):
                    if is_valid_bridge_line(line):
                        extra_bridges.add(line)
                        history_line = line
                        if transport_type == "vanilla":
                            history_line = normalize_vanilla_for_history(line)
                        if history_line not in history:
                            history[history_line] = utc_now().isoformat()
                if extra_bridges:
                    log(f"Added {len(extra_bridges)} GetBridgesBot bridge(s) to {filename}")

        all_bridges = merge_archive_bridges(existing_bridges, fetched_bridges, extra_bridges)

        if all_bridges:
            sorted_bridges = sorted(all_bridges)
            save_bridges = (
                [convert_vanilla_for_saving(bridge) for bridge in sorted_bridges]
                if transport_type == "vanilla"
                else sorted_bridges
            )
            write_lines_atomic(bridge_path, save_bridges)
            log(f"Processed {filename}: Total {len(all_bridges)}")
        else:
            log(f"No valid bridges available for {filename}; preserving the existing archive.")

        recent_bridges = []
        for bridge in all_bridges:
            bridge_key = bridge
            if transport_type == "vanilla":
                bridge_key = normalize_vanilla_for_history(bridge)
            if bridge_key in history:
                try:
                    first_seen = datetime.fromisoformat(history[bridge_key])
                    if first_seen > recent_cutoff_time:
                        recent_bridges.append(bridge)
                except ValueError:
                    pass
        
        save_recent = (
            [convert_vanilla_for_saving(bridge) for bridge in sorted(recent_bridges)]
            if transport_type == "vanilla"
            else sorted(recent_bridges)
        )
        write_lines_atomic(recent_path, save_recent)
        
        tested_bridges = batch_test_bridges(sorted(all_bridges), transport_type, ipv6=(target["ip"] == "IPv6"))
        tested_count = len(tested_bridges)

        if tested_bridges:
            write_lines_atomic(tested_path, sorted(tested_bridges))
            log(f"   -> {tested_count} bridges passed the reachability check for {filename}.")
        else:
            preserved = not write_lines_atomic(tested_path, [], preserve_existing_on_empty=True)
            if preserved:
                with open(tested_path, "r", encoding="utf-8") as f:
                    tested_count = sum(1 for line in f if line.strip())
                log(f"   -> No bridges passed this run; preserving the previous {tested_count}-bridge snapshot for {filename}.")
            else:
                log(f"   -> No bridges passed the reachability check for {filename}.")

        stats[filename] = len(all_bridges)
        stats[recent_filename] = len(recent_bridges)
        stats[tested_filename] = tested_count

    save_history(history)
    update_readme(stats)
    
    zip_path = create_zip_archive()

    if TELEGRAM_UPLOAD:
        caption = (
            "*Tor Bridges Collector Update*\n\n"
            f"*obfs4:* {stats.get('obfs4.txt', 0)} IPv4 / {stats.get('obfs4_ipv6.txt', 0)} IPv6\n"
            f"*WebTunnel:* {stats.get('webtunnel.txt', 0)} IPv4 / {stats.get('webtunnel_ipv6.txt', 0)} IPv6\n"
            f"*Vanilla:* {stats.get('vanilla.txt', 0)} IPv4 / {stats.get('vanilla_ipv6.txt', 0)} IPv6\n\n"
            f"*Archive ZIP:* {os.path.basename(zip_path)}"
        )
        send_to_telegram(zip_path, caption)

    log("Session Finished.")

if __name__ == "__main__":
    main()
