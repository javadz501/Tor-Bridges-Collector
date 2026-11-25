## If you find this helpful, don't forget to ⭐ it

_Last updated: 2026-11-25 17:32 UTC_

This repository automatically collects, checks reachability, and archives Tor bridges. A GitHub Action runs daily at 02:30 UTC to fetch new bridges from the official Tor Project.

### Reachable (Latest Check)
These lists contain bridges that passed a transport-level reachability check. A successful TCP connection or TLS handshake does not guarantee that a Tor circuit can be established.

| Transport | IPv4 (Tested) | Count | IPv6 (Tested) | Count |
| :--- | :--- | :--- | :--- | :--- |
| **obfs4** | [obfs4_tested.txt](https://raw.githubusercontent.com/javadz501/Tor-Bridges-Collector/refs/heads/main/bridge/obfs4_tested.txt) | **496** | [obfs4_ipv6_tested.txt](https://raw.githubusercontent.com/javadz501/Tor-Bridges-Collector/refs/heads/main/bridge/obfs4_ipv6_tested.txt) | **359** |
| **WebTunnel** | [webtunnel_tested.txt](https://raw.githubusercontent.com/javadz501/Tor-Bridges-Collector/refs/heads/main/bridge/webtunnel_tested.txt) | **191** | [webtunnel_ipv6_tested.txt](https://raw.githubusercontent.com/javadz501/Tor-Bridges-Collector/refs/heads/main/bridge/webtunnel_ipv6_tested.txt) | **86** |
| **Vanilla** | [vanilla_tested.txt](https://raw.githubusercontent.com/javadz501/Tor-Bridges-Collector/refs/heads/main/bridge/vanilla_tested.txt) | **500** | [vanilla_ipv6_tested.txt](https://raw.githubusercontent.com/javadz501/Tor-Bridges-Collector/refs/heads/main/bridge/vanilla_ipv6_tested.txt) | **75** |

### Fresh Bridges (Last 72 Hours)
Bridges discovered within the last 3 days.

| Transport | IPv4 (72h) | Count | IPv6 (72h) | Count |
| :--- | :--- | :--- | :--- | :--- |
| **obfs4** | [obfs4_72h.txt](https://raw.githubusercontent.com/javadz501/Tor-Bridges-Collector/refs/heads/main/bridge/obfs4_72h.txt) | **2** | [obfs4_ipv6_72h.txt](https://raw.githubusercontent.com/javadz501/Tor-Bridges-Collector/refs/heads/main/bridge/obfs4_ipv6_72h.txt) | **2** |
| **WebTunnel** | [webtunnel_72h.txt](https://raw.githubusercontent.com/javadz501/Tor-Bridges-Collector/refs/heads/main/bridge/webtunnel_72h.txt) | **2** | [webtunnel_ipv6_72h.txt](https://raw.githubusercontent.com/javadz501/Tor-Bridges-Collector/refs/heads/main/bridge/webtunnel_ipv6_72h.txt) | **2** |
| **Vanilla** | [vanilla_72h.txt](https://raw.githubusercontent.com/javadz501/Tor-Bridges-Collector/refs/heads/main/bridge/vanilla_72h.txt) | **4** | [vanilla_ipv6_72h.txt](https://raw.githubusercontent.com/javadz501/Tor-Bridges-Collector/refs/heads/main/bridge/vanilla_ipv6_72h.txt) | **4** |

### Full Archive (Since 2026-01-30)
History of all collected bridges. First-seen timestamps are retained indefinitely.

| Transport | IPv4 | Count | IPv6 | Count |
| :--- | :--- | :--- | :--- | :--- |
| **obfs4** | [obfs4.txt](https://raw.githubusercontent.com/javadz501/Tor-Bridges-Collector/refs/heads/main/bridge/obfs4.txt) | **680** | [obfs4_ipv6.txt](https://raw.githubusercontent.com/javadz501/Tor-Bridges-Collector/refs/heads/main/bridge/obfs4_ipv6.txt) | **359** |
| **WebTunnel** | [webtunnel.txt](https://raw.githubusercontent.com/javadz501/Tor-Bridges-Collector/refs/heads/main/bridge/webtunnel.txt) | **309** | [webtunnel_ipv6.txt](https://raw.githubusercontent.com/javadz501/Tor-Bridges-Collector/refs/heads/main/bridge/webtunnel_ipv6.txt) | **263** |
| **Vanilla** | [vanilla.txt](https://raw.githubusercontent.com/javadz501/Tor-Bridges-Collector/refs/heads/main/bridge/vanilla.txt) | **502** | [vanilla_ipv6.txt](https://raw.githubusercontent.com/javadz501/Tor-Bridges-Collector/refs/heads/main/bridge/vanilla_ipv6.txt) | **75** |

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
