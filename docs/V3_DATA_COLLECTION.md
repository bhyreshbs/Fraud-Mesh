# FraudMesh v3: what data can be collected, where it comes from, and how far to trust it

Scope: network, session and device signals added in v3 (contract 1.1.0). Each signal below has a source, a trust
level, and the place in the engine that uses it. Client-supplied signals are probabilistic evidence only. None of
them blocks on its own.

## 1. Sources

| Source | What it can provide | Trust |
|---|---|---|
| **Browser (bank web app, JavaScript)** | `session_id` (the app's own session identifier), `browser_timezone` (`Intl.DateTimeFormat().resolvedOptions().timeZone`), `locale` (`navigator.language`), `platform` (`navigator.platform` / UA-CH `platform`), `webgl_renderer` (`WEBGL_debug_renderer_info`, if the browser exposes it), `screen` (CSS px `width x height`), coarse `telemetry` (pointer type, keystroke timing mean/std, paste-into-sensitive-field flag, dwell times, screen-resolution changes), and the user agent | **Untrusted.** Every value can be spoofed by an attacker who controls the browser or uses an anti-detect browser. Used only as weak, combinable evidence. |
| **Trusted mobile app (signed, attested build)** | Same fields as the browser. Platform attestation (Play Integrity / App Attest) can make `platform` and the device binding more trustworthy. | **More trusted** when attestation is checked server side (not implemented in the demo), otherwise treat it like the browser. |
| **Server (the bank's own edge / API)** | The TCP peer **IP address** (behind a trusted proxy: `X-Forwarded-For` set by that proxy only), request time, TLS termination facts, the session cookie it issued itself | **Trusted for "which IP connected"**, but an IP says little about a person: carrier-grade NAT, offices, VPNs and Tor put many people behind one address. |
| **Offline IP intelligence (local files)** | `network_type` (residential / mobile / hosting / vpn / tor / unknown), ASN, `ip_timezone` | **Approximate.** Lists go stale and residential proxies look residential. Recorded with `network_source` and `network_confidence`. |
| **Integrations (IDS, cloud audit, KYC, telco)** | IDS alerts with source IP (Suricata), support-console actions, liveness and document scores, SIM-swap age | Trusted as signals from those systems. They are covered by the existing §7.1 events and are unchanged in v3. |

### What is NOT collected, and why

- **No MAC addresses.** Browsers cannot read a device's MAC address. A MAC address also never crosses an IP router,
  so the bank's server never sees the customer's MAC address. A "MAC address" sent by a client is just a string the
  client chose: it is **untrusted** and FraudMesh does not use it.
- **No raw IP addresses in storage or logs.** The API classifies the raw IP at ingestion (`api/enrichment.py`). It
  then tokenizes the address to a keyed /24 (IPv4) or /64 (IPv6) hash, and only that token and the classification
  are stored. The raw IP is never logged, including when enrichment fails.
- **No typed characters, OTPs or clipboard contents.** Telemetry is aggregate timing and flags only (contract
  `Telemetry`).
- **No JA4 / JA3 TLS fingerprints, TCP/IP stack (p0f) fingerprints or WebRTC-leaked addresses.** The demo has no TLS
  terminator or packet capture that could produce them, and WebRTC probing is intrusive. They are listed as future work
  (section 4).

## 2. IP geolocation is approximate

`lat`, `lon` and `city` usually come from IP geolocation, or from the app if the user allowed location access. IP
geolocation is often wrong by tens of kilometres, and much more for mobile carriers (one national egress) and for
VPN, Tor or hosting exits, which show where the exit server is, not where the user is. So:

- the behaviour detector multiplies `km_from_home` and the `IMPOSSIBLE_TRAVEL` floor by a **geo-confidence factor**:
  tor 0.2, vpn 0.3, hosting 0.3, unknown with confidence < 0.3 → 0.7, otherwise 1.0
  (`engine/detectors/rules/network_intel.yaml` → `geo_confidence`);
- events without enrichment (direct-mode replays, the golden fixtures) use 1.0, so the §12.4 values do not change;
- a VPN by itself raises nothing. It only makes location evidence weaker.

## 3. How each signal is used (engine)

| Signal | Feature / module | Evidence (reason code) | p (config) |
|---|---|---|---|
| network_type + confidence | `geo_confidence_factor` (engine/features/network.py) | down-weights FAR_FROM_HOME / IMPOSSIBLE_TRAVEL | factors in network_intel.yaml |
| browser_timezone vs ip_timezone (different UTC offset now) | `tz_mismatch` | behaviour `TZ_MISMATCH` (logins) | 0.02 |
| platform, pointer type, WebGL renderer, screen, platform change inside a session | `device_inconsistency`, `device_inconsistency_mask` | behaviour `DEVICE_INCONSISTENT` (logins); a supporting reason on auth evidence | 0.03 (one), 0.05 (two or more) |
| session first-seen context (network_type, ASN, device, platform, WebGL, customer) | `session_change`, `session_change_mask` | auth `SESSION_CONTEXT_CHANGE` (T1539) on mfa_change / mfa_challenge / profile_change / sim_signal; behaviour on logins | 0.05; 0.08 when the new network is hosting/vpn/tor |
| devices / accounts / sessions / client profiles per ip token in 24 h | `engine/graph/shared_ip.py` | context reason `SHARED_IP` (no p); shared IPs stop joining cases | thresholds in shared_ip.yaml |
| failed logins per account, per device and globally | engine/features/identity_windows.py | netsec `ACCOUNT_DISTRIBUTED_FAILURES`, `ACCOUNT_LOW_SLOW_FAILURES`, `DEVICE_MULTI_ACCOUNT_FAILURES`, `GLOBAL_LOGIN_FAILURE_SPIKE` | 0.04 / 0.03 / 0.05 / 0.03 (cred_stuffing.yaml) |

A session change is reported only when the **network AND the device context** change together. Wi-Fi ↔ mobile data
on the same phone changes the ASN but not the device, so it is not reported. Any session-carrying event that the
detector handles is evaluated, so a stolen session cookie replayed with no new login is still caught when it
reaches an account-control event.

### IP / device / session / location correlation in the entity graph (phase 13)

`EdgeType` is a frozen contract enum and has no session edge type, so `ses:` tokens do **not** become graph nodes or
edges. Session correlation stays in the feature windows (`engine/features/network.py`), and `ses:` tokens appear only
in `StoredEvent.entity_tokens` and evidence entities. IP ↔ device correlation uses the existing `CONNECTED_VIA` edges.
Their confidence drops to 0.0 for CGNAT IPs (cgnat.txt) and for IPs that are currently shared (shared_ip.py). Location
is kept as event attributes (lat/lon/city) and is not a graph node.

## 4. Future work (not implemented)

- **JA4 / JA4H TLS client fingerprints** from the TLS terminator (nginx/HAProxy module or a sensor) as a server-side,
  harder-to-spoof device-family signal.
- **TCP/IP stack fingerprints** (p0f-style OS guess) to cross-check the claimed `platform`.
- **WebRTC / STUN** checks for VPN leaks. Intrusive and browser-dependent; would need a privacy review.
- **Mobile platform attestation** (Play Integrity / App Attest), verified server side.
- **Commercial or fresher IP-intelligence feeds.** Today only local files: the committed demo list, plus optional
  IP2Proxy LITE CSV and MaxMind GeoLite2-ASN `.mmdb` when a path is configured (`FM_IP2PROXY_CSV`,
  `FM_GEOLITE2_ASN_MMDB`). The databases are not committed or downloaded.
- **A session edge type in the graph** (needs a contract change to `EdgeType`).
