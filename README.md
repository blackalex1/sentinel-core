# Sentinel-Core 🛡️

**Sentinel-Core** is the unified cross-platform proxy configuration, routing, and cryptography engine for the Sentinel ecosystem (**sentinel-panel**, **sentinel-desktop**, **sentinel-mobile**, and **proxmox_Sentinel controller**).

---

## 🚀 Key Features

* **Universal Multi-Core Compilers**:
  * **Sing-box** (v1.12+ and v1.13+ with modern `rule_set`, `hijack-dns`, `default_domain_resolver`, TUN, Mobile VPN loopback).
  * **Xray-core** (VLESS Reality, Post-Quantum `X25519Kyber768`, XTLS-Vision, Sniffing, Domain/IP routing).
  * **Hysteria 2** (Official server compiler with HTTP Webhook Auth backend, UDP Port Hopping `20000:50000`, Salamander Obfs, and local Xray routing forward).
* **Single Source of Truth Presets**:
  * Clean, atomic routing rules (`ru.json`, `bittorrent.json`, `ads.json`, `cn.json`, `us.json`, `ip_checkers.json`).
  * Dynamic target overrides (`DIRECT`, `BLOCKED`, `WARP`, `VPN`) without code changes.
  * Centralized Private LAN isolation (`geoip:private -> DIRECT`).
* **Multi-Language Capability Schema (`pkg/matrix`)**:
  * Dynamic metadata schema for UI forms with Russian (`ru`) and English (`en`) localization.
* **Hardened Security & Cryptography (`pkg/crypto`)**:
  * Argon2id key derivation + ChaCha20-Poly1305 / AES-256-GCM AEAD encryption.
  * Tamper detection and encrypted DB row ingestion.
* **Unified Security & IPS Subsystem (`pkg/security`)**:
  * **Active Port Guard & IPS**: Sensitive port defense (SSH 22, RDP 3389, PVE 8006, DBs), port scan detection, self-protection process whitelist.
  * **Rate Limiter & Anti-Flood**: Token-bucket client request limiter with automatic temporary IP isolation.
  * **Kill-Switch & Leak Prevention**: Fail-safe network drops, DNS leak prevention, IPv6 leak blocker, RFC1918 LAN bypass.
  * **Integrity & Secure Memory**: Ed25519/HMAC signature verification, SSRF and cloud metadata (`169.254.169.254`) blocking, runtime `Zeroize` memory wiping.
  * **Threat Shield Filtering**: High-performance Bloom Filter & Trie matcher for malware, phishing, cryptominers, and ad networks.
  * **Dynamic UI Settings Schema**: Ready-to-render UI metadata for Web Panel and Desktop/Mobile settings tabs (`ru`/`en`).
* **Universal Communication Interfaces**:
  * **Native Go API** (Direct import).
  * **C-FFI Shared Library** (`cmd/cshared` for Flutter, Kotlin, Swift, C#).
  * **CLI Engine** (`cmd/cli`).

---

## 🛠️ Building and Testing

```bash
# Run full unit and integration test suite
go test -v ./...

# Build CLI binary
go build -o bin/sentinel-core ./cmd/cli

# Build C-Shared Library for Mobile/Desktop FFI
go build -buildmode=c-shared -o bin/libsentinel_core.so ./cmd/cshared
```

---

## 📖 CLI Usage

```bash
# Parse any proxy URI
sentinel-core parse --uri "vless://..."

# Compile Sing-box client config with RU bypass preset
sentinel-core build --uri "hy2://..." --core singbox --preset ru

# Output security settings schema for Web Panel tab
sentinel-core security schema --lang ru
sentinel-core security schema --lang en

# Output default security configuration JSON
sentinel-core security default

# Output dynamic configuration schema for UI modal
sentinel-core schema --lang ru
sentinel-core schema --lang en

# List all available atomic routing presets
sentinel-core preset list
```

