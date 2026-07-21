# 🔐 Security Review — WiFi Intrusion Detection System

**Scope:** device firmware (`firmware/WIDS_ESP32/`), AWS IoT policy, Lambda + its IAM role, SNS/IoT
Rule wiring, and secrets handling.
**Context:** a home / portfolio project on the AWS free tier. Severities are rated for that context
(a home sensor), not an enterprise system.

**Overall posture: good.** The design already follows several real security best practices —
mutual TLS, least-privilege IAM, no secrets in source control, and a cost-safe serverless
architecture. The findings below are hardening opportunities and reliability gaps, not critical holes.

---

## ✅ Strengths (already done well — keep these, and talk about them in interviews)
- **Mutual TLS with server-cert validation** (`setCACert` + client cert/key) — both ends authenticated.
- **Least-privilege IoT policy** — device can only `Connect` as `WIDS_ESP32` and `Publish` to
  `wids/alerts`; no subscribe, no wildcard.
- **Least-privilege Lambda role** — a single inline `sns:Publish` to one topic.
- **No secrets in git** — `secrets.h`, `*.pem`, `*.key` are `.gitignore`d; the private key never
  leaves the device.
- **Cost-safe & attack-surface-small** — non-VPC (no NAT), one region, Budgets + billing alarm, root
  MFA + a separate IAM admin, short log retention.
- **Robust device logic** — NTP-before-TLS, tiny ISR-style sniffer callback, reconnect timeouts,
  alert cooldown, and NVS-persisted baseline.

---

## Findings

| # | Severity | Area | Finding | Recommendation |
|---|----------|------|---------|----------------|
| F1 | **Medium** | Firmware | The sniffer callback reads fixed offsets `payload[0..21]` **without checking the frame length** (`rx_ctrl.sig_len`). A malformed/truncated 802.11 frame could cause an out-of-bounds read → crash/reboot (a cheap DoS against your sensor). | Add a length guard at the top of the callback (snippet below). |
| F2 | **Medium** (physical) | Firmware | Private key + WiFi password sit in **plaintext flash** (no flash encryption / secure boot). Someone with physical possession could dump the key and impersonate the device. Blast radius is limited by the least-privilege policy (publish to one topic only). | For a "production" story, enable **ESP32 flash encryption + secure boot**; at minimum document the risk. |
| F3 | **Low** | Cloud reliability | The **IoT Rule has no error action / DLQ** — if the Lambda fails, the alert is dropped silently. | Add an error action (e.g., a second SNS/CloudWatch action) or a DLQ. |
| F4 | **Low** | Cloud / cost | **No cloud-side rate/spend guard.** A malfunctioning or compromised device could exceed SNS's 1,000 free emails/mo (cost) or cause alert fatigue. | A **CloudWatch alarm on Lambda invocations** (e.g., >100/hr) as a runaway-device tripwire. |
| F5 | **Low** | Firmware | **No offline buffering.** If WiFi is down when an attack is detected, `connectWiFi()` times out and the event is dropped. | Buffer the alert to NVS and flush on reconnect. |
| F6 | **Low** | Availability | **No device-offline detection.** If the ESP32 dies, alerts silently stop and you won't know. | Add a periodic **heartbeat** + a cloud alarm on "no heartbeat in N minutes" (dead-man's switch). |
| F7 | **Low** | Firmware | A **single shared cooldown** (`g_lastAlert`) is used for all three detections, so one alert can suppress a *different* detection type for the cooldown window. | Track cooldown **per event type**. |
| F8 | **Info** | Cloud | Lambda doesn't validate/sanitize incoming fields. Risk is low (only the authenticated device can publish), but it's good defense-in-depth. | Cap field lengths and strip control chars before building the email. |
| F9 | **Info** | Cloud | **SNS topic & CloudWatch logs are not KMS-encrypted (SSE).** Fine for a home project; KMS adds cost. | Note it; enable SSE only if you later handle sensitive data (mind KMS cost). |
| F10 | **Info** | Account | **CloudTrail not enabled.** Management-event logging is free and adds account-level auditing. | Enable a CloudTrail trail (management events) — cheap security-portfolio win. |
| F11 | **Info** | Design | **Trust-on-first-use baselines** (evil-twin at boot, device learning window): an attacker present at baseline time is trusted. | Documented limitation; optionally seed baselines from a known-good list. |

### F1 — the one code fix I'd apply first
Add this guard as the first lines of `snifferCallback` (`firmware/WIDS_ESP32/WIDS_ESP32.ino`):
```cpp
void IRAM_ATTR snifferCallback(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT) return;
  const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buf;
  if (ppkt->rx_ctrl.sig_len < 24) return;   // <-- guard: need a full 802.11 MAC header before indexing
  const uint8_t *p = ppkt->payload;
  ...
}
```
(24 bytes = frame-control + duration + the three MAC addresses + sequence — everything the parser reads.)

---

## Prioritized recommendations

**Now (quick, high-value):**
1. **F1** frame-length guard (a few lines; prevents a crash-DoS).
2. **F6** device heartbeat + "sensor offline" alarm (a monitor you can't tell is dead is worth little).
3. **F4** CloudWatch alarm on Lambda invocations (protects your $0 and catches a runaway device).

**Next:**
4. **F3** IoT Rule error action/DLQ · **F7** per-type cooldown · **F5** offline buffering (NVS).
5. **F10** enable CloudTrail · **F8** Lambda input validation.

**Later (deeper, great résumé material):**
6. **F2** flash encryption + secure boot on the ESP32.
7. A certificate **rotation/revocation** plan (rotate the device cert; practice revoking it in IoT Core).

---

## Feature roadmap (what to build next)

**Near-term (fits the current architecture):**
- **Heartbeat + offline alarm** (also fixes F6) — proves the sensor is alive.
- **Alert history dashboard** — write alerts to **DynamoDB** (free tier) via the Lambda, and view them
  in a **CloudWatch dashboard** or a tiny static page. Turns point alerts into trends.
- **Severity levels** in the alert + email subject (e.g., info/warning/critical).

**Medium:**
- **More detections:** beacon floods, WPS-attack attempts, karma/probe-request logging, PMF-bypass
  attempts. Each is just another `event` type through the same pipeline.
- **Two-way control:** subscribe to a `wids/cmd` topic to arm/disarm/ack from your phone (expands the
  IoT policy by one `Subscribe`/`Receive` statement).
- **Flash encryption + secure boot** (also F2).

**Stretch (portfolio standout):**
- **Multi-sensor mesh:** 2–3 ESP32s on different channels, correlated in the cloud — directly
  addresses the single-channel / 2.4 GHz-only limitation.
- **OTA signed firmware updates.**
- **Companion "router guardian"** (from our earlier chat): a free script that watches for router
  config changes / admin access — complements the device.

---

## Threat model (brief)
- **Assets:** the home WLAN's availability, the device's identity/credentials, the AWS account (cost).
- **Adversaries:** a nearby attacker running deauth/evil-twin tools; a curious insider on the WiFi;
  someone with physical access to the device.
- **In scope:** detecting 2.4 GHz management-frame attacks + unauthorized joins, and alerting securely.
- **Out of scope (documented):** 5 GHz, exact-BSSID clones, decrypting user traffic, real-time router
  admin-access detection, PMF-protected networks.

---

## Severity legend
**Medium** = worth fixing soon (crash/DoS or physical key exposure). **Low** = reliability/cost gap,
fix when convenient. **Info** = good-practice hardening / documented design trade-off. *(No High/
Critical findings.)*
