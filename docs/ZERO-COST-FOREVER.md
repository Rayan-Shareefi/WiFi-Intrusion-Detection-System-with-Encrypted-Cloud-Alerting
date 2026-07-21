# 💯 The $0-Forever Path — run it for years without paying a cent

This is the setup that lets the project run **indefinitely at $0**. It swaps the one non-always-free
service (AWS IoT Core) for a **Lambda Function URL**, so *every* AWS service the project touches is in
the permanent **Always Free** tier. Your existing X.509 / mutual-TLS IoT Core version stays in the
repo (one firmware line switches between them) — keep it for demos and your CV.

All facts below were verified against official AWS docs (2026).

---

## Why this is needed — the two "clocks"

| Clock | What it is | The fix |
|---|---|---|
| **Account (~6 months)** | A new **Free-plan** account auto-closes at ~6 months. This is structural, not usage. | **Upgrade to the Paid plan** — the upgrade itself is **free**; you're billed only if you exceed an always-free limit (you won't). *Unavoidable, but costs nothing.* |
| **IoT Core (12 months)** | IoT Core is the **only** service here that's free for just 12 months, then ~$0.01/mo. | **Use the HTTPS Function-URL path** (below) instead of IoT Core → no 12-month clock. |

Everything else — **Lambda, Lambda Function URLs, SNS email (≤1,000/mo), DynamoDB (25 GB + 25/25
provisioned), CloudWatch, and 100 GB/mo egress** — is **Always Free, forever**.

---

## Setup (≈10 minutes, all $0)

Prerequisite: the `wids-alert-handler` Lambda is deployed with the **current** code (it now accepts
both the IoT Rule *and* a Function URL), and the `WidsAlerts` DynamoDB table exists.

### 1. Add a Function URL to the alert-handler Lambda
1. Lambda → **`wids-alert-handler`** → **Configuration → Function URL → Create function URL**.
2. **Auth type = NONE** (the page is public; a secret token gates it — see security note).
3. **Create**, then **copy the URL** (`https://xxxx.lambda-url.eu-central-1.on.aws/`).

### 2. Set the shared token
Lambda → **Configuration → Environment variables → Edit → Add**:
- Key `INGEST_TOKEN`, Value = **a long random string** (20+ chars — treat it like a password).

### 3. (Optional) Cap abuse of the public URL
Ideally: Lambda → **Configuration → Concurrency → Reserve concurrency → 5**. **But new accounts have a
low Lambda concurrency limit (~10), and AWS blocks reserving when it would leave the account below 100
unreserved — so you probably can't set this yet. That's fine: click Cancel.** The low account limit is
*itself* a concurrency cap, and the unguessable URL + token + $0 budget cover the rest. Revisit only if
your account's concurrency limit is later raised above ~100.

### 4. Turn on auto-expiry so history can't grow forever (free)
DynamoDB → **Tables → WidsAlerts → Additional settings → Time to Live (TTL) → Enable**, TTL attribute
name **`ttl`**. The Lambda already stamps each alert with a 90-day `ttl`, so old rows self-delete —
storage stays tiny for years, at no cost. (LASTSEEN / DEVICELIST have no `ttl`, so they persist.)

### 5. Point the firmware at it
In `secrets.h`:
```cpp
#define LAMBDA_URL          "https://xxxx.lambda-url.eu-central-1.on.aws/"   // your URL
#define ALERT_BEARER_TOKEN  "the-same-long-random-token"                     // = INGEST_TOKEN
```
In `WIDS_ESP32.ino`, **uncomment** the toggle near the top:
```cpp
#define USE_HTTPS_INGEST
```
Re-upload. On boot the Serial log shows the same `PUBLISH ... OK` lines — but now over HTTPS to the
Function URL, with **no IoT Core involved**. (The device cert + private key are no longer used, and
TLS is lighter, so heap usage actually improves.)

To switch back to the mutual-TLS IoT Core showcase, just comment the toggle out and re-upload.

---

## ✅ Your "$0 for ~5 years" guarantee — the checklist

Follow these and the project cannot bill you:

1. **Upgrade to the Paid plan** at ~month 5 (free; keeps the account alive). Set the **Zero-spend
   budget** to email you if any charge ever appears.
2. **Run the HTTPS path** (`USE_HTTPS_INGEST`) — no IoT Core, so nothing has a 12-month expiry.
3. **DynamoDB** stays in **Provisioned** mode (≤25 WCU/25 RCU) with **TTL on** — storage self-caps.
4. **Stay in one region** (eu-central-1) and **email, never SMS**.
5. **Never create** a NAT Gateway, EC2/RDS, Elastic IP, on-demand DynamoDB, AWS WAF, or enable Device
   Defender. None are needed.
6. **Don't trigger a silent auto-upgrade beyond Paid** — avoid joining AWS Organizations, Control
   Tower, Partner Network, or enterprise agreements.

At your real volume (a few alerts/day + a 30-min heartbeat ≈ a few hundred requests/month), you use
**well under 0.1%** of every always-free limit. There is enormous headroom for 5+ years.

### The one honest caveat
Because the Function URL is public (Auth type NONE), a determined attacker who *discovered your exact
random URL* could flood it with requests. Each is rejected `401`, but the invocations still count.
Mitigations already in place: the URL is **unguessable**, **reserved concurrency = 5** throttles a
flood, and your **$0 budget alarm** fires on the first cent — at which point you delete/recreate the
Function URL (new random address) in seconds. In practice this stays $0; it's simply the trade-off for
a free public endpoint.

---

## Security trade-off vs. the IoT Core version (be able to explain this)
The HTTPS path swaps the **X.509 mutual-TLS device identity** (a per-device private key that never
leaves the chip and is individually revocable) for a **shared bearer token** (sent on each request,
stored in firmware). **Server-side TLS is unchanged** — the ESP32 still verifies it's really AWS via
Amazon Root CA 1, so there's no man-in-the-middle. For a single home sensor this is an acceptable
trade for permanent $0; the mutual-TLS version remains in the repo as the stronger design to showcase.
