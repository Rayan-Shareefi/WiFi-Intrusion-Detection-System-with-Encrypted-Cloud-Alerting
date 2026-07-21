# 📱 Dashboard App — view alerts + devices on desktop and iPhone (M9)

A **$0** cross-platform dashboard: one Lambda serves both the web page and its data
(from the DynamoDB history), reached through a free **Lambda Function URL** — no App Store, no
hosting, no API Gateway. On iPhone, "Add to Home Screen" makes it launch like a native app.

```
ESP32 → IoT Core → alert-handler Lambda → DynamoDB
                                              ↑ reads
   phone / laptop ──HTTPS──► dashboard Lambda (Function URL)  → serves page + JSON
```

## Prerequisites (from earlier steps)
- The **DynamoDB `WidsAlerts` table** exists ([docs/HARDENING.md](HARDENING.md) step 2).
- The **alert-handler Lambda** re-deployed with `TABLE_NAME=WidsAlerts` set.
- The **firmware re-uploaded** (it now reports its saved-device list on boot + each heartbeat).

## 1. Create the dashboard Lambda
1. Console → **Lambda → Create function → Author from scratch**.
2. Name **`wids-dashboard`**, Runtime **Python 3.13** → **Create function**.
3. **Code** tab → paste [`cloud/lambda-dashboard/lambda_function.py`](../cloud/lambda-dashboard/lambda_function.py) → **Deploy**.

## 2. Environment variables
Lambda → **Configuration → Environment variables → Edit → Add**:
| Key | Value |
|---|---|
| `TABLE_NAME` | `WidsAlerts` |
| `DEVICE_NAME` | `WIDS_ESP32` |
| `DASH_TOKEN` | **a long random passphrase you invent** (e.g. 20+ random characters) |

The `DASH_TOKEN` is what unlocks the dashboard — treat it like a password. You can change it any time
here (everyone is then logged out).

## 3. Permissions (least-privilege)
- **Configuration → Permissions** → click the **role name** (opens IAM) → **Add permissions → Create
  inline policy → JSON** → paste [`cloud/lambda-dashboard/dashboard-policy.json`](../cloud/lambda-dashboard/dashboard-policy.json)
  (`dynamodb:Query` + `GetItem` + `BatchWriteItem` — the last powers the **Clear** button below) →
  name it `wids-dashboard-read` → **Create policy**.

## 4. Create the Function URL (the free public HTTPS endpoint)
- Lambda → **Configuration → Function URL → Create function URL**.
- **Auth type = NONE** (the page is public; the *data* is protected by your token — see security note).
- **Create**, then **copy the URL** (looks like `https://xxxx.lambda-url.eu-central-1.on.aws/`).

## 5. Open it
- **Desktop:** open the URL → enter your `DASH_TOKEN` → you're in. It auto-refreshes every 15 s.
- **iPhone:** open the URL in **Safari** → tap **Share → Add to Home Screen**. It installs an app-like
  icon that launches full-screen. Enter the token once.

You'll see: an **ONLINE/OFFLINE** badge + last-contact time, a **recent-alerts** feed, and your
**saved-device** MAC list. (Type `t` on the ESP32 to generate a test alert and watch it appear.)
A **Clear** button next to *Recent activity* permanently deletes the stored alert history (token-gated;
it leaves the online status + saved-device list intact).

---

## 🔒 Security note (worth understanding)
The Function URL uses **Auth type NONE**, so the *URL* is publicly reachable — but the **/data**
endpoint returns nothing without the correct `x-wids-token` header (compared with a constant-time
`hmac`). The page itself holds no secrets; it prompts for the token and stores it in your browser.
- Use a **long, random** `DASH_TOKEN` — anyone who has it can view *and* **Clear** (delete) the alert history.
- **Rotate** it anytime by editing the env var.
- Don't post your Function URL publicly.
*(For a stricter setup you could switch the Function URL to IAM auth, but that breaks simple browser
access — the token approach is the right trade-off for a personal dashboard.)*

## 💯 Cost
**$0.** Lambda + Function URLs are always-free at this volume, and DynamoDB reads stay in the free
tier. No API Gateway, no hosting, no App Store fee.

## Troubleshooting
- **Blank / "No alerts yet"** → the device hasn't published anything since the table was created.
  Type `t` on the ESP32, or reboot it (boot sends a device-list + online ping).
- **"No devices learned yet"** → re-upload the current firmware and reboot; the device publishes its
  list on boot and every heartbeat.
- **Wrong token** → 401; re-enter it. **Connection error** → check the Function URL and that the IAM
  read policy is attached.
- **Shows OFFLINE** → the device hasn't sent a heartbeat/alert within ~65 min (it heartbeats every 30
  min; on the bench it also pings at every boot).
