# AWS IoT Core — Device Setup (Milestone 3, Phase A)

**Goal:** create your ESP32's **cloud identity** so it can send encrypted, authenticated messages to
AWS IoT Core. By the end you'll have:
- an IoT **Thing** named `WIDS_ESP32`,
- a unique **X.509 certificate + private key** (the device's tamper-proof ID card),
- a **least-privilege policy** (exactly what the device is allowed to do),
- your account's **device data endpoint** (the address the device connects to).

All of this is inside the AWS **free tier** — IoT Core is free for 12 months and you'll send only a
handful of messages, so it's effectively **$0**.

> ## 🔐 Security rules for this milestone (important)
> - The **private key** is secret. **Never** commit it, and **never** paste it into chat, a website,
>   or anywhere online — **not even to me.** `.gitignore` already blocks `*.pem` / `*.key` files.
> - You do **not** need to share your certificate, private key, or endpoint with me to continue. Just
>   tell me when each step is done. (Sharing your endpoint is low-risk, but there's no need.)

---

## Before you start
- Region selector (top-right of the console) = **Europe (Frankfurt) / eu-central-1**.
- Open the **AWS IoT Core** service (type "IoT Core" in the console search bar).

## Step 1 — Note your AWS Account ID
Top-right → click your account name → the **Account ID** is the 12-digit number (e.g. `123456789012`).
You'll paste it into the policy in Step 2.

## Step 2 — Create the security policy (what the device may do)
1. IoT Core → left menu **Security → Policies → Create policy**.
2. **Policy name:** `WIDS_ESP32_Policy`
3. Switch the editor to **JSON** and paste the contents of [`iot-policy.json`](iot-policy.json),
   replacing **`ACCOUNT_ID`** (in both places) with your 12-digit Account ID. The region is already
   `eu-central-1`.
4. Click **Create**.

This policy lets the device do exactly two things and nothing else: **connect** *as* `WIDS_ESP32`, and
**publish** to the single topic `wids/alerts`. That's "least privilege" — good security hygiene, and a
great thing to explain in an interview.

## Step 3 — Create the Thing + its certificate
1. IoT Core → **Manage → All devices → Things → Create things → Create single thing** → **Next**.
2. **Thing name:** `WIDS_ESP32` (exactly — it must match the client ID in the policy and in the
   sketch). Leave **Device Shadow = No shadow**. **Next**.
3. **Device certificate:** choose **Auto-generate a new certificate (recommended)**. **Next**.
4. **Attach policies:** tick **`WIDS_ESP32_Policy`** → **Create thing**.
5. A **"Download certificates and keys"** panel appears. Download and keep these **three** files:
   | File | Looks like | Notes |
   |---|---|---|
   | Device certificate | `xxxxxxxxxx-certificate.pem.crt` | the device's public ID |
   | Private key file | `xxxxxxxxxx-private.pem.key` | ⚠️ **offered only once — download it now** |
   | Amazon Root CA 1 | `AmazonRootCA1.pem` | click its own **Download** link |

   (The public key file isn't needed.)
6. Save the three files somewhere you **won't** accidentally commit — e.g. a new `certs/` folder in
   the project (already gitignored) or your Documents.

> If you ever lose the private key, it can't be recovered — just create a **new** certificate and
> attach the same policy to it.

## Step 4 — Get your device data endpoint
IoT Core → **Settings** (bottom of the left menu) → **Device data endpoint**. Copy the string; it
looks like `a1b2c3d4e5f6g7-ats.iot.eu-central-1.amazonaws.com`. Keep it for Phase B (it goes into
`secrets.h`). The `-ats` in the name is correct — that's the modern Amazon Trust Services endpoint.

## Step 5 — Open the MQTT test client (where you'll SEE the alert in Phase B)
IoT Core → **Test → MQTT test client** → **Subscribe to a topic** tab → type `wids/alerts` →
**Subscribe**. Leave this browser tab open; in Phase B your ESP32's test message will pop up here
live. *(Tip: subscribing to `#` shows all topics — handy if a message doesn't show up and you suspect
a topic typo.)*

---

## ✅ Phase A done when
You have all four: the **policy** created, the **Thing `WIDS_ESP32`** with an **ACTIVE** certificate,
the **three files** downloaded, and your **endpoint** copied. Then tell me **"Phase A done"** and I'll
hand you the device firmware for **Phase B** (fill `secrets.h`, install two libraries, upload, watch
it arrive).

## Cost check
Creating the Thing, certificate, policy, and endpoint is free. Message volume sits far inside the
12-month IoT Core free tier. **No charge.**
