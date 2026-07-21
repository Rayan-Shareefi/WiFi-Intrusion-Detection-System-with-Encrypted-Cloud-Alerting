# 🧭 WIDS — Step-by-Step Build Guide

This guide grows as we complete each milestone. Each milestone is a stopping point that **works on its
own** — don't move on until its "✅ Done when" check passes.

**Project region:** EU (Frankfurt) / `eu-central-1` — *except* the billing alarm, which must live in
`us-east-1` (see M0).

---

## M0 — AWS cost safety nets  ✅

Full guide: **[COST-SAFETY.md](COST-SAFETY.md)**.
✅ Done when: Zero-spend budget active (global), billing alarm verified (in `us-east-1`), Free Tier
alerts on, root MFA on, IAM admin user created.

---

## M1 — Windows dev environment + first ESP32 upload

**Goal:** prove your PC + ESP32 + toolchain all work by uploading a tiny blink/"hello" sketch. No WiFi
or AWS yet. Sketch: [`firmware/M1_hello_esp32/M1_hello_esp32.ino`](../firmware/M1_hello_esp32/M1_hello_esp32.ino).

### 1. Install Arduino IDE 2.x
Download the Windows installer from <https://www.arduino.cc/en/software> ("Arduino IDE 2.x") and
install it.

### 2. Add the ESP32 board package
- **File → Preferences**.
- In **"Additional boards manager URLs"**, paste:
  `https://espressif.github.io/arduino-esp32/package_esp32_index.json`
- **OK**, then open **Tools → Board → Boards Manager**, search **esp32**, and install
  **"esp32 by Espressif Systems" (v3.x)**. (One-time ~200 MB download of the compiler + libraries.)

### 3. Install the USB-to-UART driver (so Windows sees the board as a COM port)
Look at the small chip next to the USB connector on your board:
- **CP2102 / CP2104** (Silicon Labs) → install the **CP210x Universal Windows Driver** from Silicon
  Labs: unzip it, right-click the `.inf` for x64 → **Install**.
- **CH340 / CH9102** (WCH) → install **CH341SER.exe** from WCH (often auto-installs on Win 10/11).
- **Not sure which?** Plug the board in and open **Device Manager → Ports (COM & LPT)**. Seeing e.g.
  "Silicon Labs CP210x (COM5)" means you're set; a **yellow ⚠️** means the driver is missing.

### 4. Select the board and port
- **Tools → Board → esp32 → "ESP32 Dev Module"**.
- **Tools → Port →** choose the COM port that appeared (e.g. `COM5`). If unsure which, unplug/replug
  and see which entry disappears/returns.
- Defaults are fine (Upload Speed 921600). If uploads are flaky, drop it to **115200**.

### 5. Upload the test sketch
- Open **`firmware/M1_hello_esp32/M1_hello_esp32.ino`** in the IDE.
- Click **Upload** (→). It compiles, then flashes.
- **If it hangs on `Connecting.....`:** press and **hold the BOOT button** on the board until the IDE
  shows "Writing…", then release. (Some boards: hold BOOT, tap EN/RST once, release BOOT.)
- If nothing happens at all, suspect a **charge-only USB cable** — use a **data** cable.

### 6. Watch it run
- Open **Tools → Serial Monitor**; set the baud (bottom-right) to **115200**.
- You should see the "hello from ESP32" banner, real chip info, and a **heartbeat** line every second.
  If your board has a user LED on GPIO2, it also blinks once per second.

### ✅ M1 done when
The Serial Monitor prints heartbeat lines at 115200 baud. That confirms upload, board, and the
two-way serial link all work. (LED blink is a bonus, not required.)

**Common snags:** garbled text = wrong baud (set 115200) · no COM port = driver or cable · upload
timeout = hold BOOT during "Connecting…".

---

## M2 — Local deauth detector (Serial output, no cloud yet)

**Goal:** sniff 802.11 management frames in monitor mode and flag deauth/disassoc floods, printing to
Serial. Sketch: [`firmware/M2_deauth_detector/M2_deauth_detector.ino`](../firmware/M2_deauth_detector/M2_deauth_detector.ino).

### 1. Tell it your WiFi name
Open the sketch and edit the one line near the top:
`#define HOME_WIFI_SSID "YOUR_WIFI_NAME"` → put your **2.4 GHz** network name (SSID) in the quotes.
(No password needed here — M2 only *listens*, it never connects. If your router shows one name for
2.4 GHz and 5 GHz, that's fine; the ESP32 only sees the 2.4 GHz one.)

### 2. Upload and open Serial Monitor (115200)
On boot it scans for your SSID, locks onto that AP's channel, and remembers its BSSID (MAC) so it can
tell attacks on *your* network apart from the neighbours'. You'll see:
`Locked to "MyWiFi" on channel 6  (BSSID AA:BB:CC:DD:EE:FF)`
then a compact `[status]` line every 5 seconds (counts are normally 0).

### 3. Test the detection path safely
In the Serial Monitor's input box, type **`t`** and press Enter. This *simulates* a detection so you
see the alert output format without launching a real attack: `!!! DEAUTH / DISASSOC FLOOD DETECTED`.

### ✅ M2 done when
It locks to your channel and the **`t`** test trigger prints the DEAUTH FLOOD DETECTED block — that
proves the sniff → detect → report path works.

### Testing with real attacks (optional, later)
Generating real deauth frames needs a second device and must ONLY ever target **your own** network.
Not required — the `t` trigger already proves the pipeline. We can revisit if you get a second ESP32.

### How it works (short version)
- **Promiscuous mode** = the radio passively listens to nearby 802.11 frames without connecting.
- **Management frames** (deauth/disassoc) are always **unencrypted**, so we can read them on a WPA2
  network with no password — that's the trick that makes this possible.
- **Deauth** frame = first byte `0xC0`; **disassoc** = `0xA0`.
- We count them per 5 s window; if the count *for your BSSID* crosses `DEAUTH_THRESHOLD` and we're
  past `COOLDOWN_MS`, it flags an attack. Those `#define`s at the top are yours to tune.

---

## M3 — AWS IoT Core device + first encrypted test publish

**Goal:** give the ESP32 a cloud identity (X.509 certificate) and send its first *encrypted* MQTT
message to AWS IoT Core, then watch it arrive in the console. Two phases:

### Phase A — AWS Console (create the device's identity) — do this first
Full click-by-click guide: **[../cloud/aws-iot-setup.md](../cloud/aws-iot-setup.md)**. In short:
1. Create a least-privilege IoT **policy** — [`cloud/iot-policy.json`](../cloud/iot-policy.json).
2. Create a **Thing** named `WIDS_ESP32` with an **auto-generated certificate**; attach the policy.
3. **Download** the device certificate, private key, and Amazon Root CA 1 (private key is offered
   only once!).
4. Copy your **device data endpoint** (Settings → Device data endpoint).
5. Open **Test → MQTT test client** and subscribe to `wids/alerts`.

🔐 Never commit or share the private key (not even with me); `.gitignore` blocks it.

### Phase B — Firmware (send the encrypted test message)
Sketch: [`firmware/WIDS_ESP32/WIDS_ESP32.ino`](../firmware/WIDS_ESP32/WIDS_ESP32.ino).

1. **Install two libraries** — Arduino IDE → **Sketch → Include Library → Manage Libraries**:
   **PubSubClient** (Nick O'Leary) and **ArduinoJson** (Benoit Blanchon, v7).
   (`WiFiClientSecure` is already part of the ESP32 core.)
2. **Create `secrets.h`** — in `firmware/WIDS_ESP32/`, copy `secrets.example.h` and rename the copy to
   **`secrets.h`**, then fill it:
   - `WIFI_SSID` / `WIFI_PASSWORD` — your home WiFi.
   - `AWS_IOT_ENDPOINT` — the endpoint from Phase A.
   - Paste the **entire contents** of each downloaded file (open in Notepad, Select-All, Copy) over the
     matching `PASTE_...` line, keeping each file's own `-----BEGIN/END-----` lines:
     `AmazonRootCA1.pem`→`AWS_CERT_CA`, `…certificate.pem.crt`→`AWS_CERT_CRT`,
     `…private.pem.key`→`AWS_CERT_PRIVATE`.
   - `secrets.h` is gitignored, so it never gets committed.
3. **Upload** `WIDS_ESP32.ino` (Board = ESP32 Dev Module, Port = COM3).
4. **Serial Monitor (115200)** should show: `WiFi: connected` → `NTP: UTC time` → `AWS: connected!` →
   `PUBLISH OK`.
5. **Watch the AWS MQTT test client** (subscribed to `wids/alerts`) — the JSON appears live. Type
   **`t`** in Serial Monitor to send more.

### ✅ M3 done when
A JSON test message from the ESP32 shows up live in the AWS IoT **MQTT test client** on `wids/alerts`.

### Troubleshooting (first ESP32→AWS connections often need one small fix)
- **Stuck on `NTP: syncing`** → your network may block NTP (UDP 123); try a phone hotspot. TLS can't
  work without a correct clock.
- **`connect failed (state=-2)`** → TLS/cert issue: check all 3 certs are pasted whole, the
  certificate is **ACTIVE**, the policy is **attached to the certificate**, and the **endpoint/region**
  are right.
- **`state=5`** (unauthorized) → policy problem, or the client ID isn't exactly `WIDS_ESP32`.
- **`PUBLISH FAILED`** → not connected, or the policy doesn't allow `wids/alerts` (topic is
  case-sensitive).
- **Serial says OK but nothing in the test client** → you're subscribed to a different topic/case;
  subscribe to `#` to see everything.

---

## M4 — Wire detection to alert (the sniff ↔ send mode switch)

**Goal:** combine M2 (detection) + M3 (encrypted publish) into the real device. On boot it connects
once (to learn its channel, sync time, and send a `device_online` ping), then sits in monitor mode.
When it detects a deauth/disassoc flood — or you type `t` — it switches to station mode, connects,
publishes an encrypted alert to `wids/alerts`, and returns to monitoring. Same sketch as M3, now
grown: [`firmware/WIDS_ESP32/WIDS_ESP32.ino`](../firmware/WIDS_ESP32/WIDS_ESP32.ino). No new libraries;
`secrets.h` unchanged.

### Steps
1. Re-upload `WIDS_ESP32.ino` (Board = ESP32 Dev Module, Port = COM3).
2. Serial Monitor (115200): watch `WiFi connected → NTP → AWS connected → device_online published →
   [MONITOR] promiscuous ON`.
3. Type **`t`** + Enter to simulate an attack. Watch the phases
   `[DETECT] → [SWITCH] → [ALERT] publishing → [RESUME]`, and the alert JSON appears in your AWS MQTT
   test client on `wids/alerts`.

### Why the mode switch?
One radio, two jobs. To *sniff*, the ESP32 sits unconnected on the AP's channel; to *send*, it must
associate to the AP. It can't do both robustly during an attack (a deauth flood knocks its own link
off), so it **monitors → switches → sends → resumes**. The brief (~1–10 s) "blind window" while
sending is why we report attack *episodes* and use a cooldown.

### ✅ M4 done when
Typing `t` (or a real deauth flood) produces an alert JSON in the MQTT test client, and the device
prints `[RESUME]` and returns to monitoring.

---

## M5 — Cloud alerting: IoT Rule → Lambda → SNS email

**Goal:** when the device publishes to `wids/alerts`, automatically email you (also a phone
notification). All cloud-side, serverless, free. Full guide:
**[../cloud/cloud-alerting-setup.md](../cloud/cloud-alerting-setup.md)**.

In short (**order matters** — SNS first, then Lambda, then the Rule):
1. **SNS** → create Standard topic `wids-alerts` → add an **Email** subscription → **confirm** the link
   AWS emails you.
2. **Lambda** `wids-alert-handler` (Python) → paste
   [`cloud/lambda/lambda_function.py`](../cloud/lambda/lambda_function.py) → set env var
   `SNS_TOPIC_ARN` → add inline `sns:Publish` policy
   ([`cloud/lambda/lambda-sns-policy.json`](../cloud/lambda/lambda-sns-policy.json)) → log retention
   7 days. Keep it **non-VPC** (a VPC would need a paid NAT gateway).
3. **IoT Rule** `wids_alert_rule` → SQL `SELECT * FROM 'wids/alerts' WHERE event <> 'device_online'`
   → action **Lambda** → `wids-alert-handler`.
4. **Test:** type `t` on the device → an email arrives within seconds.

### ✅ M5 done when
Typing `t` on the device lands an alert **email on your phone**. 🎉 That's the full project working end
to end: sensor → encrypted cloud → your pocket.

---

## M6 — Evil-twin / rogue-AP detection

**Goal:** detect a rogue access point impersonating your network — same SSID name, but a new/unknown
BSSID. Same sketch, now grown: [`firmware/WIDS_ESP32/WIDS_ESP32.ino`](../firmware/WIDS_ESP32/WIDS_ESP32.ino).
No new libraries or `secrets.h` changes.

### How it works
At boot it scans and records every BSSID currently broadcasting your SSID as "known-good"
(`[BASELINE]` lines). Every `SCAN_INTERVAL_MS` (default 3 min) it briefly pauses monitoring, rescans,
and if your SSID appears under a BSSID it didn't record at boot, it fires an `evil_twin` alert through
the same cloud pipeline.

### Steps
1. Re-upload `WIDS_ESP32.ino`. On boot, watch the `[BASELINE]` lines list your real AP(s).
2. Confirm normal `[MONITOR]` + `[status]` operation, plus a `[SCAN] done` line every 3 minutes.

### Test it (real evil twin — on your OWN SSID only)
1. *(Optional, for faster testing)* temporarily set `SCAN_INTERVAL_MS` to `30000UL` and re-upload.
2. On a second phone/laptop, create a **hotspot named exactly like your WiFi** (e.g. `MyWiFi`).
3. Within one scan interval you'll see `[SCAN] EVIL TWIN suspected ...` and get an email
   `[WIDS] Evil-twin / rogue AP detected`.
4. Turn the hotspot off afterward. (A reboot re-baselines, clearing state.)

### ✅ M6 done when
Standing up a same-named hotspot triggers an `evil_twin` email; turning it off + rebooting returns to
normal. Honest limits (good for the writeup): 2.4 GHz only, and a twin that clones your *exact* BSSID
can't be distinguished this way.

---

## M7 — Unknown / new-device detection

**Goal:** alert when a device with an unrecognized MAC joins your network. Same sketch, grown:
[`firmware/WIDS_ESP32/WIDS_ESP32.ino`](../firmware/WIDS_ESP32/WIDS_ESP32.ino). One small cloud change:
the alert JSON now uses a generic `mac` field, so the Lambda is re-deployed too.

### How it works
Devices send an 802.11 (re)association request when they join — a management frame we already capture;
its source address is the joining device's MAC. For the first `DEVICE_LEARN_MS` (default 5 min) the
device silently **learns** the MACs it sees ("trust on first use"); after that, the first time a
brand-new MAC associates with your network it fires an `unknown_device` alert. Each MAC alerts once.
The learned list is **saved to flash (NVS)**, so it survives power cycles — a reboot no longer flags
your own devices. Type **`r`** in the Serial Monitor to wipe the baseline and re-learn (e.g. after
getting a new phone).

### Steps
1. **Re-deploy the Lambda:** open `wids-alert-handler`, paste the updated
   [`cloud/lambda/lambda_function.py`](../cloud/lambda/lambda_function.py), **Deploy**. (It tolerates
   both the old `bssid` and new `mac` field, so nothing breaks.)
2. **Re-upload** `WIDS_ESP32.ino`. On boot watch `[BASELINE]`, then `Learning known devices for 300s`
   and `[LEARN] known device: ...` lines as your gadgets check in.

### Test it
1. *(Recommended)* temporarily set `DEVICE_LEARN_MS` to `30000UL` (30 s) and re-upload. If it says a
   baseline was loaded from flash, type **`r`** first to clear it and start a fresh learning window.
2. Wait until it stops printing `[LEARN]` lines (learning window over).
3. Connect a device that WASN'T on the WiFi during learning — a laptop, a friend's phone, or toggle a
   phone's WiFi off→on (Forget + rejoin forces a fresh MAC on some phones).
4. You'll see `[JOIN] NEW device joined: <mac>` and get an email `[WIDS] Unknown device joined`.

### ✅ M7 done when
A device joining after the learning window produces an `unknown_device` email. Set `DEVICE_LEARN_MS`
back to `300000UL` afterward.

### Honest limits (for the writeup)
Phones randomize MACs (noisier than deauth); a device connected before boot that never re-joins won't
be seen; MAC-only (no hostnames — traffic is encrypted); 2.4 GHz + home channel only.

---

## M8 — Polish + portfolio packaging
The finish line: optional touch-pin UX, a demo recording, and finalizing README/SETUP/COST-SAFETY so
the repo reads as a real project. Coming next.
