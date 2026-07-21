"""
WIDS alert handler — AWS Lambda (Python).

Triggered by the IoT Rule on 'wids/alerts'. It:
  - emails real alerts via SNS (now with a best-effort device-vendor hint),
  - records alerts to DynamoDB (the dashboard's history),
  - tracks liveness (heartbeat/device_online) via a CloudWatch metric + a single
    "LASTSEEN" record (so heartbeats don't clutter the alert feed),
  - stores the device's saved-MAC list as a "DEVICELIST" record,
  - sanitizes every incoming field (security-review finding F8).

Env vars:  SNS_TOPIC_ARN (required),  TABLE_NAME (optional; enables history/dashboard).
IAM role:  sns:Publish, cloudwatch:PutMetricData, dynamodb:PutItem.
Keep this function OUT of a VPC (free outbound; a VPC would need a paid NAT).
"""

import json
import os
import re
import time
import hmac
import base64
import boto3

sns = boto3.client("sns")
cw = boto3.client("cloudwatch")
ddb = boto3.resource("dynamodb")

TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")
TABLE_NAME = os.environ.get("TABLE_NAME", "")

ALERT_EVENTS = {
    "deauth_flood":   "Deauthentication flood",
    "disassoc_flood": "Disassociation flood",
    "evil_twin":      "Evil-twin / rogue AP",
    "unknown_device": "Unknown device joined",
    "test_trigger":   "Test alert (manual trigger)",
}
LIVENESS_EVENTS = ("heartbeat", "device_online")

# ---------------------------------------------------------------------------
#  MAC vendor lookup (offline, best-effort)
#
#  Two signals live in a MAC address:
#   1. RANDOMIZED MACs set the "locally administered" bit (0x02 in the first
#      octet) -> the 2nd hex digit is 2, 6, A or E. The vendor is then hidden,
#      but the fact that it IS randomized is itself a hint (usually a phone).
#   2. Otherwise the first three bytes (the OUI) identify the manufacturer.
#
#  Below is a STARTER table of common consumer OUIs. To extend it, look up an
#  unknown prefix in the IEEE registry (or macvendors.com) and add a line.
#  Anything unmatched simply shows "Unknown vendor" — no harm done.
# ---------------------------------------------------------------------------
OUI = {
    # Apple
    "A4:83:E7": "Apple", "AC:BC:32": "Apple", "8C:85:90": "Apple", "F0:18:98": "Apple",
    "68:AB:BC": "Apple", "3C:15:C2": "Apple", "40:6C:8F": "Apple", "D0:81:7A": "Apple",
    "88:66:5A": "Apple", "90:B0:ED": "Apple", "DC:A9:04": "Apple", "00:23:DF": "Apple",
    "00:25:00": "Apple", "04:0C:CE": "Apple", "F4:5C:89": "Apple",
    # Samsung
    "5C:0A:5B": "Samsung", "78:1F:DB": "Samsung", "8C:77:12": "Samsung", "B4:07:F9": "Samsung",
    "C0:BD:D1": "Samsung", "E8:50:8B": "Samsung", "34:BE:00": "Samsung", "00:12:47": "Samsung",
    # Xiaomi
    "28:6C:07": "Xiaomi", "34:CE:00": "Xiaomi", "50:8F:4C": "Xiaomi", "64:09:80": "Xiaomi",
    "78:11:DC": "Xiaomi", "F0:B4:29": "Xiaomi", "8C:BE:BE": "Xiaomi",
    # Huawei (phones and routers)
    "00:E0:FC": "Huawei", "28:31:52": "Huawei", "48:AD:08": "Huawei", "54:25:EA": "Huawei",
    "60:DE:44": "Huawei", "80:B6:86": "Huawei", "88:53:D4": "Huawei", "4C:54:99": "Huawei",
    # Google
    "3C:5A:B4": "Google", "54:60:09": "Google", "94:EB:2C": "Google", "F4:F5:D8": "Google",
    # OnePlus
    "94:65:2D": "OnePlus", "C0:EE:FB": "OnePlus",
    # Sony / LG
    "30:17:C8": "Sony", "78:84:3C": "Sony", "10:F9:6F": "LG", "A8:16:B2": "LG",
    # Intel (laptop Wi-Fi cards)
    "34:02:86": "Intel", "3C:97:0E": "Intel", "7C:B2:7D": "Intel", "8C:16:45": "Intel",
    "94:65:9C": "Intel", "A4:4E:31": "Intel", "E4:A4:71": "Intel", "F8:63:3F": "Intel",
    "00:24:D7": "Intel", "48:51:B7": "Intel",
    # PC makers
    "18:03:73": "Dell", "34:17:EB": "Dell", "B8:2A:72": "Dell", "F8:BC:12": "Dell",
    "3C:D9:2B": "HP", "70:5A:0F": "HP", "9C:B6:54": "HP",
    "28:18:78": "Microsoft", "50:1A:C5": "Microsoft", "7C:1E:52": "Microsoft",
    # IoT / SBC / smart home
    "24:0A:C4": "Espressif", "30:AE:A4": "Espressif", "3C:71:BF": "Espressif",
    "84:CC:A8": "Espressif", "A4:CF:12": "Espressif", "C4:4F:33": "Espressif",
    "EC:FA:BC": "Espressif", "24:6F:28": "Espressif", "8C:AA:B5": "Espressif",
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
    "44:65:0D": "Amazon", "68:37:E9": "Amazon", "74:C2:46": "Amazon", "F0:27:2D": "Amazon",
    # Networking gear
    "14:CC:20": "TP-Link", "50:C7:BF": "TP-Link", "A0:F3:C1": "TP-Link", "EC:08:6B": "TP-Link",
    # Wi-Fi/BT modules embedded in laptops, TVs, IoT devices
    "54:27:1E": "AzureWave",
}

HINT = {
    "Apple": "iPhone / iPad / Mac",
    "Samsung": "likely phone",
    "Xiaomi": "likely phone",
    "Huawei": "phone or router",
    "Google": "Pixel / Nest",
    "OnePlus": "likely phone",
    "Sony": "phone / console / TV",
    "LG": "phone / TV",
    "Intel": "likely laptop / PC",
    "Dell": "likely laptop / PC",
    "HP": "likely laptop / PC",
    "Microsoft": "likely PC / Surface",
    "Espressif": "ESP32 / IoT device",
    "Raspberry Pi": "Raspberry Pi",
    "Amazon": "Echo / Fire device",
    "TP-Link": "network gear",
    "AzureWave": "Wi-Fi module — laptop / TV / IoT",
}


def mac_vendor(mac):
    """Best-effort vendor/device-class hint for 'AA:BB:CC:DD:EE:FF'."""
    m = (mac or "").upper().strip()
    if len(m) < 8 or m.count(":") < 2:
        return ""
    try:
        first = int(m[0:2], 16)
    except ValueError:
        return ""
    if first & 0x02:   # locally administered => randomized / private MAC
        return "Randomized MAC (privacy mode — usually a phone)"
    vendor = OUI.get(m[0:8])
    if not vendor:
        return "Unknown vendor"
    hint = HINT.get(vendor)
    return f"{vendor} ({hint})" if hint else vendor


def _clean(v, maxlen=64):
    """Strip control chars and cap length (F8)."""
    return re.sub(r"[\x00-\x1f\x7f]", "", str(v))[:maxlen]


def _as_int(v, default=0):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _emit_heartbeat_metric():
    try:
        cw.put_metric_data(Namespace="WIDS",
            MetricData=[{"MetricName": "HeartbeatReceived", "Value": 1.0, "Unit": "Count"}])
    except Exception as e:
        print("metric error:", e)


def _save_alert(etype, event):
    if not TABLE_NAME:
        print("WARNING: TABLE_NAME not set — skipping history write")
        return
    try:
        mac = _clean(event.get("mac", event.get("bssid", "")), 20)
        ddb.Table(TABLE_NAME).put_item(Item={
            "device":  _clean(event.get("device", "WIDS_ESP32")),
            "ts":      _as_int(event.get("ts")) or int(time.time()),
            "event":   _clean(etype, 32),
            "mac":     mac,
            "vendor":  mac_vendor(mac),
            "rssi":    _as_int(event.get("rssi")),
            "channel": _clean(event.get("channel", ""), 8),
            "count":   _as_int(event.get("count")),
            "ttl":     int(time.time()) + 90 * 86400,   # auto-expire after 90 days (bounds storage; free)
        })
    except Exception as e:
        print("save_alert error:", e)


def _touch_lastseen(event):
    """A single overwritable record of the last time the device was heard from."""
    if not TABLE_NAME:
        return
    try:
        ddb.Table(TABLE_NAME).put_item(Item={
            "device":     "LASTSEEN",
            "ts":         0,
            "updated":    int(time.time()),
            "last_event": _clean(event.get("event", ""), 32),
        })
    except Exception as e:
        print("lastseen error:", e)


def _save_device_list(event):
    if not TABLE_NAME:
        return
    try:
        devs = event.get("devices", [])
        if not isinstance(devs, list):
            devs = []
        devs = [_clean(d, 20) for d in devs if d][:64]
        ddb.Table(TABLE_NAME).put_item(Item={
            "device":  "DEVICELIST",
            "ts":      0,
            "event":   "device_list",
            "devices": devs,
            "count":   _as_int(event.get("count")),
            "updated": int(time.time()),
        })
    except Exception as e:
        print("device_list error:", e)


def lambda_handler(event, context):
    # Route by ingest path: Lambda Function URL (HTTPS POST) vs IoT Rule (raw JSON).
    if isinstance(event, dict) and ("requestContext" in event or "rawPath" in event):
        return _handle_http(event)
    return _process(event)


def _handle_http(event):
    """Function URL path: token-check, then hand the JSON body to _process."""
    expected = os.environ.get("INGEST_TOKEN", "")
    headers = event.get("headers") or {}
    auth = headers.get("authorization", "")
    if not expected or not hmac.compare_digest(auth, "Bearer " + expected):
        return {"statusCode": 401, "body": "unauthorized"}
    raw = event.get("body") or "{}"
    if event.get("isBase64Encoded"):
        raw = base64.b64decode(raw).decode("utf-8", "replace")
    try:
        payload = json.loads(raw)
    except Exception:
        return {"statusCode": 400, "body": "bad json"}
    _process(payload)
    return {"statusCode": 200, "body": "ok"}


def _process(event):
    print("Received event:", json.dumps(event))
    etype = _clean(event.get("event", "unknown"), 32)

    # Device list: store the saved-MAC baseline for the dashboard (no email).
    if etype == "device_list":
        _emit_heartbeat_metric()
        _touch_lastseen(event)
        _save_device_list(event)
        return {"status": "device_list"}

    # Liveness pings: metric + last-seen, but no email and no feed clutter.
    if etype in LIVENESS_EVENTS:
        _emit_heartbeat_metric()
        _touch_lastseen(event)
        return {"status": "liveness", "event": etype}

    if etype not in ALERT_EVENTS:
        print("Ignoring non-alert event:", etype)
        return {"status": "ignored", "event": etype}

    _save_alert(etype, event)     # keep a record for the dashboard
    _touch_lastseen(event)        # an alert is also proof of life

    if not TOPIC_ARN:
        print("ERROR: SNS_TOPIC_ARN environment variable is not set.")
        return {"status": "error", "reason": "SNS_TOPIC_ARN not set"}

    label   = ALERT_EVENTS[etype]
    device  = _clean(event.get("device", "unknown"))
    count   = _clean(event.get("count", "?"), 12)
    mac     = _clean(event.get("mac", event.get("bssid", "?")), 20)
    rssi    = _clean(event.get("rssi", "?"), 8)
    channel = _clean(event.get("channel", "?"), 8)
    vendor  = mac_vendor(mac)

    if etype == "unknown_device":
        details = (
            f"  New device MAC : {mac}\n"
            f"  Looks like     : {vendor or 'unknown'}\n"
            f"  Signal         : {rssi} dBm\n\n"
            "A device with an unrecognised MAC address joined your WiFi.\n"
            "If it isn't one of yours, someone may be on your network.\n"
            "Tip: match the MAC in your router's connected-devices list to see its name."
        )
    elif etype == "evil_twin":
        details = (
            f"  Rogue AP BSSID : {mac}\n"
            f"  Looks like     : {vendor or 'unknown'}\n"
            f"  Signal         : {rssi} dBm\n\n"
            "An access point is broadcasting your network name from an unknown MAC.\n"
            "This may be an evil-twin trying to lure your devices into connecting."
        )
    else:  # deauth_flood / disassoc_flood / test_trigger
        details = (
            f"  Target AP      : {mac}  (channel {channel})\n"
            f"  Looks like     : {vendor or 'unknown'}\n"
            f"  Frames         : {count}\n"
            f"  Signal         : {rssi} dBm\n\n"
            "If this wasn't a test you ran, a device on your network may be under attack."
        )

    subject = f"[WIDS] {label} detected"
    message = (
        "Your WiFi Intrusion Detection System raised an alert.\n\n"
        f"  Type           : {label} ({etype})\n"
        f"  Device         : {device}\n"
        f"{details}"
    )

    sns.publish(TopicArn=TOPIC_ARN, Subject=subject[:100], Message=message)
    print("Emailed alert for event:", etype)
    return {"status": "sent", "event": etype}
