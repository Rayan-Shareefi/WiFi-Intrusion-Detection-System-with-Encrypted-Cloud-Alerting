"""
WIDS dashboard — AWS Lambda behind a Function URL (free; no API Gateway, no hosting).

One function serves BOTH:
  - GET /          -> the dashboard web page (a PWA; desktop + iPhone)
  - GET /?data=1   -> JSON (alerts + saved devices + online status), token-gated

Each MAC is annotated with a best-effort vendor / device-class hint, and
randomized ("private") MACs are flagged as such.

Env vars:
  TABLE_NAME   (default WidsAlerts)   DynamoDB history table
  DEVICE_NAME  (default WIDS_ESP32)   Thing name used as the alert partition key
  DASH_TOKEN   (required)             a long random passphrase you choose
IAM role needs: dynamodb:Query + dynamodb:GetItem on the table.
"""

import json
import os
import time
import hmac
from decimal import Decimal
import boto3
from boto3.dynamodb.conditions import Key

ddb = boto3.resource("dynamodb")
TABLE_NAME = os.environ.get("TABLE_NAME", "WidsAlerts")
DEVICE_NAME = os.environ.get("DEVICE_NAME", "WIDS_ESP32")
TOKEN = os.environ.get("DASH_TOKEN", "")
ONLINE_WINDOW = 3900  # seconds (~65 min); the device heartbeats every 30 min

ALERT_TYPES = {"deauth_flood", "disassoc_flood", "evil_twin", "unknown_device", "test_trigger"}

# ---- MAC vendor lookup (same starter table as the alert handler) -----------
OUI = {
    "A4:83:E7": "Apple", "AC:BC:32": "Apple", "8C:85:90": "Apple", "F0:18:98": "Apple",
    "68:AB:BC": "Apple", "3C:15:C2": "Apple", "40:6C:8F": "Apple", "D0:81:7A": "Apple",
    "88:66:5A": "Apple", "90:B0:ED": "Apple", "DC:A9:04": "Apple", "00:23:DF": "Apple",
    "00:25:00": "Apple", "04:0C:CE": "Apple", "F4:5C:89": "Apple",
    "5C:0A:5B": "Samsung", "78:1F:DB": "Samsung", "8C:77:12": "Samsung", "B4:07:F9": "Samsung",
    "C0:BD:D1": "Samsung", "E8:50:8B": "Samsung", "34:BE:00": "Samsung", "00:12:47": "Samsung",
    "28:6C:07": "Xiaomi", "34:CE:00": "Xiaomi", "50:8F:4C": "Xiaomi", "64:09:80": "Xiaomi",
    "78:11:DC": "Xiaomi", "F0:B4:29": "Xiaomi", "8C:BE:BE": "Xiaomi",
    "00:E0:FC": "Huawei", "28:31:52": "Huawei", "48:AD:08": "Huawei", "54:25:EA": "Huawei",
    "60:DE:44": "Huawei", "80:B6:86": "Huawei", "88:53:D4": "Huawei", "4C:54:99": "Huawei",
    "3C:5A:B4": "Google", "54:60:09": "Google", "94:EB:2C": "Google", "F4:F5:D8": "Google",
    "94:65:2D": "OnePlus", "C0:EE:FB": "OnePlus",
    "30:17:C8": "Sony", "78:84:3C": "Sony", "10:F9:6F": "LG", "A8:16:B2": "LG",
    "34:02:86": "Intel", "3C:97:0E": "Intel", "7C:B2:7D": "Intel", "8C:16:45": "Intel",
    "94:65:9C": "Intel", "A4:4E:31": "Intel", "E4:A4:71": "Intel", "F8:63:3F": "Intel",
    "00:24:D7": "Intel", "48:51:B7": "Intel",
    "18:03:73": "Dell", "34:17:EB": "Dell", "B8:2A:72": "Dell", "F8:BC:12": "Dell",
    "3C:D9:2B": "HP", "70:5A:0F": "HP", "9C:B6:54": "HP",
    "28:18:78": "Microsoft", "50:1A:C5": "Microsoft", "7C:1E:52": "Microsoft",
    "24:0A:C4": "Espressif", "30:AE:A4": "Espressif", "3C:71:BF": "Espressif",
    "84:CC:A8": "Espressif", "A4:CF:12": "Espressif", "C4:4F:33": "Espressif",
    "EC:FA:BC": "Espressif", "24:6F:28": "Espressif", "8C:AA:B5": "Espressif",
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
    "44:65:0D": "Amazon", "68:37:E9": "Amazon", "74:C2:46": "Amazon", "F0:27:2D": "Amazon",
    "14:CC:20": "TP-Link", "50:C7:BF": "TP-Link", "A0:F3:C1": "TP-Link", "EC:08:6B": "TP-Link",
    "54:27:1E": "AzureWave",
}
HINT = {
    "Apple": "iPhone / iPad / Mac", "Samsung": "likely phone", "Xiaomi": "likely phone",
    "Huawei": "phone or router", "Google": "Pixel / Nest", "OnePlus": "likely phone",
    "Sony": "phone / console / TV", "LG": "phone / TV", "Intel": "likely laptop / PC",
    "Dell": "likely laptop / PC", "HP": "likely laptop / PC", "Microsoft": "likely PC / Surface",
    "Espressif": "ESP32 / IoT device", "Raspberry Pi": "Raspberry Pi",
    "Amazon": "Echo / Fire device", "TP-Link": "network gear",
    "AzureWave": "Wi-Fi module — laptop / TV / IoT",
}


def mac_vendor(mac):
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


def _num(o):
    if isinstance(o, Decimal):
        return int(o) if o % 1 == 0 else float(o)
    raise TypeError


def _resp(status, body, ctype="application/json"):
    return {"statusCode": status,
            "headers": {"content-type": ctype, "cache-control": "no-store"},
            "body": body}


def _data():
    t = ddb.Table(TABLE_NAME)
    q = t.query(KeyConditionExpression=Key("device").eq(DEVICE_NAME),
                ScanIndexForward=False, Limit=40)
    items = q.get("Items", [])
    now = int(time.time())
    alerts = []
    for i in items:
        if i.get("event") not in ALERT_TYPES:
            continue
        mac = i.get("mac", "")
        alerts.append({
            "event":   i.get("event", ""),
            "ts":      int(i.get("ts", 0)),
            "mac":     mac,
            "vendor":  i.get("vendor") or mac_vendor(mac),
            "rssi":    int(i.get("rssi", 0)),
            "channel": str(i.get("channel", "")),
            "count":   int(i.get("count", 0)),
        })
    alerts = alerts[:40]

    ls = t.get_item(Key={"device": "LASTSEEN", "ts": 0}).get("Item") or {}
    dl = t.get_item(Key={"device": "DEVICELIST", "ts": 0}).get("Item") or {}
    last_seen = max(int(ls.get("updated", 0)), alerts[0]["ts"] if alerts else 0)
    devices = [{"mac": m, "vendor": mac_vendor(m)} for m in list(dl.get("devices", []))]

    return {
        "online": bool(last_seen and (now - last_seen) < ONLINE_WINDOW),
        "lastSeen": last_seen,
        "now": now,
        "alerts": alerts,
        "devices": devices,
        "deviceCount": int(dl.get("count", len(devices))),
    }


def _authed(event):
    headers = event.get("headers") or {}
    token = headers.get("x-wids-token", "")
    return bool(TOKEN) and hmac.compare_digest(token, TOKEN)


def _clear():
    """Delete all alert rows (partition = DEVICE_NAME). Keeps LASTSEEN / DEVICELIST."""
    t = ddb.Table(TABLE_NAME)
    deleted, start_key = 0, None
    while True:
        kw = {"KeyConditionExpression": Key("device").eq(DEVICE_NAME), "ProjectionExpression": "ts"}
        if start_key:
            kw["ExclusiveStartKey"] = start_key
        resp = t.query(**kw)
        items = resp.get("Items", [])
        if items:
            with t.batch_writer() as bw:
                for it in items:
                    bw.delete_item(Key={"device": DEVICE_NAME, "ts": int(it["ts"])})
                    deleted += 1
        start_key = resp.get("LastEvaluatedKey")
        if not start_key:
            break
    return deleted


def lambda_handler(event, context):
    qs = event.get("queryStringParameters") or {}

    if qs.get("data") == "1":
        if not _authed(event):
            return _resp(401, json.dumps({"error": "unauthorized"}))
        try:
            return _resp(200, json.dumps(_data(), default=_num))
        except Exception as e:
            print("data error:", e)
            return _resp(500, json.dumps({"error": "server"}))

    if qs.get("clear") == "1":
        if not _authed(event):
            return _resp(401, json.dumps({"error": "unauthorized"}))
        try:
            return _resp(200, json.dumps({"ok": True, "deleted": _clear()}))
        except Exception as e:
            print("clear error:", e)
            return _resp(500, json.dumps({"error": "server"}))

    return _resp(200, HTML, "text/html; charset=utf-8")


HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="WIDS">
<meta name="theme-color" content="#080d1c">
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🛡️</text></svg>">
<title>WIDS · Network Monitor</title>
<style>
:root{
  --bg:#080d1c; --bg2:#0d1428; --card:#111a35; --line:#1d2950;
  --txt:#e8edff; --dim:#8794c4; --accent:#4f7cff; --ok:#34d399; --bad:#f87171; --warn:#fbbf24;
}
*{box-sizing:border-box}
html,body{margin:0;min-height:100%}
body{background:radial-gradient(1100px 600px at 50% -10%, #17224e 0%, var(--bg) 62%) no-repeat, var(--bg);
  color:var(--txt);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Inter,sans-serif;
  -webkit-font-smoothing:antialiased}
.topbar{position:sticky;top:0;z-index:10;display:flex;align-items:center;gap:12px;
  padding:12px 16px;padding-top:calc(12px + env(safe-area-inset-top));
  background:rgba(13,20,40,.82);backdrop-filter:blur(14px);border-bottom:1px solid var(--line)}
.brand{display:flex;align-items:center;gap:10px;flex:1;min-width:0}
.logo{font-size:22px}
.brand .t{font-weight:800;font-size:16px;letter-spacing:.3px;line-height:1.1}
.brand .s{font-size:11px;color:var(--dim);margin-top:2px}
.actions{display:flex;align-items:center;gap:8px}
.pill{font-size:11px;font-weight:800;padding:5px 10px;border-radius:999px;letter-spacing:.4px;white-space:nowrap}
.pill.on{background:rgba(52,211,153,.15);color:var(--ok);border:1px solid rgba(52,211,153,.32)}
.pill.off{background:rgba(248,113,113,.13);color:var(--bad);border:1px solid rgba(248,113,113,.32)}
button{background:var(--card);color:#c9d4ff;border:1px solid var(--line);border-radius:10px;
  padding:8px 11px;font-size:14px;cursor:pointer;transition:.15s}
button:hover{border-color:#2f3f7d}
button:active{transform:scale(.96)}
main{max-width:760px;margin:0 auto;padding:18px 16px 44px}
.gate{display:flex;align-items:center;justify-content:center;min-height:68vh}
.gatecard{width:100%;max-width:360px;text-align:center;background:var(--card);
  border:1px solid var(--line);border-radius:18px;padding:34px 26px;box-shadow:0 22px 55px rgba(0,0,0,.4)}
.logo-lg{font-size:46px;margin-bottom:8px}
.gatecard h1{font-size:19px;margin:2px 0 6px}
.gatecard p{color:var(--dim);font-size:13px;margin:0 0 18px;line-height:1.55}
input{width:100%;padding:13px 14px;border-radius:12px;border:1px solid var(--line);
  background:var(--bg2);color:var(--txt);font-size:15px;outline:none}
input:focus{border-color:var(--accent)}
.primary{width:100%;margin-top:12px;padding:13px;background:var(--accent);border-color:var(--accent);
  color:#fff;font-weight:700;font-size:15px}
.msg{color:var(--bad);font-size:12.5px;min-height:18px;margin-top:10px}
.hero{display:flex;align-items:center;gap:14px;background:var(--card);border:1px solid var(--line);
  border-radius:16px;padding:18px;margin-bottom:14px}
.dot{width:14px;height:14px;border-radius:50%;flex:none;background:var(--dim)}
.dot.on{background:var(--ok);box-shadow:0 0 0 6px rgba(52,211,153,.13)}
.dot.off{background:var(--bad);box-shadow:0 0 0 6px rgba(248,113,113,.13)}
.hero-t{font-weight:800;font-size:17px}
.hero-s{color:var(--dim);font-size:12.5px;margin-top:3px}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:8px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:15px 10px;text-align:center}
.stat .n{font-size:21px;font-weight:800;line-height:1.1}
.stat .l{font-size:10px;color:var(--dim);text-transform:uppercase;letter-spacing:.7px;margin-top:5px}
h2{font-size:11.5px;text-transform:uppercase;letter-spacing:.9px;color:var(--dim);margin:26px 0 10px}
.h2row{display:flex;align-items:center;justify-content:space-between;margin:26px 0 10px}
.h2row h2{margin:0}
.mini{font-size:11px;padding:5px 10px}
.card{display:flex;align-items:center;gap:12px;background:var(--card);border:1px solid var(--line);
  border-left:3px solid var(--accent);border-radius:12px;padding:13px 14px;margin-bottom:8px}
.card.high{border-left-color:var(--bad)}
.card.mid{border-left-color:var(--warn)}
.card.low{border-left-color:var(--accent)}
.card .ico{font-size:20px;flex:none}
.card .body{flex:1;min-width:0}
.card b{font-size:14.5px}
.card .meta{color:var(--dim);font-size:12px;margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.card .ago{color:var(--dim);font-size:11.5px;white-space:nowrap;flex:none}
.devs{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:8px}
.dev{background:var(--card);border:1px solid var(--line);border-radius:11px;padding:11px 12px}
.dev .m{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px;letter-spacing:.4px}
.dev .v{font-size:11px;color:var(--dim);margin-top:4px}
.empty{color:var(--dim);font-size:13.5px;background:rgba(17,26,53,.55);border:1px dashed var(--line);
  border-radius:12px;padding:22px;text-align:center;line-height:1.5}
.foot{color:var(--dim);font-size:11px;text-align:center;margin-top:28px;opacity:.75}
</style>
</head>
<body>
<header class="topbar">
  <div class="brand">
    <span class="logo">🛡️</span>
    <div><div class="t">WIDS</div><div class="s">WiFi Intrusion Detection</div></div>
  </div>
  <div class="actions">
    <span id="status" class="pill off">● …</span>
    <button id="refresh" title="Refresh">↻</button>
    <button id="logout" title="Lock">🔒</button>
  </div>
</header>

<main>
  <section id="gate" class="gate">
    <div class="gatecard">
      <div class="logo-lg">🛡️</div>
      <h1>Welcome back</h1>
      <p>Enter your access token to view your network monitor.</p>
      <input id="token" type="password" placeholder="Access token" autocomplete="off">
      <button id="save" class="primary">Unlock</button>
      <div id="msg" class="msg"></div>
    </div>
  </section>

  <section id="dash" hidden>
    <div class="hero">
      <div id="dot" class="dot"></div>
      <div>
        <div id="heroTitle" class="hero-t">…</div>
        <div id="heroSub" class="hero-s"></div>
      </div>
    </div>

    <div class="stats">
      <div class="stat"><div id="sAlerts" class="n">0</div><div class="l">Alerts</div></div>
      <div class="stat"><div id="sDevices" class="n">0</div><div class="l">Devices</div></div>
      <div class="stat"><div id="sSeen" class="n">—</div><div class="l">Last seen</div></div>
    </div>

    <div class="h2row"><h2>Recent activity</h2><button id="clear" class="mini">Clear</button></div>
    <div id="alerts"></div>

    <h2>Known devices</h2>
    <div id="devices" class="devs"></div>

    <div class="foot">ESP32 · AWS serverless · auto-refreshing every 15s</div>
  </section>
</main>

<script>
const $=s=>document.querySelector(s), TKEY='wids_token';
const ICON={deauth_flood:'📡',disassoc_flood:'📡',evil_twin:'👯',unknown_device:'❓',test_trigger:'🧪'};
const NAME={deauth_flood:'Deauthentication flood',disassoc_flood:'Disassociation flood',
            evil_twin:'Evil-twin access point',unknown_device:'Unknown device joined',test_trigger:'Test alert'};
const SEV ={deauth_flood:'high',disassoc_flood:'high',evil_twin:'high',unknown_device:'mid',test_trigger:'low'};

function ago(ts,now){if(!ts)return'never';let d=now-ts;if(d<0)d=0;
  if(d<60)return d+'s ago';if(d<3600)return(d/60|0)+'m ago';if(d<86400)return(d/3600|0)+'h ago';return(d/86400|0)+'d ago';}
function shortAgo(ts,now){if(!ts)return'—';let d=now-ts;if(d<0)d=0;
  if(d<60)return d+'s';if(d<3600)return(d/60|0)+'m';if(d<86400)return(d/3600|0)+'h';return(d/86400|0)+'d';}
function esc(s){return String(s).replace(/[<>&]/g,c=>({'<':'&lt;','>':'&gt;','&':'&amp;'}[c]));}
function gate(m){$('#dash').hidden=true;$('#gate').hidden=false;if(m!==undefined)$('#msg').textContent=m;}

async function load(){
  const t=localStorage.getItem(TKEY);
  if(!t){gate();return;}
  try{
    const r=await fetch('?data=1',{headers:{'x-wids-token':t}});
    if(r.status===401){localStorage.removeItem(TKEY);gate('That token was not accepted.');return;}
    if(!r.ok)throw 0;
    render(await r.json());
  }catch(e){
    if(!$('#dash').hidden){$('#heroSub').textContent='Connection problem — retrying…';}
    else{gate('Could not reach the server.');}
  }
}

function render(d){
  $('#gate').hidden=true;$('#dash').hidden=false;$('#msg').textContent='';
  const on=d.online;
  $('#status').className='pill '+(on?'on':'off');
  $('#status').textContent=on?'● ONLINE':'● OFFLINE';
  $('#dot').className='dot '+(on?'on':'off');
  $('#heroTitle').textContent = on ? (d.alerts.length?'Monitoring — recent activity':'All clear') : 'Sensor offline';
  $('#heroSub').textContent = on
    ? (d.alerts.length? d.alerts.length+' alert'+(d.alerts.length>1?'s':'')+' recorded · last contact '+ago(d.lastSeen,d.now)
                      : 'No attacks detected · last contact '+ago(d.lastSeen,d.now))
    : 'No contact since '+ago(d.lastSeen,d.now)+' — check power or WiFi';

  $('#sAlerts').textContent=d.alerts.length;
  $('#sDevices').textContent=d.deviceCount;
  $('#sSeen').textContent=shortAgo(d.lastSeen,d.now);

  $('#alerts').innerHTML = d.alerts.length ? d.alerts.map(x=>{
      const bits=[esc(x.mac||'—')]; if(x.vendor) bits.push(esc(x.vendor)); bits.push(esc(x.rssi)+' dBm');
      return `<div class="card ${SEV[x.event]||'low'}"><span class="ico">${ICON[x.event]||'⚠️'}</span>`+
        `<div class="body"><b>${NAME[x.event]||esc(x.event)}</b>`+
        `<div class="meta">${bits.join(' · ')}</div></div>`+
        `<span class="ago">${ago(x.ts,d.now)}</span></div>`;
    }).join('') : '<div class="empty">🎉 No alerts yet — your network looks quiet.</div>';

  $('#devices').innerHTML = d.devices.length
    ? d.devices.map(o=>{const mac=(typeof o==='string')?o:o.mac, v=(typeof o==='string')?'':o.vendor;
        return `<div class="dev"><div class="m">📱 ${esc(mac)}</div>`+
               (v?`<div class="v">${esc(v)}</div>`:'')+`</div>`;}).join('')
    : '<div class="empty">No devices learned yet. The sensor reports its list on boot.</div>';
}

$('#save').onclick=()=>{const t=$('#token').value.trim();if(t){localStorage.setItem(TKEY,t);load();}};
$('#token').addEventListener('keydown',e=>{if(e.key==='Enter')$('#save').click();});
$('#refresh').onclick=load;
$('#logout').onclick=()=>{localStorage.removeItem(TKEY);$('#token').value='';gate('Locked.');};
$('#clear').onclick=async()=>{
  if(!confirm('Clear all recent activity? This permanently deletes the stored alert history.'))return;
  const t=localStorage.getItem(TKEY);if(!t)return;
  const b=$('#clear');b.textContent='Clearing…';
  try{await fetch('?clear=1',{method:'POST',headers:{'x-wids-token':t}});}catch(e){}
  b.textContent='Clear';load();
};
load();setInterval(load,15000);
</script>
</body>
</html>
"""
