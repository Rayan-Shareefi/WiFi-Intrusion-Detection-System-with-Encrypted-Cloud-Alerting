/*
 * ============================================================================
 *  WIDS_ESP32.ino  —  the main device sketch (hardened)
 * ----------------------------------------------------------------------------
 *  Detections (all feed one encrypted-alert pipeline):
 *    1. Deauth / disassoc floods   (promiscuous sniffing)
 *    2. Evil-twin / rogue AP        (periodic scan)
 *    3. Unknown device joined       (association frames; baseline saved to NVS)
 *
 *  Hardening in this version (from the security review, docs/SECURITY-REVIEW.md):
 *    F1  frame-length guard in the sniffer callback (prevents OOB read / crash)
 *    F6  periodic HEARTBEAT so the cloud can detect if the sensor goes offline
 *    F7  per-detection-type cooldown (one alert type no longer suppresses another)
 *    F5  a "missed" counter for alerts dropped while offline (reported next time)
 *
 *  Serial commands: 't' = fire a test alert, 'r' = reset the device baseline.
 *  SETUP unchanged: secrets.h filled in; libs PubSubClient + ArduinoJson.
 * ============================================================================
 */

#include "secrets.h"
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include "esp_wifi.h"
#include <time.h>
#include <Preferences.h>
#include <HTTPClient.h>

// ---- Cloud path -----------------------------------------------------------
//  This build ships with the $0-FOREVER HTTPS path ENABLED (line below): the
//  device POSTs alerts to a Lambda Function URL, so every AWS service used is
//  always-free (no IoT Core, no 12-month clock). Needs LAMBDA_URL +
//  ALERT_BEARER_TOKEN in secrets.h. Guide: docs/ZERO-COST-FOREVER.md
//  To use the X.509 mutual-TLS MQTT path to AWS IoT Core instead, comment it out.
#define USE_HTTPS_INGEST

// ---- Tuning ---------------------------------------------------------------
#define WINDOW_MS         5000UL     // deauth tally window
#define DEAUTH_THRESHOLD  20         // frames/window => attack
#define COOLDOWN_MS       30000UL    // min gap between alerts of the SAME type
#define SCAN_INTERVAL_MS  180000UL   // evil-twin scan every 3 min
#define DEVICE_LEARN_MS   300000UL    // 5-min learn window (use 30000UL = 30 s for quick testing)
#define HEARTBEAT_MS      1800000UL  // send a heartbeat every 30 min (offline detection)
#define MAX_KNOWN_BSSIDS  8
#define MAX_KNOWN_DEVICES 32
#define ASSOC_QUEUE       8

WiFiClientSecure net;
PubSubClient    client(net);
Preferences     prefs;   // flash (NVS) storage for the known-device baseline

// ---- Deauth sniffer state (written inside the callback) --------------------
volatile uint32_t g_deauth = 0, g_disassoc = 0, g_relevant = 0;
volatile int      g_lastRssi = 0;
volatile uint8_t  g_lastBssid[6] = {0};

// ---- Association ring buffer (client joins seen by the callback) -----------
volatile uint8_t  g_assocMac[ASSOC_QUEUE][6];
volatile int8_t   g_assocRssi[ASSOC_QUEUE];
volatile uint8_t  g_assocHead = 0, g_assocTail = 0;

uint8_t  g_homeBssid[6] = {0};
bool     g_haveHomeBssid = false;
int      g_homeChannel   = 1;

// ---- Baselines -------------------------------------------------------------
uint8_t  g_knownBssids[MAX_KNOWN_BSSIDS][6];   int g_knownCount = 0;         // evil-twin
uint8_t  g_knownDevices[MAX_KNOWN_DEVICES][6]; int g_knownDeviceCount = 0, g_devEvict = 0;  // devices

// ---- Alert target + bookkeeping --------------------------------------------
uint8_t  g_alertMac[6] = {0};
int      g_alertRssi   = 0;
uint32_t g_missed      = 0;   // F5: sends that failed while offline

unsigned long g_windowStart = 0, g_lastScan = 0, g_learnUntil = 0, g_lastHeartbeat = 0;
unsigned long g_coolDeauth = 0, g_coolEvil = 0, g_coolDevice = 0;   // F7: per-type cooldowns

void formatMac(const uint8_t *mac, char *out) {
  snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

const char *authModeStr(wifi_auth_mode_t m) {
  switch (m) {
    case WIFI_AUTH_OPEN:          return "OPEN";
    case WIFI_AUTH_WEP:           return "WEP";
    case WIFI_AUTH_WPA_PSK:       return "WPA";
    case WIFI_AUTH_WPA2_PSK:      return "WPA2";
    case WIFI_AUTH_WPA_WPA2_PSK:  return "WPA/WPA2";
    case WIFI_AUTH_WPA3_PSK:      return "WPA3";
    case WIFI_AUTH_WPA2_WPA3_PSK: return "WPA2/WPA3";
    default:                      return "other";
  }
}

// Tiny, fast sniffer callback — classify, count/queue, store; never block here.
void IRAM_ATTR snifferCallback(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT) return;
  const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buf;
  if (ppkt->rx_ctrl.sig_len < 24) return;          // F1: need a full 802.11 MAC header before indexing
  const uint8_t *p = ppkt->payload;
  uint8_t fc = p[0];                               // frame control byte 0

  // --- Deauth (0xC0) / disassoc (0xA0): the "kick off" attack ---
  if (fc == 0xC0 || fc == 0xA0) {
    if (fc == 0xC0) g_deauth++; else g_disassoc++;
    bool relevant = true;
    if (g_haveHomeBssid) {
      bool bssidMatch = true, broadcast = true;
      for (int i = 0; i < 6; i++) {
        if (p[16 + i] != g_homeBssid[i]) bssidMatch = false;   // addr3 = BSSID
        if (p[4  + i] != 0xFF)           broadcast  = false;   // addr1 = dest
      }
      relevant = bssidMatch || broadcast;
    }
    if (relevant) {
      g_relevant++;
      g_lastRssi = ppkt->rx_ctrl.rssi;
      for (int i = 0; i < 6; i++) g_lastBssid[i] = p[16 + i];
    }
    return;
  }

  // --- (Re)association request (0x00 / 0x20): a device joining our network ---
  if (fc == 0x00 || fc == 0x20) {
    if (g_haveHomeBssid) {
      bool a1 = true, a3 = true;
      for (int i = 0; i < 6; i++) {
        if (p[4  + i] != g_homeBssid[i]) a1 = false;   // addr1 = AP (dest)
        if (p[16 + i] != g_homeBssid[i]) a3 = false;   // addr3 = BSSID
      }
      if (!a1 && !a3) return;                          // not our network
    }
    uint8_t next = (uint8_t)((g_assocHead + 1) % ASSOC_QUEUE);
    if (next != g_assocTail) {
      for (int i = 0; i < 6; i++) g_assocMac[g_assocHead][i] = p[10 + i];  // addr2 = client
      g_assocRssi[g_assocHead] = (int8_t)ppkt->rx_ctrl.rssi;
      g_assocHead = next;
    }
    return;
  }
}

// ---- Connectivity helpers --------------------------------------------------
bool connectWiFi(uint32_t timeoutMs) {
  Serial.printf("WiFi: connecting to \"%s\" ", WIFI_SSID);
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  unsigned long start = millis();
  while (WiFi.status() != WL_CONNECTED) {
    if (millis() - start > timeoutMs) { Serial.println(" timeout"); return false; }
    delay(300); Serial.print(".");
  }
  Serial.printf(" connected (IP %s)\n", WiFi.localIP().toString().c_str());
  return true;
}

void syncTime() {
  configTime(0, 0, "pool.ntp.org", "time.nist.gov");
  Serial.print("NTP: syncing ");
  time_t now = time(nullptr);
  unsigned long start = millis();
  while (now < 1700000000 && millis() - start < 20000) { delay(300); Serial.print("."); now = time(nullptr); }
  Serial.println(now < 1700000000 ? " FAILED (network may block UDP 123)" : " ok");
}

void ensureTime() { if (time(nullptr) < 1700000000) syncTime(); }

void setupAWS() {
  net.setCACert(AWS_CERT_CA);            // Amazon Root CA 1 validates BOTH IoT Core and the Function URL
#ifndef USE_HTTPS_INGEST
  net.setCertificate(AWS_CERT_CRT);      // device cert + private key: only the mutual-TLS MQTT path
  net.setPrivateKey(AWS_CERT_PRIVATE);
  client.setServer(AWS_IOT_ENDPOINT, 8883);
  client.setBufferSize(1024);
#endif
}

// Send one JSON message to the cloud via whichever path is compiled in.
bool sendJson(const char *json, size_t len) {
#ifdef USE_HTTPS_INGEST
  HTTPClient https;
  if (!https.begin(net, LAMBDA_URL)) return false;    // net already has Amazon Root CA 1
  https.addHeader("Content-Type", "application/json");
  https.addHeader("Authorization", String("Bearer ") + ALERT_BEARER_TOKEN);
  int code = https.POST((uint8_t *)json, len);
  https.end();
  return code >= 200 && code < 300;
#else
  return client.publish(AWS_TOPIC_ALERTS, (const uint8_t *)json, len);
#endif
}

bool connectAWS(uint32_t timeoutMs) {
  Serial.printf("AWS: connecting ");
  unsigned long start = millis();
  while (!client.connect(AWS_THING_NAME)) {
    if (millis() - start > timeoutMs) { Serial.printf("timeout (state=%d)\n", client.state()); return false; }
    Serial.printf("(state=%d) ", client.state());
    delay(2000);
  }
  Serial.println("connected!");
  return true;
}

void setAlertTarget(const uint8_t *mac, int rssi) {
  for (int i = 0; i < 6; i++) g_alertMac[i] = mac[i];
  g_alertRssi = rssi;
}

void publishAlert(const char *event, uint32_t count) {
  char macStr[18];
  formatMac(g_alertMac, macStr);
  JsonDocument doc;
  doc["device"]        = AWS_THING_NAME;
  doc["event"]         = event;
  doc["count"]         = count;
  doc["mac"]           = macStr;               // AP BSSID, or client MAC for unknown_device
  doc["rssi"]          = g_alertRssi;
  doc["channel"]       = g_homeChannel;
  doc["known_devices"] = g_knownDeviceCount;   // how many devices the baseline holds
  doc["missed"]        = g_missed;             // alerts dropped while offline since last success
  doc["ts"]            = (uint32_t)time(nullptr);

  char payload[320];
  size_t n = serializeJson(doc, payload);
  bool ok = sendJson(payload, n);
  if (ok) g_missed = 0;                        // reported successfully -> clear counter
  Serial.printf("PUBLISH %s (%u bytes): %s\n", ok ? "OK" : "FAILED", (unsigned)n, payload);
}

// Publish the saved-MAC baseline so the dashboard app can show your known devices.
void publishDeviceList() {
  JsonDocument doc;
  doc["device"] = AWS_THING_NAME;
  doc["event"]  = "device_list";
  doc["count"]  = g_knownDeviceCount;
  doc["ts"]     = (uint32_t)time(nullptr);
  JsonArray arr = doc["devices"].to<JsonArray>();
  char m[18];
  for (int i = 0; i < g_knownDeviceCount; i++) { formatMac(g_knownDevices[i], m); arr.add(String(m)); }

  char payload[900];
  size_t n = serializeJson(doc, payload);
  bool ok = sendJson(payload, n);
  Serial.printf("PUBLISH device_list %s (%u bytes, %d devices)\n", ok ? "OK" : "FAILED", (unsigned)n, g_knownDeviceCount);
}

void startMonitoring() {
  if (client.connected()) client.disconnect();
  WiFi.disconnect(false);
  delay(100);
  esp_wifi_set_promiscuous(true);
  wifi_promiscuous_filter_t filter = { .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT };
  esp_wifi_set_promiscuous_filter(&filter);
  esp_wifi_set_promiscuous_rx_cb(&snifferCallback);
  esp_wifi_set_channel(g_homeChannel, WIFI_SECOND_CHAN_NONE);
  g_deauth = 0; g_disassoc = 0; g_relevant = 0;
  g_windowStart = millis();
  Serial.printf("[MONITOR] promiscuous ON, channel %d.\n", g_homeChannel);
}

// Switch to station mode, publish one message, resume monitoring. Returns success.
bool sendAlert(const char *event, uint32_t count) {
  Serial.printf("\n[SEND] %s (count=%u)\n", event, count);
  esp_wifi_set_promiscuous(false);
  if (!connectWiFi(15000)) { Serial.println("[SEND] WiFi failed; resuming."); g_missed++; startMonitoring(); return false; }
  ensureTime();
#ifndef USE_HTTPS_INGEST
  if (!client.connected() && !connectAWS(15000)) { Serial.println("[SEND] AWS failed; resuming."); g_missed++; startMonitoring(); return false; }
#endif
  publishAlert(event, count);
  if (strcmp(event, "heartbeat") == 0) publishDeviceList();   // refresh device list every heartbeat
  delay(200);
  Serial.println("[RESUME] back to monitoring.");
  startMonitoring();
  return true;
}

// ---- Evil-twin -------------------------------------------------------------
bool isKnownBssid(const uint8_t *b) {
  for (int i = 0; i < g_knownCount; i++) {
    bool match = true;
    for (int j = 0; j < 6; j++) if (g_knownBssids[i][j] != b[j]) { match = false; break; }
    if (match) return true;
  }
  return false;
}

void baselineSSIDs() {
  Serial.printf("[BASELINE] recording known \"%s\" access points...\n", WIFI_SSID);
  WiFi.mode(WIFI_STA);
  int n = WiFi.scanNetworks();
  g_knownCount = 0;
  for (int i = 0; i < n && g_knownCount < MAX_KNOWN_BSSIDS; i++) {
    if (WiFi.SSID(i).equals(WIFI_SSID)) {
      memcpy(g_knownBssids[g_knownCount], WiFi.BSSID(i), 6);
      char b[18]; formatMac(g_knownBssids[g_knownCount], b);
      Serial.printf("  known AP: %s  ch %d  %s\n", b, WiFi.channel(i), authModeStr(WiFi.encryptionType(i)));
      g_knownCount++;
    }
  }
  WiFi.scanDelete();
  Serial.printf("[BASELINE] %d known AP(s) recorded.\n", g_knownCount);
}

void checkEvilTwin() {
  if (g_knownCount == 0) return;   // no baseline -> skip (keeps monitoring)
  Serial.println("[SCAN] evil-twin check (pausing monitor to scan)...");
  esp_wifi_set_promiscuous(false);
  WiFi.mode(WIFI_STA);
  int n = WiFi.scanNetworks();
  int suspicious = 0;
  uint8_t badBssid[6] = {0}; int badRssi = 0, badChan = 0; const char *badEnc = "";
  for (int i = 0; i < n; i++) {
    if (!WiFi.SSID(i).equals(WIFI_SSID)) continue;
    if (!isKnownBssid(WiFi.BSSID(i))) {
      suspicious++;
      memcpy(badBssid, WiFi.BSSID(i), 6);
      badRssi = WiFi.RSSI(i); badChan = WiFi.channel(i); badEnc = authModeStr(WiFi.encryptionType(i));
    }
  }
  WiFi.scanDelete();

  if (suspicious > 0) {
    char b[18]; formatMac(badBssid, b);
    Serial.printf("[SCAN] EVIL TWIN suspected: unknown AP %s (ch %d, %s) using \"%s\"\n", b, badChan, badEnc, WIFI_SSID);
    if (millis() - g_coolEvil >= COOLDOWN_MS) {     // F7: evil-twin's own cooldown
      g_coolEvil = millis();
      setAlertTarget(badBssid, badRssi);
      sendAlert("evil_twin", suspicious);
      return;
    }
  }
  Serial.printf("[SCAN] done (%d networks, %d suspicious). Resuming.\n", n, suspicious);
  startMonitoring();
}

// ---- Unknown-device --------------------------------------------------------
bool isKnownDevice(const uint8_t *mac) {
  for (int i = 0; i < g_knownDeviceCount; i++) {
    bool match = true;
    for (int j = 0; j < 6; j++) if (g_knownDevices[i][j] != mac[j]) { match = false; break; }
    if (match) return true;
  }
  return false;
}

void saveKnownDevices() {
  prefs.begin("wids", false);                            // read-write
  prefs.putBytes("dev_macs", g_knownDevices, g_knownDeviceCount * 6);
  prefs.end();
}

void addKnownDevice(const uint8_t *mac) {
  int idx;
  if (g_knownDeviceCount < MAX_KNOWN_DEVICES) {          // room: append
    idx = g_knownDeviceCount++;
  } else {                                               // full: evict oldest (round-robin) so a
    idx = g_devEvict;                                    // 33rd+ device is still remembered and
    g_devEvict = (g_devEvict + 1) % MAX_KNOWN_DEVICES;   // doesn't re-alert every cooldown forever
  }
  memcpy(g_knownDevices[idx], mac, 6);
  saveKnownDevices();                                    // persist to flash (survives reboot)
}

void loadKnownDevices() {
  prefs.begin("wids", true);                             // read-only
  size_t len = prefs.getBytesLength("dev_macs");
  int count = len / 6;
  if (count > MAX_KNOWN_DEVICES) count = MAX_KNOWN_DEVICES;
  if (count > 0) {
    prefs.getBytes("dev_macs", g_knownDevices, count * 6);
    g_knownDeviceCount = count;
  }
  prefs.end();
  Serial.printf("[NVS] loaded %d known device(s) from flash.\n", g_knownDeviceCount);
}

void resetBaseline() {
  prefs.begin("wids", false);
  prefs.clear();                                         // wipe the "wids" namespace
  prefs.end();
  g_knownDeviceCount = 0;
  g_learnUntil = millis() + DEVICE_LEARN_MS;
  Serial.println("[NVS] baseline cleared; re-learning known devices...");
}

void handleAssociation(const uint8_t *mac, int rssi) {
  if (isKnownDevice(mac)) return;
  addKnownDevice(mac);                        // remember it -> each MAC alerts once
  char m[18]; formatMac(mac, m);
  if (millis() < g_learnUntil) { Serial.printf("[LEARN] known device: %s\n", m); return; }
  Serial.printf("[JOIN] NEW device joined: %s\n", m);
  if (millis() - g_coolDevice >= COOLDOWN_MS) {   // F7: unknown-device's own cooldown
    g_coolDevice = millis();
    setAlertTarget(mac, rssi);
    sendAlert("unknown_device", 1);
  }
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  Serial.println("\n=== WIDS - hardened: deauth + evil-twin + unknown-device ===");
  setupAWS();

  WiFi.mode(WIFI_STA);
  while (!connectWiFi(20000)) Serial.println("WiFi retry...");
  g_homeChannel = WiFi.channel();
  memcpy(g_homeBssid, WiFi.BSSID(), 6);
  g_haveHomeBssid = true;
  char b[18]; formatMac(g_homeBssid, b);
  Serial.printf("Home AP: channel %d, BSSID %s\n", g_homeChannel, b);

  syncTime();
  loadKnownDevices();                          // NVS; ready before we publish the list
  setAlertTarget(g_homeBssid, 0);
#ifdef USE_HTTPS_INGEST
  publishAlert("device_online", 0);            // HTTPS: post directly over the live WiFi connection
  publishDeviceList();
#else
  if (connectAWS(15000)) {                     // MQTT: open the IoT Core session first
    publishAlert("device_online", 0);
    publishDeviceList();                        // report saved-MAC baseline to the cloud
  }
#endif

  baselineSSIDs();
  g_lastScan      = millis();
  g_lastHeartbeat = millis();
  g_learnUntil    = (g_knownDeviceCount > 0) ? millis() : (millis() + DEVICE_LEARN_MS);
  startMonitoring();
  if (g_knownDeviceCount > 0)
    Serial.println("Baseline loaded from flash. 't' = test alert, 'r' = reset baseline.");
  else
    Serial.printf("Learning devices for %lus. 't' = test alert, 'r' = reset baseline.\n", DEVICE_LEARN_MS / 1000);
}

void loop() {
  if (Serial.available()) {
    char c = Serial.read();
    if (c == 't' || c == 'T') { setAlertTarget(g_homeBssid, 0); sendAlert("test_trigger", DEAUTH_THRESHOLD); return; }
    if (c == 'r' || c == 'R') resetBaseline();
  }

  unsigned long now = millis();

  // 0) Heartbeat (so the cloud can tell if this sensor goes offline)
  if (now - g_lastHeartbeat >= HEARTBEAT_MS) {
    g_lastHeartbeat = now;
    setAlertTarget(g_homeBssid, 0);
    sendAlert("heartbeat", 0);
    return;
  }

  // 1) Deauth flood check
  if (now - g_windowStart >= WINDOW_MS) {
    uint32_t d = g_deauth, da = g_disassoc, rel = g_relevant;
    g_deauth = 0; g_disassoc = 0; g_relevant = 0;
    g_windowStart = now;
    uint32_t trigger = g_haveHomeBssid ? rel : (d + da);
    Serial.printf("[status] deauth=%u disassoc=%u relevant=%u known-devices=%d missed=%u (trigger=%u/%d)\n",
                  d, da, rel, g_knownDeviceCount, g_missed, trigger, DEAUTH_THRESHOLD);
    if (trigger >= DEAUTH_THRESHOLD && (now - g_coolDeauth >= COOLDOWN_MS)) {
      uint8_t snap[6]; for (int i = 0; i < 6; i++) snap[i] = g_lastBssid[i];
      setAlertTarget(snap, g_lastRssi);
      g_coolDeauth = now;                       // F7: deauth's own cooldown
      sendAlert((d >= da) ? "deauth_flood" : "disassoc_flood", trigger);
      return;
    }
  }

  // 2) Drain association events (device joins)
  while (g_assocTail != g_assocHead) {
    uint8_t mac[6]; int rssi;
    for (int i = 0; i < 6; i++) mac[i] = g_assocMac[g_assocTail][i];
    rssi = g_assocRssi[g_assocTail];
    g_assocTail = (uint8_t)((g_assocTail + 1) % ASSOC_QUEUE);
    handleAssociation(mac, rssi);
  }

  // 3) Evil-twin scan
  if (now - g_lastScan >= SCAN_INTERVAL_MS) {
    g_lastScan = now;
    checkEvilTwin();
  }
}
