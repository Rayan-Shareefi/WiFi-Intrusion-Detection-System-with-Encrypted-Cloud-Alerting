/*
 * ============================================================================
 *  M2_deauth_detector.ino  —  Milestone 2: detect deauth/disassoc attacks
 * ----------------------------------------------------------------------------
 *  What this does (still NO cloud yet — just prints to Serial):
 *    - Puts the ESP32 radio into "promiscuous" (monitor) mode: a passive
 *      listener that hears nearby 802.11 WiFi frames without connecting.
 *    - Locks onto YOUR home AP's channel and remembers its BSSID (MAC address),
 *      so it can tell attacks on YOUR network apart from the neighbours'.
 *    - Counts deauthentication + disassociation frames. A flood of these is the
 *      classic "kick devices off the WiFi" attack. If the count crosses a
 *      threshold, it prints a DEAUTH FLOOD DETECTED alert.
 *    - Lets you SAFELY test the alert path by typing 't' in the Serial Monitor.
 *
 *  WHY THIS WORKS WITHOUT A PASSWORD:
 *    802.11 "management" frames (which include deauth + disassoc) are ALWAYS
 *    sent unencrypted, even on a WPA2 network. So we can read them just by
 *    listening. (The actual data your devices send IS encrypted and unreadable
 *    — but we don't need it; the attack lives in the management frames.)
 *
 *  HOW A DEAUTH FRAME IS IDENTIFIED:
 *    The first byte of every frame (the "frame control" byte) encodes its type.
 *      - Deauthentication  = 0xC0
 *      - Disassociation    = 0xA0
 *    That single-byte check is all we need to spot the attack.
 *
 *  SETUP: edit HOME_WIFI_SSID below, upload, open Serial Monitor at 115200.
 * ============================================================================
 */

#include "WiFi.h"        // Arduino WiFi (for the startup scan)
#include "esp_wifi.h"    // native ESP-IDF API (for promiscuous/monitor mode)

// ---------------------------------------------------------------------------
//  CONFIG — the only line you MUST change is HOME_WIFI_SSID.
// ---------------------------------------------------------------------------
#define HOME_WIFI_SSID    "YOUR_WIFI_NAME"  // <-- EDIT: your 2.4 GHz network name

#define WINDOW_MS         5000UL   // how often we tally counts (5 seconds)
#define DEAUTH_THRESHOLD  20       // frames within one window => flag an attack
#define COOLDOWN_MS       15000UL  // don't re-alert more often than this
#define FALLBACK_CHANNEL  6        // used only if your SSID isn't found at boot

// ---------------------------------------------------------------------------
//  Shared state. "volatile" tells the compiler these can change at any moment
//  (the sniffer callback updates them while loop() reads them).
// ---------------------------------------------------------------------------
volatile uint32_t g_deauth   = 0;   // deauth frames seen this window
volatile uint32_t g_disassoc = 0;   // disassoc frames seen this window
volatile uint32_t g_relevant = 0;   // of those, how many target OUR network
volatile int      g_lastRssi = 0;   // signal strength of the last relevant frame
volatile uint8_t  g_lastBssid[6] = {0};

uint8_t  g_homeBssid[6] = {0};      // our AP's MAC, learned at boot (read-only in cb)
bool     g_haveHomeBssid = false;
int      g_homeChannel   = FALLBACK_CHANNEL;

unsigned long g_windowStart = 0;
unsigned long g_lastAlert   = 0;

// Format a 6-byte MAC into "AA:BB:CC:DD:EE:FF".
void formatMac(const uint8_t *mac, char *out) {
  snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// ---------------------------------------------------------------------------
//  THE SNIFFER CALLBACK.
//  The WiFi driver calls this for every captured frame. RULE: keep it tiny and
//  fast — no Serial prints, no memory allocation. Just look, count, and store a
//  couple of fields. Heavy work here makes the radio drop packets.
// ---------------------------------------------------------------------------
void IRAM_ATTR snifferCallback(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT) return;               // we only asked for mgmt frames
  const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buf;
  if (ppkt->rx_ctrl.sig_len < 24) return;          // guard: need a full 802.11 MAC header first
  const uint8_t *p = ppkt->payload;                // raw 802.11 frame bytes

  uint8_t fc = p[0];                               // frame control byte 0
  if (fc != 0xC0 && fc != 0xA0) return;            // not deauth (C0) or disassoc (A0)
  if (fc == 0xC0) g_deauth++; else g_disassoc++;

  // 802.11 addresses: addr1 = p[4..9] (destination), addr3 = p[16..21] (BSSID).
  // A frame targets OUR network if its BSSID matches ours, or it's a broadcast
  // deauth (destination = FF:FF:FF:FF:FF:FF — the classic "kick everyone" form).
  bool relevant = true;
  if (g_haveHomeBssid) {
    bool bssidMatch = true, broadcast = true;
    for (int i = 0; i < 6; i++) {
      if (p[16 + i] != g_homeBssid[i]) bssidMatch = false;
      if (p[4  + i] != 0xFF)           broadcast  = false;
    }
    relevant = bssidMatch || broadcast;
  }
  if (relevant) {
    g_relevant++;
    g_lastRssi = ppkt->rx_ctrl.rssi;               // dBm, negative (closer to 0 = stronger)
    for (int i = 0; i < 6; i++) g_lastBssid[i] = p[16 + i];
  }
}

// Print a clear, structured alert block.
void reportDetection(bool isTest, uint32_t frames) {
  char bssidStr[18];
  formatMac(isTest ? g_homeBssid : (const uint8_t *)g_lastBssid, bssidStr);

  Serial.println();
  Serial.println("!!! ===================================================== !!!");
  Serial.printf ("!!!  %s DEAUTH / DISASSOC FLOOD DETECTED\n", isTest ? "[TEST]" : "[REAL]");
  Serial.printf ("!!!  frames in window : %u  (threshold %u)\n", frames, (uint32_t)DEAUTH_THRESHOLD);
  Serial.printf ("!!!  channel          : %d\n", g_homeChannel);
  Serial.printf ("!!!  target BSSID      : %s\n", bssidStr);
  Serial.printf ("!!!  last RSSI         : %d dBm\n", g_lastRssi);
  Serial.println("!!!  (in M4 this is what will be sent as an encrypted cloud alert)");
  Serial.println("!!! ===================================================== !!!");
  Serial.println();
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  Serial.println();
  Serial.println("========================================");
  Serial.println("  WIDS - Milestone 2: deauth detector");
  Serial.println("========================================");

  if (String(HOME_WIFI_SSID) == "YOUR_WIFI_NAME") {
    Serial.println("!! Please edit HOME_WIFI_SSID at the top of the sketch to your");
    Serial.println("!! WiFi network name, then re-upload. Running in fallback mode.");
  }

  // --- Step 1: scan (in station mode) to find our AP's channel + BSSID -------
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  Serial.printf("Scanning for \"%s\" ...\n", HOME_WIFI_SSID);
  int n = WiFi.scanNetworks();
  for (int i = 0; i < n; i++) {
    if (WiFi.SSID(i).equals(HOME_WIFI_SSID)) {
      g_homeChannel = WiFi.channel(i);
      memcpy(g_homeBssid, WiFi.BSSID(i), 6);
      g_haveHomeBssid = true;
      break;
    }
  }
  WiFi.scanDelete();

  char bssidStr[18];
  if (g_haveHomeBssid) {
    formatMac(g_homeBssid, bssidStr);
    Serial.printf("Locked to \"%s\" on channel %d  (BSSID %s)\n",
                  HOME_WIFI_SSID, g_homeChannel, bssidStr);
  } else {
    Serial.printf("SSID not found. Parking on fallback channel %d and counting ALL\n",
                  FALLBACK_CHANNEL);
    Serial.println("deauth/disassoc frames (no per-network filter).");
  }

  // --- Step 2: enter promiscuous (monitor) mode -----------------------------
  esp_wifi_set_promiscuous(true);
  // Ask the driver for management frames only (lighter load; deauth lives here).
  wifi_promiscuous_filter_t filter = { .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT };
  esp_wifi_set_promiscuous_filter(&filter);
  esp_wifi_set_promiscuous_rx_cb(&snifferCallback);
  esp_wifi_set_channel(g_homeChannel, WIFI_SECOND_CHAN_NONE);

  Serial.printf("Monitoring... window=%lus  threshold=%d  cooldown=%lus\n",
                WINDOW_MS / 1000, DEAUTH_THRESHOLD, COOLDOWN_MS / 1000);
  Serial.println("Type 't' + Enter in the Serial Monitor to TEST the alert path.");
  Serial.println();

  g_windowStart = millis();
}

void loop() {
  unsigned long now = millis();

  // --- Safe test trigger: type 't' to simulate a detection ------------------
  if (Serial.available()) {
    char c = Serial.read();
    if (c == 't' || c == 'T') reportDetection(true, DEAUTH_THRESHOLD);
  }

  // --- Every WINDOW_MS: tally the counts and decide whether to alert --------
  if (now - g_windowStart >= WINDOW_MS) {
    // Snapshot then reset (a frame or two may be lost in the swap — fine for us).
    uint32_t d = g_deauth, da = g_disassoc, rel = g_relevant;
    g_deauth = 0; g_disassoc = 0; g_relevant = 0;
    g_windowStart = now;

    // What we compare to the threshold: relevant-to-us if we know our BSSID,
    // otherwise the raw total.
    uint32_t trigger = g_haveHomeBssid ? rel : (d + da);

    Serial.printf("[status] deauth=%u disassoc=%u relevant=%u  (trigger=%u/%d)\n",
                  d, da, rel, trigger, DEAUTH_THRESHOLD);

    if (trigger >= DEAUTH_THRESHOLD && (now - g_lastAlert >= COOLDOWN_MS)) {
      reportDetection(false, trigger);
      g_lastAlert = now;
    }
  }
}
