// ===========================================================================
//  secrets.example.h  —  TEMPLATE (safe to commit)
// ---------------------------------------------------------------------------
//  HOW TO USE:
//    1. Copy this file to "secrets.h" in this same folder.
//    2. Fill in the values below.
//    3. NEVER commit secrets.h — it's already blocked by .gitignore.
//
//  Why a separate file? It keeps your WiFi password and device private key out
//  of the main code and out of git. This .example version documents the shape
//  for anyone reading the repo, without leaking anything real.
// ===========================================================================
#pragma once

// ---- Home WiFi (the device connects briefly, only to send an alert) -------
#define WIFI_SSID       "YOUR_WIFI_NAME"
#define WIFI_PASSWORD   "YOUR_WIFI_PASSWORD"

// ---- AWS IoT Core ---------------------------------------------------------
// Your endpoint: AWS IoT console -> Settings -> "Device data endpoint".
// Example shape: xxxxxxxxxxxxxx-ats.iot.eu-central-1.amazonaws.com   (note -ats)
#define AWS_IOT_ENDPOINT   "xxxxxxxxxxxxxx-ats.iot.eu-central-1.amazonaws.com"

// These are already correct — leave them as-is. AWS_THING_NAME is also the MQTT
// client ID, and must match the policy's client/WIDS_ESP32 resource.
#define AWS_THING_NAME     "WIDS_ESP32"
#define AWS_TOPIC_ALERTS   "wids/alerts"

// ---- $0-forever HTTPS ingest (used ONLY if USE_HTTPS_INGEST is enabled) ----
// Create a Function URL on the wids-alert-handler Lambda -> see docs/ZERO-COST-FOREVER.md.
// The token must match the Lambda's INGEST_TOKEN environment variable.
#define LAMBDA_URL          "https://xxxxxxxxxxxxxxxxx.lambda-url.eu-central-1.on.aws/"
#define ALERT_BEARER_TOKEN  "PASTE_A_LONG_RANDOM_TOKEN"

// ---------------------------------------------------------------------------
//  X.509 credentials (the 3 files you downloaded in Phase A).
//  For each one: open the file in Notepad, Select-All, Copy, then REPLACE the
//  single PASTE_... line below with the whole file — INCLUDING its own
//  -----BEGIN...----- and -----END...----- lines. Don't add or remove anything
//  else. The R"EOF( ... )EOF" wrapper lets you paste multi-line text as-is.
// ---------------------------------------------------------------------------

// Amazon Root CA 1   <-  file: AmazonRootCA1.pem
static const char AWS_CERT_CA[] = R"EOF(
PASTE_ENTIRE_AmazonRootCA1.pem_HERE
)EOF";

// Device certificate <-  file: xxxxxxxxxx-certificate.pem.crt
static const char AWS_CERT_CRT[] = R"EOF(
PASTE_ENTIRE_certificate.pem.crt_HERE
)EOF";

// Device private key <-  file: xxxxxxxxxx-private.pem.key   (the SECRET half)
static const char AWS_CERT_PRIVATE[] = R"EOF(
PASTE_ENTIRE_private.pem.key_HERE
)EOF";
