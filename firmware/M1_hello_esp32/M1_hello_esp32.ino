/*
 * ============================================================================
 *  M1_hello_esp32.ino  —  Milestone 1: "Does my ESP32 actually work?"
 * ----------------------------------------------------------------------------
 *  This tiny sketch proves three things BEFORE we build anything real:
 *    1. Your PC can flash the ESP32 over USB      (the Upload succeeds)
 *    2. The board runs our code                   (the onboard LED blinks)
 *    3. The board can talk back to your PC         (text in Serial Monitor)
 *
 *  It does NOT use WiFi or AWS yet — it's the "hello world" of embedded.
 *
 *  HOW TO RUN (full detail in docs/SETUP.md, section M1):
 *    - Arduino IDE:  Tools > Board = "ESP32 Dev Module"
 *    -               Tools > Port  = your board's COM port
 *    - Click Upload (the → arrow). If it sticks on "Connecting....",
 *      hold the BOOT button on the board until it starts "Writing...".
 *    - Open Tools > Serial Monitor and set baud (bottom-right) to 115200.
 * ============================================================================
 */

// On most ESP32-WROOM-32 dev boards the little blue onboard LED is wired to
// GPIO 2. If your board has no user LED (or it's on a different pin), the LED
// just won't blink — the Serial messages below still prove everything works.
#define LED_PIN 2

// A simple counter so every Serial line is different — that way you can SEE
// it's live and updating, not a frozen screen.
unsigned long heartbeat = 0;

// setup() runs ONCE, right after the board powers on or is reset.
void setup() {
  // Open the USB serial link at 115200 bits per second. IMPORTANT: the Serial
  // Monitor must be set to this same 115200, or you'll see garbled symbols.
  Serial.begin(115200);
  delay(1000);  // give the USB serial link a moment to wake up

  // Tell the chip that LED_PIN is an OUTPUT (something we drive high/low).
  pinMode(LED_PIN, OUTPUT);

  Serial.println();
  Serial.println("========================================");
  Serial.println("  WIDS - Milestone 1: hello from ESP32");
  Serial.println("========================================");

  // These values are read straight off the chip. Seeing real numbers here
  // confirms it's a genuine ESP32 and that the code compiled + flashed OK.
  Serial.print("Chip model       : "); Serial.println(ESP.getChipModel());
  Serial.print("CPU cores        : "); Serial.println(ESP.getChipCores());
  Serial.print("CPU freq (MHz)   : "); Serial.println(ESP.getCpuFreqMHz());
  Serial.print("Free heap (bytes): "); Serial.println(ESP.getFreeHeap());
  Serial.println("If you can read this, the USB link works. Now watch the LED.");
  Serial.println();
}

// loop() runs over and over, forever, after setup() finishes.
void loop() {
  // Blink: LED on for half a second, off for half a second = 1 blink/second.
  digitalWrite(LED_PIN, HIGH);
  delay(500);
  digitalWrite(LED_PIN, LOW);
  delay(500);

  // Print a heartbeat line every second so you can watch it live.
  heartbeat++;
  Serial.print("heartbeat #");
  Serial.print(heartbeat);
  Serial.print("   |   uptime ");
  Serial.print(millis() / 1000);   // millis() = ms since boot; /1000 = seconds
  Serial.println("s");
}
