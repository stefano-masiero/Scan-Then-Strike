// generator.ino — background-traffic node
//
// Floods the bus with low-priority frames (IDs 0x110 / 0x111, both numerically larger
// than the victim's 0x7A) to raise the bus load and create realistic arbitration jitter.
// Because these IDs are lower priority than the victim, this node never defers the
// victim's transmissions. It only transmits; it does not act on received frames.

#include <ESP32-TWAI-CAN.hpp>
#include "driver/twai.h"

#define CAN_TX 4
#define CAN_RX 5
#define HEARTBEAT_PIN 8

#define ID1 0x110
#define ID2 0x111

const uint32_t SEND_INTERVAL_US = 350;  // gap between background frames
const uint32_t HEARTBEAT_US = 500000;   // 500 ms heartbeat half-period

uint32_t lastSendTs = 0;
uint32_t lastHeartbeatTs = 0;
bool heartbeatState = false;
bool id1 = true;  // which ID to send next

void setup() {
  // Accept-nothing filter. This node only transmits, so the RX filter is irrelevant;
  // mask = all-ones means every ID bit is don't-care.
  twai_filter_config_t fConfig;
  memset(&fConfig, 0, sizeof(fConfig));
  fConfig.acceptance_code = (0x000u << 21);
  fConfig.acceptance_mask = (~(0x000u << 21)) & 0x00000000u;

  fConfig.single_filter = true;
  pinMode(HEARTBEAT_PIN, OUTPUT);

  if (!ESP32Can.begin(ESP32Can.convertSpeed(500), CAN_TX, CAN_RX, 9, 1, &fConfig, nullptr, nullptr)) {
    digitalWrite(HEARTBEAT_PIN, LOW);
    while (1) {}  // halt: CAN init failed
  }
}

// Send one background frame, alternating between ID1 and ID2.
void sendPeriodicFrame() {
  CanFrame tx = { 0 };
  tx.identifier = id1 ? ID1 : ID2;
  tx.extd = 0;
  tx.data_length_code = 3;
  tx.data[0] = id1 ? 0x11 : 0x44;
  tx.data[1] = id1 ? 0x22 : 0x55;
  tx.data[2] = id1 ? 0x33 : 0x66;
  ESP32Can.writeFrame(tx);
  id1 = !id1;
}

void loop() {
  uint32_t now = micros();

  // Periodic background traffic.
  if (now - lastSendTs >= SEND_INTERVAL_US) {
    lastSendTs = now;
    sendPeriodicFrame();
  }

  // Heartbeat: blink while healthy, hold solid HIGH while error-passive or bus-off.
  twai_status_info_t s;
  bool allowedHeartbeat = true;
  if (twai_get_status_info(&s) == ESP_OK) {
    bool errorPassive = (s.tx_error_counter >= 128) || (s.rx_error_counter >= 128);
    bool busOff = (s.state == TWAI_STATE_BUS_OFF);
    if (errorPassive || busOff) allowedHeartbeat = false;
  }

  if (allowedHeartbeat) {
    if (now - lastHeartbeatTs >= HEARTBEAT_US) {
      lastHeartbeatTs = now;
 
    }
  } else {
    digitalWrite(HEARTBEAT_PIN, HIGH);
  }
}
