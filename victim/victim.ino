// victim.ino — deterministic victim ECU
//
// Transmits two standard IDs (0x7A / 0x7F) alternately every 5 ms, so each ID
// appears once per 10 ms. On bus-off it enforces a *fixed* recovery model: it holds
// the first post-recovery transmission until FIXED_RESUME_US after the bus-off anchor,
// giving a constant, easily learnable recovery interval for the experiments.
//
// Two tasks:
//   alertTask (prio 6): blocks on twai_read_alerts(), reacts to bus-off/recovery.
//   canTask   (prio 5): periodic send + precise TX-hold release.

#include <ESP32-TWAI-CAN.hpp>
#include "driver/twai.h"
#include <esp_timer.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/semphr.h>

#define CAN_TX 4
#define CAN_RX 5
#define HEARTBEAT_PIN 8

#define ID1 0x7A  // attacked ID, payload 11 22 33
#define ID2 0x7F  // second ID,   payload 44 55 66

const int64_t SEND_INTERVAL_US = 5000;   // 5 ms between frames (=> 10 ms per ID)
const int64_t HEARTBEAT_US = 500000;     // 500 ms heartbeat half-period
const int64_t FIXED_RESUME_US = 100000;  // 100 ms hold after bus-off => fixed recovery model

// ---------- FreeRTOS handles ----------
// Periodic send scheduling is driven by an esp_timer.
// The timer callback only releases this semaphore; all CAN activity
// happens in canTask to avoid doing driver work in timer context.
SemaphoreHandle_t canTxSemaphore = NULL;
esp_timer_handle_t sendTimer = NULL;
esp_timer_handle_t heartbeatTimer = NULL;

// ---------- Shared state ----------
// Written by alertTask (prio 6), read by canTask (prio 5) and the heartbeat ISR.
// Single-byte bool writes are atomic on this core, so volatile is sufficient.
volatile bool canSendAllowed = true;
volatile bool txHoldAfterRecovery = false;  // armed by alertTask, cleared on TX release
volatile bool errorActiveState = true;      // drives the heartbeat blink
volatile bool heartbeatToggle = false;
volatile bool id1 = true;           // which ID to send next
volatile int64_t busOffAtUs = 0;    // timing anchor: when bus-off was detected
volatile int64_t resumeTxAtUs = 0;  // busOffAtUs + FIXED_RESUME_US

// ================================================================
//  Timer callbacks
// ================================================================

// Periodic tick: signal canTask to send the next frame.
static void onSendTimer(void *) {
  BaseType_t hpw = pdFALSE;
  xSemaphoreGiveFromISR(canTxSemaphore, &hpw);
  if (hpw) portYIELD_FROM_ISR();
}

// Heartbeat: blink while healthy, hold solid HIGH while error-passive/bus-off.
static void onHeartbeatTimer(void *) {
  if (errorActiveState) {
    heartbeatToggle = !heartbeatToggle;
    digitalWrite(HEARTBEAT_PIN, heartbeatToggle ? HIGH : LOW);
  } else {
    digitalWrite(HEARTBEAT_PIN, HIGH);
  }
}

// ================================================================
//  alertTask — owns the bus-off / recovery state machine
// ================================================================
static void alertTask(void *) {
  for (;;) {
    uint32_t alerts = 0;
    if (twai_read_alerts(&alerts, portMAX_DELAY) != ESP_OK) continue;

    // ---- Bus-off: capture the anchor immediately and start recovery ----
    if (alerts & TWAI_ALERT_BUS_OFF) {
      busOffAtUs = esp_timer_get_time();            // the timing anchor
      resumeTxAtUs = busOffAtUs + FIXED_RESUME_US;  // fixed release instant
      canSendAllowed = false;
      txHoldAfterRecovery = false;

      Serial.printf("[VICTIM] BUS-OFF at %lld us\r\n", busOffAtUs);

      if (twai_initiate_recovery() != ESP_OK) {
        Serial.println("[VICTIM] initiate_recovery FAILED");
      }
    }

    // ---- Hardware recovery complete (controller STOPPED): restart it now ----
    // Doing this here (not on the next canTask tick) avoids ~5 ms of extra latency.
    if (alerts & TWAI_ALERT_BUS_RECOVERED) {
      if (twai_start() == ESP_OK) {
        txHoldAfterRecovery = true;  // let canTask hold TX until resumeTxAtUs
        Serial.printf("[VICTIM] restarted at %lld us (+%lld us from BUS-OFF)\r\n",
                      esp_timer_get_time(),
                      esp_timer_get_time() - busOffAtUs);
      } else {
        Serial.println("[VICTIM] twai_start FAILED in alertTask");
      }
    }

    if (alerts & TWAI_ALERT_TX_FAILED) {
      Serial.println("[VICTIM] TX_FAILED");
    }
    // TWAI_ALERT_ERR_PASS needs no action here.
  }
}

// ================================================================
//  canTask — periodic send + precise TX-hold release
// ================================================================
static void canTask(void *) {
  for (;;) {
    if (xSemaphoreTake(canTxSemaphore, portMAX_DELAY) != pdTRUE) continue;

    twai_status_info_t status;
    if (twai_get_status_info(&status) != ESP_OK) continue;

    // Refresh the heartbeat flag (read by the heartbeat ISR).
    errorActiveState = (status.state == TWAI_STATE_RUNNING && status.tx_error_counter < 128 && status.rx_error_counter < 128);  // True only while the controller is in the CAN Error Active state.

    // TX hold: after recovery, spin-wait so the first frame goes out exactly at
    // resumeTxAtUs (= 100 ms after bus-off), giving the fixed recovery interval.
    if (status.state == TWAI_STATE_RUNNING && !canSendAllowed && txHoldAfterRecovery) {

      int64_t remUs = resumeTxAtUs - esp_timer_get_time();
      if (remUs > 200) {
        continue;  // far from release: yield, re-check next tick, do not busy wait
      }
      while (esp_timer_get_time() < resumeTxAtUs) {}  // final <=200 us precision spin

      canSendAllowed = true;
      txHoldAfterRecovery = false;
      id1 = true;  // first recovery frame is always 0x7A
      Serial.printf("[VICTIM] TX released, delta_from_busoff=%lld us\r\n",
                    esp_timer_get_time() - busOffAtUs);
    }

    // Normal periodic send (alternating ID1 / ID2).
    if (canSendAllowed) {
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
  }
}

// ================================================================
//  Setup
// ================================================================
void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.println("\n=== VICTIM NODE ===");

  pinMode(HEARTBEAT_PIN, OUTPUT);
  digitalWrite(HEARTBEAT_PIN, HIGH);

  // Hardware acceptance filter: accept the 0x000..0x0FF range Loose by design; signature matching is done in software.
  twai_filter_config_t fConfig;
  memset(&fConfig, 0, sizeof(fConfig));
  fConfig.acceptance_code = (0x000u << 21);
  fConfig.acceptance_mask = (~(0x700u << 21)) & 0xFFFFFFFFu;
  fConfig.single_filter = true;

  if (!ESP32Can.begin(ESP32Can.convertSpeed(500), CAN_TX, CAN_RX,
                      9, 1, &fConfig, nullptr, nullptr)) {
    Serial.println("[VICTIM] CAN FAILED");
    digitalWrite(HEARTBEAT_PIN, LOW);
    while (1) {}
  }
  Serial.println("[VICTIM] CAN started");

  twai_reconfigure_alerts(
    TWAI_ALERT_BUS_OFF | TWAI_ALERT_BUS_RECOVERED | TWAI_ALERT_ERR_PASS | TWAI_ALERT_TX_FAILED,
    nullptr);

  canTxSemaphore = xSemaphoreCreateBinary();
  configASSERT(canTxSemaphore);

  const esp_timer_create_args_t sendArgs = { .callback = onSendTimer, .name = "sendTimer" };  // Designated initializer for esp_timer_create_args_t
  esp_timer_create(&sendArgs, &sendTimer);

  const esp_timer_create_args_t hbArgs = { .callback = onHeartbeatTimer, .name = "heartbeatTimer" };
  esp_timer_create(&hbArgs, &heartbeatTimer);

  // alertTask must exist (and outrank canTask) before the timers start firing.
  xTaskCreate(alertTask, "CAN-ALERT", 2048, NULL, 6, NULL);
  xTaskCreate(canTask, "CAN-TX", 4096, NULL, 5, NULL);

  esp_timer_start_periodic(sendTimer, SEND_INTERVAL_US);
  esp_timer_start_periodic(heartbeatTimer, HEARTBEAT_US);
}

void loop() {
  vTaskDelay(portMAX_DELAY);  // Arduino loop is unused; the application is entirely task-driven.
}
