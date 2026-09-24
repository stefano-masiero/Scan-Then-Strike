// pc_logger.c — experiment-oriented CAN logger/controller for SFBO/PBO tests
//
// Build: gcc -O2 -Wall -Wextra -pthread -o pc_logger pc_logger.c
// Usage: ./pc_logger <iface> [wait_sec=3] [load_interval_us=200] [--trace]
//
// Roles (it orchestrates and observes; it does NOT run the attack — SocketCAN cannot do
// the bit-level collision timing SFBO needs, so the attack runs on the ESP32):
//   1) inject background load on LOAD_ID1..4 every load_interval_us;
//   2) after wait_sec, send the TRIGGER_ID frame that starts the attacker;
//   3) trace the bus, detect victim silence/recovery, decode the attacker's REPORT_ID
//      frames, and print a periodic suppression summary.
//
// REPORT frame layout (must match attacker sendReport exactly):
//   d[0..1] = gTotalAttempts      (uint16 LE)
//   d[2..3] = gLearnSuccesses     (uint16 LE)
//   d[4]    = state               (0x01=LEARN 0x02=PERSIST 0x03=DONE)
//   d[5..6] = gPersistBusOffs     (uint16 LE)
//   d[7]    = gRunCount           (uint8)

#include <errno.h>
#include <linux/can.h>
#include <linux/can/raw.h>
#include <net/if.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

// ------------------------------------------------------------------ IDs ----
#define TARGET_ID  0x07A
#define TRIGGER_ID 0x600
#define REPORT_ID  0x601
// Background-load IDs. Note: 0x54..0x57 are *higher* priority than the victim's 0x7A.
#define LOAD_ID1 0x54
#define LOAD_ID2 0x55
#define LOAD_ID3 0x56
#define LOAD_ID4 0x57

// ----------------------------------------------------------- Timing knobs --
#define DEFAULT_WAIT_SEC    3
#define DEFAULT_LOAD_IV_US  200       // 200 us load interval => ~79% bus-load contribution
#define GAP_ALERT_US        50000ULL  // victim gap above this => "silence"/bus-off event
#define PRESENT_WINDOW_US   100000ULL // victim counted PRESENT if seen within this window
#define SUMMARY_PERIOD_SEC  2

// ---- Persist-phase inference (firmware sends no reports during PERSIST) -----
// LEARN_PHASES_EXPECTED MUST match the firmware's LEARN_PHASES. The last LEARN report
// shows learn_ok = LEARN_PHASES-1 (emitted before the success increment that transitions).
#define LEARN_PHASES_EXPECTED   30
#define REPORT_SILENCE_INFER_US 3000000ULL  // 3 s without a report => infer PERSIST entry

// ---- Intra-run suppression --------------------------------------------------
// Between persist runs the firmware idles (~500 ms + bus-off re-acquisition), which would
// otherwise drag the suppression metric down. A "run" is a chain of silence events spaced
// closer than this threshold; a larger gap closes the run and excludes its dead time.
// Inside a run silence events cycle every ~150 ms; between runs the gap is >= ~700 ms.
#define RUN_GAP_THRESHOLD_US 650000ULL

// ------------------------------------------------------- ESP state enum ----
typedef enum {
  ESP_IDLE      = 0,
  ESP_ATTACKING = 1,  // learning phase
  ESP_PERSIST   = 2,
  ESP_DONE      = 3
} esp_state_t;

// --------------------------------------------------------- Thread args -----
typedef struct { int s; uint32_t interval_us; } tx_arg_t;
typedef struct { int s; int wait_sec; }         trig_arg_t;

// -------------------------------------------------------- Global state -----
typedef struct {
  pthread_mutex_t lock;

  // ---- control ----
  bool trace;
  bool attack_started;

  // ---- victim tracking ----
  bool     victim_seen_once;
  bool     victim_present;
  bool     victim_missing_latched;   // currently inside a silence window
  uint64_t victim_first_seen_us;
  uint64_t victim_last_seen_us;
  uint64_t victim_prev_seen_us;
  uint64_t victim_period_sum_us;
  uint64_t victim_period_min_us;
  uint64_t victim_period_max_us;
  uint32_t victim_period_samples;
  uint32_t victim_count_total;
  uint32_t victim_count_attack;       // victim frames seen since attack_started

  // ---- gap / silence ----
  uint64_t attack_start_us;
  uint64_t trigger_sent_us;
  uint64_t first_silence_us;
  uint64_t longest_gap_us;
  uint32_t victim_gaps_over_50ms;
  uint32_t silence_windows;

  // ---- recovery ----
  uint64_t recovery_sum_us;
  uint32_t recovery_count;
  uint32_t expected_victim_attack;    // est. frames expected since attack start (context only)

  // ---- attacker report fields ----
  esp_state_t esp_state;
  uint16_t esp_attempts;    // gTotalAttempts
  uint16_t esp_learn_ok;    // gSuccessfulBusOffsLearn
  uint16_t esp_pers_boffs;  // gPersistBusOffs (current run)
  uint8_t  esp_run_count;   // gRunCount

  // ---- report tracking (for inference) ----
  uint64_t last_report_us;
  uint32_t victim_count_at_last_report;

  // ---- PERSIST-phase tracking ----
  bool     persist_started;
  bool     persist_inferred;          // set when persist entry came from inference, not a report
  uint64_t persist_start_us;
  uint32_t victim_count_at_persist_start;

  // ---- Intra-run accounting (only the time inside active runs is counted) ----
  uint64_t intra_run_total_us;        // accumulated duration of closed runs
  uint32_t intra_run_total_victim;    // victim frames seen during closed runs
  uint32_t run_count;                 // number of closed runs observed
  bool     current_run_active;
  uint64_t current_run_start_us;
  uint32_t current_run_start_victim;
  uint64_t current_run_last_event_us;
  uint32_t current_run_last_victim;
} app_state_t;

static volatile sig_atomic_t running = 1;

static app_state_t g = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .victim_period_min_us = UINT64_MAX,
};

// =========================================================== Utilities =====

static uint64_t now_us(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)(ts.tv_nsec / 1000);
}

static void wall_ts(char *buf, size_t sz) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  struct tm tm;
  localtime_r(&ts.tv_sec, &tm);
  snprintf(buf, sz, "%04d-%02d-%02d %02d:%02d:%02d.%06ld", tm.tm_year + 1900,
           tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
           ts.tv_nsec / 1000);
}

static const char *esp_state_name(esp_state_t st) {
  switch (st) {
  case ESP_ATTACKING: return "LEARNING";
  case ESP_PERSIST:   return "PERSIST";
  case ESP_DONE:      return "DONE";
  default:            return "IDLE";
  }
}

// =========================================================== CAN socket ====

static int open_socket(const char *iface) {
  int s = socket(PF_CAN, SOCK_RAW, CAN_RAW);
  if (s < 0) { perror("socket"); return -1; }

  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
  if (ioctl(s, SIOCGIFINDEX, &ifr) < 0) { perror("ioctl"); close(s); return -1; }

  struct sockaddr_can addr;
  memset(&addr, 0, sizeof(addr));
  addr.can_family = AF_CAN;
  addr.can_ifindex = ifr.ifr_ifindex;
  if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) { perror("bind"); close(s); return -1; }
  return s;
}

static void on_sig(int sig) { (void)sig; running = 0; }

// ====================================================== Frame handlers ======

// Decode an attacker REPORT_ID frame and update mirrored state.
static void handle_report(const struct can_frame *f) {
  if (f->can_dlc != 8) return;

  uint16_t att      = (uint16_t)(f->data[0] | (f->data[1] << 8));
  uint16_t learn_ok = (uint16_t)(f->data[2] | (f->data[3] << 8));
  esp_state_t st    = (esp_state_t)f->data[4];
  uint16_t pers     = (uint16_t)(f->data[5] | (f->data[6] << 8));
  uint8_t  run_ct   = f->data[7];

  pthread_mutex_lock(&g.lock);

  bool state_changed = (g.esp_state != st);
  bool data_changed  = (g.esp_attempts != att) || (g.esp_learn_ok != learn_ok) ||
                       (g.esp_pers_boffs != pers) || (g.esp_run_count != run_ct);

  // Detect PERSIST entry. The firmware sends only ONE 0x02 report at persist start and
  // then tears the controller down, so that frame is easily lost. Treat any of these as
  // proof we are in persist (all are zero during learning): state byte PERSIST/DONE,
  // a nonzero persist bus-off counter, or a nonzero run counter.
  bool persist_signal = (st == ESP_PERSIST) || (st == ESP_DONE) || (pers > 0) || (run_ct > 0);
  if (persist_signal && !g.persist_started) {
    g.persist_started = true;
    g.persist_inferred = false;
    g.persist_start_us = now_us();
    g.victim_count_at_persist_start = g.victim_count_attack;
    printf("[PHASE] >>> PERSIST started (report) — run %u, blind_boffs=%u <<<\n", run_ct, pers);
    fflush(stdout);
  }

  g.esp_state = st;
  g.esp_attempts = att;
  g.esp_learn_ok = learn_ok;
  g.esp_pers_boffs = pers;
  g.esp_run_count = run_ct;
  g.last_report_us = now_us();
  g.victim_count_at_last_report = g.victim_count_attack;

  pthread_mutex_unlock(&g.lock);

  if (state_changed || data_changed) {
    if (st == ESP_ATTACKING) {
      printf("[ESP]  %-8s | total_att=%u  learn_ok=%u\n", esp_state_name(st), att, learn_ok);
    } else if (st == ESP_PERSIST) {
      printf("[ESP]  %-8s | run=%u  blind_boffs=%u\n", esp_state_name(st), run_ct, pers);
    } else {
      printf("[ESP]  %-8s | total_att=%u  learn_ok=%u  run=%u\n",
             esp_state_name(st), att, learn_ok, run_ct);
    }
    fflush(stdout);
  }
}

// Record a victim frame: update period stats, and if we were in a silence window,
// close it and log the recovery interval.
static void handle_victim(uint64_t ts) {
  pthread_mutex_lock(&g.lock);

  if (g.victim_seen_once) {
    uint64_t delta = ts - g.victim_last_seen_us;
    g.victim_period_sum_us += delta;
    g.victim_period_samples++;
    if (delta < g.victim_period_min_us) g.victim_period_min_us = delta;
    if (delta > g.victim_period_max_us) g.victim_period_max_us = delta;
    if (g.attack_started && delta > GAP_ALERT_US) {
      g.victim_gaps_over_50ms++;
      if (delta > g.longest_gap_us) g.longest_gap_us = delta;
    }
  } else {
    g.victim_first_seen_us = ts;
  }

  bool had_missing = g.victim_missing_latched;
  uint64_t recovery_gap = 0;
  if (had_missing) {  // frame reappeared after a silence window => recovery
    recovery_gap = ts - g.victim_last_seen_us;
    g.recovery_count++;
    g.recovery_sum_us += recovery_gap;
    g.victim_missing_latched = false;
  }

  g.victim_prev_seen_us = g.victim_last_seen_us;
  g.victim_last_seen_us = ts;
  g.victim_seen_once = true;
  g.victim_present = true;
  g.victim_count_total++;
  if (g.attack_started) g.victim_count_attack++;

  pthread_mutex_unlock(&g.lock);

  if (had_missing) {
    printf("[RECOVERY] 0x%03X reappeared after %.3f ms\n", TARGET_ID, recovery_gap / 1000.0);
    fflush(stdout);
  }
}

// Close the in-flight run, folding its duration and victim count into the totals.
// Caller must hold g.lock.
static void close_current_run_locked(void) {
  if (!g.current_run_active) return;
  g.intra_run_total_us     += g.current_run_last_event_us - g.current_run_start_us;
  g.intra_run_total_victim += g.current_run_last_victim   - g.current_run_start_victim;
  g.run_count++;
  g.current_run_active = false;
}

// Called on every received frame: if the victim has been absent longer than GAP_ALERT_US,
// latch a silence window and (during persist) update intra-run bookkeeping.
static void maybe_mark_missing(uint64_t ts) {
  pthread_mutex_lock(&g.lock);
  if (g.attack_started && g.victim_seen_once && !g.victim_missing_latched) {
    uint64_t since = ts - g.victim_last_seen_us;
    if (since > GAP_ALERT_US) {
      g.victim_missing_latched = true;
      g.silence_windows++;
      if (g.first_silence_us == 0) g.first_silence_us = ts;
      if (since > g.longest_gap_us) g.longest_gap_us = since;

      // Intra-run intervals are only meaningful once we believe we're in persist.
      if (g.persist_started) {
        // Close a stale run before opening a new one, excluding inter-run dead time.
        if (g.current_run_active &&
            (ts - g.current_run_last_event_us) > RUN_GAP_THRESHOLD_US) {
          close_current_run_locked();
        }
        if (!g.current_run_active) {
          g.current_run_active = true;
          g.current_run_start_us = ts;
          g.current_run_start_victim = g.victim_count_attack;
        }
        g.current_run_last_event_us = ts;
        g.current_run_last_victim = g.victim_count_attack;
      }

      pthread_mutex_unlock(&g.lock);
      printf("[EVENT] 0x%03X missing %.3f ms — bus-off/silence\n", TARGET_ID, since / 1000.0);
      fflush(stdout);
      return;
    }
  }
  pthread_mutex_unlock(&g.lock);
}

// ============================================================= RX thread ===

static void *rx_thread(void *arg) {
  int s = *(int *)arg;
  struct can_frame f;

  while (running) {
    ssize_t n = read(s, &f, sizeof(f));
    if (n < 0) {
      if (errno == EINTR) continue;
      perror("read");
      break;
    }
    if (n != (ssize_t)sizeof(f)) continue;

    uint64_t ts = now_us();
    canid_t id = f.can_id & CAN_SFF_MASK;

    maybe_mark_missing(ts);

    if (g.trace) {
      char ts_str[64];
      wall_ts(ts_str, sizeof(ts_str));
      printf("(%s) %03X [%d]", ts_str, id, f.can_dlc);
      for (int i = 0; i < f.can_dlc; i++) printf(" %02X", f.data[i]);
      printf("\n");
    }

    if (id == TARGET_ID)      handle_victim(ts);
    else if (id == REPORT_ID) handle_report(&f);
  }
  return NULL;
}

// ============================================================= TX thread ===

// Round-robin the four load frames at the configured interval.
static void *tx_load_thread(void *arg) {
  tx_arg_t *a = (tx_arg_t *)arg;
  int s = a->s;
  uint32_t iv = a->interval_us;

  struct can_frame frames[4] = {
      {.can_id = LOAD_ID1, .can_dlc = 3, .data = {0x10, 0x11, 0x12}},
      {.can_id = LOAD_ID2, .can_dlc = 3, .data = {0x20, 0x21, 0x22}},
      {.can_id = LOAD_ID3, .can_dlc = 3, .data = {0x30, 0x31, 0x32}},
      {.can_id = LOAD_ID4, .can_dlc = 3, .data = {0x40, 0x41, 0x42}},
  };

  int idx = 0;
  while (running) {
    if (write(s, &frames[idx], sizeof(struct can_frame)) < 0 && errno != EINTR)
      perror("write(load)");
    idx = (idx + 1) & 3;
    struct timespec req = {.tv_sec = iv / 1000000, .tv_nsec = (long)(iv % 1000000) * 1000L};
    nanosleep(&req, NULL);
  }
  return NULL;
}

// ========================================================= Trigger thread ==

// After wait_sec, send the trigger frame that starts the attacker.
static void *trigger_thread(void *arg) {
  trig_arg_t *a = (trig_arg_t *)arg;

  printf("[PHASE] pre-attack — waiting %d s before trigger\n", a->wait_sec);
  fflush(stdout);
  sleep(a->wait_sec);

  struct can_frame trig = {.can_id = TRIGGER_ID, .can_dlc = 1, .data = {0xA5}};
  if (write(a->s, &trig, sizeof(trig)) < 0) perror("write(trigger)");

  pthread_mutex_lock(&g.lock);
  g.attack_started = true;
  g.trigger_sent_us = now_us();
  g.attack_start_us = g.trigger_sent_us;
  pthread_mutex_unlock(&g.lock);

  printf("[PHASE] trigger sent (0x%03X) — attack started\n", TRIGGER_ID);
  fflush(stdout);
  return NULL;
}

// ======================================================== Summary / print ==

static void print_summary(void) {
  pthread_mutex_lock(&g.lock);

  uint64_t now = now_us();

  // ---- PERSIST inference (fallback if the single 0x02 report was lost) ----
  // Infer persist when: attack running, last state still LEARNING at the transition
  // threshold (learn_ok = LEARN_PHASES-1), no report for REPORT_SILENCE_INFER_US, and
  // bus-off activity is still happening.
  if (!g.persist_started && g.attack_started && g.esp_state == ESP_ATTACKING &&
      g.esp_learn_ok >= (uint16_t)(LEARN_PHASES_EXPECTED - 1) &&
      g.last_report_us > 0 &&
      (now - g.last_report_us) > REPORT_SILENCE_INFER_US &&
      g.silence_windows > 0) {
    g.persist_started = true;
    g.persist_inferred = true;
    g.persist_start_us = g.last_report_us;  // best estimate: just after the last LEARN report
    g.victim_count_at_persist_start = g.victim_count_at_last_report;
    uint64_t silence = now - g.last_report_us;
    pthread_mutex_unlock(&g.lock);
    printf("[PHASE] >>> PERSIST inferred (no report for %.2fs after learn_ok=%u/%d) <<<\n",
           silence / 1e6, LEARN_PHASES_EXPECTED - 1, LEARN_PHASES_EXPECTED);
    fflush(stdout);
    pthread_mutex_lock(&g.lock);
  }

  bool attack_on  = g.attack_started;
  bool persist_on = g.persist_started;
  bool persist_inf = g.persist_inferred;
  uint64_t attack_age  = attack_on  ? (now - g.attack_start_us)  : 0;
  uint64_t persist_age = persist_on ? (now - g.persist_start_us) : 0;

  uint32_t victim_total  = g.victim_count_total;
  uint32_t victim_attack = g.victim_count_attack;
  uint32_t gaps          = g.victim_gaps_over_50ms;
  uint32_t silence_wins  = g.silence_windows;
  uint32_t recoveries    = g.recovery_count;
  uint64_t longest_gap   = g.longest_gap_us;

  uint64_t avg_period = g.victim_period_samples
                            ? (g.victim_period_sum_us / g.victim_period_samples) : 0;
  uint64_t min_period = (g.victim_period_min_us == UINT64_MAX) ? 0 : g.victim_period_min_us;
  uint64_t max_period = g.victim_period_max_us;
  uint64_t avg_recovery = g.recovery_count ? (g.recovery_sum_us / g.recovery_count) : 0;

  bool present = g.victim_seen_once && ((now - g.victim_last_seen_us) < PRESENT_WINDOW_US);

  // ---- Intra-run suppression ----
  // Sum only the time inside detected runs: close a stale run, then add the still-active
  // portion so the metric updates smoothly while a run is in progress.
  if (g.current_run_active &&
      (now - g.current_run_last_event_us) > RUN_GAP_THRESHOLD_US) {
    close_current_run_locked();
  }
  uint64_t intra_time   = g.intra_run_total_us;
  uint32_t intra_victim = g.intra_run_total_victim;
  uint32_t runs_closed  = g.run_count;
  bool run_in_flight    = g.current_run_active;
  if (run_in_flight) {
    intra_time   += now - g.current_run_start_us;
    intra_victim += g.victim_count_attack - g.current_run_start_victim;
  }

  // suppression = 1 - (victim frames seen)/(frames expected at the nominal period).
  double suppression = 0.0;
  if (intra_time > 0 && avg_period > 0) {
    uint32_t expected = (uint32_t)(intra_time / avg_period);
    if (expected > 0) {
      suppression = 100.0 * (1.0 - ((double)intra_victim / (double)expected));
      if (suppression < 0.0) suppression = 0.0;
    }
  }

  if (attack_on && avg_period > 0) {
    g.expected_victim_attack = (uint32_t)(attack_age / avg_period);  // context only
  }

  esp_state_t st = g.esp_state;
  uint16_t att   = g.esp_attempts;
  uint16_t lok   = g.esp_learn_ok;
  uint16_t pb    = g.esp_pers_boffs;
  uint8_t  run_ct = g.esp_run_count;

  pthread_mutex_unlock(&g.lock);

  // Show PERSIST once the ESP has clearly advanced past learning, even if persist_started
  // was never armed (lost 0x02 report).
  bool show_persist = persist_on || (st == ESP_PERSIST) || (st == ESP_DONE);

  if (!attack_on) {
    printf("[STATUS] pre-attack | victim_rx=%u | period≈%.3f ms | load running\n",
           victim_total, avg_period / 1000.0);

  } else if (!show_persist) {
    printf("[STATUS] LEARNING t+%.2fs | victim_rx=%u | learn_ok=%u | total_att=%u | "
           "period(avg/min/max)=%.3f/%.3f/%.3f ms | esp=%s\n",
           attack_age / 1e6, victim_attack, lok, att, avg_period / 1000.0,
           min_period / 1000.0, max_period / 1000.0, esp_state_name(st));

  } else {
    printf("[STATUS] PERSIST%s t+%.2fs (pers_t+%.2fs) | "
           "suppression=%.1f%% over %.2fs active (%u runs%s) | victim=%s | "
           "run=%u/30 blind_boffs=%u | gaps>50ms=%u silence=%u recov=%u | "
           "longest_gap=%.3f ms avg_recov=%.3f ms | period=%.3f ms\n",
           persist_inf ? "(inf)" : "", attack_age / 1e6, persist_age / 1e6,
           suppression, intra_time / 1e6, runs_closed,
           run_in_flight ? "+1 active" : "", present ? "PRESENT" : "MISSING",
           run_ct, pb, gaps, silence_wins, recoveries, longest_gap / 1000.0,
           avg_recovery / 1000.0, avg_period / 1000.0);
  }
  fflush(stdout);
}

// ================================================================== main ===

static void usage(const char *prog) {
  fprintf(stderr,
          "Usage: %s <iface> [wait_sec=%d] [load_interval_us=%d] [--trace]\n"
          "  --trace      print every CAN frame\n",
          prog, DEFAULT_WAIT_SEC, DEFAULT_LOAD_IV_US);
}

int main(int argc, char **argv) {
  if (argc < 2) { usage(argv[0]); return 1; }

  const char *iface = argv[1];
  int wait_sec = DEFAULT_WAIT_SEC;
  uint32_t load_iv = DEFAULT_LOAD_IV_US;
  bool trace = false;

  // Optional positional args (wait_sec, load_interval_us) then flags.
  int pos = 2;
  if (pos < argc && argv[pos][0] != '-') wait_sec = atoi(argv[pos++]);
  if (pos < argc && argv[pos][0] != '-') load_iv = (uint32_t)atoi(argv[pos++]);
  while (pos < argc) {
    if (strcmp(argv[pos], "--trace") == 0) { trace = true; pos++; }
    else { usage(argv[0]); return 1; }
  }

  g.trace = trace;

  printf("[PC] iface=%s | trigger_delay=%ds | load_iv=%uµs | trace=%s\n",
         iface, wait_sec, load_iv, trace ? "on" : "off");
  fflush(stdout);

  signal(SIGINT, on_sig);
  signal(SIGTERM, on_sig);

  // Separate sockets: one RX, one for load TX, one for the trigger.
  int s_rx = open_socket(iface);
  int s_tx1 = open_socket(iface);
  int s_tx2 = open_socket(iface);
  if (s_rx < 0 || s_tx1 < 0 || s_tx2 < 0) return 1;

  int off = 0;  // don't receive our own TX frames on the RX socket
  setsockopt(s_rx, SOL_CAN_RAW, CAN_RAW_RECV_OWN_MSGS, &off, sizeof(off));

  pthread_t rx_tid, tx_tid, trig_tid;
  pthread_create(&rx_tid, NULL, rx_thread, &s_rx);

  tx_arg_t tx_arg = {.s = s_tx1, .interval_us = load_iv};
  pthread_create(&tx_tid, NULL, tx_load_thread, &tx_arg);

  trig_arg_t trig_arg = {.s = s_tx2, .wait_sec = wait_sec};
  pthread_create(&trig_tid, NULL, trigger_thread, &trig_arg);

  while (running) {
    sleep(SUMMARY_PERIOD_SEC);
    print_summary();
  }

  pthread_join(rx_tid, NULL);
  pthread_join(tx_tid, NULL);
  pthread_join(trig_tid, NULL);

  print_summary();

  close(s_rx);
  close(s_tx1);
  close(s_tx2);
  return 0;
}
