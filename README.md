# Scan-Then-Strike on ESP32-C3 — SFBO / Persistent Bus-Off testbed

A physical reproduction of the timing-critical core of the **Scan-Then-Strike (STS)**
CAN attack from Serag et al., *"Exposing New Vulnerabilities of Error Handling
Mechanism in CAN"* (USENIX Security 2021). It implements the **Single Frame Bus-Off
(SFBO)** primitive and its escalation into a **Persistent Bus-Off (PBO)** denial of
service on a small three-node CAN bus.

Course project — *Cyber-Physical Systems and IoT Security*, University of Padua.

> **Scope / disclaimer.** This is an academic reproduction intended to run on your own
> isolated bench testbed. Do not connect it to a real vehicle or any bus you do not own.
> It deliberately reproduces only Stages 3–4 of STS (timing-critical core); it does **not**
> perform the network-mapping / victim-identification stages.

---

## What it does

Three ESP32-C3 SuperMini nodes share one 500 kbps CAN bus, plus a Linux PC on a
USB-to-CAN (uCAN) adapter as orchestrator/logger:

- **victim** — transmits IDs `0x7A` / `0x7F` every 5 ms (each ID every 10 ms) and
  enforces a deterministic *fixed* 100 ms recovery interval after bus-off.
- **attacker** — runs the state machine `IDLE → MEASURE → LEARN → PERSIST → DONE`:
  measures the victim's period, forces single bus-offs (SFBO), learns the recovery
  interval, then tries to keep the victim suppressed (PBO).
- **generator** — background traffic on `0x110` / `0x111` (lower priority than the
  victim) to raise bus load and add realistic jitter.
- **pc_logger** (binary name `attack`) — injects extra load, sends the start trigger,
  and traces the bus to report victim silence/recovery and a live suppression metric.

---

## Repository layout

```
.
├── attacker/
│   ├── attacker.ino
│   └── sketch.yaml
├── victim/
│   ├── victim.ino
│   └── sketch.yaml
├── generator/
│   ├── generator.ino
│   └── sketch.yaml
├── pc_logger.c
├── Makefile          # builds ./attack
└── README.md
```

Each ESP folder is a self-contained Arduino sketch with its own `sketch.yaml`, so it can
be compiled/flashed/monitored independently and on either supported board.

---

## CAN ID map

| ID            | Sender    | Meaning                                   |
|---------------|-----------|-------------------------------------------|
| `0x7A`        | victim    | attacked frame, payload `11 22 33`        |
| `0x7F`        | victim    | second victim frame, payload `44 55 66`   |
| `0x110/0x111` | generator | background load (lower priority than `0x7A`) |
| `0x54–0x57`   | pc_logger | PC background load (higher priority than `0x7A`) |
| `0x001`       | attacker  | preceded / synchronization frame          |
| `0x07A`       | attacker  | forged collision frame, payload `00 00 00`|
| `0x777`       | attacker  | clutter (passive-error regeneration)      |
| `0x600`       | pc_logger | trigger: start the attack                 |
| `0x601`       | attacker  | progress report (8 bytes) to the logger   |

---

## Hardware requirements

- 3 × ESP32-C3 SuperMini (or other ESP32 with the `wroom` profile).
- 3 × CAN transceiver (e.g. SN65HVD230 / TJA1050), one per ESP.
- 1 × USB-to-CAN (uCAN) adapter exposed as a SocketCAN interface (`can0`).
- Breadboard + twisted CANH/CANL pair, **120 Ω termination at both ends** of the bus.

### Wiring (per ESP node)

| Signal      | ESP32-C3 pin |
|-------------|--------------|
| CAN TX      | GPIO 4       |
| CAN RX      | GPIO 5       |
| Heartbeat   | GPIO 8       |

Each ESP's TX/RX go to its transceiver; all transceiver CANH/CANL join the shared bus.
The uCAN adapter sits on the same CANH/CANL pair. Bus speed is 500 kbps on every node.

---

## Software requirements

**ESP nodes**
- [`arduino-cli`](https://arduino.github.io/arduino-cli/)
- ESP32 core: `arduino-cli core install esp32:esp32`
- Library **ESP32-TWAI-CAN 1.0.1**: `arduino-cli lib install "ESP32-TWAI-CAN@1.0.1"`
  (also pinned in each `sketch.yaml`)

**Linux logger**
- `gcc`, `make`
- `can-utils` (for `candump`): `sudo apt install can-utils`
- Root (or `CAP_NET_RAW`) to set the can interface up.

---

## Build & flash the ESP nodes

Each `sketch.yaml` defines two profiles; `c3mini` is the default:

```yaml
profiles:
  c3mini:
    fqbn: esp32:esp32:esp32c3:CDCOnBoot=cdc
    port: /dev/ttyACM0
    ...
  wroom:
    fqbn: esp32:esp32:esp32
    port: /dev/ttyUSB0
    ...
default_profile: c3mini
```

From inside each node folder (`attacker/`, `victim/`, `generator/`):

```bash
# Compile (uses default_profile = c3mini)
arduino-cli compile --build-path ./build

# Upload to the board on the profile's port
arduino-cli upload --build-path ./build

# Serial monitor at 115200 baud
arduino-cli monitor -c 115200
```

For a classic ESP32 (WROOM) board, add the profile and use its port:

```bash
arduino-cli compile --profile wroom --build-path ./build
arduino-cli upload  --profile wroom --build-path ./build -p /dev/ttyUSB0
```

> Adjust `/dev/ttyACM0` / `/dev/ttyUSB0` to match your boards. When several ESPs are
> plugged in at once they enumerate as `ttyACM0`, `ttyACM1`, … — pass the right `-p`.

### Selecting the persistence mode (attacker)

The attacker compiles one persistence strategy at a time, chosen by a flag in
`attacker.ino`:

```c
#define USE_FIXED_ATTACK true   // true  = prediction / open-loop  (fixed-recovery victim)
                                // false = trailing  / closed-loop (random-recovery victim)
```

Set the flag, recompile, and re-upload the attacker to switch between the two modes.

---

## Build & run the logger

Bring up the CAN interface at 500 kbps first.

```bash
# Native SocketCAN adapter (gs_usb / candleLight, etc.)
sudo ip link set can0 up type can bitrate 500000
sudo ip link set can0 txqueuelen 1000       # This is not required but suggested,
                                            # in order to give interface more queue space
                                            # for incoming messages to support higher loads 

# --- OR, for a serial slcan adapter (USBtin / CANtact) ---
# sudo slcand -o -c -s6 /dev/ttyACM0 can0   # s6 = 500 kbps
# sudo ip link set up can0
```

Build and run:

```bash
# in the project root folder
make                 # produces ./attack
./attack can0 2 500
```

Arguments: `./attack <iface> [wait_sec] [load_interval_us]`
- `can0` — CAN interface.
- `2` — seconds to wait before sending the `0x600` trigger.
- `500` — background-load interval in µs (≈79 % bus-load contribution).

Useful extras:
```bash
./attack can0 2 500 --trace        # print every frame
candump can0,07A:7FF -t A -e       # raw view of every message with ID 07A and absolute timestamp
make clean                         # remove ./attack and build/
```

---

## Run procedure

1. Bring up `can0` (above).
2. Flash all three ESPs (`victim`, `generator`, `attacker`) and power them on the bus.
3. Start the logger: `./attack can0 2 500`.
   - It generates load immediately, then after `wait_sec` sends `0x600`.
4. On the trigger, the attacker runs `MEASURE → LEARN → PERSIST → DONE`.
   Watch its serial monitor and the logger's `[STATUS]` lines in parallel.

The logger prints a live summary, e.g.:

```
[STATUS] LEARNING t+4.20s | victim_rx=412 | learn_ok=15 | total_att=18 | period(avg/min/max)=10.00/9.99/10.01 ms | esp=LEARNING
[EVENT] 0x07A missing 101.0 ms — bus-off/silence
[RECOVERY] 0x07A reappeared after 101.0 ms
[STATUS] PERSIST t+21.4s (pers_t+3.1s) | suppression=78.0% over 2.40s active (3 runs) | victim=MISSING | run=4/30 ...
```

---

## Results (this testbed)

| Stage                        | Result                                                        |
|------------------------------|---------------------------------------------------------------|
| Victim period (measured)     | 10.00 ms, signature `11 22 33`                                |
| SFBO single-shot success     | ≈83 % (30/30 bus-offs collected over ≈36 attempts)            |
| Recovery interval (learned)  | median 100.97 ms (min 100.12, max 101.64) → 100 ms hold + ~1.5 ms overhead |
| Bus load                     | more load helps; load that *outranks* the victim hurts (jitter) |
| Prediction mode (open-loop)  | true silence per hit but not sustained — typically 9–10 consecutive bus-offs before drift |
| Trailing mode (closed-loop)  | sustained; ≈91 % instantaneous (one trace window), ≈78 % run-averaged suppression |

Interpretation: SFBO and recovery-learning reproduce the paper faithfully. Open-loop
prediction cannot be sustained on this hardware because the TWAI stack and the
controller-reinit workaround inject too much per-cycle jitter; closed-loop trailing
re-anchors on each observed recovery frame and therefore sustains suppression, at the
cost of one leaked genuine frame per cycle — matching the paper's random-recovery
behaviour. See the report for full discussion.

---

## Notes & known limitations

- The attacker fully re-initialises its CAN controller after every attack (`ESP32Can.end()`
  → `begin()`). This is a reliability workaround for the TWAI peripheral latching up after
  heavy error bursts; it costs ~25–30 ms of variable dead time, which is the main reason
  open-loop prediction does not sustain.
- The victim's recovery is timer-driven (fixed 100 ms), so it is independent of bus load —
  unlike the bare-minimum model in the paper.
- The report layout in the `0x601` frame must match between `attacker.ino` (`sendReport`)
  and `pc_logger.c` (`handle_report`); if you change one, change both.

---

## References

[1] S. Serag, M. M. Nasralla, K. M. F. Elsayed, M. M. E. A. Mahmoud, and M. Abdallah,
*Exposing New Vulnerabilities of Error Handling Mechanism in CAN*,
30th USENIX Security Symposium (USENIX Security 21), 2021.

[2] Espressif Systems,
*Two-Wire Automotive Interface (TWAI) — ESP-IDF Programming Guide*,
2024. Available: https://docs.espressif.com/projects/esp-idf/en/latest/esp32c3/api-reference/peripherals/twai.html
(Accessed: 2026-06-09).

[3] FreeRTOS,
*Task Management — FreeRTOS Kernel*,
Amazon Web Services, 2024. Available: https://www.freertos.org/taskandcr.html
(Accessed: 2026-06-09).

[4] The Linux Kernel,
*SocketCAN — Controller Area Network*,
The Linux Kernel Documentation, 2024. Available: https://www.kernel.org/doc/html/latest/networking/can.html
(Accessed: 2026-06-09).
