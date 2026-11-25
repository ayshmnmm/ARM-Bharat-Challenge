# NetWatch — Architecture (as built)

Status as of 20 Nov 2026.

## Data flow

```
 wlan0 ──► Suricata 7 (passive, af-packet, no promisc, detection engine off)
 pcap  ──►   │  EVE JSON: flow · dns · tls(+JA3/JA4) · quic · http · dhcp · ssh
             ▼
 netwatch/ingest/eve.py  ──►  SQLite (WAL) var/netwatch.db
             │                devices · flows · dns · tls · http · resolutions
             ▼
 netwatch/detectors/*  (event-time windows: 60 s, step 30 s)
   scan.py   port scan · host sweep · SYN flood · brute force      (M0)
   feeds.py  phishing / malware / C2 lists on DNS, SNI, HTTP, IPs  (M2, threat feeds)
   behaviour.py  beaconing · DGA · DNS tunnelling · new TLS fingerprint (JA4)   (M2, metadata only)
   baseline.py   per-device normal: upload, destinations, services per minute     (M1)
   ml.py     gradient-boosted trees (CIC-IDS2017) score every flow  (M0, ML; runs last,
             attaches a second opinion to rule alerts or raises its own)
             ▼
 alerts (merged per kind+device+peer, 15 min gap)  ──►  explain/
   facts.py      grounded facts in plain words: device names, services, counts, ML verdict
   templates.py  risk + next steps (always rule-based); instant fallback text
   llama.py      Llama 3.2 1B Instruct · ExecuTorch llama_main · writes "What happened /
                 Why it matters" from the facts; fact-checked, else the fallback is shown
             ▼
 netwatch/api.py  FastAPI, bound to 192.168.1.1 or 127.0.0.1 only
             ▼
 web/  Next.js 16 static export + shadcn/ui + Tailwind 4, served by FastAPI
```

## Components

| Path | Role |
|---|---|
| `sensor/suricata.yaml` | Sensor config. wlan0 only, `disable-promisc`, `copy-mode: none`, memcaps, short flow timeouts |
| `netwatch/ingest/eve.py` | EVE → SQLite; device inventory (IP-keyed: bridged VMs share their host's MAC); `Tail` for live follow with rotation handling |
| `netwatch/devices.py` | MAC vendor from Wireshark's bundled OUI table (offline), randomised-MAC flag, device-type guess |
| `netwatch/detectors/` | `run_range` for replays, `run_pending` for live (stays 20 s behind the event clock while flows finish) |
| `netwatch/feeds.py` | Offline feed index; parent-domain matching stops at the registrable domain; shared-platform hosts are low confidence |
| `netwatch/feedbuild.py` | Builds feed bundles **on a laptop**; refuses to run on the router |
| `netwatch/alerts.py` | Alert merge rules; `count` = separate bursts, not detection windows |
| `netwatch/ml/` | Flow features shared by CIC-IDS2017 and Suricata (`features.py`), training (`train.py`), checksum-verified loading (`model.py`), evaluation on this network's captures (`evaluate.py`) |
| `netwatch/detectors/ml.py` | ML detector: ≥ 10 flows of one attack family at ≥ 90 % confidence from one source in a window |
| `netwatch/explain/` | Facts, templates, Llama; the most severe unexplained alerts go first, in a background thread |
| `netwatch/actions.py` | M5 dry run: command previews + request log. Imports nothing that can execute (enforced by a test) |
| `netwatch/api.py` | REST API (`/api/docs`) + static UI |
| `netwatch/system.py` | Pi health: CPU, memory, temperature, throttling, router service liveness |
| `lab/make_pcaps.py` | Synthetic attack captures (phishing visit/lookup, SYN flood, SSH guessing, host sweep). Written to disk, never sent |
| `setup/netsafety.sh` | Router-safety checks: state snapshot diff, new-listener check, eth0 promiscuity |
| `web/` | Dashboard for non-experts: Home (status + what needs attention), Alerts, Devices, How it works (both AI models, measured results, router health) |

## Detection logic (M0)

TCP flags come from Suricata per direction (`flags_ts` client→server, `flags_tc` server→client).

- **Probe**: client sent SYN, ≤ 3 packets, ≤ 320 bytes (no payload). UDP: ≤ 2 packets out, none back.
- **Port scan**: ≥ 15 distinct ports from one source to one host in a window (high at ≥ 100).
  Overlapping scans are split by source-port behaviour: crafted-packet scanners (nmap `-sS`) reuse one
  source port, OS-socket scans (`-sT`) use one per probe. Techniques seen are accumulated on the alert.
- **Host sweep**: ≥ 10 LAN hosts probed by one source.
- **SYN flood**: ≥ 200 SYN-only flows at ≤ 3 ports of one host.
- **Brute force**: ≥ 8 completed sessions with payload to an auth port (SSH, RDP, SMB, VNC…) (high at ≥ 30).
- Alerts are filed under the **inside device** when the source is a Wi-Fi client, otherwise under the victim.

## Behaviour detectors (M1, M2)

All work on connection metadata; nothing is decrypted.

| Detector | Rule | Severity |
|---|---|---|
| Beaconing | ≥ 8 connections from one device to one internet address and port within 30 min, gaps 10 s–15 min, spread/average ≤ 0.15, ≤ 4 KB sent per check-in (DNS, NTP, DHCP, mDNS, SSDP ports excluded) | medium |
| DGA | ≥ 10 distinct non-existent (NXDOMAIN) names from one device in 60 s, ≥ 60 % random-looking (length ≥ 10, entropy ≥ 3 bits, few vowels or mixed digits) | high |
| DNS tunnelling | ≥ 20 distinct names under one domain in 60 s, average hidden part ≥ 25 characters, entropy ≥ 3.5 bits/char | high |
| New fingerprint | a JA4 TLS fingerprint never seen on that device or any other device, after a 24 h learning period | low |
| Per-device baseline | per device and active minute: upload bytes, distinct internet addresses, distinct ports; Welford mean/spread; alert at ≥ 6 spreads above its own normal and above a floor (50 MB, 40 addresses, 25 ports), after 120 learned minutes. The anomalous minute is learned capped, so an attack does not become "normal" | medium / low |

Lab captures (synthetic, never sent): `lab_beaconing.pcap` (IoT device, 20 check-ins every 60 ± 1 s),
`lab_dga.pcap` (25 random NXDOMAIN names), `lab_dns_tunnel.pcap` (40 TXT queries with base32 labels).
Each is detected; the real household capture and the real nmap capture raise none of these alerts.

## Weekly summary, PIN, resident model

- **Your week**: the counts are written by NetWatch; Llama writes only the advice, from number-free facts,
  and any number in it is rejected. Tested: given the counts, the 1B model copied "2 new" from its worked
  example, merged two counts and invented "6 false positives". Counted facts (devices, new devices, alerts by type, open ones, ML confirmations, busiest device) → Llama paragraph, on request from the home page.
- **PIN** (`NETWATCH_PIN`, optional): every `/api` call needs a session cookie (HMAC of the PIN with a
  per-install key; HttpOnly, SameSite=Strict, 30 days); 5 wrong PINs per minute → locked for a minute.
- **Fact checks added since the first version**: per-task worked examples (alert, summary); plain prose
  without labels is accepted, lists are not; outcomes the facts never state ("false positive", "resolved",
  "fixed") are rejected.
- **Slow writing runs in the live service**, which has the memory budget for the model; the dashboard
  service only queues jobs. One model at a time across processes (file lock).
- **Resident runner** `netwatch_llm` (`llm/server/netwatch_llm.cpp`, built beside `llama_main`): loads the
  model once, answers prompts over stdin/stdout, exits after 5 idle minutes to give the memory back. Falls
  back to one `llama_main` per prompt if it fails.
- **Memory guard**: the model is not started unless ≥ 1.7 GB is available (it needs ~1.4 GB); otherwise
  NetWatch's own text is shown. Measured: with the Next.js *dev* server running (≈ 1 GB) the guard refused
  to start Llama, as intended. Production serves the static build from the API instead.

## ML detector (M0)

A flow classifier, trained on the Pi (`python -m netwatch ml-train`, ~3 min at nice 15, 2 threads) from the
public **CIC-IDS2017** MachineLearningCVE CSVs (2.83 M labelled flows; Sharafaldin et al., ICISSP 2018).

- **8 features both tools can measure** (`netwatch/ml/features.py`): service port, packets and payload bytes
  each way, mean payload per packet each way, reply ratio. CICFlowMeter counts payload only, Suricata counts
  whole frames, so Suricata bytes are corrected by a per-packet header size. Using the dataset's 78 columns
  would score higher on the dataset but could not be computed live. **No timing features** (duration, rates):
  see lesson 4 below.
- **Data hygiene**: exact duplicate raw records (all six raw columns + label) dropped before the split (they
  otherwise leak from train into test); benign capped at 600k; 80/20 stratified split.
- **Families**: benign, flooding (DoS Hulk/GoldenEye/slowloris/Slowhttptest, DDoS), scanning (PortScan),
  password guessing (FTP/SSH-Patator), botnet (Bot). Web attacks were tried as a class and dropped: at flow level
  they are indistinguishable from browsing (precision 0.17, recall 0.08). Infiltration (36) and Heartbleed (11)
  are too small.
- **Model**: scikit-learn `HistGradientBoostingClassifier`, no class re-weighting (re-weighting raised rare-class
  recall but mislabelled ~1 % of benign flows: false alarms at home).
- **Live use** (`netwatch/detectors/ml.py`): every TCP/UDP flow in each 60 s window is scored. A flow counts
  only at ≥ 90 % confidence; an alert needs ≥ 10 such flows of one family from one source. If a rule alert
  already covers that device, the verdict is attached to it as an independent second opinion (agree/disagree
  shown on the alert page) instead of a duplicate alert.
- **Safety**: the model file is a pickle, so it is loaded only if its SHA-256 matches the model card.

**Held-out test set** (202,783 flows never seen in training; 139 boosting rounds, 132 s fit on the Pi):

| | Accuracy | Macro F1 | Benign flows wrongly flagged |
|---|---|---|---|
| Plain argmax | 97.9 % | 0.910 | 1.5 % |
| Operating point (≥ 90 % confidence) | 96.0 % | 0.844 | 0.57 % |

| Family (at ≥ 90 %) | Precision | Recall |
|---|---|---|
| Flooding (DoS/DDoS) | 99.9 % | 97.5 % |
| Password guessing | 99.8 % | 92.9 % |
| Scanning | 95.3 % | 69.5 % |
| Botnet | 95.7 % | 34.1 % |

Scoring speed on the Pi: ~56 µs per flow (one Cortex-A72 core). Model file: 1.2 MB.

**On this network's own captures** (`python -m netwatch ml-eval`; none used in training):

| Capture | Rules | ML |
|---|---|---|
| 6 min of real household traffic (717 flows) | no alert | **no alert** |
| Real nmap scans of the router (`-sS`, `-sT`, `-sV`) | port scan | **scan, 1,397 connections at ≥ 90 %: agrees with the rule** |
| Synthetic host sweep, SYN flood, SSH guessing (scapy-made) | detected | not recognised |
| Synthetic worm-style probing: top-10 ports on 3 devices | **nothing (below every threshold)** | **scan** |

**What ML adds over the rules** (`bench/ml_vs_rules.py` → `bench/ML_VS_RULES.md`): real nmap probe records,
re-addressed to other home devices with a 3 ms Wi-Fi reply time. nmap's top-10 ports on 2–9 devices within a
minute stays under both scan rules (< 15 ports per host, < 10 hosts) and is caught only by the ML detector,
which adds up probe-like connections from one device across every host and port.

What the numbers taught us, and the fixes they led to:

1. **Dataset quirk.** CICFlowMeter counts Ethernet padding as payload, so every bare scan probe "carries" 2–6
   bytes. Suricata does not count it, and the first model missed the real nmap scan entirely. Treating under
   10 bytes per packet as "no data" on both sides fixed it. That lowered the dataset score (99.7 % → 98.7 %)
   and raised real-world detection from 0 to 946 flows. We kept the version that works on real traffic.
2. **Long sessions.** One open SSH window was logged by Suricata as 47 short records, which the model read as
   password guessing. Alerts now count distinct connections (address + ports), not flow records.
3. **Synthetic captures** are hand-made packets with unrealistic timing and sizes; only the rules catch them.
   CIC-IDS2017 also has no SYN flood (its DoS attacks are HTTP floods). Live attacks from a laptop (nmap, hydra,
   hping3) are the real test, and are part of the demo.
4. **Timing features did not transfer.** The first model also used duration and byte/packet rates. It
   flagged real scan probes only when the reply came back in under ~0.5 ms, which is true when nmap scans the
   router itself (~30 µs) but never for a phone or laptop answering over Wi-Fi (1–50 ms): 0 of 1,000 real
   probes flagged at those reply times. Dropping the three timing features cost under a point of dataset
   accuracy (98.7 → 97.9 %) and made the verdict independent of reply time (698 of 1,000 probes flagged at every reply time
   from 30 µs to 50 ms).
5. **De-duplicate raw records, not features.** Without timing, thousands of different scan probes have the
   same features (that is what a scan is). De-duplicating in feature space shrank the scan class to 1,238
   rows and the model stopped recognising scans; de-duplicating on the raw record fixed it.
6. **Scanning recall at 69 %** is per flow; a scan is hundreds of flows, so the per-device threshold is still met.

## Measured (Pi 4, 4 GB)

| Test | Result |
|---|---|
| Real nmap capture (13.7k packets: `-sS`, `-sT`, `-sV`) | 1 high alert, both techniques, open ports 22/53/3000 correct; 1.7 s end to end |
| Real normal traffic (6 min, 153k packets, 139 MB) | **0 alerts**; 5.3 s end to end (~65× real time) |
| Lab: phishing visit / lookup, SYN flood, SSH guessing, host sweep | All detected with expected severity |
| Benign HTTPS in the same capture | Not flagged |
| Test suite | 71 tests (`.venv/bin/python -m pytest`) |
| ExecuTorch `llama_main` build on the Pi (v1.5.1, `-j2`, nice 19) | Built; 6.9 MB binary + 3.5 MB `libllama_runner.so` (found via `$ORIGIN`) |
| UI static build on the Pi | ~45 s, `nice 15`, Node heap capped at 1.5 GB |

### Benchmarks (`bench/run_bench.py`, 20 Nov 2026)

See [bench/RESULTS.md](../bench/RESULTS.md). Resident runner with the model loaded: 65.5 s per explanation vs 82.9 s
one-shot (−21 %); 1 thread: 129 s. ML scoring 18.6k flows/s on one core. Pipeline 43–140× real time.
Peak 80 °C during back-to-back Llama runs: use a heatsink/fan.

## Supply chain

- Python deps pinned in `requirements.lock`, installed from PyPI with `--uploaded-prior-to` (≥ 2 weeks old).
- npm: `web/.npmrc` sets `before=2026-11-02` (all transitive deps resolve to versions at least two weeks old)
  and `ignore-scripts=true`; versions pinned exactly in `package.json` with a lockfile.
- shadcn's CLI added its new `cn` package; replaced with the long-established `clsx` + `tailwind-merge`.
- No runtime downloads anywhere: system fonts, offline public-suffix list, offline OUI table, sideloaded feeds.

## Running as services

`bash setup/install_services.sh` deploys to `/opt/netwatch` (root-owned) and runs three units as the
unprivileged `netwatch` user. State lives in `/var/lib/netwatch`. Undo with `setup/uninstall_services.sh`.

| Unit | Runs | Network fence (kernel-enforced) | Limits |
|---|---|---|---|
| `netwatch-sensor` | Suricata, `--af-packet=wlan0` | packet + netlink sockets only; only `CAP_NET_RAW`/`CAP_NET_ADMIN` | 1 core, 1.5 GB address space |
| `netwatch-live` | ingest, detection, explanations (+ `llama_main` child) | **no network at all** (`IPAddressDeny=any`, `AF_UNIX` only) | 1.5 cores, 4 GB AS, 400 MB RSS self-check |
| `netwatch-web` | API + dashboard on `192.168.1.1:8088` | may only talk to `192.168.1.0/24` and loopback | ½ core, 1 GB AS |

All three: `Nice=10`, `OOMScoreAdjust=500` (killed before dnsmasq/hostapd), read-only system,
no home access, no privilege escalation; `systemd-analyze security` exposure 2.6 to 3.3 ("OK").

**Memory cgroup is disabled on this Pi** (`cgroup_disable=memory` on the kernel command line), so
`MemoryMax` would be ignored. Limits are enforced with `LimitAS`, OOM priority, Suricata memcaps and
an RSS self-check in the live loop instead. Enabling the controller needs a boot-config change and a
router reboot (not done).

The installer runs the same router-safety checks as before (state diff, new listeners, eth0 promiscuity,
sensor sockets on wlan0 only, dnsmasq/hostapd alive) and disables everything again if any check fails.

## On-device Llama (ExecuTorch)

| Step | Where | Script |
|---|---|---|
| Build `llama_main` + `libllama_runner.so` (ExecuTorch v1.5.1, XNNPACK, CPU) | Pi, nice 19, 2 jobs | `llm/build_runner.sh` (done) |
| Download + export Llama 3.2 1B Instruct (8da4w, group 32, 1024 context) and fetch Meta's SpinQuant export | x86 machine, ≥ 16 GB RAM | `llm/export_model.sh` |
| Copy models to the Pi over Wi-Fi | x86 machine | `llm/push_to_pi.sh` |
| Enable | Pi | re-run `setup/install_services.sh` |

**Rules decide, the AI explains, from grounded facts.** `explain/facts.py` turns each alert into short
"label: value" lines in plain words: who (device name, maker, IP), what was seen (counts, time span), which
services (port numbers translated: "port 22, remote login (SSH)"), the ML detector's verdict and what stood out
to it, a one-line background on the attack type, and the severity set by the rules. Llama gets only these
lines plus one worked example, and writes its own two-part answer ("What happened" / "Why it matters") for a
non-technical reader. The answer is rejected, and NetWatch's own text shown, if either part is missing, it
contains an IP address or a number that is not in the facts, or it plays the alert down ("normal", "safe").
How serious the alert is, and the next steps, always come from the rules. The facts are stored with the
explanation and shown on the alert page ("What the AI writer was told"), so every sentence can be checked.

History: asked for JSON, the 1B model broke the format on 4 of 4 real alerts and misread "3 open ports out of
1000 probed" as "1000 open ports". Rewording pre-written sentences was reliable but added little. Plain fact
lines with labels, translated jargon and a worked example gave both readable and checkable output.

While Llama is writing (about a minute), the alert page already shows NetWatch's instant text from the same facts.

The runner runs as a subprocess in a background thread beside detection (`--temperature=0`,
`--max_new_tokens=140`, `--cpu_threads=2` so two cores stay with the router). Its echoed prompt is stripped
before parsing. Prefill/decode speed is stored per explanation and shown in the UI.

Measured on the Pi 4 with Meta's `Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8.pte` (2 threads), grounded-facts
prompt, 6 real alerts (port scan with ML second opinion, host sweep, SYN flood, SSH guessing, 2 phishing tests):

| | Result |
|---|---|
| Model load | ~12–19 s (every call; the runner is a fresh process) |
| Prompt | 381–538 tokens (facts + one worked example) |
| Prefill | 6.4–8.2 tokens/s |
| Decode | 2.8–3.4 tokens/s, 77–119 tokens written |
| End to end per alert | 94–134 s (the alert page shows NetWatch's instant text meanwhile) |
| Peak RSS of `llama_main` | 1.4 GB |
| Accepted by the fact check | 6 of 6 |
| Quality (read by hand) | 5 of 6 clear and correct. One lab-test answer said the test "could be a sign your network is vulnerable", which is misleading but passed the checks |
| Pi during the runs | up to 78 °C; firmware flag 0x80000 (soft temperature limit reached at some point since boot, no throttling at the time of reading); ≥ 1.3 GB RAM free; router services unaffected. A heatsink or fan is advised |

Earlier designs, same hardware: JSON output failed 4 of 4; rewording pre-written sentences passed 3 of 4.

The in-process Python bindings in the ExecuTorch wheel were rejected: they link libtorch (~1 GB RAM).

## Not done yet

- Prefix caching (prefill the fixed system prompt once); ExecuTorch's runner has no KV-cache checkpoint API yet.
- Benchmark matrix: 8da4w vs SpinQuant, threads, latency, memory, temperature.
- ML: web attacks need payload features; a second dataset (UNSW-NB15) and per-network fine-tuning.
- PIN is optional and off by default; HTTPS on the LAN is not set up.
- Scam SMS are out of scope: NetWatch sees traffic, not message contents (scam links are caught when visited, if listed).
