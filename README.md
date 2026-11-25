# NetWatch

Offline AI guardian for a home Wi-Fi network, running on the router itself (Raspberry Pi 4, Arm Cortex-A72).
Bharat AI-SoC Challenge 2026–27, Problem Statement 3: on-device threat, phishing & scam detection.

NetWatch watches the Wi-Fi side of the router, identifies every device, and detects intrusions and visits to
known phishing/malware sites with two independent methods: fixed rules plus threat lists, and a machine-learning
flow classifier trained on CIC-IDS2017. Each alert is then explained for non-experts by Llama 3.2 1B running
on the Pi through ExecuTorch, written from grounded, fact-checked facts. Nothing leaves the home.

Built with Llama. Llama 3.2 is licensed under the [Llama 3.2 Community License](https://github.com/meta-llama/llama-models/blob/main/models/llama3_2/LICENSE),
Copyright © Meta Platforms, Inc. All Rights Reserved. The model weights are not in this repository.

- [Final project report (PDF)](docs/NetWatch_Final_Report.pdf)
- [Architecture as built](docs/ARCHITECTURE.md)

## Quick start (offline replay)

```bash
bash setup/install_deps.sh                      # once: Suricata etc. (verifies the router is untouched)
python3 -m venv .venv && .venv/bin/pip install -r requirements.lock
.venv/bin/python lab/make_pcaps.py captures/lab # synthetic attack captures
.venv/bin/python -m netwatch replay captures/lab/*.pcap
(cd web && npm ci && npx next build)            # static dashboard -> web/out
.venv/bin/python -m netwatch serve --host 127.0.0.1
```

Then from a laptop on the Wi-Fi: `ssh -L 8088:localhost:8088 <user>@192.168.1.1` and open http://localhost:8088.

## ML detector

```bash
# once: CIC-IDS2017 MachineLearningCVE CSVs (~235 MB zip) into var/datasets/cic/
.venv/bin/python -m netwatch ml-train      # ~3 min on the Pi; writes models/flow_classifier.{joblib,json}
.venv/bin/python -m netwatch ml-eval       # replays this network's captures, records results in the model card
```

## Tests

```bash
.venv/bin/python -m pytest
```

## Threat feeds

Built on a laptop (the router never downloads anything at runtime), then pushed over Wi-Fi:

```bash
python -m netwatch feeds-build      # on the laptop
bash feeds/push_to_pi.sh            # copies the bundle to the Pi
```
