# NetWatch benchmarks (2026-11-20 23:15, Raspberry Pi 4, 4x Cortex-A72 @ 1.8 GHz, 3795 MB)

## ML flow classifier

| Model load | RAM added | Flows/s (1 thread) | µs per flow |
|---|---|---|---|
| 4.5 s | 99 MB | 18,155 | 55.1 |

## Offline pipeline (pcap → Suricata → detectors, incl. ML)

| Capture | Events | Capture length | Processing | × real time |
|---|---|---|---|---|
| try.pcapng | 1,502 | 357.9 s | 5.6 s | 63.9 |
| nmap_scan.pcapng | 2,405 | 92.5 s | 2.19 s | 42.2 |

## Llama 3.2 1B (SpinQuant INT4) explanation of one alert

| Setup | Call | OK | Wall time | Prefill tok/s | Decode tok/s | Tokens in → out | Peak model RSS | Min free RAM | Max temp |
|---|---|---|---|---|---|---|---|---|---|
| one-shot llama_main, 2 threads | 1 | yes | 82.9 s | 8.29268 | 3.54921 | 340 → 89 | 1370 MB | 1310 MB | 76.0 °C |
| resident netwatch_llm, 2 threads | 1 | yes | 82.6 s | 8.33497 | 3.54539 | 340 → 89 | 1350 MB | 1313 MB | 76.9 °C |
| resident netwatch_llm, 2 threads | 2 | yes | 65.5 s | 8.37005 | 3.57502 | 340 → 89 | 1201 MB | 1367 MB | 79.9 °C |
| resident netwatch_llm, 1 thread | 1 | yes | 129.0 s | 4.23602 | 2.60089 | 340 → 89 | 1363 MB | 1324 MB | 75.0 °C |

Firmware throttle flags after the run: `throttled=0x80000`
