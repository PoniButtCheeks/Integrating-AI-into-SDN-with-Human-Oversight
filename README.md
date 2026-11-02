# Human-in-the-Loop LLM Threat Mitigation for SDN

31261 Internetworking Project, Spring 2026, University of Technology Sydney.

An emulated software-defined network in which a machine-learning detector flags attacks, an LLM recommends a mitigation, a deterministic validator checks that recommendation against policy, and a human operator approves or declines it before anything changes on the network. The project evaluates whether attacker-controlled DNS names that reach the LLM can manipulate its recommendation, and how far three prompt-level defences and the validator limit that.

```
traffic -> Ryu controller -> ML detector -> context API -> LLM -> validator -> operator -> switch
```

Installation and usage: [docs/USER_MANUAL.md](docs/USER_MANUAL.md), also available as [a PDF](docs/USER_MANUAL.pdf).

## Repository layout

| Path | Contents |
|---|---|
| `src/network/` | Mininet topology: 4 switches, 6 hosts |
| `src/backend/` | Ryu controller (flow logging), context API, traffic generator |
| `src/agent/` | LLM agent, deterministic validator, incident generator, experiment harness and analysis |
| `src/demo/` | Orchestrator for the live demonstration |
| `models/` | XGBoost detectors trained on our own capture (see `models/README.md`) |
| `data/network_capture_v2/` | Labelled flow dataset the detector was trained on (see its README) |
| `data/network_capture/` | First capture, superseded by v2 and kept as evidence (see its README) |
| `data/incidents/` | The 20 scripted incidents used by the adversarial experiment |
| `data/results/` | Experiment results: `RESULTS.md`, `VALIDATOR_TRUTH_TABLE.md`, raw outputs, and pilot data (`pilot_n3_*`) |
| `data/demo/` | Log of every live demonstration incident |
| `docs/` | User manual and its figures |

## Results at a glance

- **Adversarial experiment:** 960 trials (20 incidents, 8 defence conditions, 6 trials each), run against frozen code at commit `d48a7cf`. Summary tables in `data/results/RESULTS.md`.
- **Live demonstration:** 23 incidents between 12 and 23 October 2026, each with its detection, LLM recommendation, validator verdict and operator decision, in `data/demo/demo_log.jsonl`.

## Team

| Member | Role |
|---|---|
| Maximus Joosse | Project coordinator; LLM agent, validator, adversarial experiment, live demonstration orchestrator and integration |
| Dorjsuren Naranbaatar | Mininet topology, Ryu controller, traffic generation, context API |
| Zekai Ma | ML detector (`models/`) |
| Jack Boulis | Adversarial evaluation and threat model |
| Mahnoor Qureshi | Documentation and reporting |

Individual contributions are detailed in Section 11 of the final report.
