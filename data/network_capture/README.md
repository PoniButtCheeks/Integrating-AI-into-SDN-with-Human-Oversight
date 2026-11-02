# Network capture v1 (superseded)

First labelled capture, generated on 10 October 2026 with the original versions of `src/backend/traffic_gen.py` and the Ryu controller. It has been superseded by `data/network_capture_v2/`, which the detector in `models/` was trained on. Neither the live demonstration nor the adversarial experiment uses it.

It is kept because two findings discussed in the report come from it:

- The first detector trained on our own telemetry was trained and evaluated on `flow_log_full.csv`.
- Packet sizes in this capture identified the tool that generated a flow rather than the attack, which led to the payload-free detector features.

## Files

- `flow_log_full.csv`: every logged flow, with its label.
- `flow_log.csv`: a class-balanced sample of `flow_log_full.csv`.
- `scenario_windows.csv`: start and end times of each labelled attack episode.
- `context_log.jsonl`: every record posted to the context API during the capture.
