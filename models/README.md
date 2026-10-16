# ML detector - network_capture_v2

Trained on **our own** capture (`flow_log.csv`), 6 runs x 15 min, 13,188 flows,
90.9% normal. **Not** trained on CICIDS2017.

## Two models

| File | Features | Why |
|---|---|---|
| `best_model.pkl` + `label_map.json` | 7 | Drop-in for the existing pipeline. `dst_port, duration, total_packets, total_bytes, avg_packet_size, packets_per_sec, bytes_per_sec` |
| `best_model_payload_free.pkl` + `label_map_payload_free.json` | 4 | Best macro-F1 and immune to the padding artefact. `dst_port, duration, total_packets, packets_per_sec` |

**Which one?** The payload-free model scores slightly better and does not rely on
packet size, which ~30% of our scans fake with `--data-length` padding. The 7-feature
model is the safest drop-in if the pipeline expects those columns.

## How to use

```python
import pickle, json
model = pickle.load(open("best_model.pkl", "rb"))    # joblib.load also works
meta  = json.load(open("label_map.json"))
proba = model.predict_proba(flow_df[meta["feature_names"]])
label = [meta["code_to_label"][str(c)] for c in proba.argmax(axis=1)]
confidence = proba.max(axis=1)
```

## Honest performance (leave-one-run-out, XGBoost)

| Model | macro-F1 | recall normal / dos / portscan | FP on normal |
|---|---|---|---|
| 7 features | 0.948 | 0.999 / 0.832 / 0.918 | 0.14% |
| payload-free | **0.954** | 0.997 / 0.822 / **0.990** | 0.31% |

Per technique (7 feat -> payload-free):
- SYN flood **1.00**, UDP flood 0.97
- **HTTP flood 0.07**, slow flood 0.38  <- both effectively invisible
- scans 1.00, except **padded SYN scans 0.83 -> 0.98**

Accuracy is ~0.987 but **do not quote it** - predicting "normal" for everything
already scores 0.909 on this dataset.

## Known limits
- Trained/evaluated on one capture (seed 1), 6 runs.
- No aggregate features yet (`distinct_dst_ports`, `flow_count`, `packetin_rate`).
  Without them, port scans are recognised by packet size or by an unusual
  destination port - not by behaviour. Removing both drops scan recall to 0.002.
- `src_ip` and `dst_port` are label giveaways in this lab; `src_ip` is excluded.
