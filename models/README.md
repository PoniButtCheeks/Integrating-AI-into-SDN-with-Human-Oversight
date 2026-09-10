# ML Detector — CICIDS2017 (3-class)

Machine-learning **screening stage** of the Human-in-the-Loop pipeline.
It classifies each network flow as `normal`, `ddos` or `port_scan` and
passes the result to the LLM agent. Detection stays with traditional ML;
the LLM performs the analysis and reporting.

## Files

| File | Purpose | Used by |
|---|---|---|
| `best_model.pkl` | Trained XGBoost classifier (joblib format) | code |
| `label_map.json` | Machine-readable spec: label codes + feature order | code |
| `README.md` | This document | humans |

## Dependencies

```bash
pip install joblib scikit-learn xgboost pandas numpy
```

> **Version note:** the model is an XGBoost object. Loading a `joblib`-serialised
> XGBoost model with a very different XGBoost version may print a warning (or,
> rarely, fail). Use a recent version and, if you see a version warning, align
> XGBoost between training and inference environments.

## How to use

```python
import joblib, json

model = joblib.load("best_model.pkl")
spec  = json.load(open("label_map.json"))

# One flow = 7 numbers; ORDER MUST MATCH spec["feature_names"]:
# dst_port, duration, total_packets, total_bytes,
# avg_packet_size, packets_per_sec, bytes_per_sec
flow = [443, 123456, 50, 20000, 400.0, 500.0, 160.0]

code = int(model.predict([flow])[0])          # 0, 1 or 2
conf = float(max(model.predict_proba([flow])[0]))

label = spec["code_to_label"][str(code)]      # normal / ddos / port_scan
result = {"label": label, "confidence": round(conf, 4)}
print(result)
```

## Input features (order matters)

| # | Feature | Meaning | Unit (CICFlowMeter convention) |
|---|---|---|---|
| 1 | `dst_port` | Destination port | integer |
| 2 | `duration` | Flow duration | **microseconds** |
| 3 | `total_packets` | Total forward + backward packets | count |
| 4 | `total_bytes` | Total forward + backward bytes | bytes |
| 5 | `avg_packet_size` | Average packet size | bytes |
| 6 | `packets_per_sec` | Packet rate | packets / second |
| 7 | `bytes_per_sec` | Byte rate | bytes / second |

> ⚠️ **Units and definitions must match the ones used at training time.**
> If the live statistics exported by the SDN controller use different units
> (e.g. seconds instead of microseconds), predictions will be unreliable.

## Output format (feed this to the LLM agent)

```json
{ "label": "normal|ddos|port_scan", "confidence": 0.0-1.0 }
```

## Model performance

### Chronological hold-out split (primary, more conservative)

Per class & per capture session: earliest 40,000 rows -> train, latest
10,000 rows -> test (middle rows discarded), so test flows are captured
**after** training flows.

| Model | Accuracy | F1 |
|---|---|---|
| Decision Tree | 0.9936 | 0.9936 |
| Random Forest | 0.9943 | 0.9943 |
| **XGBoost (deployed)** | **0.9951** | **0.9951** |

### Random stratified split (upper bound, for reference)

| Model | F1 |
|---|---|
| Decision Tree | 0.9984 |
| Random Forest | 0.9985 |
| XGBoost | 0.9985 |

The small drop between the two protocols (~0.4 pp) indicates the classes are
genuinely separable and the random-split figure was only mildly optimistic.

## Notes / provenance

- Dataset: **CICIDS2017**, Friday sessions (`Friday-WorkingHours-Afternoon-DDos`
  and `Friday-WorkingHours-Afternoon-PortScan`), giving the three classes
  `normal` (BENIGN), `ddos` and `port_scan`.
- Exact-duplicate rows removed before training (76,511 rows).
- Balanced sampling: 50,000 flows per class; 120,000 train / 30,000 test
  for the random split, 160,000 train / 40,000 test for the chronological split.
- Seven flow-statistics features were used because they are sufficient
  (>99.3% accuracy), extractable in real time by the Ryu controller, and keep
  the model simple and generalisable. The dataset distribution used does not
  contain Protocol or Source-Port columns.
- XGBoost was selected over Random Forest and Decision Tree because it gave the
  highest overall F1 and the largest advantage on the DDoS class, while its
  per-flow inference cost (~8-14 microseconds) is negligible compared with the
  LLM analysis and human-approval latency in the response pipeline.
