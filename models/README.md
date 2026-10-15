# ML Detector - own telemetry model

Trained on **our own Mininet/Ryu capture** (`flow_log_full.csv`), not on CICIDS2017.

## Files
- `best_model.pkl`  - XGBoost classifier (scikit-learn API)
- `label_map.json`  - feature order and class codes
- `metrics.json`    - per-episode evaluation and confidence stats

## How to use

```python
import pickle, json, pandas as pd

model = pickle.load(open("best_model.pkl", "rb"))     # joblib.load also works
meta  = json.load(open("label_map.json"))

FEATURES = meta["feature_names"]
# ["dst_port","duration","total_packets","total_bytes",
#  "avg_packet_size","packets_per_sec","bytes_per_sec"]

row = flow_df[FEATURES]          # one flow per row, same order
proba = model.predict_proba(row)
code  = proba.argmax(axis=1)
label = [meta["code_to_label"][str(c)] for c in code]   # normal / dos / portscan
confidence = proba.max(axis=1)
```

## Important
- Feature `duration` is the controller's `duration_us` column (microseconds).
- The model expects exactly these 7 columns, in this order.
- `src_ip`, `dst_ip` and `timestamp_us` are **not** used, on purpose.
- Saved with `pickle` (protocol 4). Loading with a different xgboost version
  may print a warning; it is harmless.
