#!/usr/bin/env python3
"""Bridges Ryu's flow_log.csv rows to the ML detector's expected input."""
import csv, json, joblib, os

_HERE = os.path.dirname(os.path.abspath(__file__))
_MODELS = os.path.join(_HERE, "..", "..", "models")

model = joblib.load(os.path.join(_MODELS, "best_model.pkl"))
spec = json.load(open(os.path.join(_MODELS, "label_map.json")))

def row_to_features(row: dict) -> list:
    return [
        float(row["dst_port"]),
        float(row["duration_us"]),
        float(row["total_packets"]),
        float(row["total_bytes"]),
        float(row["avg_packet_size"]),
        float(row["packets_per_sec"]),
        float(row["bytes_per_sec"]),
    ]

def classify(row: dict) -> dict:
    features = row_to_features(row)
    code = int(model.predict([features])[0])
    conf = float(max(model.predict_proba([features])[0]))
    return {"label": spec["code_to_label"][str(code)], "confidence": round(conf, 4)}

if __name__ == "__main__":
    with open(os.path.join(_HERE, "..", "backend", "flow_log.csv")) as f:
        for row in csv.DictReader(f):
            print(row["src_ip"], "->", row["dst_ip"], classify(row))
