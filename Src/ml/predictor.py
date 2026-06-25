# src/ml/predictor.py
import re
import pickle
import numpy as np
import os
from urllib.parse import urlparse

MODEL_PATH  = "data/models/rf_model.pkl"
SCALER_PATH = "data/models/scaler.pkl"

URL_SHORTENERS = {"bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","short.link","rb.gy"}

def extract_features(url: str) -> list:
    try:
        parsed   = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        path     = parsed.path or ""
    except Exception:
        return [0] * 15

    return [
        len(url),
        len(hostname),
        url.count("."),
        url.count("-"),
        url.count("@"),
        url.count("//"),
        url.count("/"),
        url.count("?"),
        len(parsed.query),
        1 if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname) else 0,
        1 if parsed.scheme == "https" else 0,
        len(hostname.split(".")),
        len([p for p in path.split("/") if p]),
        sum(c.isdigit() for c in hostname),
        1 if any(s in hostname for s in URL_SHORTENERS) else 0
    ]

# Load once at startup
_model  = None
_scaler = None

def _load():
    global _model, _scaler
    if _model is None and os.path.exists(MODEL_PATH):
        with open(MODEL_PATH, "rb") as f:
            _model = pickle.load(f)
        with open(SCALER_PATH, "rb") as f:
            _scaler = pickle.load(f)

def predict(url: str) -> dict:
    try:
        _load()
        if _model is None:
            return {"verdict": "UNKNOWN", "confidence": 0.0, "available": False}

        features = np.array(extract_features(url)).reshape(1, -1)
        scaled   = _scaler.transform(features)
        pred     = _model.predict(scaled)[0]
        proba    = _model.predict_proba(scaled)[0]

        return {
            "verdict":    "MALICIOUS" if pred == 1 else "SAFE",
            "confidence": round(float(max(proba)) * 100, 1),
            "available":  True
        }
    except Exception as e:
        return {"verdict": "UNKNOWN", "confidence": 0.0, "available": False}