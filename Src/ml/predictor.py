# src/ml/predictor.py
import re
import pickle
import numpy as np
from urllib.parse import urlparse
from config import MODEL_PATH, SCALER_PATH


def extract_features(url: str) -> list:
    """Extract 15 numerical features from a URL for the ML model."""
    try:
        parsed   = urlparse(url)
        hostname = parsed.hostname or ""
        path     = parsed.path or ""
    except Exception:
        return [0] * 15

    features = [
        len(url),                                                  # 1. URL length
        len(hostname),                                             # 2. Domain length
        url.count("."),                                            # 3. Dot count
        url.count("-"),                                            # 4. Hyphen count
        url.count("@"),                                            # 5. At-sign count
        url.count("//"),                                           # 6. Double-slash count
        url.count("/"),                                            # 7. Slash count
        url.count("?"),                                            # 8. Query param count
        len(parsed.query),                                         # 9. Query string length
        1 if re.match(r'\d+\.\d+\.\d+\.\d+', hostname) else 0,   # 10. IP as host
        1 if parsed.scheme == "https" else 0,                     # 11. HTTPS flag
        len(hostname.split(".")),                                  # 12. Subdomain depth
        len([p for p in path.split("/") if p]),                   # 13. Path depth
        sum(c.isdigit() for c in hostname),                        # 14. Digits in domain
        1 if any(s in url for s in ["bit.ly","tinyurl","t.co"]) else 0  # 15. Shortener
    ]
    return features


def predict(url: str) -> dict:
    """
    Returns ML prediction dict:
      { verdict: str, confidence: float, available: bool }
    """
    try:
        with open(MODEL_PATH, "rb") as f:
            model = pickle.load(f)
        with open(SCALER_PATH, "rb") as f:
            scaler = pickle.load(f)

        features = np.array(extract_features(url)).reshape(1, -1)
        scaled   = scaler.transform(features)
        pred     = model.predict(scaled)[0]
        proba    = model.predict_proba(scaled)[0]
        confidence = float(max(proba)) * 100

        return {
            "verdict":    "MALICIOUS" if pred == 1 else "SAFE",
            "confidence": round(confidence, 1),
            "available":  True
        }
    except FileNotFoundError:
        # Model not trained yet — graceful degradation
        return {"verdict": "UNKNOWN", "confidence": 0.0, "available": False}
    except Exception as e:
        return {"verdict": "UNKNOWN", "confidence": 0.0, "available": False}