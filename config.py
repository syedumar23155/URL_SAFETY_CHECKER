# config.py
import os
from dotenv import load_dotenv

load_dotenv()

# ── API Keys ──────────────────────────────────────────
GROQ_API_KEY      = os.getenv("GROQ_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

# ── App Settings ──────────────────────────────────────
APP_TITLE    = "ShieldAI"
APP_SUBTITLE = "Intelligent URL Threat Intelligence"
APP_VERSION  = "2.0.0"

# ── Thresholds ────────────────────────────────────────
RISK_HIGH        = 65   # >= 65 → MALICIOUS
RISK_MEDIUM      = 35   # 35–64 → SUSPICIOUS
                        # < 35  → SAFE

# ── Model path ────────────────────────────────────────
MODEL_PATH = "data/models/rf_model.pkl"
SCALER_PATH = "data/models/scaler.pkl"

# ── DB ────────────────────────────────────────────────
DB_PATH = "data/shieldai.db"

# ── Colour map ────────────────────────────────────────
VERDICT_COLOURS = {
    "MALICIOUS":  "#FF4444",
    "SUSPICIOUS": "#FFA500",
    "SAFE":       "#00C853",
}

# ── Heuristic weights (must sum influence correctly) ──
HEURISTIC_WEIGHTS = {
    "url_length":          0.10,
    "ip_as_host":          0.20,
    "excessive_subdomains":0.15,
    "shortener":           0.10,
    "at_symbol":           0.10,
    "double_slash":        0.08,
    "no_https":            0.08,
    "suspicious_keywords": 0.10,
    "typosquatting":       0.25,
    "long_path_depth":     0.05,
}