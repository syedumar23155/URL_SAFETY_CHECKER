# app.py
import os, re, json
from flask import (Flask, render_template, request,
                   redirect, url_for, session, jsonify)
from config import RISK_HIGH, RISK_MEDIUM
from src.db.database  import (init_db, authenticate, register,
                               save_scan, get_history, get_stats)
from src.engine.heuristics import analyse  as heuristic_analyse
from src.engine.virustotal  import check   as vt_check
from src.api.groq_client    import get_explanation
from src.ml.predictor       import predict as ml_predict
import validators as val

app = Flask(__name__)
app.secret_key = "shieldai_secret_2024_xk92"

init_db()

# ── helpers ──────────────────────────────────────────
def build_verdict(h_score, ml_result, vt_result):
    score = h_score
    if ml_result["available"] and ml_result["verdict"] == "MALICIOUS":
        score = min(score + (ml_result["confidence"] / 100) * 25, 100)
    if vt_result["available"] and vt_result["total"] > 0:
        score = min(score + (vt_result["hits"] / vt_result["total"]) * 40, 100)
    score = round(score)
    if score >= RISK_HIGH:   verdict = "MALICIOUS"
    elif score >= RISK_MEDIUM: verdict = "SUSPICIOUS"
    else:                    verdict = "SAFE"
    return verdict, score

# ── auth routes ──────────────────────────────────────
@app.route("/", methods=["GET"])
def index():
    if "username" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        u = request.form.get("username","").strip()
        p = request.form.get("password","").strip()
        if authenticate(u, p):
            session["username"] = u
            session["groq_key"] = ""
            session["vt_key"]   = ""
            return redirect(url_for("dashboard"))
        error = "Invalid username or password."
    return render_template("login.html", error=error)

@app.route("/register", methods=["POST"])
def register_route():
    u = request.form.get("username","").strip()
    p = request.form.get("password","").strip()
    ok, msg = register(u, p)
    if ok:
        return render_template("login.html", success=msg + " Please log in.")
    return render_template("login.html", error=msg)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ── dashboard ─────────────────────────────────────────
@app.route("/dashboard", methods=["GET"])
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))
    stats   = get_stats(session["username"])
    history = get_history(session["username"], limit=10)
    return render_template("dashboard.html",
                           username=session["username"],
                           stats=stats,
                           history=history)

# ── scan endpoint ─────────────────────────────────────
@app.route("/scan", methods=["POST"])
def scan():
    if "username" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    raw      = request.form.get("urls", "")
    groq_key = request.form.get("groq_key", "").strip()
    vt_key   = request.form.get("vt_key", "").strip()

    urls = list(set(re.findall(r'https?://[^\s,\n]+', raw)))
    if not urls:
        return jsonify({"error": "No valid URLs found"}), 400

    results = []
    for url in urls[:10]:  # max 10 per scan
        if not val.url(url):
            results.append({"url": url, "error": "Invalid URL format"})
            continue

        h       = heuristic_analyse(url)
        ml      = ml_predict(url)
        vt      = vt_check(url, vt_key)
        verdict, score = build_verdict(h["score"], ml, vt)
        ai      = get_explanation(url, verdict, score, h["reasons"], groq_key)

        save_scan(session["username"], url, verdict, score,
                  ml.get("verdict",""), ml.get("confidence",0),
                  vt.get("hits",0), str(h["reasons"]), ai)

        results.append({
            "url":        url,
            "verdict":    verdict,
            "score":      score,
            "reasons":    h["reasons"],
            "ml_verdict": ml.get("verdict","N/A"),
            "ml_conf":    ml.get("confidence",0),
            "ml_available": ml.get("available", False),
            "vt_hits":    vt.get("hits",0),
            "vt_total":   vt.get("total",0),
            "vt_link":    vt.get("link",""),
            "vt_available": vt.get("available",False),
            "ai_summary": ai,
            "flags":      h["flags"]
        })

    return jsonify({"results": results})

# ── history API ───────────────────────────────────────
@app.route("/history")
def history_page():
    if "username" not in session:
        return redirect(url_for("login"))
    history = get_history(session["username"], limit=50)
    return jsonify(history)

if __name__ == "__main__":
    app.run(debug=True, port=5000)