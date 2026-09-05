"""
app.py  –  Flask backend for the NIDS Agent
"""

import os
import io
import re
import json
import uuid
import datetime

import numpy as np
import pandas as pd
from flask import (Flask, request, jsonify, render_template,
                   send_from_directory)
from flask_cors import CORS

from backend.config import (SECRET_KEY, DEBUG, HOST, PORT,
                             UPLOAD_FOLDER, MAX_CONTENT_LENGTH)
from backend.predictor import predict, predict_batch, FEATURE_NAMES
from backend.watsonx_client import get_ai_explanation, get_chat_response

# ── App setup ─────────────────────────────────────────────────────────────────
app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), "..", "frontend", "templates"),
    static_folder=os.path.join(os.path.dirname(__file__), "..", "frontend", "static")
)
app.secret_key           = SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
CORS(app)

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# In-memory alert log (production: use a DB)
alert_log: list[dict] = []

# Per-session last prediction (keyed by session id sent from frontend)
# Simple dict is fine for a single-process dev server
_last_prediction: dict = {}   # session_id -> {prediction, features, raw_text}


# ── Helper ────────────────────────────────────────────────────────────────────
def _log_alert(prediction: dict, source: str = "manual"):
    if prediction.get("is_attack"):
        alert_log.append({
            "id":         str(uuid.uuid4())[:8],
            "timestamp":  datetime.datetime.utcnow().isoformat() + "Z",
            "label":      prediction["label"],
            "confidence": prediction["confidence"],
            "severity":   prediction["severity"],
            "source":     source
        })
        # Keep last 200 alerts
        if len(alert_log) > 200:
            alert_log.pop(0)


# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/health")
def health():
    return jsonify({"status": "ok",
                    "time": datetime.datetime.utcnow().isoformat()})


@app.route("/api/features")
def feature_names():
    """Return the list of expected feature names."""
    return jsonify({"features": FEATURE_NAMES})


@app.route("/api/predict", methods=["POST"])
def predict_single():
    """
    Body: JSON dict of feature_name → value
    Returns: prediction + WatsonX explanation
    """
    data = request.get_json(force=True)
    if not data:
        return jsonify({"error": "No JSON body"}), 400

    try:
        result = predict(data)
        _log_alert(result, source="api")
        result["explanation"] = get_ai_explanation(result)
        return jsonify(result)
    except FileNotFoundError:
        return jsonify({"error": "Model not trained yet. "
                                  "Run: python backend/model_trainer.py"}), 503
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/predict/batch", methods=["POST"])
def predict_batch_endpoint():
    """
    Accepts a CSV file upload (multipart/form-data, field name 'file')
    OR a JSON array of feature dicts.
    Returns list of predictions + summary statistics.
    """
    if "file" in request.files:
        f = request.files["file"]
        filename = f.filename or "upload.csv"
        if not filename.lower().endswith(".csv"):
            return jsonify({"error": "Only CSV files are supported"}), 400

        try:
            df = pd.read_csv(io.StringIO(f.read().decode("utf-8")))
        except Exception as e:
            return jsonify({"error": f"CSV parse error: {e}"}), 400

        # Keep only known feature columns
        for col in FEATURE_NAMES:
            if col not in df.columns:
                df[col] = 0

        df = df[FEATURE_NAMES]
    else:
        data = request.get_json(force=True)
        if not data or not isinstance(data, list):
            return jsonify({"error": "Provide a CSV file or JSON array"}), 400
        df = pd.DataFrame(data)
        for col in FEATURE_NAMES:
            if col not in df.columns:
                df[col] = 0
        df = df[FEATURE_NAMES]

    try:
        results  = predict_batch(df)
    except FileNotFoundError:
        return jsonify({"error": "Model not trained yet. "
                                  "Run: python backend/model_trainer.py"}), 503
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    for r in results:
        _log_alert(r, source="batch")

    labels   = [r["label"] for r in results]
    summary  = {lbl: labels.count(lbl) for lbl in set(labels)}
    attacks  = [r for r in results if r["is_attack"]]

    return jsonify({
        "total":     len(results),
        "summary":   summary,
        "attacks":   len(attacks),
        "results":   results
    })


@app.route("/api/simulate", methods=["GET"])
def simulate_traffic():
    """
    Generate a single synthetic traffic sample, classify it, and return result.
    Useful for demo / live traffic simulation.
    """
    np.random.seed()          # different each call
    sample = {}
    for f in FEATURE_NAMES:
        sample[f] = float(np.random.uniform(0, 100))

    # Occasionally inject attack patterns
    attack_type = np.random.choice(
        ["Normal", "DoS", "Probe", "R2L", "U2R"],
        p=[0.55, 0.20, 0.12, 0.08, 0.05]
    )
    if attack_type == "DoS":
        sample["serror_rate"] = float(np.random.uniform(0.7, 1.0))
        sample["count"]       = float(np.random.randint(400, 512))
        sample["src_bytes"]   = float(np.random.randint(0, 200))
    elif attack_type == "Probe":
        sample["rerror_rate"] = float(np.random.uniform(0.6, 0.9))
        sample["diff_srv_rate"] = float(np.random.uniform(0.5, 1.0))

    try:
        result = predict(sample)
        _log_alert(result, source="simulation")
        result["simulated_input"] = {
            k: round(v, 4) for k, v in list(sample.items())[:10]
        }
        return jsonify(result)
    except FileNotFoundError:
        return jsonify({"error": "Model not trained yet."}), 503
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/alerts")
def get_alerts():
    """Return the last N alerts (default 50)."""
    n = min(int(request.args.get("limit", 50)), 200)
    return jsonify({"alerts": alert_log[-n:][::-1],
                    "total":  len(alert_log)})


# ── Chat helpers ──────────────────────────────────────────────────────────────

# Numeric aliases used in natural-language traffic descriptions
_PROTO_MAP  = {"tcp": 1, "udp": 2, "icmp": 3}
_SERVICE_MAP = {
    "http": 1, "ftp": 2, "smtp": 3, "ssh": 4, "telnet": 5,
    "eco_i": 6, "ecr_i": 7, "private": 8, "domain_u": 9,
    "http_443": 10, "finger": 11, "ftp_data": 12, "imap4": 13,
}
_FLAG_MAP = {
    "sf": 1, "s0": 2, "rej": 3, "rsto": 4, "rstos0": 5,
    "rstr": 6, "sh": 7, "oth": 8, "s1": 9, "s2": 10, "s3": 11,
}


def _extract_features_from_text(text: str) -> dict | None:
    """
    Scan free-form text for key=value pairs (e.g. duration=0, src_bytes=215).
    Returns a full feature dict if at least 2 numeric fields are found,
    else None.
    """
    found = {}
    # Match  name=value  or  name: value  where value is a number or word token
    for m in re.finditer(
        r'\b([\w]+)\s*[=:]\s*([a-zA-Z0-9_\.]+)', text, re.IGNORECASE
    ):
        key, val = m.group(1).lower(), m.group(2).lower()
        # Map categorical fields to numerics
        if key == "protocol" or key == "protocol_type":
            found["protocol_type"] = float(_PROTO_MAP.get(val, 0))
        elif key == "service":
            found["service"] = float(_SERVICE_MAP.get(val, 0))
        elif key == "flag":
            found["flag"] = float(_FLAG_MAP.get(val, 0))
        elif key in FEATURE_NAMES:
            try:
                found[key] = float(val)
            except ValueError:
                pass

    # Need at least 2 recognised numeric features to be worth predicting
    if len(found) < 2:
        return None

    base = {f: 0.0 for f in FEATURE_NAMES}
    base.update(found)
    return base


def _is_reasoning_question(text: str) -> bool:
    """True when the user asks why/how a classification was made."""
    patterns = [
        r'\bwhy\b', r'\bhow\b.*classif', r'\bwalk.*(me|us|through)\b',
        r'\breason(ing)?\b', r'\bexplain.*classif', r'\bjustif',
        r'\bwhat.*made.*you\b', r'\bwhy.*classif', r'\bwhy.*that\b',
    ]
    t = text.lower()
    return any(re.search(p, t) for p in patterns)


def _is_log_query(text: str) -> bool:
    """True when the user asks about the traffic/alert log."""
    patterns = [
        r'\btraffic.*(log|history|record)\b',
        r'\balert.*(log|history|record)\b',
        r'\bcheck.*(log|traffic|alert)\b',
        r'\bany\b.*\battack\b',
        r'\bsummar\b',
        r'\brecent.*(attack|traffic|alert)\b',
        r'\bscan.*log\b',
        r'\bfind.*dos\b', r'\bdetect.*dos\b',
        r'\bdos.*pattern\b', r'\bpattern.*dos\b',
    ]
    t = text.lower()
    return any(re.search(p, t) for p in patterns)


def _summarise_alert_log_for_prompt(filter_label: str | None = None) -> str:
    """Build a compact text block describing the current alert log."""
    if not alert_log:
        return "The alert log is currently empty — no attacks have been recorded in this session."

    subset = alert_log if filter_label is None else [
        a for a in alert_log if a["label"].lower() == filter_label.lower()
    ]
    if not subset:
        return (f"No '{filter_label}' attacks found in the alert log "
                f"({len(alert_log)} total alerts recorded).")

    by_type: dict = {}
    by_sev: dict = {}
    for a in subset:
        by_type[a["label"]] = by_type.get(a["label"], 0) + 1
        by_sev[a["severity"]] = by_sev.get(a["severity"], 0) + 1

    recent = subset[-5:][::-1]
    lines = [
        f"Alert log snapshot ({len(subset)} entries{' for ' + filter_label if filter_label else ''}):",
        f"  By type    : {by_type}",
        f"  By severity: {by_sev}",
        "  Most recent entries:",
    ]
    for a in recent:
        lines.append(
            f"    [{a['timestamp']}] {a['label']} | {a['confidence']}% conf "
            f"| severity={a['severity']} | source={a['source']}"
        )
    return "\n".join(lines)


@app.route("/api/chat", methods=["POST"])
def chat():
    """
    Body: {
        "message" : str,
        "history" : [{"role": "user"|"assistant", "content": str}],
        "session_id": str   (optional, used to track last prediction for follow-ups)
    }
    Returns: { "reply": str }
    """
    data = request.get_json(force=True)
    if not data or not data.get("message"):
        return jsonify({"error": "No message provided"}), 400

    user_message = str(data["message"])[:2000]
    history      = data.get("history", [])
    session_id   = str(data.get("session_id", "default"))

    # ── Branch 1: message contains a traffic sample → classify it ────────────
    features = _extract_features_from_text(user_message)
    if features is not None:
        try:
            prediction = predict(features)
        except Exception as e:
            return jsonify({"reply": f"[Prediction error: {e}]"})

        # Store for follow-up reasoning questions
        _last_prediction[session_id] = {
            "prediction": prediction,
            "features":   {k: v for k, v in features.items() if v != 0.0},
            "raw_text":   user_message,
        }
        _log_alert(prediction, source="chat")

        label      = prediction["label"]
        confidence = prediction["confidence"]
        severity   = prediction["severity"]
        is_attack  = prediction["is_attack"]
        probs      = prediction["probabilities"]

        # Build a rich context prompt so WatsonX can give a full answer
        top_feats = {k: v for k, v in features.items() if v != 0.0}
        prob_str  = ", ".join(f"{k}: {v*100:.1f}%" for k, v in sorted(
            probs.items(), key=lambda x: -x[1]))

        system_ctx = (
            f"The user submitted a network traffic sample for classification.\n"
            f"Extracted features: {top_feats}\n"
            f"ML model result   : {label} ({confidence}% confidence)\n"
            f"Class probabilities: {prob_str}\n"
            f"Severity          : {severity}\n"
            f"Is attack         : {is_attack}\n\n"
            f"User question: {user_message}\n\n"
            f"Answer in two parts:\n"
            f"1. State clearly whether this is normal traffic or an intrusion "
            f"(and the attack type if applicable), citing the confidence.\n"
            f"2. Give a brief technical explanation of why these feature values "
            f"indicate {label}, and (if it is an attack) list 2-3 mitigation steps."
        )
        reply = get_chat_response([], system_ctx)
        return jsonify({"reply": reply})

    # ── Branch 2: reasoning/explanation follow-up ─────────────────────────────
    if _is_reasoning_question(user_message):
        last = _last_prediction.get(session_id)
        if last:
            p         = last["prediction"]
            top_feats = last["features"]
            probs     = p["probabilities"]
            prob_str  = ", ".join(f"{k}: {v*100:.1f}%" for k, v in sorted(
                probs.items(), key=lambda x: -x[1]))

            system_ctx = (
                f"The user wants a detailed reasoning walkthrough for a recent classification.\n"
                f"Original traffic text: {last['raw_text']}\n"
                f"Features used (non-zero): {top_feats}\n"
                f"ML model result: {p['label']} ({p['confidence']}% confidence)\n"
                f"All class probabilities: {prob_str}\n"
                f"Severity: {p['severity']}\n\n"
                f"User question: {user_message}\n\n"
                f"Walk the user step-by-step through which specific feature values "
                f"most strongly influenced the {p['label']} classification, "
                f"referencing the NSL-KDD feature semantics. "
                f"Explain why the model preferred {p['label']} over the next-closest class."
            )
            reply = get_chat_response([], system_ctx)
            return jsonify({"reply": reply})
        else:
            # No prior prediction in this session — answer from general knowledge
            reply = get_chat_response(
                history,
                user_message + "\n\n(No traffic sample has been classified in this session yet. "
                "Answer from general NIDS/cybersecurity knowledge.)"
            )
            return jsonify({"reply": reply})

    # ── Branch 3: log / pattern query ─────────────────────────────────────────
    if _is_log_query(user_message):
        # Detect if user is asking specifically about a particular attack type
        label_filter = None
        for lbl in ("DoS", "Probe", "R2L", "U2R", "Normal"):
            if lbl.lower() in user_message.lower():
                label_filter = lbl
                break

        log_summary = _summarise_alert_log_for_prompt(label_filter)

        system_ctx = (
            f"{log_summary}\n\n"
            f"User question: {user_message}\n\n"
            f"Based on the alert log data above, answer the user's question. "
            f"If DoS patterns are present, describe the attack characteristics "
            f"and recommend immediate countermeasures. "
            f"If the log is empty, say so and suggest running a simulation first."
        )
        reply = get_chat_response([], system_ctx)
        return jsonify({"reply": reply})

    # ── Branch 4: general cybersecurity / fallback ────────────────────────────
    reply = get_chat_response(history, user_message)
    return jsonify({"reply": reply})


@app.route("/api/alerts/clear", methods=["DELETE"])
def clear_alerts():
    alert_log.clear()
    return jsonify({"status": "cleared"})


@app.route("/api/stats")
def stats():
    """Aggregate statistics from the alert log."""
    total    = len(alert_log)
    by_type  = {}
    by_sev   = {}
    for a in alert_log:
        by_type[a["label"]]    = by_type.get(a["label"],    0) + 1
        by_sev[a["severity"]]  = by_sev.get(a["severity"],  0) + 1
    return jsonify({
        "total_attacks": total,
        "by_type":       by_type,
        "by_severity":   by_sev
    })


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(host=HOST, port=PORT, debug=DEBUG)
