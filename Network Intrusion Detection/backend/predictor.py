"""
predictor.py
Loads the trained model/scaler and exposes a predict() helper.
"""

import os
import pickle
import numpy as np
import pandas as pd

BASE_DIR     = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH   = os.path.join(BASE_DIR, "models", "nids_model.pkl")
SCALER_PATH  = os.path.join(BASE_DIR, "models", "scaler.pkl")
ENCODER_PATH = os.path.join(BASE_DIR, "models", "label_encoder.pkl")

FEATURE_NAMES = [
    "duration", "protocol_type", "service", "flag",
    "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent",
    "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count",
    "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate"
]

_model   = None
_scaler  = None
_encoder = None


def _load_artifacts():
    global _model, _scaler, _encoder
    if _model is None:
        with open(MODEL_PATH,   "rb") as f: _model   = pickle.load(f)
        with open(SCALER_PATH,  "rb") as f: _scaler  = pickle.load(f)
        with open(ENCODER_PATH, "rb") as f: _encoder = pickle.load(f)


def predict(features: dict) -> dict:
    """
    Parameters
    ----------
    features : dict  {feature_name: value, …}

    Returns
    -------
    dict  {label, confidence, probabilities, is_attack, severity}
    """
    _load_artifacts()

    row = [float(features.get(f, 0)) for f in FEATURE_NAMES]
    X   = np.array(row).reshape(1, -1)
    X   = _scaler.transform(X)

    proba  = _model.predict_proba(X)[0]
    idx    = int(np.argmax(proba))
    label  = _encoder.classes_[idx]
    conf   = float(proba[idx])

    prob_map = {cls: float(p)
                for cls, p in zip(_encoder.classes_, proba)}

    severity_map = {"Normal": "none", "DoS": "critical",
                    "Probe": "medium", "R2L": "high", "U2R": "critical"}

    return {
        "label":         label,
        "confidence":    round(conf * 100, 2),
        "probabilities": prob_map,
        "is_attack":     label != "Normal",
        "severity":      severity_map.get(label, "unknown")
    }


def predict_batch(df: pd.DataFrame) -> list:
    """Run predict() on every row of a DataFrame."""
    _load_artifacts()
    results = []
    for _, row in df.iterrows():
        results.append(predict(row.to_dict()))
    return results
