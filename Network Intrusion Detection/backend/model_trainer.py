"""
model_trainer.py
Trains a Random-Forest classifier on a synthetic NSL-KDD-style dataset
and persists both the model and the feature scaler to disk.

Run once:  python backend/model_trainer.py
"""

import os
import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH  = os.path.join(BASE_DIR, "models", "nids_model.pkl")
SCALER_PATH = os.path.join(BASE_DIR, "models", "scaler.pkl")
ENCODER_PATH= os.path.join(BASE_DIR, "models", "label_encoder.pkl")

# ── Feature names (NSL-KDD subset) ───────────────────────────────────────────
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

NUMERIC_FEATURES = [
    "duration", "src_bytes", "dst_bytes", "wrong_fragment", "urgent",
    "hot", "num_failed_logins", "num_compromised", "num_root",
    "num_file_creations", "num_shells", "num_access_files",
    "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
]

ATTACK_CATEGORIES = ["Normal", "DoS", "Probe", "R2L", "U2R"]


def generate_synthetic_data(n_samples: int = 5000) -> pd.DataFrame:
    """Generate a synthetic NSL-KDD-style DataFrame for demo training."""
    np.random.seed(42)
    rows = []
    labels = []

    per_class = n_samples // len(ATTACK_CATEGORIES)

    for label in ATTACK_CATEGORIES:
        for _ in range(per_class):
            row = {}
            if label == "Normal":
                row["duration"]           = np.random.exponential(2)
                row["src_bytes"]          = np.random.randint(100, 5000)
                row["dst_bytes"]          = np.random.randint(100, 5000)
                row["serror_rate"]        = np.random.uniform(0, 0.1)
                row["rerror_rate"]        = np.random.uniform(0, 0.05)
                row["same_srv_rate"]      = np.random.uniform(0.8, 1.0)
                row["count"]              = np.random.randint(1, 100)
                row["srv_count"]          = np.random.randint(1, 100)
            elif label == "DoS":
                row["duration"]           = np.random.exponential(0.5)
                row["src_bytes"]          = np.random.randint(0, 500)
                row["dst_bytes"]          = 0
                row["serror_rate"]        = np.random.uniform(0.7, 1.0)
                row["rerror_rate"]        = np.random.uniform(0.5, 1.0)
                row["same_srv_rate"]      = np.random.uniform(0.9, 1.0)
                row["count"]              = np.random.randint(200, 512)
                row["srv_count"]          = np.random.randint(200, 512)
            elif label == "Probe":
                row["duration"]           = np.random.exponential(1)
                row["src_bytes"]          = np.random.randint(10, 300)
                row["dst_bytes"]          = np.random.randint(10, 300)
                row["serror_rate"]        = np.random.uniform(0, 0.3)
                row["rerror_rate"]        = np.random.uniform(0.3, 0.9)
                row["same_srv_rate"]      = np.random.uniform(0.0, 0.4)
                row["count"]              = np.random.randint(10, 255)
                row["srv_count"]          = np.random.randint(1, 50)
            elif label == "R2L":
                row["duration"]           = np.random.exponential(10)
                row["src_bytes"]          = np.random.randint(1000, 20000)
                row["dst_bytes"]          = np.random.randint(500, 10000)
                row["serror_rate"]        = np.random.uniform(0, 0.1)
                row["rerror_rate"]        = np.random.uniform(0, 0.1)
                row["same_srv_rate"]      = np.random.uniform(0.5, 1.0)
                row["count"]              = np.random.randint(1, 10)
                row["srv_count"]          = np.random.randint(1, 10)
            else:  # U2R — strong privilege-escalation signature
                row["duration"]           = np.random.exponential(5)
                row["src_bytes"]          = np.random.randint(500, 5000)
                row["dst_bytes"]          = np.random.randint(200, 3000)
                row["serror_rate"]        = np.random.uniform(0, 0.1)
                row["rerror_rate"]        = np.random.uniform(0, 0.1)
                row["same_srv_rate"]      = np.random.uniform(0.4, 0.9)
                row["count"]              = np.random.randint(1, 15)
                row["srv_count"]          = np.random.randint(1, 15)
                # Hallmark U2R features — always set
                row["root_shell"]         = 1
                row["su_attempted"]       = 1
                row["num_root"]           = np.random.randint(3, 20)
                row["num_shells"]         = np.random.randint(1, 5)
                row["num_compromised"]    = np.random.randint(2, 15)
                row["num_file_creations"] = np.random.randint(1, 8)

            # Fill remaining numeric features with noise
            for f in NUMERIC_FEATURES:
                if f not in row:
                    row[f] = np.random.uniform(0, 1)

            # Categorical features (encoded as integers for simplicity)
            row["protocol_type"] = np.random.randint(0, 3)
            row["service"]       = np.random.randint(0, 70)
            row["flag"]          = np.random.randint(0, 11)
            row["land"]          = np.random.randint(0, 2)
            row["logged_in"]     = np.random.randint(0, 2)
            row["is_host_login"] = 0
            row["is_guest_login"]= np.random.randint(0, 2)
            # For non-U2R: randomise root_shell/su_attempted
            if label != "U2R":
                row["root_shell"]    = np.random.randint(0, 2)
                row["su_attempted"]  = np.random.randint(0, 2)
            row["num_outbound_cmds"] = 0

            rows.append(row)
            labels.append(label)

    df = pd.DataFrame(rows, columns=FEATURE_NAMES)
    df["label"] = labels
    return df.sample(frac=1, random_state=42).reset_index(drop=True)


def train_and_save():
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)

    print("Generating synthetic training data …")
    df = generate_synthetic_data(5000)

    X = df[FEATURE_NAMES].values
    y = df["label"].values

    le = LabelEncoder()
    y_enc = le.fit_transform(y)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y_enc, test_size=0.2, random_state=42, stratify=y_enc
    )

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test  = scaler.transform(X_test)

    print("Training Random Forest …")
    clf = RandomForestClassifier(n_estimators=150, max_depth=20,
                                  random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    print(f"\nAccuracy: {accuracy_score(y_test, y_pred):.4f}")
    print(classification_report(y_test, y_pred, target_names=le.classes_))

    with open(MODEL_PATH,  "wb") as f: pickle.dump(clf, f)
    with open(SCALER_PATH, "wb") as f: pickle.dump(scaler, f)
    with open(ENCODER_PATH,"wb") as f: pickle.dump(le, f)

    print(f"\nModel   saved: {MODEL_PATH}")
    print(f"Scaler  saved: {SCALER_PATH}")
    print(f"Encoder saved: {ENCODER_PATH}")


if __name__ == "__main__":
    train_and_save()
