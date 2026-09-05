import sys, os
sys.path.insert(0, '.')
from backend.predictor import predict, FEATURE_NAMES
from backend.app import app

print("=" * 55)
print("  NIDS AGENT - FULL VALIDATION REPORT")
print("=" * 55)

# ── 1. Model artifacts ────────────────────────────────────
print("\n[1] MODEL ARTIFACTS")
for f in ['models/nids_model.pkl','models/scaler.pkl','models/label_encoder.pkl']:
    size = os.path.getsize(f)
    print(f"    {f}: {size:,} bytes  OK")

# ── 2. Feature count ──────────────────────────────────────
print(f"\n[2] NSL-KDD FEATURES: {len(FEATURE_NAMES)} features loaded  OK")

# ── 3. All 5 attack categories ────────────────────────────
print("\n[3] ML CLASSIFICATION - ALL 5 CATEGORIES")
scenarios = {
    'Normal': dict(serror_rate=0.01, rerror_rate=0.01, same_srv_rate=0.95, count=20, src_bytes=4000, dst_bytes=3000, logged_in=1),
    'DoS'   : dict(serror_rate=0.95, rerror_rate=0.90, count=500, src_bytes=100, dst_bytes=0),
    'Probe' : dict(rerror_rate=0.80, diff_srv_rate=0.70, same_srv_rate=0.05, count=200),
    'R2L'   : dict(duration=20, src_bytes=18000, dst_bytes=9000, count=2, logged_in=1),
    'U2R'   : dict(root_shell=1, su_attempted=1, num_root=5, num_shells=3, duration=10),
}

passes = 0
for name, feats in scenarios.items():
    base = {f: 0.0 for f in FEATURE_NAMES}
    base.update(feats)
    r = predict(base)
    ok = r['label'] == name
    passes += int(ok)
    tag = "PASS" if ok else ("CLOSE" if r['confidence'] < 50 else "FAIL")
    print(f"    {name:8s} => predicted: {r['label']:8s} | {r['confidence']:5.1f}% conf | severity: {r['severity']:8s} | [{tag}]")

print(f"\n    Score: {passes}/5 categories correctly classified")

# ── 4. API routes ─────────────────────────────────────────
print("\n[4] FLASK API ROUTES")
expected = ['/api/health','/api/features','/api/predict',
            '/api/predict/batch','/api/simulate','/api/alerts',
            '/api/alerts/clear','/api/stats']
registered = [r.rule for r in app.url_map.iter_rules()]
for ep in expected:
    found = ep in registered
    print(f"    {'OK' if found else 'MISSING':6s} {ep}")

# ── 5. Frontend files ─────────────────────────────────────
print("\n[5] FRONTEND FILES")
fe_files = [
    'frontend/templates/index.html',
    'frontend/static/css/style.css',
    'frontend/static/js/app.js',
    'frontend/static/js/charts.js',
]
for f in fe_files:
    size = os.path.getsize(f)
    lines = open(f, encoding='utf-8').read().count('\n')
    print(f"    OK  {f} ({lines} lines, {size:,} bytes)")

# ── 6. WatsonX config ─────────────────────────────────────
print("\n[6] WATSONX AI CONFIG")
from backend.config import WATSONX_URL, WATSONX_MODEL_ID, WATSONX_PROJECT_ID
print(f"    URL      : {WATSONX_URL[:60]}...")
print(f"    Model    : {WATSONX_MODEL_ID}")
print(f"    Project  : {WATSONX_PROJECT_ID}")

# ── 7. Predict response structure ─────────────────────────
print("\n[7] PREDICTION RESPONSE STRUCTURE")
base = {f: 0.0 for f in FEATURE_NAMES}
base['serror_rate'] = 0.95
base['count'] = 450
r = predict(base)
required_keys = ['label','confidence','probabilities','is_attack','severity']
for k in required_keys:
    print(f"    {k}: {str(r.get(k, 'MISSING'))[:40]}")

# ── 8. Batch inference ────────────────────────────────────
print("\n[8] BATCH INFERENCE")
import pandas as pd
from backend.predictor import predict_batch
rows = []
for _ in range(10):
    import random
    row = {f: random.uniform(0,1) for f in FEATURE_NAMES}
    rows.append(row)
df = pd.DataFrame(rows)
results = predict_batch(df)
labels = [r['label'] for r in results]
print(f"    Processed 10 samples => {dict((l, labels.count(l)) for l in set(labels))}")

# ── 9. Chat dispatcher smoke tests ───────────────────────────────────────────
print("\n[9] CHAT DISPATCHER - ALL 5 QUESTION TYPES")
from backend.app import (
    _extract_features_from_text, _is_reasoning_question,
    _is_log_query, _summarise_alert_log_for_prompt,
    alert_log, _last_prediction
)

chat_tests = [
    # (description, question, expected_branch)
    (
        "Basic classification",
        "Analyze this traffic: duration=0, protocol=tcp, service=http, flag=SF, src_bytes=215, dst_bytes=45076",
        "feature_extraction"
    ),
    (
        "Attack-type detection",
        "Classify this flow: duration=0, protocol=icmp, service=eco_i, flag=SF, src_bytes=1032, dst_bytes=0, count=511",
        "feature_extraction"
    ),
    (
        "Reasoning follow-up",
        "Why did you classify the last traffic sample the way you did? Walk me through your reasoning.",
        "reasoning"
    ),
    (
        "Log / DoS pattern query",
        "Check the current traffic log for any DoS attack patterns and summarize the findings.",
        "log_query"
    ),
    (
        "Edge-case classification",
        "This traffic looks unusual — protocol=udp, service=private, flag=REJ, src_bytes=0, dst_bytes=0. Is this an intrusion?",
        "feature_extraction"
    ),
]

all_pass = True
for desc, question, expected in chat_tests:
    branch = "fallback"
    feats = _extract_features_from_text(question)
    if feats is not None:
        branch = "feature_extraction"
        # Run the actual prediction
        pred = predict(feats)
        _last_prediction["__validate__"] = {
            "prediction": pred,
            "features":   {k: v for k, v in feats.items() if v != 0.0},
            "raw_text":   question,
        }
        result_str = f"=> {pred['label']} ({pred['confidence']}% conf, severity={pred['severity']})"
    elif _is_reasoning_question(question):
        branch = "reasoning"
        has_prior = "__validate__" in _last_prediction
        result_str = f"=> has prior prediction: {has_prior}"
    elif _is_log_query(question):
        branch = "log_query"
        summary = _summarise_alert_log_for_prompt()
        result_str = f"=> {summary[:60]}..."
    else:
        result_str = "=> fallback to WatsonX"

    ok  = branch == expected
    tag = "PASS" if ok else "FAIL"
    all_pass = all_pass and ok
    print(f"    [{tag}] {desc}")
    print(f"           branch={branch}  {result_str}")

print(f"\n    Chat dispatcher: {'ALL PASS' if all_pass else 'SOME FAILURES'}")

print("\n" + "=" * 55)
print("  ALL CHECKS COMPLETE")
print("=" * 55)
