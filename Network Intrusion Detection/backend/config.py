"""
Configuration for the NIDS backend.
Sensitive values are read from environment variables with sensible defaults
for local development.  Never commit real credentials.
"""
import os

# ── IBM WatsonX ──────────────────────────────────────────────────────────────
WATSONX_URL     = os.getenv("WATSONX_URL",
                             "https://eu-gb.ml.cloud.ibm.com/ml/v1/text/generation?version=2023-05-29")
WATSONX_API_KEY = os.getenv("WATSONX_API_KEY",
                             "d3VDCTIfcolrVjCaXavyMmJQsPCH2tH9RJutlD0DvsXZ")
WATSONX_PROJECT_ID = os.getenv("WATSONX_PROJECT_ID",
                                "46251c34-6c9f-41b0-94b5-bdba509c7dcf")
WATSONX_MODEL_ID   = os.getenv("WATSONX_MODEL_ID",
                                "meta-llama/llama-4-maverick-17b-128e-instruct-fp8")

# ── Flask ─────────────────────────────────────────────────────────────────────
SECRET_KEY   = os.getenv("SECRET_KEY", "nids-secret-2024")
DEBUG        = os.getenv("DEBUG", "true").lower() == "true"
HOST         = os.getenv("HOST", "0.0.0.0")
PORT         = int(os.getenv("PORT", 5000))

# ── Model / data ──────────────────────────────────────────────────────────────
MODEL_PATH   = os.path.join(os.path.dirname(__file__), "..", "models", "nids_model.pkl")
SCALER_PATH  = os.path.join(os.path.dirname(__file__), "..", "models", "scaler.pkl")
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "..", "data", "uploads")
MAX_CONTENT_LENGTH = 16 * 1024 * 1024   # 16 MB
