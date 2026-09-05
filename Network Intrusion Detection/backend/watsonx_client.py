"""
watsonx_client.py
Calls the IBM WatsonX text-generation endpoint to produce a natural-language
explanation / recommendation for a given NIDS prediction result.
"""

import time
import requests
from backend.config import (
    WATSONX_URL, WATSONX_API_KEY, WATSONX_PROJECT_ID, WATSONX_MODEL_ID
)

# ── IAM token cache (refreshes 5 min before expiry) ──────────────────────────
_iam_token: str | None = None
_iam_token_expiry: float = 0.0   # unix timestamp


def _get_iam_token() -> str:
    global _iam_token, _iam_token_expiry
    # Refresh if missing or expiring within 5 minutes
    if _iam_token is None or time.time() >= _iam_token_expiry - 300:
        resp = requests.post(
            "https://iam.cloud.ibm.com/identity/token",
            data={
                "grant_type": "urn:ibm:params:oauth:grant-type:apikey",
                "apikey":     WATSONX_API_KEY,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=30
        )
        resp.raise_for_status()
        body = resp.json()
        _iam_token = body["access_token"]
        # IBM IAM tokens are valid for 3600 s; honour expiration field if present
        _iam_token_expiry = time.time() + body.get("expires_in", 3600)
    return _iam_token


def get_ai_explanation(prediction: dict) -> str:
    """
    Given a prediction dict (label, confidence, severity, probabilities),
    ask WatsonX to explain the threat and suggest remediation steps.
    """
    label      = prediction.get("label", "Unknown")
    confidence = prediction.get("confidence", 0)
    severity   = prediction.get("severity", "unknown")

    prompt = f"""You are a cybersecurity expert specialising in Network Intrusion Detection.

A machine-learning model has classified a network traffic sample with the following result:
- Attack Type  : {label}
- Confidence   : {confidence}%
- Severity     : {severity}

Provide:
1. A concise explanation (2-3 sentences) of what this attack type means.
2. The likely impact on the target system.
3. Three concrete remediation / mitigation steps a network administrator should take immediately.

Keep the response structured and professional."""

    try:
        token = _get_iam_token()
    except Exception as e:
        return f"[WatsonX unavailable – IAM token error: {e}]"

    payload = {
        "model_id":   WATSONX_MODEL_ID,
        "project_id": WATSONX_PROJECT_ID,
        "input":      prompt,
        "parameters": {
            "decoding_method": "greedy",
            "max_new_tokens":  400,
            "temperature":     0.7,
            "repetition_penalty": 1.1
        }
    }

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json",
        "Accept":        "application/json"
    }

    try:
        resp = requests.post(WATSONX_URL, json=payload,
                             headers=headers, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        return data["results"][0]["generated_text"].strip()
    except Exception as e:
        return f"[WatsonX error: {e}]"


def get_chat_response(history: list, user_message: str) -> str:
    """
    Given a conversation history and a new user message, ask WatsonX to
    respond as a cybersecurity expert assistant.

    history: list of {"role": "user"|"assistant", "content": str}
    """
    conversation = ""
    for turn in history:
        role = "User" if turn["role"] == "user" else "Assistant"
        conversation += f"{role}: {turn['content']}\n"
    conversation += f"User: {user_message}\nAssistant:"

    prompt = f"""You are an expert cybersecurity assistant specialising in Network Intrusion Detection Systems (NIDS), network security, and threat analysis. Answer clearly and concisely. If the question is unrelated to cybersecurity, politely redirect to security topics.

{conversation}"""

    try:
        token = _get_iam_token()
    except Exception as e:
        return f"[WatsonX unavailable – IAM token error: {e}]"

    payload = {
        "model_id":   WATSONX_MODEL_ID,
        "project_id": WATSONX_PROJECT_ID,
        "input":      prompt,
        "parameters": {
            "decoding_method": "greedy",
            "max_new_tokens":  500,
            "temperature":     0.7,
            "repetition_penalty": 1.1,
            "stop_sequences": ["\nUser:"]
        }
    }

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json",
        "Accept":        "application/json"
    }

    try:
        resp = requests.post(WATSONX_URL, json=payload,
                             headers=headers, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        return data["results"][0]["generated_text"].strip()
    except Exception as e:
        return f"[WatsonX error: {e}]"
