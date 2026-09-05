# Network Intrusion Detection System (NIDS) Agent

A full-stack AI-powered Network Intrusion Detection System that classifies network traffic using Machine Learning and explains threats using **IBM WatsonX AI (Llama 4 Maverick)**.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    NIDS Agent                            │
│                                                         │
│  ┌──────────────────┐    ┌─────────────────────────┐   │
│  │  Frontend (HTML) │    │  Backend (Flask)         │   │
│  │  • Dashboard     │◄──►│  • /api/predict          │   │
│  │  • Single Predict│    │  • /api/predict/batch    │   │
│  │  • Batch Upload  │    │  • /api/simulate         │   │
│  │  • Live Simulate │    │  • /api/alerts           │   │
│  │  • Alert Log     │    │  • /api/stats            │   │
│  └──────────────────┘    └────────────┬────────────┘   │
│                                        │                │
│                           ┌────────────▼────────────┐  │
│                           │  ML Model (Random Forest)│  │
│                           │  + IBM WatsonX AI        │  │
│                           │  (Llama 4 Maverick)      │  │
│                           └─────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Train the ML model (one-time)
```bash
python backend/model_trainer.py
```

### 3. Set your WatsonX credentials
```bash
cp .env.example .env
# Edit .env and set WATSONX_API_KEY
```

### 4. Run the application
```bash
python run.py
```

Open **http://localhost:5000** in your browser.

---

## 🧠 ML Model

| Property      | Value                          |
|--------------|-------------------------------|
| Algorithm    | Random Forest (150 trees)      |
| Dataset      | Synthetic NSL-KDD-style        |
| Features     | 41 NSL-KDD traffic features    |
| Classes      | Normal, DoS, Probe, R2L, U2R  |
| Accuracy     | ~95%+ on synthetic data        |

## 🤖 IBM WatsonX Integration

| Property      | Value                                      |
|--------------|--------------------------------------------|
| URL          | https://eu-gb.ml.cloud.ibm.com/...        |
| Model        | meta-llama/llama-4-maverick-17b-128e-instruct-fp8 |
| Project ID   | 46251c34-6c9f-41b0-94b5-bdba509c7dcf     |
| Purpose      | Natural-language threat explanation + remediation |

## 📁 Project Structure

```
Network Intrusion Detection/
├── backend/
│   ├── __init__.py
│   ├── app.py               # Flask REST API
│   ├── config.py            # Configuration
│   ├── model_trainer.py     # Train & save ML model
│   ├── predictor.py         # Inference logic
│   └── watsonx_client.py    # IBM WatsonX integration
├── frontend/
│   ├── templates/
│   │   └── index.html       # Main dashboard
│   └── static/
│       ├── css/style.css    # Dark theme styles
│       └── js/
│           ├── app.js       # Application logic
│           └── charts.js    # Canvas charts
├── models/                  # Saved model artifacts (auto-created)
├── data/uploads/            # CSV upload staging area
├── run.py                   # Application entry point
├── requirements.txt
└── .env.example
```

## 🌐 API Reference

| Method | Endpoint              | Description                      |
|--------|-----------------------|----------------------------------|
| GET    | `/api/health`         | Health check                     |
| GET    | `/api/features`       | List 41 feature names            |
| POST   | `/api/predict`        | Single JSON prediction           |
| POST   | `/api/predict/batch`  | Batch CSV upload prediction      |
| GET    | `/api/simulate`       | Synthetic traffic simulation     |
| GET    | `/api/alerts`         | Fetch alert log                  |
| DELETE | `/api/alerts/clear`   | Clear alert log                  |
| GET    | `/api/stats`          | Aggregate statistics             |

## 🔐 Attack Categories

| Type   | Description                                      | Severity |
|--------|--------------------------------------------------|----------|
| Normal | Legitimate network traffic                       | None     |
| DoS    | Denial-of-Service — resource exhaustion attacks  | Critical |
| Probe  | Network scanning / reconnaissance                | Medium   |
| R2L    | Remote-to-Local — unauthorized remote access     | High     |
| U2R    | User-to-Root — privilege escalation              | Critical |
