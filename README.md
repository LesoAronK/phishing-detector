# ⚡ PhishGuard — AI Phishing Email Detector

A machine learning web app that classifies emails as **Phishing** or **Safe** using a Random Forest classifier trained on 30+ extracted features.

![Python](https://img.shields.io/badge/Python-3.11-blue)
![Flask](https://img.shields.io/badge/Flask-3.0-green)
![scikit-learn](https://img.shields.io/badge/scikit--learn-1.5-orange)

## Features

- **ML Model**: Random Forest with 200 estimators, 100% test accuracy
- **30+ Features**: URL count, phishing keywords, caps ratio, urgency signals, HTML tags, IP addresses, and more
- **Real-time Analysis**: Instant verdict with probability scores
- **Risk Factors**: Human-readable breakdown of suspicious signals
- **Dark UI**: Modern, responsive interface

## Quick Start

```bash
# 1. Clone
git clone https://github.com/YOUR_USERNAME/phishguard.git
cd phishguard

# 2. Install dependencies
pip install -r requirements.txt

# 3. Train the model (creates model/ directory)
python train_model.py

# 4. Run the app
python app.py
```

Open `http://localhost:5000` in your browser.

## Project Structure

```
phishguard/
├── app.py              # Flask backend + feature extraction
├── train_model.py      # Model training script
├── requirements.txt
├── Procfile            # For Railway/Heroku deployment
├── model/              # Generated after training
│   ├── phishing_model.pkl
│   ├── feature_names.pkl
│   └── metrics.pkl
├── templates/
│   └── index.html
└── static/
    ├── css/style.css
    └── js/app.js
```

## Model Details

| Metric | Value |
|--------|-------|
| Algorithm | Random Forest |
| Estimators | 200 |
| Test Accuracy | 100% |
| AUC-ROC | 1.00 |
| Training Samples | 1,600 |
| Test Samples | 400 |

### Top Features by Importance
1. URL Count (26.1%)
2. HTTP Links Present (19.7%)
3. Keyword Ratio (15.4%)
4. Phishing Keyword Count (10.2%)
5. Safe Keyword Count (7.8%)

## Deploy to Railway

1. Push to GitHub
2. Go to [railway.app](https://railway.app) → New Project → Deploy from GitHub
3. Set `python train_model.py && gunicorn app:app` as start command
4. Done!

## Deploy to Render

1. Push to GitHub
2. New Web Service on [render.com](https://render.com)
3. Build Command: `pip install -r requirements.txt && python train_model.py`
4. Start Command: `gunicorn app:app`

## API Usage

```bash
curl -X POST http://localhost:5000/analyze \
  -H "Content-Type: application/json" \
  -d '{"email_text": "URGENT: Your account has been suspended! Click here: http://bit.ly/verify"}'
```

Response:
```json
{
  "prediction": 1,
  "label": "Phishing",
  "phishing_probability": 98.5,
  "safe_probability": 1.5,
  "confidence": "Very High",
  "risk_factors": [...],
  "features": {...}
}
```

## Disclaimer

This tool is for **educational purposes**. The model is trained on synthetic data and should not be relied upon as the sole security measure.
