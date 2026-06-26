# 📧 Email Threat Analyzer

**A machine learning web app that scans email text and classifies it as Phishing or Safe — in real time, right in your browser.**

### 🔗 Live Demo
**[https://phishing-detector-iskq.onrender.com](https://phishing-detector-iskq.onrender.com)**

> Note: the app runs on a free hosting tier, so if it's been idle for a while, the first load can take 20–30 seconds to wake up. After that it responds instantly.

---

## What This Project Does

Paste any email — subject, body, links and all — into the scanner, and the app analyzes it using a trained machine learning model rather than a simple keyword blocklist. It returns:

- A clear **Phishing** or **Safe** verdict
- A confidence percentage
- A plain-English breakdown of *why* — which specific red flags (or lack of them) drove the decision

It also includes a Model Stats section showing the actual accuracy, confusion matrix, and which features the model relies on most, so the reasoning isn't a black box.

## How It Works (High Level)

1. **Feature extraction** — the raw email text is converted into 27 numerical signals: number of URLs, whether links use `http://` vs `https://`, suspicious shortened-link patterns, counts of phishing-style phrases ("verify," "urgent," "suspended") vs. normal business phrases ("meeting," "attached," "regards"), capital-letter ratio, generic greetings like "Dear Customer," presence of raw IP addresses, and more.
2. **Classification** — those 27 numbers are fed into a trained **Random Forest** model (an ensemble of 200 decision trees that each vote, with the majority vote becoming the final prediction).
3. **Result** — the app translates the model's output into a verdict, a probability score, and a human-readable list of the specific risk factors detected in that email.

## Tools & Technologies Used

| Layer | Tool | Purpose |
|---|---|---|
| **ML / Modeling** | scikit-learn | Trains and runs the Random Forest classifier |
| **Data handling** | pandas, NumPy | Feature engineering and numerical processing |
| **Backend** | Flask | Serves the web app and exposes the `/analyze` API endpoint |
| **Model persistence** | joblib | Saves/loads the trained model so it doesn't retrain on every request |
| **Frontend** | HTML, CSS, vanilla JavaScript | Dark-themed responsive UI, no frontend framework needed |
| **Production server** | Gunicorn | Runs the Flask app reliably in production |
| **Hosting** | Render | Free cloud hosting, auto-deploys from this repo |

## Model Performance

| Metric | Value |
|---|---|
| Algorithm | Random Forest (200 trees) |
| Accuracy | 100% on held-out test set |
| AUC-ROC | 1.00 |
| Training samples | 1,600 |
| Test samples | 400 |
| Features used | 27 |

**Top 5 most influential features:**
1. URL count (26.1%)
2. Use of insecure `http://` links (19.7%)
3. Ratio of phishing-style to safe-style keywords (15.4%)
4. Phishing keyword count (10.2%)
5. Safe/professional keyword count (7.8%)

> The model is trained on a synthetic, programmatically generated dataset of phishing and legitimate email examples — it demonstrates the full ML pipeline end-to-end, but real-world phishing is messier and more varied, so this is best treated as an educational/portfolio project rather than a production security tool.

## Project Structure

```
email-threat-analyzer/
├── app.py              
├── train_model.py      
├── requirements.txt    
├── Procfile             
├── templates/
│   └── index.html       
├── static/
│   ├── css/style.css
│   └── js/app.js        
└── model/                
    ├── phishing_model.pkl
    ├── feature_names.pkl
    └── metrics.pkl
```

## Running It Locally

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/email-threat-analyzer.git
cd email-threat-analyzer

# Install dependencies
pip install -r requirements.txt

# Train the model (creates the model/ folder)
python train_model.py

# Start the app
python app.py
```

Then open `http://localhost:5000` in your browser.

> You don't strictly need to run `train_model.py` yourself — `app.py` will automatically train the model on first startup if it doesn't find one already saved, so it self-heals even on a fresh deploy.

## API Reference

The same logic powering the UI is available as a simple JSON API:

```bash
curl -X POST https://phishing-detector-iskq.onrender.com/analyze \
  -H "Content-Type: application/json" \
  -d '{"email_text": "URGENT: Your account has been suspended! Click here: http://bit.ly/verify"}'
```

**Response:**
```json
{
  "prediction": 1,
  "label": "Phishing",
  "phishing_probability": 98.5,
  "safe_probability": 1.5,
  "confidence": "Very High",
  "risk_factors": [
    { "icon": "🔗", "label": "1 URL(s) detected", "severity": "medium" },
    { "icon": "⚠️", "label": "Uses insecure HTTP links", "severity": "high" }
  ],
  "features": { "url_count": 1, "phishing_keywords": 5 }
}
```

There's also a lightweight `/health` endpoint to confirm the model loaded correctly on the server.

## Deploying Your Own Copy

This repo deploys cleanly to Render's free tier:

1. Fork or push this repo to your own GitHub account.
2. On Render: **New +** → **Web Service** → connect your repo.
3. Build command: `pip install -r requirements.txt`
4. Start command: `gunicorn app:app`
5. Deploy — the app trains its own model automatically on first boot.

## Disclaimer

Built as an educational machine learning project to demonstrate feature engineering, ensemble classification, and full-stack ML deployment. It is not a substitute for enterprise email security tools and should not be relied upon as a sole line of defense against real phishing attacks.
