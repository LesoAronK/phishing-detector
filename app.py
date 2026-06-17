"""
Phishing Email Detector - Flask Backend
"""

from flask import Flask, render_template, request, jsonify
import joblib
import numpy as np
import re
import os
import sys
import subprocess

app = Flask(__name__)

# ─── Load model ────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, 'model', 'phishing_model.pkl')
FEATURES_PATH = os.path.join(BASE_DIR, 'model', 'feature_names.pkl')
METRICS_PATH = os.path.join(BASE_DIR, 'model', 'metrics.pkl')

model = None
feature_names = None
metrics = None


def load_model():
    """Load the trained model. If the model files are missing for any reason
    (e.g. build step didn't run, or filesystem was reset), train it on the fly
    so the app can never end up serving with model=None."""
    global model, feature_names, metrics

    if not (os.path.exists(MODEL_PATH) and os.path.exists(FEATURES_PATH) and os.path.exists(METRICS_PATH)):
        print(">>> Model files missing — training now (one-time, ~10-20s)...", flush=True)
        train_script = os.path.join(BASE_DIR, 'train_model.py')
        result = subprocess.run(
            [sys.executable, train_script],
            cwd=BASE_DIR,
            capture_output=True,
            text=True
        )
        print(result.stdout, flush=True)
        if result.returncode != 0:
            print(">>> TRAINING FAILED:", result.stderr, flush=True)
            raise RuntimeError(f"Model training failed: {result.stderr}")

    model = joblib.load(MODEL_PATH)
    feature_names = joblib.load(FEATURES_PATH)
    metrics = joblib.load(METRICS_PATH)
    print(">>> Model loaded successfully. Features:", len(feature_names), flush=True)


# ─── Feature Extraction (mirrors train_model.py) ───────────────────────────────
PHISHING_KEYWORDS = [
    'verify', 'account', 'suspended', 'urgent', 'immediately', 'click here',
    'confirm', 'update', 'password', 'login', 'bank', 'credit card', 'paypal',
    'amazon', 'microsoft', 'apple', 'secure', 'limited time', 'expires',
    'winner', 'prize', 'congratulations', 'free', 'claim', 'act now',
    'unusual activity', 'unauthorized', 'locked', 'verify your identity',
    'validate', 'billing', 'invoice', 'refund', 'transaction failed',
    'dear customer', 'dear user', 'valued member', 'your account',
    'security alert', 'warning', 'attention required', 'action required'
]

SAFE_KEYWORDS = [
    'meeting', 'project', 'report', 'schedule', 'team', 'update',
    'please find', 'attached', 'regards', 'sincerely', 'kind regards',
    'as discussed', 'following up', 'feedback', 'review', 'proposal',
    'thank you', 'thanks', 'appreciate', 'best wishes', 'looking forward'
]

SUSPICIOUS_URL_PATTERNS = [
    r'bit\.ly', r'tinyurl', r'goo\.gl', r't\.co', r'ow\.ly',
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
    r'paypal.*\.com(?!$)', r'amazon.*\.net', r'microsoft.*\.info',
    r'login.*\.(xyz|tk|ml|ga|cf|gq)', r'secure.*\.(xyz|tk|ml)',
    r'account.*\.(xyz|tk|ml|ga|cf|gq)',
]


def extract_features(text: str) -> dict:
    text_lower = text.lower()
    words = text_lower.split()
    features = {}

    features['text_length'] = len(text)
    features['word_count'] = len(words)
    features['avg_word_length'] = np.mean([len(w) for w in words]) if words else 0
    features['sentence_count'] = text.count('.') + text.count('!') + text.count('?')

    features['phishing_keyword_count'] = sum(1 for kw in PHISHING_KEYWORDS if kw in text_lower)
    features['safe_keyword_count'] = sum(1 for kw in SAFE_KEYWORDS if kw in text_lower)
    features['keyword_ratio'] = features['phishing_keyword_count'] / max(features['safe_keyword_count'], 1)

    urls = re.findall(r'https?://\S+|www\.\S+', text_lower)
    features['url_count'] = len(urls)
    features['has_http'] = int('http://' in text_lower)
    features['has_https'] = int('https://' in text_lower)
    features['suspicious_url_count'] = sum(
        1 for pattern in SUSPICIOUS_URL_PATTERNS
        if any(re.search(pattern, url) for url in urls)
    )

    features['exclamation_count'] = text.count('!')
    features['caps_ratio'] = sum(1 for c in text if c.isupper()) / max(len(text), 1)
    features['has_urgent_words'] = int(
        any(w in text_lower for w in ['urgent', 'immediately', 'asap', 'act now', 'expires'])
    )

    features['has_generic_greeting'] = int(
        any(g in text_lower for g in ['dear customer', 'dear user', 'valued member', 'dear account holder'])
    )
    features['has_personal_greeting'] = int(
        any(g in text_lower for g in ['hi ', 'hello ', 'dear '])
    )

    features['dollar_sign_count'] = text.count('$')
    features['percent_sign_count'] = text.count('%')
    features['question_mark_count'] = text.count('?')

    features['has_html_tags'] = int(bool(re.search(r'<[^>]+>', text)))
    features['has_script_tag'] = int('<script' in text_lower)
    features['has_form_tag'] = int('<form' in text_lower)

    features['has_ip_address'] = int(bool(re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', text)))
    features['has_login_link'] = int('login' in text_lower and ('http' in text_lower or 'click' in text_lower))
    features['has_verify_link'] = int('verify' in text_lower and ('http' in text_lower or 'click' in text_lower))
    features['has_attachment_mention'] = int(
        any(w in text_lower for w in ['attachment', 'attached', 'open this', 'download'])
    )

    features['digit_ratio'] = sum(1 for c in text if c.isdigit()) / max(len(text), 1)
    return features


def get_risk_factors(text: str, features: dict) -> list:
    factors = []
    text_lower = text.lower()

    if features['url_count'] > 0:
        factors.append({"icon": "🔗", "label": f"{features['url_count']} URL(s) detected", "severity": "medium"})
    if features['has_http']:
        factors.append({"icon": "⚠️", "label": "Uses insecure HTTP links", "severity": "high"})
    if features['suspicious_url_count'] > 0:
        factors.append({"icon": "🚨", "label": f"{features['suspicious_url_count']} suspicious URL pattern(s)", "severity": "high"})
    if features['has_ip_address']:
        factors.append({"icon": "🚨", "label": "Contains IP address (unusual for legitimate email)", "severity": "high"})
    if features['phishing_keyword_count'] > 3:
        factors.append({"icon": "🔑", "label": f"{features['phishing_keyword_count']} phishing keywords found", "severity": "high"})
    elif features['phishing_keyword_count'] > 0:
        factors.append({"icon": "🔑", "label": f"{features['phishing_keyword_count']} suspicious keyword(s)", "severity": "medium"})
    if features['has_urgent_words']:
        factors.append({"icon": "⏰", "label": "Creates artificial urgency", "severity": "high"})
    if features['has_generic_greeting']:
        factors.append({"icon": "👤", "label": "Generic impersonal greeting used", "severity": "medium"})
    if features['exclamation_count'] > 2:
        factors.append({"icon": "❗", "label": f"Excessive exclamation marks ({features['exclamation_count']})", "severity": "low"})
    if features['caps_ratio'] > 0.15:
        factors.append({"icon": "🔠", "label": f"High use of capital letters ({features['caps_ratio']*100:.0f}%)", "severity": "medium"})
    if features['dollar_sign_count'] > 0:
        factors.append({"icon": "💲", "label": f"Contains monetary references ({features['dollar_sign_count']} $ signs)", "severity": "low"})
    if features['has_html_tags']:
        factors.append({"icon": "🏷️", "label": "Contains HTML markup", "severity": "low"})
    if features['has_login_link']:
        factors.append({"icon": "🔐", "label": "Contains login link — verify the domain carefully", "severity": "high"})
    if features['has_verify_link']:
        factors.append({"icon": "✅", "label": "Contains verification link — common phishing tactic", "severity": "high"})
    if features['safe_keyword_count'] > 2:
        factors.append({"icon": "✔️", "label": f"{features['safe_keyword_count']} professional/safe keywords found", "severity": "safe"})

    return factors


# ─── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html', metrics=metrics)


@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    email_text = data.get('email_text', '').strip()

    if not email_text:
        return jsonify({'error': 'No email text provided'}), 400

    if len(email_text) < 10:
        return jsonify({'error': 'Email text too short'}), 400

    features = extract_features(email_text)
    feature_vector = [features.get(f, 0) for f in feature_names]

    import pandas as pd
    X_df = pd.DataFrame([feature_vector], columns=feature_names)

    prediction = int(model.predict(X_df)[0])
    probability = model.predict_proba(X_df)[0]

    phishing_prob = float(probability[1])
    safe_prob = float(probability[0])

    if phishing_prob >= 0.85:
        confidence = 'Very High'
    elif phishing_prob >= 0.65:
        confidence = 'High'
    elif phishing_prob >= 0.45:
        confidence = 'Moderate'
    else:
        confidence = 'Low'

    risk_factors = get_risk_factors(email_text, features)

    return jsonify({
        'prediction': prediction,
        'label': 'Phishing' if prediction == 1 else 'Safe',
        'phishing_probability': round(phishing_prob * 100, 1),
        'safe_probability': round(safe_prob * 100, 1),
        'confidence': confidence,
        'risk_factors': risk_factors,
        'features': {
            'url_count': features['url_count'],
            'phishing_keywords': features['phishing_keyword_count'],
            'safe_keywords': features['safe_keyword_count'],
            'suspicious_urls': features['suspicious_url_count'],
            'caps_ratio': round(features['caps_ratio'] * 100, 1),
            'exclamation_count': features['exclamation_count'],
            'word_count': features['word_count'],
        }
    })


@app.route('/metrics')
def get_metrics():
    return jsonify(metrics)


@app.route('/health')
def health():
    """Quick endpoint to verify the model is actually loaded."""
    return jsonify({
        'model_loaded': model is not None,
        'feature_names_loaded': feature_names is not None,
        'num_features': len(feature_names) if feature_names else 0,
    })


# Load the model immediately at import time. This line runs whether the app
# is started via `python app.py` OR via `gunicorn app:app` (gunicorn imports
# this module directly and never executes the __main__ block below).
load_model()

if __name__ == '__main__':
    app.run(debug=True, port=5000)
