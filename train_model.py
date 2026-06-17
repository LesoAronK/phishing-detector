"""
Phishing Email Detector - Model Training Script
Trains a Random Forest classifier on synthetic phishing/legitimate email data.
"""

import numpy as np
import pandas as pd
import joblib
import re
import os
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (accuracy_score, confusion_matrix,
                              classification_report, roc_auc_score)
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline


# ─── Feature Extraction ────────────────────────────────────────────────────────

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
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP address URLs
    r'paypal.*\.com(?!$)', r'amazon.*\.net', r'microsoft.*\.info',
    r'login.*\.(xyz|tk|ml|ga|cf|gq)', r'secure.*\.(xyz|tk|ml)',
    r'account.*\.(xyz|tk|ml|ga|cf|gq)',
]


def extract_features(text: str) -> dict:
    """Extract numerical features from email text."""
    text_lower = text.lower()
    words = text_lower.split()
    
    features = {}
    
    # Length features
    features['text_length'] = len(text)
    features['word_count'] = len(words)
    features['avg_word_length'] = np.mean([len(w) for w in words]) if words else 0
    features['sentence_count'] = text.count('.') + text.count('!') + text.count('?')
    
    # Keyword features
    features['phishing_keyword_count'] = sum(
        1 for kw in PHISHING_KEYWORDS if kw in text_lower
    )
    features['safe_keyword_count'] = sum(
        1 for kw in SAFE_KEYWORDS if kw in text_lower
    )
    features['keyword_ratio'] = (
        features['phishing_keyword_count'] / max(features['safe_keyword_count'], 1)
    )
    
    # URL features
    urls = re.findall(r'https?://\S+|www\.\S+', text_lower)
    features['url_count'] = len(urls)
    features['has_http'] = int('http://' in text_lower)
    features['has_https'] = int('https://' in text_lower)
    features['suspicious_url_count'] = sum(
        1 for pattern in SUSPICIOUS_URL_PATTERNS
        if any(re.search(pattern, url) for url in urls)
    )
    
    # Urgency / pressure tactics
    features['exclamation_count'] = text.count('!')
    features['caps_ratio'] = sum(1 for c in text if c.isupper()) / max(len(text), 1)
    features['has_urgent_words'] = int(
        any(w in text_lower for w in ['urgent', 'immediately', 'asap', 'act now', 'expires'])
    )
    
    # Greeting / impersonation signals
    features['has_generic_greeting'] = int(
        any(g in text_lower for g in ['dear customer', 'dear user', 'valued member', 'dear account holder'])
    )
    features['has_personal_greeting'] = int(
        any(g in text_lower for g in ['hi ', 'hello ', 'dear '])
    )
    
    # Special character features
    features['dollar_sign_count'] = text.count('$')
    features['percent_sign_count'] = text.count('%')
    features['question_mark_count'] = text.count('?')
    
    # HTML / script tags (often in phishing)
    features['has_html_tags'] = int(bool(re.search(r'<[^>]+>', text)))
    features['has_script_tag'] = int('<script' in text_lower)
    features['has_form_tag'] = int('<form' in text_lower)
    
    # Suspicious patterns
    features['has_ip_address'] = int(
        bool(re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', text))
    )
    features['has_login_link'] = int('login' in text_lower and ('http' in text_lower or 'click' in text_lower))
    features['has_verify_link'] = int('verify' in text_lower and ('http' in text_lower or 'click' in text_lower))
    features['has_attachment_mention'] = int(
        any(w in text_lower for w in ['attachment', 'attached', 'open this', 'download'])
    )
    
    # Numeric features
    features['digit_ratio'] = sum(1 for c in text if c.isdigit()) / max(len(text), 1)
    
    return features


# ─── Synthetic Dataset Generation ──────────────────────────────────────────────

PHISHING_TEMPLATES = [
    "URGENT: Your {bank} account has been suspended! Click here immediately to verify: http://bit.ly/secure{bank}login. Dear Customer, act now before your account expires!",
    "Congratulations! You've won a $1000 prize! Claim your reward NOW at http://192.168.1.1/claim. Limited time offer expires today!",
    "Dear Valued Member, unusual activity detected on your PayPal account. Verify your identity immediately: http://paypal-secure.xyz/verify",
    "SECURITY ALERT: Your Microsoft account will be locked! Update your password within 24 hours: http://microsoftsupport.tk/update",
    "Your Amazon order has a billing problem. Update your credit card details immediately to avoid cancellation: http://amazon.net.xyz/billing",
    "WARNING: Unauthorized access to your account! Confirm your identity now or your account will be permanently deleted: http://secure-login.ml/confirm",
    "Dear Account Holder, your bank transaction failed. Click here to complete the transaction: http://bit.ly/banktransfer99",
    "You have been selected for a FREE iPhone! Act now, limited time only! Claim at: http://free-iphone-winner.tk/claim",
    "URGENT ACTION REQUIRED: Your email account will be suspended in 24 hours. Verify now: http://email-verify.ga/secure",
    "Your credit card was charged $499. If you did not authorize this, click here IMMEDIATELY: http://tinyurl.com/stopcharge",
    "Apple ID suspended! Dear user, verify your Apple ID to restore access: http://apple-id-verify.cf/login",
    "CONGRATULATIONS! You've been randomly selected to receive a $500 Walmart Gift Card! Click now: http://goo.gl/giftcard500",
    "Your Netflix account will be cancelled! Update billing information immediately: http://netflix-billing.xyz/update",
    "Security Warning: Someone tried to login to your account from Russia. Verify your account: http://secure.account.ml/verify",
    "IRS TAX REFUND: You are owed $2,450 in tax refund. Claim now: http://irs-refund.tk/claim"
]

SAFE_TEMPLATES = [
    "Hi team, please find attached the Q3 report for your review. Let me know if you have any questions. Best regards, Sarah",
    "Hello, following up on our meeting last Tuesday. As discussed, I've prepared the project proposal. Looking forward to your feedback.",
    "Dear colleagues, the monthly team meeting has been rescheduled to Thursday at 2pm. Please update your calendars accordingly.",
    "Hi John, thanks for sending over the documents. I've reviewed them and everything looks good. We can proceed with the next steps.",
    "Hello, I wanted to share the updated schedule for the upcoming conference. Please let me know if there are any conflicts.",
    "Hi Sarah, I wanted to reach out regarding the new feature request from the client. Can we schedule a call to discuss?",
    "Dear team, please note that the office will be closed on Monday for the holiday. Normal operations will resume Tuesday.",
    "Hello, just a friendly reminder that the quarterly performance reviews are coming up next week. Please prepare your self-assessments.",
    "Hi there, I'm following up on the proposal we discussed last week. Have you had a chance to review it with your team?",
    "Dear colleagues, I'm happy to announce that our project has been approved by the board. Thank you all for your hard work!",
    "Hello, attached is the invoice for services rendered in October. Please process at your earliest convenience. Thank you.",
    "Hi, I wanted to let you know that I'll be out of the office from Dec 20-27. For urgent matters, please contact my colleague Mike.",
    "Dear team, I'm sharing the updated company policies for your reference. Please review and acknowledge receipt by Friday.",
    "Hello, thank you for attending yesterday's workshop. Please find attached the presentation slides and additional resources.",
    "Hi, just checking in on the status of the report. Let me know if you need any additional information from our end."
]

# More varied phishing examples
ADDITIONAL_PHISHING = [
    "FINAL NOTICE: Your account is overdue! Pay now or face legal action. Click: http://debt-collect.ml/pay",
    "Dear Customer: Your password expires today! Reset at: http://192.168.0.1/reset immediately!",
    "You have 1 unread security notification! Your account shows suspicious login. Verify: http://ow.ly/securecheck",
    "WINNER! You are our lucky customer #100000! Claim your $5000 prize: http://lucky-winner.ga/claim",
    "WARNING!! Your computer is infected with 3 viruses! Install protection NOW: http://tinyurl.com/antivirus-free",
]

ADDITIONAL_SAFE = [
    "Hi, hope you're doing well. I wanted to touch base about the upcoming product launch. Can we sync tomorrow?",
    "Dear all, please find the minutes from yesterday's meeting attached. Action items are highlighted in yellow.",
    "Hello, I'm writing to confirm our appointment scheduled for next Monday at 10am. Please let me know if this still works.",
    "Hi team, great work on the presentation today! The client was very impressed with our proposal.",
    "Dear Sarah, I wanted to thank you for your help with the project. Your expertise made a significant difference.",
]


def generate_dataset(n_samples: int = 2000) -> pd.DataFrame:
    """Generate a labeled dataset of phishing and legitimate emails."""
    np.random.seed(42)
    
    all_phishing = PHISHING_TEMPLATES + ADDITIONAL_PHISHING
    all_safe = SAFE_TEMPLATES + ADDITIONAL_SAFE
    
    records = []
    
    half = n_samples // 2
    
    # Generate phishing samples with augmentation
    for i in range(half):
        base = all_phishing[i % len(all_phishing)]
        # Add noise/variation
        noise_words = ['', ' Please respond ASAP!', ' Your account is at risk!', '']
        text = base + np.random.choice(noise_words)
        banks = ['Chase', 'Bank of America', 'Wells Fargo', 'Citibank', 'HSBC']
        text = text.replace('{bank}', np.random.choice(banks))
        records.append({'text': text, 'label': 1})
    
    # Generate safe samples with augmentation
    for i in range(half):
        base = all_safe[i % len(all_safe)]
        noise_words = ['', ' Thanks!', ' Best wishes.', '']
        text = base + np.random.choice(noise_words)
        records.append({'text': text, 'label': 0})
    
    df = pd.DataFrame(records)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    return df


# ─── Main Training ──────────────────────────────────────────────────────────────

def train_and_save():
    print("Generating dataset...")
    df = generate_dataset(2000)
    print(f"Dataset: {len(df)} samples | Phishing: {df['label'].sum()} | Safe: {(df['label']==0).sum()}")
    
    print("Extracting features...")
    feature_list = [extract_features(text) for text in df['text']]
    X = pd.DataFrame(feature_list)
    y = df['label']
    
    feature_names = X.columns.tolist()
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print("Training model...")
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train, y_train)
    
    # Evaluate
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]
    
    accuracy = accuracy_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)
    report = classification_report(y_test, y_pred, target_names=['Safe', 'Phishing'])
    auc = roc_auc_score(y_test, y_prob)
    
    print(f"\nAccuracy: {accuracy:.4f}")
    print(f"AUC-ROC:  {auc:.4f}")
    print(f"\nConfusion Matrix:\n{cm}")
    print(f"\nClassification Report:\n{report}")
    
    # Feature importance
    importances = pd.Series(model.feature_importances_, index=feature_names)
    top_features = importances.nlargest(10)
    print(f"\nTop 10 Features:\n{top_features}")
    
    # Save artifacts
    os.makedirs('model', exist_ok=True)
    joblib.dump(model, 'model/phishing_model.pkl')
    joblib.dump(feature_names, 'model/feature_names.pkl')
    
    # Save metrics
    metrics = {
        'accuracy': float(accuracy),
        'auc_roc': float(auc),
        'confusion_matrix': cm.tolist(),
        'classification_report': report,
        'top_features': top_features.to_dict(),
        'train_size': len(X_train),
        'test_size': len(X_test),
    }
    joblib.dump(metrics, 'model/metrics.pkl')
    
    print("\nModel saved to model/")
    return model, metrics


if __name__ == '__main__':
    train_and_save()
