import ipaddress
import pandas as pd
import streamlit as st

from pathlib import Path
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

SUSPICIOUS_WORDS = [
    "login", "verify", "update", "free", "bonus",
    "secure", "account", "bank", "password",
    "confirm", "wallet", "malware", "download"
]

SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "is.gd",
    "ow.ly", "cutt.ly"
]

MAX_URL_LENGTH = 2048
HISTORY_FILE = Path(__file__).with_name("scan_history.csv")
HISTORY_COLUMNS = ["Scan Time", "URL", "Prediction", "Confidence (%)", "Safe Probability (%)"]

TRAINING_URLS = [
    ("https://www.wikipedia.org", "Safe"),
    ("https://www.python.org", "Safe"),
    ("https://www.microsoft.com", "Safe"),
    ("https://www.bbc.com/news", "Safe"),
    ("https://www.google.com/search", "Safe"),
    ("https://www.amazon.com/products", "Safe"),
    ("https://www.apple.com", "Safe"),
    ("https://www.nasa.gov", "Safe"),
    ("https://www.karnataka.gov.in", "Safe"),
    ("https://docs.python.org/3/", "Safe"),
    ("http://free-prize-bonus.example/claim", "Spam"),
    ("http://win-money-now.example", "Spam"),
    ("http://cheap-products.example/buy-now", "Spam"),
    ("http://get-free-gift.example", "Spam"),
    ("http://bonus-offer.example/subscribe", "Spam"),
    ("http://click-now.example/?offer=123", "Spam"),
    ("http://earn-cash-fast.example", "Spam"),
    ("http://discount-deal.example/promo", "Spam"),
    ("http://free-reward.example/claim-now", "Spam"),
    ("http://limited-offer.example", "Spam"),
    ("http://192.0.2.1/login/verify", "Malicious"),
    ("http://198.51.100.2/account/password", "Malicious"),
    ("http://203.0.113.5/secure/update", "Malicious"),
    ("http://fake-login.example/verify-account", "Malicious"),
    ("http://bank-security.example/login", "Malicious"),
    ("http://wallet-confirm.example/password", "Malicious"),
    ("http://account-verify.example/secure/login", "Malicious"),
    ("http://malware-download.example/file.exe", "Malicious"),
    ("http://xn--fake-example.example/login", "Malicious"),
    ("http://secure-update.example/confirm", "Malicious"),
]


def extract_features(url):
    url = url.strip()[:MAX_URL_LENGTH]
    lower = url.lower()

    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
        host = parsed.hostname or ""
        is_https = int(parsed.scheme.lower() == "https")
    except Exception:
        host = ""
        is_https = 0

    try:
        ipaddress.ip_address(host)
        has_ip = 1
    except (ValueError, TypeError):
        has_ip = 0

    return [
        len(url),
        url.count("."),
        url.count("-"),
        sum(c.isdigit() for c in url),
        url.count("@"),
        url.count("//"),
        url.count("/"),
        url.count("?"),
        url.count("="),
        is_https,
        has_ip,
        sum(word in lower for word in SUSPICIOUS_WORDS),
        int(any(s in host.lower() for s in SHORTENERS)),
        int(host.startswith("xn--") or ".xn--" in host)
    ]


def valid_url(url):
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
        return bool(parsed.hostname and "." in parsed.hostname and " " not in url)
    except Exception:
        return False


@st.cache_resource
def load_model():
    X = [extract_features(url) for url, _ in TRAINING_URLS]
    y = [label for _, label in TRAINING_URLS]
    pipeline = make_pipeline(
        StandardScaler(),
        RandomForestClassifier(n_estimators=200, random_state=42, class_weight="balanced")
    )
    pipeline.fit(X, y)
    return pipeline


def load_history():
    if HISTORY_FILE.exists():
        try:
            df = pd.read_csv(HISTORY_FILE)
            for col in HISTORY_COLUMNS:
                if col not in df.columns:
                    df[col] = None
            return df[HISTORY_COLUMNS]
        except Exception:
            pass
    return pd.DataFrame(columns=HISTORY_COLUMNS)


def save_history(new_df):
    combined = pd.concat([load_history(), new_df], ignore_index=True)
    combined.to_csv(HISTORY_FILE, index=False)


COMMON_CSS = """
<style>
    .stApp { background: #0b1120; color: #e5e7eb; }
    [data-testid="stSidebar"] { background: #111827; border-right: 1px solid #253247; }
    .block-container { padding-top: 2rem; padding-bottom: 3rem; max-width: 1400px; }
    .hero {
        background: linear-gradient(120deg, #172554, #123047, #123b35);
        padding: 28px 32px; border-radius: 18px;
        border: 1px solid #29445a; margin-bottom: 24px;
    }
    .hero h1 { color: #ffffff; font-size: 2rem; margin-bottom: 6px; }
    .hero p  { color: #cbd5e1; font-size: 1rem; }
    .metric-card {
        background: #111c2f; border: 1px solid #26364c;
        padding: 20px; border-radius: 14px; min-height: 110px;
    }
    .metric-label { color: #9caec4; font-size: 0.88rem; }
    .metric-value { color: #ffffff; font-size: 1.8rem; font-weight: 700; margin-top: 6px; }
    .section-title { font-size: 1.25rem; font-weight: 700; margin: 22px 0 10px; color: #f8fafc; }
    .notice {
        background: #18263a; border-left: 4px solid #38bdf8;
        padding: 14px; border-radius: 8px; color: #dbeafe; margin: 12px 0;
    }
    div.stButton > button[kind="primary"] {
        background: #0d9488; border: none; color: white;
        border-radius: 9px; min-height: 44px; font-weight: 600;
    }
    div.stButton > button[kind="primary"]:hover { background: #0f766e; }
    h1, h2, h3 { color: #f8fafc; }
    [data-testid="stDataFrame"] { border: 1px solid #26364c; border-radius: 10px; }
</style>
"""
