
import re
import ipaddress
from urllib.parse import urlparse
from datetime import datetime
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler


# ---------------- PAGE SETTINGS ----------------

st.set_page_config(
    page_title="SecureScan AI | URL Security",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

HISTORY_FILE = Path(__file__).with_name("scan_history.csv")


# ---------------- CUSTOM DESIGN ----------------

st.markdown("""
<style>
    .stApp {
        background: #0b1120;
        color: #e5e7eb;
    }

    [data-testid="stSidebar"] {
        background: #111827;
        border-right: 1px solid #253247;
    }

    .block-container {
        padding-top: 2rem;
        padding-bottom: 3rem;
        max-width: 1400px;
    }

    .hero {
        background: linear-gradient(120deg, #172554, #123047, #123b35);
        padding: 30px;
        border-radius: 18px;
        border: 1px solid #29445a;
        margin-bottom: 24px;
    }

    .hero h1 {
        color: #ffffff;
        font-size: 2.2rem;
        margin-bottom: 8px;
    }

    .hero p {
        color: #cbd5e1;
        font-size: 1rem;
    }

    .metric-card {
        background: #111c2f;
        border: 1px solid #26364c;
        padding: 20px;
        border-radius: 14px;
        min-height: 120px;
    }

    .metric-label {
        color: #9caec4;
        font-size: 0.9rem;
    }

    .metric-value {
        color: #ffffff;
        font-size: 1.8rem;
        font-weight: 700;
        margin-top: 8px;
    }

    .section-title {
        font-size: 1.35rem;
        font-weight: 700;
        margin: 24px 0 12px 0;
        color: #f8fafc;
    }

    .notice {
        background: #18263a;
        border-left: 4px solid #38bdf8;
        padding: 14px;
        border-radius: 8px;
        color: #dbeafe;
        margin: 12px 0;
    }

    div.stButton > button[kind="primary"] {
        background: #0d9488;
        border: none;
        color: white;
        border-radius: 9px;
        min-height: 45px;
        font-weight: 600;
    }

    div.stButton > button[kind="primary"]:hover {
        background: #0f766e;
        border: none;
    }

    h1, h2, h3 {
        color: #f8fafc;
    }

    [data-testid="stDataFrame"] {
        border: 1px solid #26364c;
        border-radius: 10px;
    }
</style>
""", unsafe_allow_html=True)


# ---------------- FEATURE EXTRACTION ----------------

SUSPICIOUS_WORDS = [
    "login", "verify", "update", "free", "bonus",
    "secure", "account", "bank", "password",
    "confirm", "wallet", "malware", "download"
]

SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "is.gd",
    "ow.ly", "cutt.ly"
]


def extract_features(url):
    url = url.strip()
    lower = url.lower()

    try:
        parsed = urlparse(
            url if "://" in url else "http://" + url
        )
        host = parsed.hostname or ""
    except (ValueError, TypeError):
        host = ""

    try:
        ipaddress.ip_address(host)
        has_ip = 1
    except ValueError:
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
        int(parsed_scheme_is_https(url)),
        has_ip,
        sum(word in lower for word in SUSPICIOUS_WORDS),
        int(any(s in host.lower() for s in SHORTENERS)),
        int(host.startswith("xn--") or ".xn--" in host)
    ]


def parsed_scheme_is_https(url):
    try:
        parsed = urlparse(
            url if "://" in url else "http://" + url
        )
        return parsed.scheme.lower() == "https"
    except (ValueError, TypeError):
        return False


def valid_url_format(url):
    try:
        parsed = urlparse(
            url if "://" in url else "http://" + url
        )
        return bool(
            parsed.hostname
            and "." in parsed.hostname
            and " " not in url
        )
    except (ValueError, TypeError):
        return False


# ---------------- DEMONSTRATION DATASET ----------------
# Replace these examples with a verified, labeled dataset
# before evaluating real-world model accuracy.

training_urls = [
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

X_train = [
    extract_features(url) for url, label in training_urls
]
y_train = [label for url, label in training_urls]

model = make_pipeline(
    StandardScaler(),
    RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        class_weight="balanced"
    )
)

model.fit(X_train, y_train)


# ---------------- HISTORY FUNCTIONS ----------------

HISTORY_COLUMNS = [
    "Scan Time", "URL", "Prediction",
    "Confidence (%)", "Safe Probability (%)"
]


def load_history():
    if HISTORY_FILE.exists():
        try:
            history = pd.read_csv(HISTORY_FILE)
            for col in HISTORY_COLUMNS:
                if col not in history.columns:
                    history[col] = None
            return history[HISTORY_COLUMNS]
        except (OSError, ValueError, pd.errors.ParserError):
            return pd.DataFrame(columns=HISTORY_COLUMNS)

    return pd.DataFrame(columns=HISTORY_COLUMNS)


def save_history(new_results):
    old_history = load_history()
    combined = pd.concat(
        [old_history, new_results],
        ignore_index=True
    )
    combined.to_csv(HISTORY_FILE, index=False)


# ---------------- SIDEBAR ----------------

with st.sidebar:
    st.markdown("## 🛡️ SecureScan AI")
    st.caption("URL Security Intelligence")
    st.divider()

    page = st.radio(
        "NAVIGATION",
        ["Dashboard", "Scan History", "About Project"]
    )

    st.divider()
    st.markdown("**Model:** Random Forest")
    st.markdown("**Mode:** Educational prototype")
    st.caption("No live threat-intelligence lookup is enabled.")


# ---------------- HEADER ----------------

st.markdown("""
<div class="hero">
    <h1>🛡️ AI-Based URL Security Scanner</h1>
    <p>
        Analyze URL patterns, identify suspicious links, and
        review your scan results in one place.
    </p>
</div>
""", unsafe_allow_html=True)


# ---------------- DASHBOARD ----------------

if page == "Dashboard":

    st.markdown("### 🔍 URL Scanner")
    st.write(
        "Enter one URL per line. You can analyze multiple URLs "
        "in one scan."
    )

    url_text = st.text_area(
        "Website URLs",
        placeholder=(
            "https://www.google.com\n"
            "http://example.com/login"
        ),
        height=125,
        key="url_input"
    )

    scan_clicked = st.button(
        "🔎 Analyze URLs",
        type="primary",
        use_container_width=True
    )

    if scan_clicked:
        urls = list(dict.fromkeys(
            u.strip() for u in url_text.splitlines()
            if u.strip()
        ))

        if not urls:
            st.warning("Please enter at least one URL.")

        else:
            results = []
            invalid_urls = []

            for url in urls:
                if not valid_url_format(url):
                    invalid_urls.append(url)
                    continue

                features = extract_features(url)
                prediction = model.predict([features])[0]
                probabilities = model.predict_proba([features])[0]

                classes = list(model.classes_)
                probability_map = dict(zip(classes, probabilities))

                confidence = max(probabilities) * 100
                safe_probability = (
                    probability_map.get("Safe", 0) * 100
                )

                results.append({
                    "Scan Time": datetime.now().strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                    "URL": url,
                    "Prediction": prediction,
                    "Confidence (%)": round(
                        confidence, 2
                    ),
                    "Safe Probability (%)": round(
                        safe_probability, 2
                    )
                })

            if invalid_urls:
                st.warning(
                    "Some entries did not look like valid URLs: "
                    + ", ".join(invalid_urls)
                )

            if results:
                result_df = pd.DataFrame(results)

                # Keep current scan visible across page reruns.
                st.session_state["last_results"] = result_df

                try:
                    save_history(result_df)
                    st.success(
                        f"Analysis complete: {len(result_df)} URL(s). "
                        "Scan history saved."
                    )
                except OSError:
                    st.warning(
                        "Results are displayed, but scan history "
                        "could not be saved to disk."
                    )

    # Display the latest scan after a button click or rerun.
    if "last_results" in st.session_state:
        df = st.session_state["last_results"]

        safe_count = int((df["Prediction"] == "Safe").sum())
        spam_count = int((df["Prediction"] == "Spam").sum())
        malicious_count = int(
            (df["Prediction"] == "Malicious").sum()
        )
        total = len(df)

        st.markdown(
            '<div class="section-title">📊 Detection Summary</div>',
            unsafe_allow_html=True
        )

        c1, c2, c3, c4 = st.columns(4)

        cards = [
            (c1, "URLs Analyzed", total, "#38bdf8"),
            (c2, "Predicted Safe", safe_count, "#34d399"),
            (c3, "Predicted Spam", spam_count, "#fbbf24"),
            (c4, "Predicted Malicious", malicious_count, "#fb7185"),
        ]

        for col, label, value, color in cards:
            with col:
                st.markdown(
                    f"""
                    <div class="metric-card">
                        <div class="metric-label">{label}</div>
                        <div class="metric-value"
                             style="color:{color}">
                            {value}
                        </div>
                        <div class="metric-label">
                            {value / total * 100:.1f}% of scan
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

        st.markdown(
            '<div class="section-title">📈 Safety Analysis</div>',
            unsafe_allow_html=True
        )

        chart_data = pd.DataFrame({
            "Category": ["Safe", "Spam", "Malicious"],
            "Count": [safe_count, spam_count, malicious_count]
        })
        chart_data = chart_data[chart_data["Count"] > 0]

        left, right = st.columns([1.15, 1])

        with left:
            fig = px.pie(
                chart_data,
                names="Category",
                values="Count",
                hole=0.48,
                color="Category",
                color_discrete_map={
                    "Safe": "#34d399",
                    "Spam": "#fbbf24",
                    "Malicious": "#fb7185"
                }
            )

            fig.update_traces(
                textinfo="label+percent",
                textfont_size=13,
                hovertemplate=(
                    "%{label}<br>Count: %{value}"
                    "<br>Share: %{percent}<extra></extra>"
                )
            )

            fig.update_layout(
                title="Distribution of URL Predictions",
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#e5e7eb",
                legend_title_text="Category",
                margin=dict(t=60, b=20, l=10, r=10),
                height=370
            )

            st.plotly_chart(
                fig,
                use_container_width=True
            )

        with right:
            st.markdown("#### Category breakdown")

            for label, count, color in [
                ("Safe", safe_count, "#34d399"),
                ("Spam", spam_count, "#fbbf24"),
                ("Malicious", malicious_count, "#fb7185")
            ]:
                pct = count / total * 100

                st.markdown(
                    f"""
                    <div style="margin: 22px 0;">
                        <div style="display:flex;
                                    justify-content:space-between;">
                            <span style="color:{color};
                                         font-weight:600;">
                                {label}
                            </span>
                            <span>{count} ({pct:.1f}%)</span>
                        </div>
                        <div style="background:#253247;
                                    border-radius:8px;
                                    height:9px;
                                    margin-top:8px;">
                            <div style="background:{color};
                                        width:{pct}%;
                                        height:9px;
                                        border-radius:8px;">
                            </div>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

            avg_safe = df["Safe Probability (%)"].mean()

            st.metric(
                "Average estimated Safe probability",
                f"{avg_safe:.1f}%"
            )

        st.markdown(
            '<div class="section-title">🔎 Individual URL Results</div>',
            unsafe_allow_html=True
        )

        st.dataframe(
            df,
            use_container_width=True,
            hide_index=True
        )

        csv_data = df.to_csv(index=False).encode("utf-8")

        st.download_button(
            "⬇️ Download Current Scan (CSV)",
            data=csv_data,
            file_name="url_detection_results.csv",
            mime="text/csv"
        )

        st.markdown(
            """
            <div class="notice">
                <strong>Important:</strong> Predictions and
                probability scores are estimates from a small
                demonstration model. They are not verified safety
                ratings. Do not open a suspicious URL just to test it.
            </div>
            """,
            unsafe_allow_html=True
        )

    else:
        st.info(
            "Your results will appear here after you analyze URLs."
        )

        st.markdown("#### Try example URLs")

        st.code(
            "https://www.wikipedia.org\n"
            "https://www.python.org\n"
            "http://free-prize-bonus.example/claim\n"
            "http://192.0.2.1/login/verify"
        )


# ---------------- SCAN HISTORY ----------------

elif page == "Scan History":

    st.markdown("### 🕘 Previous Scans")
    history_df = load_history()

    if history_df.empty:
        st.info(
            "No saved scan history yet. Analyze URLs from the "
            "Dashboard first."
        )

    else:
        st.write(
            f"Total saved URL records: **{len(history_df)}**"
        )

        st.dataframe(
            history_df.iloc[::-1],
            use_container_width=True,
            hide_index=True
        )

        history_csv = history_df.to_csv(
            index=False
        ).encode("utf-8")

        st.download_button(
            "⬇️ Download All Scan History",
            data=history_csv,
            file_name="scan_history.csv",
            mime="text/csv"
        )

        if st.button("🗑️ Clear Scan History"):
            try:
                HISTORY_FILE.unlink(missing_ok=True)
                st.success("Saved scan history cleared.")
                st.rerun()
            except OSError:
                st.error("Unable to delete the history file.")


# ---------------- ABOUT PROJECT ----------------

elif page == "About Project":

    st.markdown("### ℹ️ About This Project")

    st.write(
        "This is an educational cybersecurity prototype that "
        "classifies URL patterns into Safe, Spam, and Malicious "
        "categories using a Random Forest classifier."
    )

    st.markdown("#### Technologies Used")
    st.markdown("""
    - Python
    - Streamlit
    - Pandas
    - Plotly
    - Scikit-learn
    - Random Forest Classification
    """)

    st.markdown("#### How it works")
    st.markdown("""
    1. The user enters one or more URLs.
    2. The program extracts URL-based features.
    3. The trained model predicts a category.
    4. The dashboard displays summaries and a pie chart.
    5. The results are saved in a local CSV history file.
    """)

    st.warning(
        "The current model uses only 30 manually labeled examples. "
        "It has not been validated for real-world security use. "
        "A larger verified dataset and independent testing are "
        "required before making accuracy claims."
    )


# ---------------- FOOTER ----------------

st.divider()
st.caption(
    "SecureScan AI • BCA Academic Project • "
    "Educational use only — not a substitute for a security scanner"
)
