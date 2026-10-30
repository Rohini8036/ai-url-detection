import streamlit as st
from utils import COMMON_CSS

st.set_page_config(
    page_title="SecureScan AI | About",
    page_icon="ℹ️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown(COMMON_CSS, unsafe_allow_html=True)

st.markdown("""
<div class="hero">
    <h1>ℹ️ About This Project</h1>
    <p>An educational cybersecurity prototype built with Python and Streamlit.</p>
</div>
""", unsafe_allow_html=True)

st.markdown("### What does it do?")
st.write(
    "SecureScan AI classifies URL patterns into **Safe**, **Spam**, and **Malicious** "
    "categories using a Random Forest machine learning classifier trained on URL-based features."
)

col1, col2 = st.columns(2)

with col1:
    st.markdown("### 🛠️ Technologies Used")
    st.markdown("""
    | Technology | Purpose |
    |---|---|
    | Python | Core language |
    | Streamlit | Web UI framework |
    | Scikit-learn | ML model (Random Forest) |
    | Pandas | Data handling |
    | Plotly | Interactive charts |
    """)

with col2:
    st.markdown("### ⚙️ Features Extracted from URLs")
    st.markdown("""
    | Feature | Description |
    |---|---|
    | URL length | Longer URLs can be suspicious |
    | Dot count | Many dots may indicate subdomain abuse |
    | Digit count | High digit count is a spam signal |
    | Has IP address | Direct IP usage is a red flag |
    | HTTPS | Presence of secure protocol |
    | Suspicious words | login, verify, free, bank, etc. |
    | URL shortener | bit.ly, tinyurl, etc. |
    | Punycode domain | Homograph attack indicator |
    """)

st.markdown("### 🔄 How It Works")
st.markdown("""
1. User enters one or more URLs in the Dashboard
2. Each URL is parsed and 14 features are extracted
3. The trained Random Forest model predicts a category
4. Results are displayed with confidence scores and a pie chart
5. All scans are saved locally to `scan_history.csv`
""")

st.warning(
    "⚠️ The current model uses only 30 manually labeled examples. "
    "It has not been validated for real-world security use. "
    "A larger verified dataset is required before making accuracy claims."
)

st.markdown("### 📁 Project Structure")
st.code("""
ai spam dtection/
├── app.py               ← Dashboard (main page)
├── pages/
│   ├── 1_Scan_History.py  ← Scan history viewer
│   └── 2_About.py         ← This page
├── utils.py             ← Shared model, features, helpers
├── scan_history.csv     ← Auto-created on first scan
└── requirements.txt     ← Dependencies
""")

st.divider()
st.caption("SecureScan AI • BCA Academic Project • Educational use only")
