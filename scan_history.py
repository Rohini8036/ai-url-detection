import streamlit as st
from utils import load_history, HISTORY_FILE, COMMON_CSS

st.set_page_config(
    page_title="SecureScan AI | Scan History",
    page_icon="🕘",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown(COMMON_CSS, unsafe_allow_html=True)

st.markdown("""
<div class="hero">
    <h1>🕘 Scan History</h1>
    <p>Review all previously analyzed URLs stored on this device.</p>
</div>
""", unsafe_allow_html=True)

history_df = load_history()

if history_df.empty:
    st.info("No saved scan history yet. Analyze URLs from the Dashboard first.")
else:
    st.write(f"Total saved URL records: **{len(history_df)}**")

    col1, col2, col3 = st.columns(3)
    col1.metric("Total Scanned",  len(history_df))
    col2.metric("Unique URLs",    history_df["URL"].nunique())
    col3.metric("Malicious Found", int((history_df["Prediction"] == "Malicious").sum()))

    st.markdown('<div class="section-title">📋 All Scan Records</div>', unsafe_allow_html=True)
    st.dataframe(history_df.iloc[::-1], use_container_width=True, hide_index=True)

    st.download_button(
        "⬇️ Download All Scan History (CSV)",
        data=history_df.to_csv(index=False).encode("utf-8"),
        file_name="scan_history.csv",
        mime="text/csv"
    )

    st.divider()
    if st.button("🗑️ Clear All Scan History", type="primary"):
        try:
            HISTORY_FILE.unlink(missing_ok=True)
            st.success("Scan history cleared.")
            st.rerun()
        except OSError:
            st.error("Unable to delete the history file.")

st.divider()
st.caption("SecureScan AI • Educational prototype • Not a substitute for a real security scanner")
