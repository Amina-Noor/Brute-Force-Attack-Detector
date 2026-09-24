"""
app.py
Main Streamlit dashboard for the Brute Force Attack Detector.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st

import constants
import visualizer
from analyzer import LogAnalyzer
from config import DetectionConfig
from detector import BruteForceDetector
from logger import get_logger
from parser import LogParser, ParsingError
from report_generator import ReportGenerator
from sample_data_generator import write_sample_files

logger = get_logger(__name__)

st.set_page_config(
    page_title="Brute Force Attack Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Custom styling
# ---------------------------------------------------------------------------
st.markdown("""
<style>
    .metric-card {
        background: rgba(255,255,255,0.03);
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 10px;
        padding: 1rem;
    }
    .alert-card {
        border-radius: 10px;
        padding: 0.9rem 1.2rem;
        margin-bottom: 0.6rem;
        border-left: 6px solid #888;
    }
    .alert-critical { background: rgba(239,68,68,0.12); border-left-color:#ef4444; }
    .alert-high { background: rgba(249,115,22,0.12); border-left-color:#f97316; }
    .alert-medium { background: rgba(245,158,11,0.12); border-left-color:#f59e0b; }
    .alert-low { background: rgba(59,130,246,0.12); border-left-color:#3b82f6; }
    .stTabs [data-baseweb="tab-list"] { gap: 6px; }
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Session state initialization
# ---------------------------------------------------------------------------
def init_state() -> None:
    defaults = {
        "entries": None,
        "alerts": None,
        "stats": None,
        "recommendations": None,
        "analyzed": False,
        "log_content": None,
        "log_type": constants.LOG_TYPE_LINUX,
        "source_name": None,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


init_state()


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
def render_sidebar() -> DetectionConfig:
    st.sidebar.title("🛡️ Detector Controls")
    st.sidebar.markdown("---")

    st.sidebar.subheader("1. Load Log Data")
    log_type_label = st.sidebar.selectbox(
        "Log Type", ["Linux (auth.log)", "Windows (CSV/JSON)"],
    )
    log_type = (
        constants.LOG_TYPE_LINUX if "Linux" in log_type_label
        else constants.LOG_TYPE_WINDOWS
    )
    st.session_state["log_type"] = log_type

    uploaded_file = st.sidebar.file_uploader(
        "Upload a log file", type=["log", "txt", "csv", "json"],
    )

    col_a, col_b = st.sidebar.columns(2)
    load_sample_clicked = col_a.button("📂 Load Sample", use_container_width=True)
    regen_sample_clicked = col_b.button("🔄 Regenerate", use_container_width=True)

    if regen_sample_clicked:
        with st.spinner("Regenerating sample datasets..."):
            write_sample_files()
        st.sidebar.success("Sample datasets regenerated.")

    if uploaded_file is not None:
        try:
            raw_bytes = uploaded_file.read()
            content = raw_bytes.decode("utf-8", errors="replace")
            st.session_state["log_content"] = content
            st.session_state["source_name"] = uploaded_file.name
            st.sidebar.success(f"Loaded {uploaded_file.name}")
        except Exception as exc:  # noqa: BLE001
            st.sidebar.error(f"Failed to read uploaded file: {exc}")
            logger.error("Upload read error: %s", exc)

    if load_sample_clicked:
        sample_path = (
            Path(constants.SAMPLE_LINUX_LOG) if log_type == constants.LOG_TYPE_LINUX
            else Path(constants.SAMPLE_WINDOWS_CSV)
        )
        if not sample_path.exists():
            write_sample_files()
        st.session_state["log_content"] = sample_path.read_text(encoding="utf-8")
        st.session_state["source_name"] = sample_path.name
        st.sidebar.success(f"Loaded sample: {sample_path.name}")

    st.sidebar.markdown("---")
    st.sidebar.subheader("2. Detection Thresholds")
    failed_threshold = st.sidebar.slider(
        "Failed login threshold", min_value=2, max_value=50,
        value=constants.DEFAULT_FAILED_THRESHOLD,
    )
    time_window = st.sidebar.slider(
        "Time window (minutes)", min_value=1, max_value=60,
        value=constants.DEFAULT_TIME_WINDOW_MINUTES,
    )
    ignore_internal = st.sidebar.checkbox("Ignore internal/private IPs", value=False)
    trusted_users_raw = st.sidebar.text_input(
        "Trusted users (comma-separated)", value="",
        help="These usernames will be excluded from detection.",
    )
    trusted_users = [u.strip() for u in trusted_users_raw.split(",") if u.strip()]

    st.sidebar.markdown("---")
    analyze_clicked = st.sidebar.button("🚀 Analyze", type="primary", use_container_width=True)

    st.sidebar.markdown("---")
    st.sidebar.caption(f"Brute Force Attack Detector v1.0.0")

    config = DetectionConfig(
        failed_threshold=failed_threshold,
        time_window_minutes=time_window,
        ignore_internal_ips=ignore_internal,
        trusted_users=trusted_users,
    )

    if analyze_clicked:
        run_analysis(config)

    return config


# ---------------------------------------------------------------------------
# Analysis pipeline
# ---------------------------------------------------------------------------
def run_analysis(config: DetectionConfig) -> None:
    content = st.session_state.get("log_content")
    if not content:
        st.sidebar.error("Please upload or load a log file first.")
        return

    with st.spinner("Parsing and analyzing log data..."):
        try:
            parser = LogParser()
            entries = parser.parse_content(
                content, st.session_state["log_type"],
                source_name=st.session_state.get("source_name", "<upload>"),
            )
        except ParsingError as exc:
            st.sidebar.error(f"Parsing failed: {exc}")
            logger.error("Parsing failed: %s", exc)
            return

        if not entries:
            st.sidebar.warning(
                "No recognizable log entries were found. Check the log type "
                "matches the uploaded file."
            )
            return

        detector = BruteForceDetector(config)
        alerts = detector.detect(entries)

        analyzer = LogAnalyzer()
        stats = analyzer.analyze(entries, alerts)
        recommendations = analyzer.generate_recommendations(stats, alerts)

        st.session_state["entries"] = entries
        st.session_state["alerts"] = alerts
        st.session_state["stats"] = stats
        st.session_state["recommendations"] = recommendations
        st.session_state["analyzed"] = True

    st.sidebar.success(f"Analysis complete: {len(alerts)} alert(s) found.")


# ---------------------------------------------------------------------------
# Main dashboard rendering
# ---------------------------------------------------------------------------
def render_header() -> None:
    st.title("🛡️ Brute Force Attack Detector")
    st.caption(
        "SOC-grade authentication log analysis — detect brute-force attacks, "
        "credential stuffing, and password spraying in Linux and Windows logs."
    )


def render_metrics() -> None:
    stats = st.session_state["stats"]
    alerts = st.session_state["alerts"]

    cols = st.columns(6)
    cols[0].metric("Total Entries", stats.total_entries)
    cols[1].metric("Successful Logins", stats.successful_logins)
    cols[2].metric("Failed Logins", stats.failed_logins)
    cols[3].metric("Total Alerts", stats.total_alerts)
    cols[4].metric("Unique Attackers", stats.unique_attackers)
    critical_count = stats.severity_breakdown.get(constants.SEVERITY_CRITICAL, 0)
    cols[5].metric("Critical Alerts", critical_count,
                    delta=None if critical_count == 0 else "⚠️")


def render_alert_cards(limit: int = 10) -> None:
    alerts = st.session_state["alerts"]
    if not alerts:
        st.info("No alerts detected for the current dataset and thresholds.")
        return

    css_class_map = {
        constants.SEVERITY_CRITICAL: "alert-critical",
        constants.SEVERITY_HIGH: "alert-high",
        constants.SEVERITY_MEDIUM: "alert-medium",
        constants.SEVERITY_LOW: "alert-low",
    }
    icon_map = {
        constants.SEVERITY_CRITICAL: "🔴",
        constants.SEVERITY_HIGH: "🟠",
        constants.SEVERITY_MEDIUM: "🟡",
        constants.SEVERITY_LOW: "🔵",
    }

    for alert in alerts[:limit]:
        css_class = css_class_map.get(alert.severity, "alert-low")
        icon = icon_map.get(alert.severity, "⚪")
        ts_str = alert.timestamp.strftime("%Y-%m-%d %H:%M:%S") if alert.timestamp else "N/A"
        st.markdown(f"""
        <div class="alert-card {css_class}">
            <strong>{icon} {alert.severity.upper()} — {alert.alert_type}</strong><br>
            <strong>Attacker IP:</strong> {alert.ip} &nbsp;|&nbsp;
            <strong>Target:</strong> {alert.username} &nbsp;|&nbsp;
            <strong>Failed Attempts:</strong> {alert.failed_attempts} &nbsp;|&nbsp;
            <strong>Time:</strong> {ts_str}<br>
            <strong>MITRE:</strong> {alert.mitre_id} {alert.mitre_name} &nbsp;|&nbsp;
            <strong>Risk Score:</strong> {alert.risk_score}/100 &nbsp;|&nbsp;
            <strong>Confidence:</strong> {alert.confidence_score}%<br>
            <span style="opacity:0.85;">{alert.description}</span>
        </div>
        """, unsafe_allow_html=True)


def render_charts() -> None:
    stats = st.session_state["stats"]
    alerts = st.session_state["alerts"]
    entries = st.session_state["entries"]

    row1 = st.columns(2)
    with row1[0]:
        st.plotly_chart(visualizer.attack_timeline(alerts), use_container_width=True)
    with row1[1]:
        st.plotly_chart(visualizer.success_vs_failure_pie(stats), use_container_width=True)

    row2 = st.columns(2)
    with row2[0]:
        st.plotly_chart(visualizer.top_attacker_ips_chart(stats), use_container_width=True)
    with row2[1]:
        st.plotly_chart(visualizer.top_targeted_users_chart(stats), use_container_width=True)

    row3 = st.columns(2)
    with row3[0]:
        st.plotly_chart(visualizer.hourly_heatmap(entries), use_container_width=True)
    with row3[1]:
        st.plotly_chart(visualizer.daily_attacks_chart(entries), use_container_width=True)

    st.plotly_chart(visualizer.severity_distribution_chart(stats), use_container_width=True)


def render_tables_and_filters() -> None:
    alerts = st.session_state["alerts"]
    if not alerts:
        st.info("No alerts to display.")
        return

    df = pd.DataFrame([a.to_dict() for a in alerts])

    st.subheader("🔎 Search & Filter Alerts")
    fcols = st.columns(5)
    search_user = fcols[0].text_input("Username contains")
    search_ip = fcols[1].text_input("IP contains")
    severity_filter = fcols[2].multiselect(
        "Severity", [constants.SEVERITY_LOW, constants.SEVERITY_MEDIUM,
                      constants.SEVERITY_HIGH, constants.SEVERITY_CRITICAL],
    )
    service_filter = fcols[3].multiselect("Service", sorted(df["Service"].unique()))
    quick_filter = fcols[4].selectbox(
        "Quick filter", ["None", "High & Critical only", "SSH only", "Sudo only", "Root only"],
    )

    filtered = df.copy()
    if search_user:
        filtered = filtered[filtered["Target User"].str.contains(search_user, case=False, na=False)]
    if search_ip:
        filtered = filtered[filtered["Attacker IP"].str.contains(search_ip, case=False, na=False)]
    if severity_filter:
        filtered = filtered[filtered["Severity"].isin(severity_filter)]
    if service_filter:
        filtered = filtered[filtered["Service"].isin(service_filter)]
    if quick_filter == "High & Critical only":
        filtered = filtered[filtered["Severity"].isin([constants.SEVERITY_HIGH, constants.SEVERITY_CRITICAL])]
    elif quick_filter == "SSH only":
        filtered = filtered[filtered["Service"] == "ssh"]
    elif quick_filter == "Sudo only":
        filtered = filtered[filtered["Service"] == "sudo"]
    elif quick_filter == "Root only":
        filtered = filtered[filtered["Target User"].str.contains("root", case=False, na=False)]

    st.dataframe(filtered, use_container_width=True, height=400)
    st.caption(f"Showing {len(filtered)} of {len(df)} alerts")


def render_recommendations() -> None:
    st.subheader("📋 Incident Response Recommendations")
    for rec in st.session_state["recommendations"]:
        st.markdown(f"- {rec}")

    st.subheader("🔬 Extracted IOCs (Indicators of Compromise)")
    iocs = LogAnalyzer.extract_iocs(st.session_state["alerts"])
    if iocs:
        st.code("\n".join(iocs), language="text")
    else:
        st.info("No IOCs extracted.")


def render_downloads() -> None:
    st.subheader("⬇️ Export Reports")
    stats = st.session_state["stats"]
    alerts = st.session_state["alerts"]
    recommendations = st.session_state["recommendations"]

    generator = ReportGenerator()
    md_report = generator.generate_markdown(stats, alerts, recommendations)
    csv_report = generator.generate_csv(alerts)
    html_report = generator.generate_html(stats, alerts, recommendations)

    ts_tag = datetime.now().strftime("%Y%m%d_%H%M%S")
    cols = st.columns(3)
    cols[0].download_button(
        "📝 Download Markdown", data=md_report,
        file_name=f"brute_force_report_{ts_tag}.md", mime="text/markdown",
        use_container_width=True,
    )
    cols[1].download_button(
        "📊 Download CSV", data=csv_report,
        file_name=f"brute_force_alerts_{ts_tag}.csv", mime="text/csv",
        use_container_width=True,
    )
    cols[2].download_button(
        "🌐 Download HTML", data=html_report,
        file_name=f"brute_force_report_{ts_tag}.html", mime="text/html",
        use_container_width=True,
    )


def render_main() -> None:
    render_header()

    if not st.session_state["analyzed"]:
        st.info(
            "👈 Use the sidebar to load a sample log or upload your own, then "
            "click **Analyze** to begin."
        )
        with st.expander("ℹ️ About this tool"):
            st.markdown("""
            This dashboard parses Linux `auth.log` files and Windows authentication
            exports (CSV/JSON) to detect brute-force attacks, credential stuffing,
            password spraying, and other suspicious authentication patterns —
            generating SOC-ready alerts, statistics, visualizations, and reports.
            """)
        return

    render_metrics()
    st.markdown("---")

    tabs = st.tabs([
        "🚨 Alerts", "📈 Charts", "📊 Alert Table", "📋 Recommendations", "⬇️ Export",
    ])

    with tabs[0]:
        st.subheader("Recent Alerts")
        render_alert_cards()

    with tabs[1]:
        render_charts()

    with tabs[2]:
        render_tables_and_filters()

    with tabs[3]:
        render_recommendations()

    with tabs[4]:
        render_downloads()


def main() -> None:
    render_sidebar()
    render_main()


if __name__ == "__main__":
    main()
