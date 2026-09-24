"""Unit tests for report_generator.py and analyzer.py"""

import sys
import tempfile
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import constants
from analyzer import LogAnalyzer
from detector import Alert
from parser import LogEntry
from report_generator import ReportGenerator


def make_alert(alert_type=constants.ALERT_BRUTE_FORCE, severity=constants.SEVERITY_HIGH):
    return Alert(
        alert_type=alert_type, severity=severity, ip="203.0.113.45",
        username="root", failed_attempts=10, timestamp=datetime(2026, 8, 1, 14, 5),
        description="Test alert description", mitre_id="T1110", mitre_name="Brute Force",
        risk_score=80, confidence_score=90,
    )


def make_entry(status=constants.STATUS_FAILED):
    return LogEntry(
        timestamp=datetime(2026, 8, 1, 14, 5), username="root", ip="203.0.113.45",
        hostname="host1", status=status,
    )


def test_analyzer_computes_basic_stats():
    entries = [make_entry(constants.STATUS_FAILED), make_entry(constants.STATUS_SUCCESS)]
    alerts = [make_alert()]
    analyzer = LogAnalyzer()
    stats = analyzer.analyze(entries, alerts)
    assert stats.total_entries == 2
    assert stats.failed_logins == 1
    assert stats.successful_logins == 1
    assert stats.total_alerts == 1


def test_analyzer_handles_empty_entries():
    analyzer = LogAnalyzer()
    stats = analyzer.analyze([], [])
    assert stats.total_entries == 0


def test_extract_iocs_returns_unique_valid_ips():
    alerts = [make_alert(), make_alert()]
    iocs = LogAnalyzer.extract_iocs(alerts)
    assert iocs == ["203.0.113.45"]


def test_generate_recommendations_not_empty():
    analyzer = LogAnalyzer()
    entries = [make_entry(constants.STATUS_FAILED)]
    alerts = [make_alert(severity=constants.SEVERITY_CRITICAL)]
    stats = analyzer.analyze(entries, alerts)
    recs = analyzer.generate_recommendations(stats, alerts)
    assert len(recs) > 0
    assert any("isolate" in r.lower() or "critical" in r.lower() for r in recs)


def test_markdown_report_contains_key_sections():
    analyzer = LogAnalyzer()
    entries = [make_entry()]
    alerts = [make_alert()]
    stats = analyzer.analyze(entries, alerts)
    recs = analyzer.generate_recommendations(stats, alerts)

    generator = ReportGenerator(export_dir=tempfile.mkdtemp())
    md = generator.generate_markdown(stats, alerts, recs)
    assert "# Brute Force Attack Detection Report" in md
    assert "## Executive Summary" in md
    assert "## Recommendations" in md


def test_csv_report_contains_alert_data():
    generator = ReportGenerator(export_dir=tempfile.mkdtemp())
    csv_content = generator.generate_csv([make_alert()])
    assert "203.0.113.45" in csv_content
    assert "Brute Force Attack" in csv_content


def test_html_report_is_valid_html():
    analyzer = LogAnalyzer()
    entries = [make_entry()]
    alerts = [make_alert()]
    stats = analyzer.analyze(entries, alerts)
    recs = analyzer.generate_recommendations(stats, alerts)

    generator = ReportGenerator(export_dir=tempfile.mkdtemp())
    html = generator.generate_html(stats, alerts, recs)
    assert "<!DOCTYPE html>" in html
    assert "203.0.113.45" in html


def test_save_report_writes_file():
    generator = ReportGenerator(export_dir=tempfile.mkdtemp())
    path = generator.save_report("test content", "test.md")
    assert path.exists()
    assert path.read_text(encoding="utf-8") == "test content"
