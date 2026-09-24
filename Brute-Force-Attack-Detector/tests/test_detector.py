"""Unit tests for detector.py"""

import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import constants
from config import DetectionConfig
from detector import BruteForceDetector
from parser import LogEntry


def make_entry(username, ip, status, minute_offset=0, is_root=False, service="ssh"):
    base = datetime(2026, 8, 1, 12, 0, 0)
    return LogEntry(
        timestamp=base + timedelta(minutes=minute_offset),
        username=username, ip=ip, hostname="host1", status=status,
        service=service, is_root=is_root,
    )


def test_detects_brute_force_by_ip():
    config = DetectionConfig(failed_threshold=5, time_window_minutes=5)
    detector = BruteForceDetector(config)
    entries = [
        make_entry("root", "203.0.113.45", constants.STATUS_FAILED, minute_offset=i * 0.1)
        for i in range(6)
    ]
    alerts = detector.detect(entries)
    assert any(a.alert_type == constants.ALERT_BRUTE_FORCE for a in alerts)


def test_no_alerts_for_normal_traffic():
    config = DetectionConfig(failed_threshold=5, time_window_minutes=5)
    detector = BruteForceDetector(config)
    entries = [
        make_entry("alice", "10.0.0.5", constants.STATUS_SUCCESS, minute_offset=0),
        make_entry("bob", "10.0.0.6", constants.STATUS_SUCCESS, minute_offset=5),
    ]
    alerts = detector.detect(entries)
    assert len(alerts) == 0


def test_detects_credential_stuffing():
    config = DetectionConfig(failed_threshold=100, time_window_minutes=5,
                              credential_stuffing_user_threshold=3)
    detector = BruteForceDetector(config)
    entries = [
        make_entry(f"user{i}", "198.51.100.23", constants.STATUS_INVALID_USER, minute_offset=i)
        for i in range(4)
    ]
    alerts = detector.detect(entries)
    assert any(a.alert_type == constants.ALERT_CREDENTIAL_STUFFING for a in alerts)


def test_detects_password_spraying():
    config = DetectionConfig(failed_threshold=100, time_window_minutes=5,
                              password_spray_ip_threshold=3)
    detector = BruteForceDetector(config)
    entries = [
        make_entry("svc-sql", f"203.0.113.{i}", constants.STATUS_FAILED, minute_offset=i)
        for i in range(4)
    ]
    alerts = detector.detect(entries)
    assert any(a.alert_type == constants.ALERT_PASSWORD_SPRAYING for a in alerts)


def test_detects_success_after_failures():
    config = DetectionConfig(failed_threshold=3, time_window_minutes=5)
    detector = BruteForceDetector(config)
    entries = [
        make_entry("root", "203.0.113.45", constants.STATUS_FAILED, minute_offset=0, is_root=True),
        make_entry("root", "203.0.113.45", constants.STATUS_FAILED, minute_offset=1, is_root=True),
        make_entry("root", "203.0.113.45", constants.STATUS_FAILED, minute_offset=2, is_root=True),
        make_entry("root", "203.0.113.45", constants.STATUS_SUCCESS, minute_offset=3, is_root=True),
    ]
    alerts = detector.detect(entries)
    assert any(a.alert_type == constants.ALERT_ROOT_LOGIN_AFTER_FAILURES for a in alerts)
    critical_alerts = [a for a in alerts if a.severity == constants.SEVERITY_CRITICAL]
    assert len(critical_alerts) >= 1


def test_trusted_users_are_ignored():
    config = DetectionConfig(failed_threshold=3, time_window_minutes=5,
                              trusted_users=["alice"])
    detector = BruteForceDetector(config)
    entries = [
        make_entry("alice", "203.0.113.45", constants.STATUS_FAILED, minute_offset=i * 0.1)
        for i in range(6)
    ]
    alerts = detector.detect(entries)
    assert len(alerts) == 0


def test_internal_ips_ignored_when_configured():
    config = DetectionConfig(failed_threshold=3, time_window_minutes=5,
                              ignore_internal_ips=True)
    detector = BruteForceDetector(config)
    entries = [
        make_entry("alice", "10.0.0.5", constants.STATUS_FAILED, minute_offset=i * 0.1)
        for i in range(6)
    ]
    alerts = detector.detect(entries)
    assert len(alerts) == 0


def test_empty_entries_returns_empty_alerts():
    config = DetectionConfig()
    detector = BruteForceDetector(config)
    assert detector.detect([]) == []
