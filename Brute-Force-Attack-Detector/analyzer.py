"""
analyzer.py
Computes aggregate statistics from parsed log entries and generated alerts.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

import constants
import utils
from detector import Alert
from logger import get_logger
from parser import LogEntry

logger = get_logger(__name__)


@dataclass
class Statistics:
    """Aggregate statistics for a single analysis run."""

    total_entries: int = 0
    successful_logins: int = 0
    failed_logins: int = 0
    invalid_user_attempts: int = 0
    total_alerts: int = 0
    unique_attackers: int = 0
    unique_users_targeted: int = 0
    most_attacked_account: str = "N/A"
    top_attacker_ip: str = "N/A"
    top_services: List[tuple] = field(default_factory=list)
    first_event_time: Optional[datetime] = None
    last_event_time: Optional[datetime] = None
    attack_duration_seconds: float = 0.0
    average_attacks_per_hour: float = 0.0
    severity_breakdown: Dict[str, int] = field(default_factory=dict)
    top_attacker_ips: List[tuple] = field(default_factory=list)
    top_targeted_users: List[tuple] = field(default_factory=list)

    def to_summary_dict(self) -> dict:
        return {
            "Total Log Entries": self.total_entries,
            "Successful Logins": self.successful_logins,
            "Failed Logins": self.failed_logins,
            "Invalid User Attempts": self.invalid_user_attempts,
            "Total Alerts": self.total_alerts,
            "Unique Attacker IPs": self.unique_attackers,
            "Unique Users Targeted": self.unique_users_targeted,
            "Most Attacked Account": self.most_attacked_account,
            "Top Attacker IP": self.top_attacker_ip,
            "Attack Duration": utils.format_duration(self.attack_duration_seconds),
            "Avg Attacks / Hour": round(self.average_attacks_per_hour, 2),
        }


class LogAnalyzer:
    """Computes statistics from parsed log entries and detection alerts."""

    def analyze(self, entries: List[LogEntry], alerts: List[Alert]) -> Statistics:
        stats = Statistics()

        if not entries:
            logger.warning("Analyzer received no entries to analyze")
            return stats

        stats.total_entries = len(entries)
        stats.successful_logins = sum(
            1 for e in entries if e.status == constants.STATUS_SUCCESS
        )
        stats.failed_logins = sum(
            1 for e in entries if e.status == constants.STATUS_FAILED
        )
        stats.invalid_user_attempts = sum(
            1 for e in entries if e.status == constants.STATUS_INVALID_USER
        )
        stats.total_alerts = len(alerts)

        failed_entries = [
            e for e in entries
            if e.status in (constants.STATUS_FAILED, constants.STATUS_INVALID_USER)
        ]

        attacker_ip_counts = Counter(e.ip for e in failed_entries)
        targeted_user_counts = Counter(e.username for e in failed_entries)

        stats.unique_attackers = len(attacker_ip_counts)
        stats.unique_users_targeted = len(targeted_user_counts)

        if targeted_user_counts:
            stats.most_attacked_account = targeted_user_counts.most_common(1)[0][0]
        if attacker_ip_counts:
            stats.top_attacker_ip = attacker_ip_counts.most_common(1)[0][0]

        stats.top_attacker_ips = attacker_ip_counts.most_common(10)
        stats.top_targeted_users = targeted_user_counts.most_common(10)

        service_counts = Counter(e.service for e in entries)
        stats.top_services = service_counts.most_common(5)

        timestamps = sorted(e.timestamp for e in entries if e.timestamp is not None)
        if timestamps:
            stats.first_event_time = timestamps[0]
            stats.last_event_time = timestamps[-1]
            duration = (timestamps[-1] - timestamps[0]).total_seconds()
            stats.attack_duration_seconds = duration
            hours = max(duration / 3600.0, 1 / 60.0)
            stats.average_attacks_per_hour = len(failed_entries) / hours

        severity_counts = Counter(a.severity for a in alerts)
        stats.severity_breakdown = {
            sev: severity_counts.get(sev, 0)
            for sev in (
                constants.SEVERITY_LOW,
                constants.SEVERITY_MEDIUM,
                constants.SEVERITY_HIGH,
                constants.SEVERITY_CRITICAL,
            )
        }

        logger.info(
            "Analysis complete: %d entries, %d alerts, %d unique attackers",
            stats.total_entries, stats.total_alerts, stats.unique_attackers,
        )
        return stats

    @staticmethod
    def extract_iocs(alerts: List[Alert]) -> List[str]:
        """Extract Indicators of Compromise (IOCs) - primarily attacker IPs."""
        iocs = set()
        for alert in alerts:
            ip = alert.ip
            if utils.is_valid_ip(ip):
                iocs.add(ip)
        return sorted(iocs)

    @staticmethod
    def generate_recommendations(stats: Statistics, alerts: List[Alert]) -> List[str]:
        """Generate incident-response recommendations based on findings."""
        recs: List[str] = []

        if stats.severity_breakdown.get(constants.SEVERITY_CRITICAL, 0) > 0:
            recs.append(
                "Immediately isolate and investigate accounts involved in CRITICAL "
                "alerts; rotate credentials and enforce MFA."
            )
        if any(a.alert_type == constants.ALERT_ROOT_LOGIN_AFTER_FAILURES for a in alerts):
            recs.append(
                "Disable direct root/administrator SSH login and require sudo with "
                "individual accounts and MFA."
            )
        if stats.unique_attackers > 5:
            recs.append(
                "Consider blocking or rate-limiting the top attacker IPs at the "
                "firewall or WAF, and enable fail2ban or equivalent."
            )
        if any(a.alert_type == constants.ALERT_CREDENTIAL_STUFFING for a in alerts):
            recs.append(
                "Enforce unique, breach-checked passwords and enable account "
                "lockout / CAPTCHA after repeated failures to counter credential "
                "stuffing."
            )
        if any(a.alert_type == constants.ALERT_PASSWORD_SPRAYING for a in alerts):
            recs.append(
                "Deploy conditional access policies and geo-velocity checks to "
                "counter distributed password spraying."
            )
        if stats.failed_logins > stats.successful_logins * 5 and stats.successful_logins > 0:
            recs.append(
                "Failed-to-success login ratio is unusually high; review "
                "authentication logs for further automated attack activity."
            )
        if not recs:
            recs.append(
                "No high-risk patterns detected. Continue routine monitoring and "
                "maintain current security controls."
            )

        return recs
