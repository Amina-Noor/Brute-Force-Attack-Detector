"""
detector.py
Core detection engine: analyzes parsed LogEntry records and produces
Alert objects for brute-force attacks, credential stuffing, password
spraying, and other suspicious authentication patterns.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional

import constants
import utils
from config import DetectionConfig
from logger import get_logger
from parser import LogEntry

logger = get_logger(__name__)


@dataclass
class Alert:
    """A single detection alert."""

    alert_type: str
    severity: str
    ip: str
    username: str
    failed_attempts: int
    timestamp: Optional[datetime]
    description: str
    mitre_id: str = ""
    mitre_name: str = ""
    risk_score: int = 0
    confidence_score: int = 0
    service: str = "ssh"

    def to_dict(self) -> dict:
        return {
            "Alert Type": self.alert_type,
            "Severity": self.severity,
            "Attacker IP": self.ip,
            "Target User": self.username,
            "Failed Attempts": self.failed_attempts,
            "Timestamp": self.timestamp,
            "Description": self.description,
            "MITRE Technique": f"{self.mitre_id} - {self.mitre_name}".strip(" -"),
            "Risk Score": self.risk_score,
            "Confidence": self.confidence_score,
            "Service": self.service,
        }


class BruteForceDetector:
    """Runs all detection rules against a list of parsed LogEntry records."""

    def __init__(self, config: DetectionConfig) -> None:
        self.config = config

    # ------------------------------------------------------------------
    # Public entrypoint
    # ------------------------------------------------------------------
    def detect(self, entries: List[LogEntry]) -> List[Alert]:
        """Run all detection rules and return a combined, sorted alert list."""
        if not entries:
            return []

        entries = self._apply_filters(entries)
        entries = sorted(
            (e for e in entries if e.timestamp is not None),
            key=lambda e: e.timestamp,
        )

        alerts: List[Alert] = []
        alerts.extend(self._detect_brute_force_by_ip(entries))
        alerts.extend(self._detect_credential_stuffing(entries))
        alerts.extend(self._detect_password_spraying(entries))
        alerts.extend(self._detect_success_after_failures(entries))
        alerts.extend(self._detect_invalid_users(entries))

        alerts.sort(
            key=lambda a: (utils.severity_rank(a.severity), a.timestamp or datetime.min),
            reverse=True,
        )
        logger.info("Detection complete: %d alerts generated", len(alerts))
        return alerts

    # ------------------------------------------------------------------
    # Filtering
    # ------------------------------------------------------------------
    def _apply_filters(self, entries: List[LogEntry]) -> List[LogEntry]:
        filtered = []
        for entry in entries:
            if self.config.ignore_internal_ips and utils.is_internal_ip(entry.ip):
                continue
            if entry.username in self.config.trusted_users:
                continue
            filtered.append(entry)
        return filtered

    # ------------------------------------------------------------------
    # Rule 1: Brute force - one IP, many failures within time window
    # ------------------------------------------------------------------
    def _detect_brute_force_by_ip(self, entries: List[LogEntry]) -> List[Alert]:
        alerts: List[Alert] = []
        failures_by_ip: Dict[str, List[LogEntry]] = defaultdict(list)

        for entry in entries:
            if entry.status in (constants.STATUS_FAILED, constants.STATUS_INVALID_USER):
                failures_by_ip[entry.ip].append(entry)

        window = timedelta(minutes=self.config.time_window_minutes)

        for ip, fail_list in failures_by_ip.items():
            fail_list.sort(key=lambda e: e.timestamp)
            window_start = 0
            for i in range(len(fail_list)):
                while fail_list[i].timestamp - fail_list[window_start].timestamp > window:
                    window_start += 1
                count_in_window = i - window_start + 1
                if count_in_window == self.config.failed_threshold:
                    targets = {e.username for e in fail_list[window_start:i + 1]}
                    has_root = any(e.is_root for e in fail_list[window_start:i + 1])
                    severity = self._severity_for_bruteforce(count_in_window, has_root)
                    risk = utils.calc_risk_score(
                        count_in_window, 1, len(targets), False, has_root
                    )
                    confidence = utils.calc_confidence_score(
                        count_in_window, self.config.failed_threshold, len(targets)
                    )
                    alerts.append(Alert(
                        alert_type=constants.ALERT_BRUTE_FORCE,
                        severity=severity,
                        ip=ip,
                        username=", ".join(sorted(targets)) if len(targets) <= 3
                        else f"{len(targets)} accounts",
                        failed_attempts=count_in_window,
                        timestamp=fail_list[i].timestamp,
                        description=(
                            f"IP {ip} generated {count_in_window} failed login attempts "
                            f"within {self.config.time_window_minutes} minute(s), targeting "
                            f"{len(targets)} account(s)."
                        ),
                        mitre_id=constants.MITRE_MAP["brute_force"]["id"],
                        mitre_name=constants.MITRE_MAP["brute_force"]["name"],
                        risk_score=risk,
                        confidence_score=confidence,
                        service=fail_list[i].service,
                    ))

        return alerts

    @staticmethod
    def _severity_for_bruteforce(count: int, has_root: bool) -> str:
        if has_root:
            return constants.SEVERITY_CRITICAL
        if count >= 20:
            return constants.SEVERITY_CRITICAL
        if count >= 10:
            return constants.SEVERITY_HIGH
        return constants.SEVERITY_MEDIUM

    # ------------------------------------------------------------------
    # Rule 2: Credential stuffing - one IP attacking many distinct usernames
    # ------------------------------------------------------------------
    def _detect_credential_stuffing(self, entries: List[LogEntry]) -> List[Alert]:
        alerts: List[Alert] = []
        users_by_ip: Dict[str, set] = defaultdict(set)
        last_seen: Dict[str, datetime] = {}
        fail_count: Dict[str, int] = defaultdict(int)

        for entry in entries:
            if entry.status in (constants.STATUS_FAILED, constants.STATUS_INVALID_USER):
                users_by_ip[entry.ip].add(entry.username)
                fail_count[entry.ip] += 1
                last_seen[entry.ip] = entry.timestamp

        for ip, usernames in users_by_ip.items():
            if len(usernames) >= self.config.credential_stuffing_user_threshold:
                risk = utils.calc_risk_score(fail_count[ip], 1, len(usernames), False, False)
                confidence = utils.calc_confidence_score(
                    fail_count[ip], self.config.failed_threshold, len(usernames)
                )
                alerts.append(Alert(
                    alert_type=constants.ALERT_CREDENTIAL_STUFFING,
                    severity=constants.SEVERITY_HIGH if len(usernames) < 8
                    else constants.SEVERITY_CRITICAL,
                    ip=ip,
                    username=f"{len(usernames)} accounts",
                    failed_attempts=fail_count[ip],
                    timestamp=last_seen.get(ip),
                    description=(
                        f"IP {ip} attempted authentication against "
                        f"{len(usernames)} distinct usernames, consistent with "
                        f"credential stuffing behavior."
                    ),
                    mitre_id=constants.MITRE_MAP["credential_stuffing"]["id"],
                    mitre_name=constants.MITRE_MAP["credential_stuffing"]["name"],
                    risk_score=risk,
                    confidence_score=confidence,
                ))

        return alerts

    # ------------------------------------------------------------------
    # Rule 3: Password spraying - one username attacked by many distinct IPs
    # ------------------------------------------------------------------
    def _detect_password_spraying(self, entries: List[LogEntry]) -> List[Alert]:
        alerts: List[Alert] = []
        ips_by_user: Dict[str, set] = defaultdict(set)
        last_seen: Dict[str, datetime] = {}
        fail_count: Dict[str, int] = defaultdict(int)

        for entry in entries:
            if entry.status in (constants.STATUS_FAILED, constants.STATUS_INVALID_USER):
                ips_by_user[entry.username].add(entry.ip)
                fail_count[entry.username] += 1
                last_seen[entry.username] = entry.timestamp

        for username, ip_set in ips_by_user.items():
            if len(ip_set) >= self.config.password_spray_ip_threshold:
                risk = utils.calc_risk_score(
                    fail_count[username], len(ip_set), 1, False, username == "root"
                )
                confidence = utils.calc_confidence_score(
                    fail_count[username], self.config.failed_threshold, len(ip_set)
                )
                alerts.append(Alert(
                    alert_type=constants.ALERT_PASSWORD_SPRAYING,
                    severity=constants.SEVERITY_HIGH if len(ip_set) < 8
                    else constants.SEVERITY_CRITICAL,
                    ip=f"{len(ip_set)} IPs",
                    username=username,
                    failed_attempts=fail_count[username],
                    timestamp=last_seen.get(username),
                    description=(
                        f"Account '{username}' received failed login attempts from "
                        f"{len(ip_set)} distinct IP addresses, consistent with "
                        f"password spraying."
                    ),
                    mitre_id=constants.MITRE_MAP["password_spraying"]["id"],
                    mitre_name=constants.MITRE_MAP["password_spraying"]["name"],
                    risk_score=risk,
                    confidence_score=confidence,
                ))

        return alerts

    # ------------------------------------------------------------------
    # Rule 4: Successful login immediately after repeated failures
    # ------------------------------------------------------------------
    def _detect_success_after_failures(self, entries: List[LogEntry]) -> List[Alert]:
        alerts: List[Alert] = []
        recent_failures: Dict[str, List[LogEntry]] = defaultdict(list)
        window = timedelta(minutes=self.config.time_window_minutes)

        for entry in entries:
            key = entry.ip
            if entry.status in (constants.STATUS_FAILED, constants.STATUS_INVALID_USER):
                recent_failures[key].append(entry)
            elif entry.status == constants.STATUS_SUCCESS:
                fails = [
                    f for f in recent_failures[key]
                    if entry.timestamp - f.timestamp <= window
                ]
                if len(fails) >= self.config.failed_threshold:
                    severity = (
                        constants.SEVERITY_CRITICAL if entry.is_root
                        else constants.SEVERITY_HIGH
                    )
                    risk = utils.calc_risk_score(
                        len(fails), 1, 1, True, entry.is_root
                    )
                    confidence = utils.calc_confidence_score(
                        len(fails), self.config.failed_threshold, 1
                    )
                    alert_type = (
                        constants.ALERT_ROOT_LOGIN_AFTER_FAILURES if entry.is_root
                        else constants.ALERT_SUCCESS_AFTER_FAILURES
                    )
                    alerts.append(Alert(
                        alert_type=alert_type,
                        severity=severity,
                        ip=entry.ip,
                        username=entry.username,
                        failed_attempts=len(fails),
                        timestamp=entry.timestamp,
                        description=(
                            f"Successful login for '{entry.username}' from {entry.ip} "
                            f"occurred after {len(fails)} failed attempts within "
                            f"{self.config.time_window_minutes} minute(s) — possible "
                            f"compromised credentials."
                        ),
                        mitre_id=constants.MITRE_MAP["valid_accounts"]["id"],
                        mitre_name=constants.MITRE_MAP["valid_accounts"]["name"],
                        risk_score=risk,
                        confidence_score=confidence,
                        service=entry.service,
                    ))
                recent_failures[key] = []

        return alerts

    # ------------------------------------------------------------------
    # Rule 5: Invalid / unknown user attempts (medium severity, informational)
    # ------------------------------------------------------------------
    def _detect_invalid_users(self, entries: List[LogEntry]) -> List[Alert]:
        alerts: List[Alert] = []
        counts: Dict[str, int] = defaultdict(int)
        last_seen: Dict[str, datetime] = {}
        usernames: Dict[str, set] = defaultdict(set)

        for entry in entries:
            if entry.status == constants.STATUS_INVALID_USER:
                counts[entry.ip] += 1
                last_seen[entry.ip] = entry.timestamp
                usernames[entry.ip].add(entry.username)

        for ip, count in counts.items():
            if count >= max(2, self.config.failed_threshold // 2):
                alerts.append(Alert(
                    alert_type=constants.ALERT_INVALID_USER,
                    severity=constants.SEVERITY_MEDIUM,
                    ip=ip,
                    username=", ".join(sorted(usernames[ip]))[:60],
                    failed_attempts=count,
                    timestamp=last_seen.get(ip),
                    description=(
                        f"IP {ip} attempted {count} logins with invalid/unknown "
                        f"usernames — possible reconnaissance or enumeration."
                    ),
                    mitre_id=constants.MITRE_MAP["brute_force"]["id"],
                    mitre_name=constants.MITRE_MAP["brute_force"]["name"],
                    risk_score=utils.calc_risk_score(count, 1, len(usernames[ip]), False, False),
                    confidence_score=utils.calc_confidence_score(
                        count, self.config.failed_threshold, len(usernames[ip])
                    ),
                ))

        return alerts
