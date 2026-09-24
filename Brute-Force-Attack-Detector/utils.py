"""
utils.py
General-purpose helper utilities used across the application.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Optional

import constants


def is_valid_ip(ip: str) -> bool:
    """Return True if the given string is a valid IPv4/IPv6 address."""
    if not ip:
        return False
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_internal_ip(ip: str) -> bool:
    """Return True if the IP falls within common private/internal ranges."""
    if not is_valid_ip(ip):
        return False
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private
    except ValueError:
        return ip.startswith(constants.INTERNAL_IP_PREFIXES)


def parse_syslog_timestamp(month: str, day: str, time_str: str,
                            year: Optional[int] = None) -> Optional[datetime]:
    """
    Parse a syslog-style timestamp (e.g. 'Aug', '1', '14:05:23') into a
    datetime object. Syslog does not include a year, so the current year
    is assumed unless one is provided.
    """
    if year is None:
        year = datetime.now().year
    try:
        cleaned_day = day.strip().zfill(2)
        dt_str = f"{year} {month} {cleaned_day} {time_str}"
        return datetime.strptime(dt_str, "%Y %b %d %H:%M:%S")
    except (ValueError, AttributeError):
        return None


def safe_str(value) -> str:
    """Return a stripped string version of value, or empty string if None."""
    if value is None:
        return ""
    return str(value).strip()


def clamp(value: float, low: float, high: float) -> float:
    """Clamp value into the inclusive range [low, high]."""
    return max(low, min(high, value))


def calc_risk_score(failed_attempts: int, unique_ips: int, unique_users: int,
                     had_success_after_failures: bool, is_root: bool) -> int:
    """
    Compute a heuristic risk score from 0-100 based on attack characteristics.
    This is a bonus feature providing a single at-a-glance risk indicator.
    """
    score = 0.0
    score += min(failed_attempts * 2.0, 40.0)
    score += min(unique_ips * 5.0, 20.0)
    score += min(unique_users * 3.0, 15.0)
    if had_success_after_failures:
        score += 15.0
    if is_root:
        score += 10.0
    return int(clamp(score, 0, 100))


def calc_confidence_score(failed_attempts: int, threshold: int,
                           distinct_targets: int) -> int:
    """
    Compute an attack confidence score (0-100) reflecting how certain the
    detector is that a given pattern represents a genuine attack rather
    than benign noise (e.g. a user mistyping a password twice).
    """
    if threshold <= 0:
        threshold = 1
    ratio_component = clamp((failed_attempts / threshold) * 50.0, 0, 70)
    spread_component = clamp(distinct_targets * 10.0, 0, 30)
    return int(clamp(ratio_component + spread_component, 0, 100))


def severity_rank(severity: str) -> int:
    """Return a numeric rank for a severity string for sorting purposes."""
    return constants.SEVERITY_ORDER.get(severity, -1)


def format_duration(seconds: float) -> str:
    """Format a duration in seconds into a human-readable string."""
    seconds = int(seconds)
    hours, remainder = divmod(seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes}m {secs}s"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"
