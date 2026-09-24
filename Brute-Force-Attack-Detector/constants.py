"""
constants.py
Centralized constants used across the Brute Force Attack Detector project.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Severity Levels
# ---------------------------------------------------------------------------
SEVERITY_LOW = "Low"
SEVERITY_MEDIUM = "Medium"
SEVERITY_HIGH = "High"
SEVERITY_CRITICAL = "Critical"

SEVERITY_ORDER = {
    SEVERITY_LOW: 0,
    SEVERITY_MEDIUM: 1,
    SEVERITY_HIGH: 2,
    SEVERITY_CRITICAL: 3,
}

SEVERITY_COLORS = {
    SEVERITY_LOW: "#3b82f6",       # blue
    SEVERITY_MEDIUM: "#f59e0b",    # amber
    SEVERITY_HIGH: "#f97316",      # orange
    SEVERITY_CRITICAL: "#ef4444",  # red
}

# ---------------------------------------------------------------------------
# Authentication statuses
# ---------------------------------------------------------------------------
STATUS_SUCCESS = "SUCCESS"
STATUS_FAILED = "FAILED"
STATUS_INVALID_USER = "INVALID_USER"

# ---------------------------------------------------------------------------
# Log types
# ---------------------------------------------------------------------------
LOG_TYPE_LINUX = "linux"
LOG_TYPE_WINDOWS = "windows"

# ---------------------------------------------------------------------------
# Regex patterns for Linux auth.log parsing
# ---------------------------------------------------------------------------
# Example lines this must handle:
# Aug  1 14:05:23 webserver sshd[12345]: Failed password for root from 203.0.113.45 port 51244 ssh2
# Aug  1 14:05:24 webserver sshd[12345]: Failed password for invalid user admin from 203.0.113.45 port 51245 ssh2
# Aug  1 14:05:25 webserver sshd[12345]: Accepted password for deploy from 10.0.0.5 port 51300 ssh2
# Aug  1 14:05:26 webserver sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/ls
# Aug  1 14:05:27 webserver sshd[12345]: Invalid user test from 203.0.113.45 port 51250

LINUX_SYSLOG_PREFIX = (
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<process>\S+?)(\[(?P<pid>\d+)\])?:\s*"
)

RE_LINUX_FAILED_PASSWORD = (
    LINUX_SYSLOG_PREFIX
    + r"Failed password for (invalid user )?(?P<username>\S+) from "
    r"(?P<ip>[\d\.]+) port (?P<port>\d+)(\s+(?P<method>\w+\d?))?"
)

RE_LINUX_ACCEPTED_PASSWORD = (
    LINUX_SYSLOG_PREFIX
    + r"Accepted (?P<method>\w+) for (?P<username>\S+) from "
    r"(?P<ip>[\d\.]+) port (?P<port>\d+)"
)

RE_LINUX_INVALID_USER = (
    LINUX_SYSLOG_PREFIX
    + r"Invalid user (?P<username>\S+) from (?P<ip>[\d\.]+)(\s+port\s+(?P<port>\d+))?"
)

RE_LINUX_SUDO = (
    LINUX_SYSLOG_PREFIX
    + r"(?P<sudo_user>\S+)\s*:\s*TTY=(?P<tty>\S+)\s*;\s*PWD=(?P<pwd>\S+)\s*;\s*"
    r"USER=(?P<target_user>\S+)\s*;\s*COMMAND=(?P<command>.+)"
)

RE_LINUX_ROOT_LOGIN = re_root = r"root"

# ---------------------------------------------------------------------------
# Windows CSV expected columns (case-insensitive, flexible mapping)
# ---------------------------------------------------------------------------
WINDOWS_COLUMN_MAP = {
    "timestamp": ["timestamp", "time", "eventtime", "date"],
    "username": ["username", "user", "account", "targetusername"],
    "ip": ["ip", "ipaddress", "sourceip", "source_ip", "workstation"],
    "hostname": ["hostname", "computer", "host", "workstationname"],
    "status": ["status", "result", "eventtype", "outcome"],
    "service": ["service", "logontype", "process"],
}

# ---------------------------------------------------------------------------
# Detection defaults
# ---------------------------------------------------------------------------
DEFAULT_FAILED_THRESHOLD = 5
DEFAULT_TIME_WINDOW_MINUTES = 5
DEFAULT_CREDENTIAL_STUFFING_USER_THRESHOLD = 4  # distinct usernames from 1 IP
DEFAULT_PASSWORD_SPRAY_IP_THRESHOLD = 4         # distinct IPs against 1 username

INTERNAL_IP_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                         "172.2", "172.30.", "172.31.", "192.168.", "127.")

# ---------------------------------------------------------------------------
# MITRE ATT&CK mapping
# ---------------------------------------------------------------------------
MITRE_MAP = {
    "brute_force": {"id": "T1110", "name": "Brute Force"},
    "password_guessing": {"id": "T1110.001", "name": "Password Guessing"},
    "password_spraying": {"id": "T1110.003", "name": "Password Spraying"},
    "credential_stuffing": {"id": "T1110.004", "name": "Credential Stuffing"},
    "valid_accounts": {"id": "T1078", "name": "Valid Accounts"},
    "root_login": {"id": "T1078.003", "name": "Valid Accounts: Local Accounts"},
}

# ---------------------------------------------------------------------------
# Alert types
# ---------------------------------------------------------------------------
ALERT_BRUTE_FORCE = "Brute Force Attack"
ALERT_CREDENTIAL_STUFFING = "Credential Stuffing"
ALERT_PASSWORD_SPRAYING = "Password Spraying"
ALERT_ROOT_LOGIN_AFTER_FAILURES = "Root Login After Repeated Failures"
ALERT_SUCCESS_AFTER_FAILURES = "Successful Login After Repeated Failures"
ALERT_INVALID_USER = "Invalid User Attempt"
ALERT_REPEATED_FAILURES = "Repeated Failed Logins"

# ---------------------------------------------------------------------------
# File paths / directories
# ---------------------------------------------------------------------------
SAMPLE_LOG_DIR = "sample_logs"
REPORTS_DIR = "reports"
LOGS_DIR = "logs"
APP_LOG_FILE = "logs/app.log"

SAMPLE_LINUX_LOG = "sample_logs/auth.log"
SAMPLE_WINDOWS_CSV = "sample_logs/windows_auth.csv"
