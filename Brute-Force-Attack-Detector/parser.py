"""
parser.py
Parses Linux auth.log files and Windows authentication CSV/JSON exports
into a unified list of LogEntry records for downstream analysis.
"""

from __future__ import annotations

import csv
import io
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Union

import constants
import utils
from logger import get_logger

logger = get_logger(__name__)


@dataclass
class LogEntry:
    """A single normalized authentication log record."""

    timestamp: Optional[datetime]
    username: str
    ip: str
    hostname: str
    status: str  # SUCCESS / FAILED / INVALID_USER
    service: str = "ssh"
    auth_method: str = "password"
    raw_line: str = ""
    is_root: bool = False
    is_sudo_event: bool = False

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "username": self.username,
            "ip": self.ip,
            "hostname": self.hostname,
            "status": self.status,
            "service": self.service,
            "auth_method": self.auth_method,
            "is_root": self.is_root,
            "is_sudo_event": self.is_sudo_event,
        }


class ParsingError(Exception):
    """Raised when a log file cannot be parsed at all."""


class LogParser:
    """Parses raw log content (Linux syslog or Windows CSV/JSON) into LogEntry objects."""

    def __init__(self) -> None:
        self._re_failed = re.compile(constants.RE_LINUX_FAILED_PASSWORD)
        self._re_accepted = re.compile(constants.RE_LINUX_ACCEPTED_PASSWORD)
        self._re_invalid = re.compile(constants.RE_LINUX_INVALID_USER)
        self._re_sudo = re.compile(constants.RE_LINUX_SUDO)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def parse_file(self, file_path: Union[str, Path],
                    log_type: str = constants.LOG_TYPE_LINUX) -> List[LogEntry]:
        """Read a file from disk and parse it according to log_type."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {file_path}")

        try:
            raw_bytes = path.read_bytes()
        except PermissionError as exc:
            logger.error("Permission denied reading %s: %s", file_path, exc)
            raise

        content = self._decode(raw_bytes)
        return self.parse_content(content, log_type, source_name=str(path))

    def parse_content(self, content: str, log_type: str = constants.LOG_TYPE_LINUX,
                       source_name: str = "<uploaded>") -> List[LogEntry]:
        """Parse raw text content into a list of LogEntry objects."""
        start_time = time.time()
        entries: List[LogEntry] = []

        if not content or not content.strip():
            logger.warning("Empty log content received from %s", source_name)
            return entries

        try:
            if log_type == constants.LOG_TYPE_LINUX:
                entries = self._parse_linux(content)
            elif log_type == constants.LOG_TYPE_WINDOWS:
                entries = self._parse_windows(content)
            else:
                raise ParsingError(f"Unsupported log type: {log_type}")
        except Exception as exc:  # noqa: BLE001 - we want to log & continue gracefully
            logger.error("Fatal parsing error for %s: %s", source_name, exc)
            raise ParsingError(f"Could not parse log content: {exc}") from exc

        elapsed = time.time() - start_time
        logger.info(
            "Parsed %d entries from %s (%s) in %.3fs",
            len(entries), source_name, log_type, elapsed,
        )
        return entries

    # ------------------------------------------------------------------
    # Decoding
    # ------------------------------------------------------------------
    @staticmethod
    def _decode(raw_bytes: bytes) -> str:
        """Attempt to decode bytes as UTF-8, falling back to latin-1."""
        for encoding in ("utf-8", "latin-1"):
            try:
                return raw_bytes.decode(encoding)
            except UnicodeDecodeError:
                continue
        logger.warning("Falling back to lossy decoding (invalid encoding detected)")
        return raw_bytes.decode("utf-8", errors="replace")

    # ------------------------------------------------------------------
    # Linux auth.log parsing
    # ------------------------------------------------------------------
    def _parse_linux(self, content: str) -> List[LogEntry]:
        entries: List[LogEntry] = []
        skipped = 0

        for line_num, line in enumerate(content.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                entry = self._parse_linux_line(line)
                if entry:
                    entries.append(entry)
                else:
                    skipped += 1
            except Exception as exc:  # noqa: BLE001
                skipped += 1
                logger.debug("Skipped malformed line %d: %s (%s)", line_num, line[:80], exc)

        if skipped:
            logger.warning("Skipped %d unparsable/irrelevant lines in Linux log", skipped)
        return entries

    def _parse_linux_line(self, line: str) -> Optional[LogEntry]:
        match = self._re_failed.search(line)
        if match:
            gd = match.groupdict()
            username = gd.get("username", "unknown")
            return LogEntry(
                timestamp=self._syslog_ts(gd),
                username=username,
                ip=gd.get("ip", "0.0.0.0"),
                hostname=gd.get("hostname", "unknown-host"),
                status=(
                    constants.STATUS_INVALID_USER
                    if "invalid user" in line
                    else constants.STATUS_FAILED
                ),
                service="ssh",
                auth_method=gd.get("method") or "password",
                raw_line=line,
                is_root=(username == "root"),
            )

        match = self._re_accepted.search(line)
        if match:
            gd = match.groupdict()
            username = gd.get("username", "unknown")
            return LogEntry(
                timestamp=self._syslog_ts(gd),
                username=username,
                ip=gd.get("ip", "0.0.0.0"),
                hostname=gd.get("hostname", "unknown-host"),
                status=constants.STATUS_SUCCESS,
                service="ssh",
                auth_method=gd.get("method", "password"),
                raw_line=line,
                is_root=(username == "root"),
            )

        match = self._re_invalid.search(line)
        if match:
            gd = match.groupdict()
            return LogEntry(
                timestamp=self._syslog_ts(gd),
                username=gd.get("username", "unknown"),
                ip=gd.get("ip", "0.0.0.0"),
                hostname=gd.get("hostname", "unknown-host"),
                status=constants.STATUS_INVALID_USER,
                service="ssh",
                auth_method="password",
                raw_line=line,
                is_root=False,
            )

        match = self._re_sudo.search(line)
        if match:
            gd = match.groupdict()
            return LogEntry(
                timestamp=self._syslog_ts(gd),
                username=gd.get("sudo_user", "unknown"),
                ip="127.0.0.1",
                hostname=gd.get("hostname", "unknown-host"),
                status=constants.STATUS_SUCCESS,
                service="sudo",
                auth_method="sudo",
                raw_line=line,
                is_root=(gd.get("target_user") == "root"),
                is_sudo_event=True,
            )

        return None

    @staticmethod
    def _syslog_ts(groupdict: dict) -> Optional[datetime]:
        return utils.parse_syslog_timestamp(
            groupdict.get("month", ""),
            groupdict.get("day", ""),
            groupdict.get("time", ""),
        )

    # ------------------------------------------------------------------
    # Windows CSV / JSON parsing
    # ------------------------------------------------------------------
    def _parse_windows(self, content: str) -> List[LogEntry]:
        stripped = content.strip()
        if stripped.startswith("[") or stripped.startswith("{"):
            return self._parse_windows_json(content)
        return self._parse_windows_csv(content)

    def _parse_windows_csv(self, content: str) -> List[LogEntry]:
        entries: List[LogEntry] = []
        reader = csv.DictReader(io.StringIO(content))
        if not reader.fieldnames:
            raise ParsingError("Windows CSV has no header row")

        col_lookup = self._build_column_lookup(reader.fieldnames)

        for row_num, row in enumerate(reader, start=1):
            try:
                entry = self._row_to_entry(row, col_lookup)
                if entry:
                    entries.append(entry)
            except Exception as exc:  # noqa: BLE001
                logger.debug("Skipped malformed CSV row %d: %s", row_num, exc)

        return entries

    def _parse_windows_json(self, content: str) -> List[LogEntry]:
        entries: List[LogEntry] = []
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ParsingError(f"Invalid JSON: {exc}") from exc

        records = data if isinstance(data, list) else [data]
        if records:
            col_lookup = self._build_column_lookup(list(records[0].keys()))
        else:
            col_lookup = {}

        for row in records:
            try:
                entry = self._row_to_entry(row, col_lookup)
                if entry:
                    entries.append(entry)
            except Exception as exc:  # noqa: BLE001
                logger.debug("Skipped malformed JSON record: %s", exc)

        return entries

    @staticmethod
    def _build_column_lookup(fieldnames: List[str]) -> dict:
        """Map logical field names -> actual CSV column names (case-insensitive)."""
        lookup = {}
        lowered = {f.lower().strip(): f for f in fieldnames}
        for logical_name, aliases in constants.WINDOWS_COLUMN_MAP.items():
            for alias in aliases:
                if alias in lowered:
                    lookup[logical_name] = lowered[alias]
                    break
        return lookup

    def _row_to_entry(self, row: dict, col_lookup: dict) -> Optional[LogEntry]:
        def get(field_name: str, default: str = "") -> str:
            col = col_lookup.get(field_name)
            if col and col in row:
                return utils.safe_str(row[col])
            return default

        username = get("username", "unknown") or "unknown"
        ip = get("ip", "0.0.0.0") or "0.0.0.0"
        hostname = get("hostname", "WORKSTATION") or "WORKSTATION"
        raw_status = (get("status", "") or "").lower()
        service = get("service", "windows-login") or "windows-login"
        ts_raw = get("timestamp", "")

        if any(k in raw_status for k in ("success", "accepted", "logon success", "4624")):
            status = constants.STATUS_SUCCESS
        elif any(k in raw_status for k in ("invalid", "unknown user", "no such user")):
            status = constants.STATUS_INVALID_USER
        else:
            status = constants.STATUS_FAILED

        timestamp = self._parse_flexible_timestamp(ts_raw)

        return LogEntry(
            timestamp=timestamp,
            username=username,
            ip=ip,
            hostname=hostname,
            status=status,
            service=service,
            auth_method="ntlm",
            raw_line=str(row),
            is_root=(username.lower() in ("administrator", "admin", "root")),
        )

    @staticmethod
    def _parse_flexible_timestamp(ts_raw: str) -> Optional[datetime]:
        if not ts_raw:
            return None
        formats = (
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%m/%d/%Y %H:%M:%S",
            "%d/%m/%Y %H:%M:%S",
            "%Y-%m-%d %H:%M",
        )
        for fmt in formats:
            try:
                return datetime.strptime(ts_raw, fmt)
            except ValueError:
                continue
        logger.debug("Unable to parse Windows timestamp: %s", ts_raw)
        return None
