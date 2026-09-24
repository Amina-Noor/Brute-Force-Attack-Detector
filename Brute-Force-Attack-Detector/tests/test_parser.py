"""Unit tests for parser.py"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import constants
from parser import LogParser, ParsingError


def test_parse_failed_password_line():
    parser = LogParser()
    line = "Aug  1 14:05:23 webserver sshd[12345]: Failed password for root from 203.0.113.45 port 51244 ssh2"
    entries = parser.parse_content(line, constants.LOG_TYPE_LINUX)
    assert len(entries) == 1
    entry = entries[0]
    assert entry.username == "root"
    assert entry.ip == "203.0.113.45"
    assert entry.status == constants.STATUS_FAILED
    assert entry.is_root is True


def test_parse_invalid_user_line():
    parser = LogParser()
    line = "Aug  1 14:05:24 webserver sshd[12345]: Failed password for invalid user admin from 203.0.113.45 port 51245 ssh2"
    entries = parser.parse_content(line, constants.LOG_TYPE_LINUX)
    assert len(entries) == 1
    assert entries[0].status == constants.STATUS_INVALID_USER
    assert entries[0].username == "admin"


def test_parse_accepted_password_line():
    parser = LogParser()
    line = "Aug  1 14:05:25 webserver sshd[12345]: Accepted password for deploy from 10.0.0.5 port 51300 ssh2"
    entries = parser.parse_content(line, constants.LOG_TYPE_LINUX)
    assert len(entries) == 1
    assert entries[0].status == constants.STATUS_SUCCESS
    assert entries[0].username == "deploy"


def test_parse_sudo_line():
    parser = LogParser()
    line = "Aug  1 14:05:26 webserver sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/ls"
    entries = parser.parse_content(line, constants.LOG_TYPE_LINUX)
    assert len(entries) == 1
    assert entries[0].is_sudo_event is True
    assert entries[0].is_root is True


def test_parse_empty_content_returns_empty_list():
    parser = LogParser()
    entries = parser.parse_content("", constants.LOG_TYPE_LINUX)
    assert entries == []


def test_parse_garbage_lines_are_skipped_not_fatal():
    parser = LogParser()
    content = "this is not a valid syslog line\nneither is this one"
    entries = parser.parse_content(content, constants.LOG_TYPE_LINUX)
    assert entries == []


def test_parse_windows_csv_basic():
    parser = LogParser()
    csv_content = (
        "Timestamp,Username,IP,Hostname,Status,Service\n"
        "2026-08-01 08:00:00,jsmith,10.1.0.10,WIN-DC01,Success,NTLM\n"
        "2026-08-01 08:00:05,administrator,198.51.100.99,WIN-DC01,Failed,NTLM\n"
    )
    entries = parser.parse_content(csv_content, constants.LOG_TYPE_WINDOWS)
    assert len(entries) == 2
    assert entries[0].status == constants.STATUS_SUCCESS
    assert entries[1].status == constants.STATUS_FAILED
    assert entries[1].username == "administrator"


def test_parse_windows_json_basic():
    parser = LogParser()
    json_content = (
        '[{"timestamp": "2026-08-01 08:00:00", "username": "bob", '
        '"ip": "10.1.0.11", "hostname": "WIN-FS02", "status": "Failed", "service": "NTLM"}]'
    )
    entries = parser.parse_content(json_content, constants.LOG_TYPE_WINDOWS)
    assert len(entries) == 1
    assert entries[0].username == "bob"
    assert entries[0].status == constants.STATUS_FAILED


def test_unsupported_log_type_raises():
    parser = LogParser()
    try:
        parser.parse_content("some content", "unsupported_type")
        assert False, "Expected ParsingError"
    except ParsingError:
        pass


def test_parse_file_not_found_raises():
    parser = LogParser()
    try:
        parser.parse_file("/nonexistent/path/auth.log")
        assert False, "Expected FileNotFoundError"
    except FileNotFoundError:
        pass
