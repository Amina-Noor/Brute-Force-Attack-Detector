"""
sample_data_generator.py
Generates realistic sample datasets: a Linux auth.log with 500+ entries
covering normal usage, SSH logins, sudo events, root login attempts,
password spraying, credential stuffing, and brute-force attacks; and a
Windows authentication CSV with equivalent scenarios.

Run directly to (re)generate sample_logs/auth.log and
sample_logs/windows_auth.csv:

    python sample_data_generator.py
"""

from __future__ import annotations

import csv
import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import List

import constants

random.seed(42)

NORMAL_USERS = ["deploy", "alice", "bob", "carol", "dave", "svc-backup", "jenkins"]
COMMON_ATTACK_USERS = ["admin", "root", "test", "guest", "administrator", "oracle",
                        "postgres", "ubuntu", "ec2-user", "user", "support", "info"]
HOSTNAME = "webserver01"
MONTH_DAY = "Aug  1"

ATTACKER_IPS = ["203.0.113.45", "198.51.100.23", "192.0.2.77", "45.129.14.6",
                 "185.220.101.5", "91.240.118.6"]
INTERNAL_IPS = ["10.0.0.5", "10.0.0.12", "10.0.0.18", "192.168.1.20"]


def _fmt_time(base: datetime, offset_seconds: int) -> str:
    t = base + timedelta(seconds=offset_seconds)
    return t.strftime("%H:%M:%S")


def generate_linux_log(min_entries: int = 500) -> List[str]:
    """Generate a realistic Linux auth.log with mixed normal and attack traffic."""
    lines: List[str] = []
    base = datetime(2026, 8, 1, 8, 0, 0)
    t = 0
    pid = 10000

    def add(line_body: str, seconds_offset: int, host_pid: int) -> None:
        lines.append(f"{MONTH_DAY} {_fmt_time(base, seconds_offset)} {HOSTNAME} {line_body}")

    # --- Normal SSH activity throughout the day ---
    for _ in range(120):
        t += random.randint(20, 300)
        user = random.choice(NORMAL_USERS)
        ip = random.choice(INTERNAL_IPS)
        pid += 1
        add(f"sshd[{pid}]: Accepted password for {user} from {ip} port {random.randint(40000,60000)} ssh2", t, pid)

    # --- sudo events ---
    for _ in range(60):
        t += random.randint(20, 200)
        user = random.choice(NORMAL_USERS)
        pid += 1
        cmd = random.choice(["/usr/bin/systemctl restart nginx", "/bin/ls /var/log",
                              "/usr/bin/apt update", "/bin/cat /etc/passwd"])
        add(f"sudo:   {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}", t, pid)

    # --- Occasional benign typo failures (not an attack) ---
    for _ in range(15):
        t += random.randint(30, 400)
        user = random.choice(NORMAL_USERS)
        ip = random.choice(INTERNAL_IPS)
        pid += 1
        add(f"sshd[{pid}]: Failed password for {user} from {ip} port {random.randint(40000,60000)} ssh2", t, pid)

    # --- SCENARIO 1: Brute-force attack against root from a single IP ---
    attacker = ATTACKER_IPS[0]
    t += 500
    for _ in range(38):
        t += random.randint(1, 4)
        pid += 1
        add(f"sshd[{pid}]: Failed password for root from {attacker} port {random.randint(40000,60000)} ssh2", t, pid)
    t += 3
    pid += 1
    add(f"sshd[{pid}]: Accepted password for root from {attacker} port {random.randint(40000,60000)} ssh2", t, pid)

    # --- SCENARIO 2: Credential stuffing - 1 IP against many usernames ---
    attacker2 = ATTACKER_IPS[1]
    t += 600
    for user in COMMON_ATTACK_USERS:
        for _ in range(2):
            t += random.randint(1, 5)
            pid += 1
            add(f"sshd[{pid}]: Failed password for invalid user {user} from {attacker2} port {random.randint(40000,60000)} ssh2", t, pid)

    # --- SCENARIO 3: Password spraying - 1 username from many IPs ---
    target_user = "backup"
    t += 700
    spray_ips = ATTACKER_IPS + [f"203.0.113.{n}" for n in range(80, 90)]
    for ip in spray_ips:
        t += random.randint(5, 20)
        pid += 1
        add(f"sshd[{pid}]: Failed password for {target_user} from {ip} port {random.randint(40000,60000)} ssh2", t, pid)

    # --- SCENARIO 4: Invalid user enumeration ---
    attacker3 = ATTACKER_IPS[2]
    t += 500
    for user in ["test1", "test2", "qwerty", "sysadmin", "operator"]:
        t += random.randint(2, 8)
        pid += 1
        add(f"sshd[{pid}]: Invalid user {user} from {attacker3}", t, pid)

    # --- SCENARIO 5: Medium brute force against normal user, no success ---
    attacker4 = ATTACKER_IPS[3]
    t += 400
    for _ in range(12):
        t += random.randint(1, 6)
        pid += 1
        add(f"sshd[{pid}]: Failed password for alice from {attacker4} port {random.randint(40000,60000)} ssh2", t, pid)

    # --- Fill remaining entries with normal background noise to hit min_entries ---
    while len(lines) < min_entries:
        t += random.randint(10, 200)
        user = random.choice(NORMAL_USERS)
        ip = random.choice(INTERNAL_IPS)
        pid += 1
        add(f"sshd[{pid}]: Accepted password for {user} from {ip} port {random.randint(40000,60000)} ssh2", t, pid)

    return lines


def generate_windows_csv() -> List[dict]:
    """Generate realistic Windows authentication events."""
    rows: List[dict] = []
    base = datetime(2026, 8, 1, 8, 0, 0)
    t = 0

    normal_users = ["jsmith", "mgarcia", "kwilliams", "svc-sql", "administrator"]
    hosts = ["WIN-DC01", "WIN-FS02", "WIN-APP03"]
    internal_ips = ["10.1.0.10", "10.1.0.11", "10.1.0.15"]

    def add(user, ip, host, status, service, seconds_offset):
        ts = base + timedelta(seconds=seconds_offset)
        rows.append({
            "Timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "Username": user, "IP": ip, "Hostname": host,
            "Status": status, "Service": service,
        })

    # Normal logons
    for _ in range(100):
        t += random.randint(20, 250)
        add(random.choice(normal_users), random.choice(internal_ips),
            random.choice(hosts), "Success", "NTLM", t)

    # Brute force against Administrator
    attacker = "198.51.100.99"
    t += 500
    for _ in range(25):
        t += random.randint(1, 5)
        add("administrator", attacker, "WIN-DC01", "Failed", "NTLM", t)
    t += 2
    add("administrator", attacker, "WIN-DC01", "Success", "NTLM", t)

    # Credential stuffing
    attacker2 = "45.33.32.156"
    t += 500
    for user in ["administrator", "guest", "admin", "sqladmin", "backupadmin", "operator"]:
        t += random.randint(2, 6)
        add(user, attacker2, "WIN-DC01", "Failed", "NTLM", t)

    # Password spraying against svc-sql
    t += 500
    for i in range(6):
        t += random.randint(5, 15)
        add("svc-sql", f"203.0.113.{150+i}", "WIN-APP03", "Failed", "NTLM", t)

    return rows


def write_sample_files() -> None:
    Path(constants.SAMPLE_LOG_DIR).mkdir(parents=True, exist_ok=True)

    linux_lines = generate_linux_log()
    linux_path = Path(constants.SAMPLE_LINUX_LOG)
    linux_path.write_text("\n".join(linux_lines) + "\n", encoding="utf-8")

    windows_rows = generate_windows_csv()
    windows_path = Path(constants.SAMPLE_WINDOWS_CSV)
    with windows_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "Timestamp", "Username", "IP", "Hostname", "Status", "Service"
        ])
        writer.writeheader()
        writer.writerows(windows_rows)

    print(f"Generated {len(linux_lines)} Linux auth.log entries -> {linux_path}")
    print(f"Generated {len(windows_rows)} Windows auth CSV entries -> {windows_path}")


if __name__ == "__main__":
    write_sample_files()
