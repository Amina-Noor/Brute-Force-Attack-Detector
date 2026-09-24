# 🛡️ Brute Force Attack Detector

A SOC-grade authentication log analysis tool that detects brute-force attacks, credential stuffing, password spraying, and other suspicious authentication patterns in Linux `auth.log` files and Windows authentication exports (CSV/JSON). Built with Python and Streamlit for an interactive, portfolio-ready security dashboard.

---

## Overview

Brute Force Attack Detector parses authentication logs, applies a rule-based detection engine, and surfaces the results through a modern Streamlit dashboard: alert cards, interactive Plotly visualizations, searchable/filterable alert tables, incident-response recommendations, and downloadable reports (Markdown, CSV, HTML).

It is designed to resemble the kind of internal tooling a SOC (Security Operations Center) analyst might build to triage authentication logs during an investigation — and to serve as a strong, well-tested project for a cybersecurity or blue-team portfolio.

---

## Features

- **Multi-format log ingestion** — Linux `auth.log` (syslog format) and Windows authentication logs (CSV or JSON), with automatic encoding fallback and graceful handling of malformed lines.
- **Rule-based detection engine**
  - Brute-force attacks (single IP, high-volume failures within a configurable time window)
  - Credential stuffing (one IP attacking many distinct usernames)
  - Password spraying (one username attacked from many distinct IPs)
  - Successful login immediately following repeated failures (possible compromise)
  - Root/administrator login attempts and successes
  - Invalid/unknown user enumeration
- **Severity scoring** — Low / Medium / High / Critical, driven by attempt volume, account sensitivity, and outcome.
- **Bonus scoring** — 0–100 risk score and attack-confidence score per alert, plus MITRE ATT&CK technique mapping (T1110, T1110.001/.003/.004, T1078).
- **Interactive dashboard**
  - KPI metrics, alert cards, attack timeline, top-attacker/top-target charts, success/failure pie chart, hourly heatmap, daily trend, severity distribution
  - Search and filter by username, IP, severity, and service
  - Configurable thresholds: failed-login count, time window, internal-IP exclusion, trusted-user exclusion
- **Reporting** — One-click export to Markdown, CSV, and HTML, including executive summary, statistics, alert tables, and recommendations.
- **Sample data generator** — Produces 500+ realistic Linux log entries and a companion Windows CSV covering normal traffic plus multiple attack scenarios.
- **Production hygiene** — Centralized logging (`logs/app.log`), typed dataclasses, docstrings, PEP8-oriented modules, and a pytest suite covering parsing, detection, and reporting.

---

## Architecture

```
┌─────────────┐     ┌──────────┐     ┌───────────┐     ┌───────────┐
│  Raw Logs   │ --> │  parser  │ --> │ detector  │ --> │  analyzer │
│ (.log/.csv) │     │ .py      │     │ .py       │     │  .py      │
└─────────────┘     └──────────┘     └───────────┘     └─────┬─────┘
                                                               │
                     ┌─────────────────────────────────────────┘
                     ▼
       ┌────────────────────────┐      ┌────────────────────┐
       │  visualizer.py (Plotly) │      │ report_generator.py │
       └────────────────────────┘      └────────────────────┘
                     │                            │
                     └───────────┬────────────────┘
                                 ▼
                          ┌─────────────┐
                          │   app.py    │
                          │ (Streamlit) │
                          └─────────────┘
```

- **`parser.py`** — Converts raw log text into normalized `LogEntry` dataclass records.
- **`detector.py`** — Applies detection rules to `LogEntry` records and produces `Alert` objects with severity, MITRE mapping, and scoring.
- **`analyzer.py`** — Aggregates entries and alerts into `Statistics`, extracts IOCs, and generates recommendations.
- **`visualizer.py`** — Builds Plotly figures consumed by the dashboard.
- **`report_generator.py`** — Renders Markdown, CSV, and HTML reports.
- **`app.py`** — Streamlit UI wiring everything together.
- **`config.py` / `constants.py` / `logger.py` / `utils.py`** — Shared configuration, constants, logging, and helper functions.

---

## Folder Structure

```
Brute-Force-Attack-Detector/
├── app.py                   # Streamlit dashboard entry point
├── config.py                 # Detection & app configuration (dataclasses)
├── parser.py                  # Log parsing (Linux + Windows)
├── detector.py                 # Detection rules & alert generation
├── analyzer.py                  # Statistics, IOCs, recommendations
├── visualizer.py                 # Plotly chart builders
├── report_generator.py            # Markdown / CSV / HTML report builders
├── utils.py                        # Helper functions
├── constants.py                     # Regex patterns, severities, MITRE map
├── logger.py                         # Centralized logging setup
├── sample_data_generator.py           # Sample dataset generator
├── requirements.txt
├── README.md
├── LICENSE
├── .gitignore
├── .env.example
├── assets/                             # Static assets (icons, screenshots)
├── sample_logs/
│   ├── auth.log                          # 500+ line sample Linux log
│   └── windows_auth.csv                   # Sample Windows auth export
├── reports/                                # Generated reports land here
└── tests/
    ├── test_parser.py
    ├── test_detector.py
    └── test_reports.py
```

---

## Installation

```bash
git clone https://github.com/<your-username>/Brute-Force-Attack-Detector.git
cd Brute-Force-Attack-Detector

python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt

cp .env.example .env            # optional: customize defaults
```

---

## Usage

### Run the dashboard

```bash
streamlit run app.py
```

Then, in the browser tab that opens:

1. Choose a log type (Linux or Windows) in the sidebar.
2. Click **Load Sample** to use the bundled sample dataset, or upload your own `.log` / `.csv` / `.json` file.
3. Adjust the failed-login threshold, time window, and any exclusions.
4. Click **Analyze**.
5. Explore alerts, charts, the searchable alert table, and recommendations across the tabs.
6. Export a Markdown, CSV, or HTML report from the **Export** tab.

### Regenerate sample data

```bash
python sample_data_generator.py
```

### Run the test suite

```bash
pytest tests/ -v
```

---

## Screenshots

_Add screenshots of the dashboard here, e.g.:_

- `assets/dashboard-overview.png`
- `assets/alert-cards.png`
- `assets/charts.png`

---

## Future Improvements

- Live GeoIP lookups for attacker IP geolocation (currently mocked/optional)
- Native PDF report export
- Streaming/tail mode for real-time log ingestion
- Pluggable detection rules via a rules-as-config system
- Integration with SIEM/SOAR platforms via webhook alerting
- Multi-file / multi-host correlation

---

## License

Released under the [MIT License](LICENSE).
