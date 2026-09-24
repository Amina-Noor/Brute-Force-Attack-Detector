# 🛡️ Brute-Force Attack Detector

A Python-based Security Operations Center (SOC) log analysis tool designed to detect, analyze, and report brute-force authentication attacks across Linux system logs (`auth.log`) and Windows Event Logs.

---

## ✨ Features

- **Multi-Format Log Parsing:** Parses Linux `auth.log` files and Windows authentication export files (`.csv`)[cite: 1].
- **Threat Detection Engine:** Identifies high-frequency failed login attempts, suspicious user account targeting, and potential brute-force patterns[cite: 1].
- **Automated Data Visualization:** Generates visual charts highlighting top targeted usernames, attacker IP frequencies, and attack timelines[cite: 1].
- **Report Generation:** Exports automated summary and detailed security reports in the `reports/` folder[cite: 1].
- **Modular Code Architecture:** Designed with isolated modules for parsing, detection analysis, logging, and visual rendering[cite: 1].

---

## 📁 Repository Structure

```text
Brute-Force-Attack-Detector/
├── sample_logs/             # Example Linux & Windows authentication logs
├── tests/                   # Unit test suite for parser and detector modules
├── app.py                   # Main application entry point
├── analyzer.py              # Core log analysis logic
├── detector.py              # Brute-force detection algorithms
├── parser.py                # Log parsing utilities
├── visualizer.py            # Data visualization and charting module
├── report_generator.py      # Automated report exporter
├── config.py                # Application configuration settings
├── logger.py                # Custom logging handler
├── requirements.txt         # Required Python packages
└── README.md                # Project documentation

```

---

## 🛠️ Tech Stack & Dependencies

* **Language:** Python 3.x
* **Data Processing:** `pandas`
* **Visualization:** `matplotlib`, `seaborn`
* **Testing:** `pytest`

---

## 🚀 Getting Started

### 1. Prerequisites

Ensure you have Python 3.8+ installed on your system.

### 2. Installation

Clone the repository and install the dependencies:

```bash
git clone [https://github.com/Amina-Noor/Brute-Force-Attack-Detector.git](https://github.com/Amina-Noor/Brute-Force-Attack-Detector.git)
cd Brute-Force-Attack-Detector
pip install -r requirements.txt

```

### 3. Running the Tool

To run the full detection pipeline on sample logs:

```bash
python app.py

```

To generate synthetic test logs for custom analysis:

```bash
python sample_data_generator.py

```

To run the automated unit test suite:

```bash
pytest

```

---

## 📜 License

This project is open-source and available under the MIT License.

```

