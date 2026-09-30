# IqraSec Academy — Cybersecurity Scripting & Automation Internship
## Phase 1 Submission — Practical Scripting & Automation

| Task | Tool | Language | Folder |
|---|---|---|---|
| 1 | **LinuxSec Audit** – Linux security checker with scoring | Bash | [`Bash-Tool/`](Bash-Tool) |
| 2 | **IOCX** – IOC extractor & threat-report generator | Python 3 | [`Python-Tool/`](Python-Tool) |

```
Phase-1/
├── Bash-Tool/
│   ├── tool.sh
│   ├── README.md
│   ├── sample-output/audit_report.txt
│   └── screenshots/
└── Python-Tool/
    ├── tool.py
    ├── README.md
    ├── samples/   tests/
    └── screenshots/
```

**Quick start**
```bash
bash Bash-Tool/tool.sh --help
sudo bash Bash-Tool/tool.sh
python3 Python-Tool/tool.py Python-Tool/samples/incident_report.txt
python3 -m unittest discover -v -s Python-Tool/tests
```
# IqraSec Cybersecurity Scripting & Automation — Phase 1

A practical cybersecurity automation project developed as part of the **IqraSec Academy Cybersecurity Scripting & Automation Internship — Phase 1**.

The project demonstrates practical security automation using **Bash and Python**, with a focus on Linux security auditing, Indicator of Compromise (IOC) extraction, security reporting, error handling, and command-line automation.

---

##  Project Overview

This project contains two independent cybersecurity tools:

### 1. LinuxSec Audit — Bash

A read-only Linux security auditing tool designed to identify common system security weaknesses and configuration issues.

The tool performs security checks across areas such as:

* System configuration
* User accounts
* File permissions
* SSH configuration
* Network and exposed ports
* Firewall status
* SUID and world-writable files
* System updates
* Authentication logs
* Kernel security settings
* Running services

The tool presents findings using **PASS, WARN, and FAIL** classifications and generates an overall security score.

### 2. IOCX — Python

A command-line **Indicator of Compromise (IOC) extraction and reporting tool** designed for basic security-analysis workflows.

It can analyze text files, incident reports, logs, or directly provided text and extract indicators such as:

* IPv4 addresses
* IPv6 addresses
* Domains
* URLs
* Email addresses
* File hashes
* CVE identifiers
* MITRE ATT&CK identifiers
* Suspicious filenames

The tool also supports defanged indicators, allowlists, risk tagging, and multiple report formats.

---

##  Objectives

The main objectives of this project are to:

* Apply Python and Bash scripting to cybersecurity tasks.
* Automate repetitive security-analysis activities.
* Develop practical command-line security tools.
* Practice defensive Linux security auditing.
* Extract and organize indicators from security-related data.
* Generate structured security reports.
* Implement basic error handling and user-friendly CLI options.
* Develop testing and documentation practices.

---

##  Technologies Used

| Technology | Purpose                                |
| ---------- | -------------------------------------- |
| Bash       | Linux security auditing and automation |
| Python 3   | IOC extraction and report generation   |
| Linux      | Security testing environment           |
| Git        | Version control                        |
| GitHub     | Project hosting and submission         |
| JSON       | Structured IOC output                  |
| CSV        | IOC data export                        |
| Markdown   | Security reporting                     |
| HTML       | Report generation                      |

---

##  Project Structure

```text
iqrasec-phase1-scripting/
│
├── README.md
│
├── Bash-Tool/
│   ├── tool.sh
│   ├── README.md
│   ├── sample-output/
│   └── screenshots/
│
└── Python-Tool/
    ├── tool.py
    ├── README.md
    ├── samples/
    │   ├── incident_report.txt
    │   ├── allowlist.txt
    │   └── output/
    ├── tests/
    │   └── test_tool.py
    └── screenshots/
```

---

#  Tool 1 — LinuxSec Audit

## Overview

**LinuxSec Audit** is a read-only Bash-based Linux security auditing tool.

It examines security-relevant system configurations and reports potential weaknesses without intentionally modifying the system.

### Key Features

* System security checks
* User and account auditing
* Critical file permission checks
* SSH security checks
* Network and listening-port checks
* Firewall status verification
* SUID and world-writable file detection
* Pending update detection
* Authentication-log analysis
* Kernel security checks
* Service checks
* Security scoring
* PASS/WARN/FAIL classification
* Section-based execution
* Report generation
* Basic error handling
* CLI help and usage options

### Usage

```bash
cd Bash-Tool

chmod +x tool.sh
```

Display help:

```bash
./tool.sh --help
```

Run a complete audit:

```bash
sudo ./tool.sh
```

Show only security findings:

```bash
sudo ./tool.sh -q
```

Run selected sections:

```bash
sudo ./tool.sh -s ssh,network,accounts
```

Save the audit result:

```bash
sudo ./tool.sh -o audit_report.txt
```

Run a deeper filesystem scan:

```bash
sudo ./tool.sh -d
```

List available sections:

```bash
./tool.sh --list
```

> Run the tool only on systems that you own or are explicitly authorized to audit.

---

#  Tool 2 — IOCX

## Overview

**IOCX** is a Python command-line tool for extracting Indicators of Compromise from security-related text.

It can process incident reports, logs, text files, folders, or directly supplied text.

### Key Features

* IPv4 extraction
* IPv6 extraction
* URL extraction
* Domain extraction
* Email extraction
* Hash extraction
* CVE extraction
* MITRE ATT&CK ID extraction
* Suspicious filename detection
* Defanged IOC recognition
* IOC defanging
* Allowlist support
* Risk tagging
* Recursive directory analysis
* Multiple output formats
* Unit testing

### Supported Output Formats

```text
table
JSON
CSV
TXT
Markdown
HTML
```

### Usage

Display help:

```bash
cd Python-Tool

python3 tool.py --help
```

Analyze an incident report:

```bash
python3 tool.py samples/incident_report.txt
```

Analyze direct text:

```bash
python3 tool.py -t "malware at hxxp://evil[.]xyz/a.exe from 45.83.64.12"
```

Generate JSON output:

```bash
python3 tool.py samples/ -r -f json -o iocs.json
```

Generate a Markdown report:

```bash
python3 tool.py samples/incident_report.txt -f md --defang -o report.md
```

Use an allowlist:

```bash
python3 tool.py samples/incident_report.txt --allowlist samples/allowlist.txt
```

Read input through a pipe:

```bash
cat samples/incident_report.txt | python3 tool.py -f txt
```

Generate an HTML report:

```bash
python3 tool.py samples/incident_report.txt -f html -o report.html
```

---

#  Testing

The Python tool includes automated unit tests.

Run:

```bash
cd Python-Tool

python3 -m unittest discover -v tests
```

The test suite verifies important IOC extraction and processing functionality.

---

#  Example Workflow

The project can be used as a basic defensive security workflow:

```text
Linux System
     │
     ▼
LinuxSec Audit
     │
     ├── System Checks
     ├── Account Checks
     ├── SSH Checks
     ├── Network Checks
     ├── Firewall Checks
     ├── File Checks
     └── Log Checks
     │
     ▼
Security Findings
```

For IOC analysis:

```text
Incident Report / Log
          │
          ▼
        IOCX
          │
          ├── IP Addresses
          ├── Domains
          ├── URLs
          ├── Hashes
          ├── CVEs
          └── Other Indicators
          │
          ▼
   Filtering & Risk Tagging
          │
          ▼
 JSON / CSV / TXT / MD / HTML
```

---

#  Screenshots

The repository contains screenshots demonstrating:

* Command-line help
* Linux security audit
* Security findings
* Section-based execution
* Error handling
* IOC extraction
* Defanged IOC processing
* JSON generation
* Markdown report generation
* Python unit tests

Screenshots are available inside:

```text
Bash-Tool/screenshots/
Python-Tool/screenshots/
```

---

#  Requirements

### Bash Tool

* Linux operating system
* Bash
* Standard Linux utilities
* `sudo` for checks requiring elevated privileges

### Python Tool

* Python 3.8+
* Python standard library
* No external Python packages required

---

#  Security & Responsible Use

These tools are intended for **defensive security, learning, authorized testing, and security automation**.

LinuxSec Audit should only be executed on systems that you own or have explicit permission to audit.

IOCX should be used for legitimate security-analysis activities such as analyzing authorized logs, incident reports, and security data.

Do not use these tools to access, scan, or analyze systems or information without authorization.

---

#  Future Improvements

Potential future improvements include:

* Additional Linux security checks
* More configurable security policies
* Improved risk scoring
* Scheduled security audits
* Email-based report delivery
* Additional IOC types
* Threat-intelligence API integration
* SIEM integration
* Automated report dashboards
* Expanded unit-test coverage
* Configuration files for customized security checks

---


##  Project Highlights

**LinuxSec Audit**

> Read-only Linux security auditing and configuration assessment using Bash.

**IOCX**

> Python-based IOC extraction, filtering, risk tagging, and security report generation.

**Core Skills Demonstrated**

```text
Python
Bash Scripting
Linux Security
Cybersecurity Automation
IOC Analysis
CLI Development
Security Reporting
Unit Testing
Git & GitHub
```

---

