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

**Author:** _Your Name_ · [GitHub](https://github.com/your-username) · [LinkedIn](https://linkedin.com/in/your-profile)

> Test security tools only on systems, labs and CTFs where you have authorisation.
