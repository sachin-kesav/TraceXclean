## TraceXclean

TraceXclean is a Linux-based post-exploitation footprint analysis and cleanup simulation tool designed for educational use in controlled lab environments.

It helps identify forensic artifacts left behind after common attacker activities such as SSH access, privilege escalation, command execution, and temporary file usage.

This tool is intended for CTF practice, red team learning, and forensic awareness training.

## Features

- Linux authentication log analysis

- SSH artifact detection

- Bash history analysis

- Temporary directory artifact detection

- Risk and noise scoring

- Ethical cleanup simulation (non-destructive)

- Terminal and Markdown reporting

## Installation

Clone the repository:

git clone https://github.com/sachin-kesav/TraceXclean.git
cd TraceXclean

Install dependencies:

pip3 install -r requirements.txt
Usage

Run analysis:

sudo python3 tracexclean.py --analyze

Run analysis with cleanup simulation:

sudo python3 tracexclean.py --analyze --simulate-cleanup

Generate Markdown report:

sudo python3 tracexclean.py --analyze --report markdown

Reports will be saved inside the reports/ directory.

## Project Structure

TraceXclean
│
├── tracexclean.py          # Main CLI entry point
│
├── core
│   ├── scanner.py          # Artifact scanning engine
│   ├── scorer.py           # Risk scoring system
│   └── reporter.py         # Report generation
│
├── utils
│   ├── helpers.py          # Helper utilities
│   └── permissions.py      # Permission checks
│
├── rules
│   ├── artifacts.yaml      # Artifact detection rules
│   └── linux_logs.yaml     # Log analysis rules
│
├── docs
│   ├── disclaimer.md
│   └── TracexClean_Project_Report.pdf
│
└── reports                 # Generated reports

## Example Use Case

TraceXclean can help security learners understand what traces are left behind during activities such as:

- SSH logins

- Privilege escalation

- Command execution

- Temporary file usage

- Shell history modification

This helps build forensic awareness for red teamers and CTF players.

## Disclaimer

TraceXclean is intended only for educational purposes and authorized testing environments.
Do not run this tool on systems without proper authorization.

## Author

K M Sachin Kesav 
Midhunraj M
Cybersecurity Enthusiast | CTF Player | Security Tool Builder

