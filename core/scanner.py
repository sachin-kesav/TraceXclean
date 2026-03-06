import os
from pathlib import Path


AUTH_LOG = "/var/log/auth.log"
TMP_DIRS = ["/tmp", "/var/tmp"]


def scan_auth_log():
    findings = []

    if not os.path.exists(AUTH_LOG):
        return findings

    try:
        with open(AUTH_LOG, "r", errors="ignore") as f:
            for line in f:
                if "Accepted password" in line or "Accepted publickey" in line:
                    findings.append({
                        "type": "SSH Login",
                        "severity": "High",
                        "evidence": line.strip(),
                        "log": AUTH_LOG
                    })

                elif "sudo:" in line:
                    findings.append({
                        "type": "Sudo Usage",
                        "severity": "High",
                        "evidence": line.strip(),
                        "log": AUTH_LOG
                    })

                elif "Failed password" in line:
                    findings.append({
                        "type": "Failed Login",
                        "severity": "Medium",
                        "evidence": line.strip(),
                        "log": AUTH_LOG
                    })
    except PermissionError:
        findings.append({
            "type": "Permission Error",
            "severity": "Low",
            "evidence": "Cannot read auth.log",
            "log": AUTH_LOG
        })

    return findings


def scan_bash_history():
    findings = []
    home_dirs = Path("/home").glob("*")

    for user_home in home_dirs:
        history_file = user_home / ".bash_history"

        if history_file.exists():
            try:
                with open(history_file, "r", errors="ignore") as f:
                    lines = f.readlines()

                if lines:
                    findings.append({
                        "type": "Bash History",
                        "severity": "Medium",
                        "evidence": f"{len(lines)} commands found in {history_file}",
                        "log": str(history_file)
                    })
            except PermissionError:
                continue

    return findings


def scan_ssh_artifacts():
    findings = []
    home_dirs = Path("/home").glob("*")

    for user_home in home_dirs:
        ssh_dir = user_home / ".ssh"

        if ssh_dir.exists():
            for artifact in ["authorized_keys", "known_hosts"]:
                artifact_path = ssh_dir / artifact
                if artifact_path.exists():
                    findings.append({
                        "type": "SSH Artifact",
                        "severity": "High",
                        "evidence": f"{artifact} present in {ssh_dir}",
                        "log": str(artifact_path)
                    })

    return findings


def scan_tmp_dirs():
    findings = []

    for tmp in TMP_DIRS:
        try:
            for item in os.listdir(tmp):
                path = os.path.join(tmp, item)
                if os.path.isfile(path):
                    findings.append({
                        "type": "Temp File",
                        "severity": "Medium",
                        "evidence": f"File found: {path}",
                        "log": tmp
                    })
        except PermissionError:
            continue

    return findings


def run_scan():
    all_findings = []

    all_findings.extend(scan_auth_log())
    all_findings.extend(scan_bash_history())
    all_findings.extend(scan_ssh_artifacts())
    all_findings.extend(scan_tmp_dirs())

    return all_findings
