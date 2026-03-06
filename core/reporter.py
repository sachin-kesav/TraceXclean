from datetime import datetime


def generate_report(findings, score_summary, output_format="terminal", simulate_cleanup=False):
    if output_format == "terminal":
        terminal_report(findings, score_summary, simulate_cleanup)
    elif output_format == "markdown":
        markdown_report(findings, score_summary, simulate_cleanup)


def terminal_report(findings, score_summary, simulate_cleanup):
    print("=" * 60)
    print(" TracexClean - Post-Exploitation Footprint Report")
    print("=" * 60)
    print(f" Scan Time   : {datetime.now()}")
    print(f" Risk Level  : {score_summary['risk_level']}")
    print(f" Total Score : {score_summary['total_score']}")
    print("-" * 60)

    if not findings:
        print("[+] No post-exploitation footprints detected.")
        return

    print("\n[+] Detected Footprints:\n")

    for idx, item in enumerate(findings, 1):
        print(f"{idx}. Type      : {item['type']}")
        print(f"   Severity  : {item['severity']}")
        print(f"   Log File  : {item['log']}")
        print(f"   Evidence  : {item['evidence'][:120]}...")
        print("-" * 60)

    if simulate_cleanup:
        print("\n[!] Cleanup Simulation (NO changes applied)\n")
        simulate_cleanup_actions(findings)


def simulate_cleanup_actions(findings):
    print("[!] Ethical Notice:")
    print("    Cleanup actions are simulated and should only be")
    print("    performed in controlled lab environments.\n")

    suggested = set()

    for item in findings:
        ftype = item["type"]

        if ftype == "SSH Login":
            suggested.add(
                "Review /var/log/auth.log entries related to SSH logins. "
                "Use log rotation instead of deletion."
            )

        elif ftype == "Sudo Usage":
            suggested.add(
                "Audit sudo usage in auth.log. Excessive sudo attempts "
                "can trigger alerts in SIEM systems."
            )

        elif ftype == "Failed Login":
            suggested.add(
                "Investigate failed login attempts for brute-force detection."
            )

        elif ftype == "Bash History":
            suggested.add(
                "Review ~/.bash_history for sensitive commands. "
                "Consider using HISTCONTROL in future sessions."
            )

        elif ftype == "SSH Artifact":
            suggested.add(
                "Audit ~/.ssh/authorized_keys for unauthorized persistence."
            )

        elif ftype == "Temp File":
            suggested.add(
                "Inspect files in /tmp and /var/tmp. "
                "Unexpected binaries may indicate post-exploitation tools."
            )

    for action in suggested:
        print(f" - {action}")



def markdown_report(findings, score_summary, simulate_cleanup):
    filename = f"reports/tracexclean_report.md"

    with open(filename, "w") as f:
        f.write("# TracexClean - Post-Exploitation Report\n\n")
        f.write(f"**Scan Time:** {datetime.now()}\n\n")
        f.write(f"**Risk Level:** {score_summary['risk_level']}\n\n")
        f.write(f"**Total Score:** {score_summary['total_score']}\n\n")

        if not findings:
            f.write("No footprints detected.\n")
        else:
            f.write("## Detected Footprints\n\n")
            for item in findings:
                f.write(f"- **Type:** {item['type']}\n")
                f.write(f"  - Severity: {item['severity']}\n")
                f.write(f"  - Log: {item['log']}\n")
                f.write(f"  - Evidence: `{item['evidence'][:200]}`\n\n")

        if simulate_cleanup:
            f.write("## Cleanup Simulation (Non-destructive)\n")
            f.write("- Review and rotate auth logs using logrotate\n")

    print(f"[+] Markdown report generated: {filename}")
