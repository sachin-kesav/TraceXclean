import os
import sys


def check_root():
    if os.geteuid() != 0:
        print("[!] This tool must be run as root.")
        print("[!] Reason: System logs require elevated permissions.")
        sys.exit(1)
