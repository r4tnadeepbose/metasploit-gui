#!/usr/bin/env python3
import os
import sys
import subprocess
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent


def main():
    os.chdir(PROJECT_DIR)
    venv_python = PROJECT_DIR / ".venv" / ("Scripts" if os.name == "nt" else "bin") / (
        "python.exe" if os.name == "nt" else "python"
    )
    python = str(venv_python) if venv_python.exists() else sys.executable

    # Ensure deps
    try:
        subprocess.check_call([python, "-c", "import PyQt6, msgpack, requests"], stdout=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        print("Installing dependencies...")
        subprocess.check_call([python, "-m", "pip", "install", "-r", "requirements.txt"])
        # Verify again
        subprocess.check_call([python, "-c", "import PyQt6, msgpack, requests"])

    print("Starting Metasploit GUI...")
    os.execv(python, [python, "main.py"])


if __name__ == "__main__":
    main()
