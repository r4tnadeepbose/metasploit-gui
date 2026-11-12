# Metasploit GUI for Windows (PyQt6)

A lightweight Windows-friendly GUI client for Metasploit Framework's RPC daemon (`msfrpcd`).

> **Authorized use only.** Use this tool only on systems and networks you own or have explicit permission to test.

## Features (v1)

- Connect to a running `msfrpcd` instance over HTTP/HTTPS
- Browse modules (exploits, auxiliary, post, payloads)
- View module info/options and run modules with parameters
- View jobs and sessions and run basic session commands

## Prerequisites

- Windows 10/11
- Python 3.10+
- Metasploit Framework installed, with `msfrpcd` available

## Setup

1. Start `msfrpcd` (example):

   ```powershell
   msfrpcd -U msf -P yourpassword -S -a 127.0.0.1 -p 55553
   ```

   - `-S` disables SSL (use only on localhost). Remove `-S` and enable SSL for non-local use.
   - Adjust user/password/host/port as needed.

2. Install dependencies:

   ```powershell
   cd "C:\Users\boser\Downloads\metasploi-gui"
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```

3. Run the GUI:

   ```powershell
   python main.py
   ```

## Notes

- This client talks to Metasploit via the MSGRPC API (`/api/`). Ensure the host, port, SSL setting, username, and password match your `msfrpcd` configuration.
- Running modules and interacting with sessions can have significant impact. Double-check targets and options before executing.
- This is an initial RPC client scaffold and does not cover every Metasploit feature.

## Project layout

- `main.py` — application entry point
- `app/msf_client.py` — minimal MSGRPC client
- `app/ui/main_window.py` — PyQt6 GUI
