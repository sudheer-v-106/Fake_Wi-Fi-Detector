# Fake Wi-Fi Detector Using Python

This project scans nearby Wi-Fi networks and flags possible Evil Twin attacks by checking for duplicate SSIDs with different BSSIDs.

## Features
- Scan nearby networks (SSID, BSSID, signal, security)
- Detect suspicious duplicate SSIDs
- Show warnings in Streamlit UI and CLI
- Save scan history to `data/network_log.txt`

## Project Structure
```text
Fake-Wifi-Detector/
|- main.py
|- wifi_scanner.py
|- detector.py
|- app_launcher.py
|- streamlit_app.py
|- utils.py
|- data/
|  |- network_log.txt
|- screenshots/
|  |- output.png
|- report/
|  |- project_report.docx
|  |- presentation.pptx
|- README.md
```

## Requirements
- Python 3.9+
- streamlit
- Optional: prettytable for better CLI table display

Install dependencies:

```bash
pip install -r requirements.txt
```

## Run
Streamlit UI mode:

```bash
python main.py
```

Direct Streamlit launch:

```bash
streamlit run streamlit_app.py
```

CLI mode:

```bash
python main.py --cli
```

## Detection Logic
If the same SSID appears with different BSSIDs, it is marked as suspicious.

Example:
- `AirportWiFi` -> `AA:BB:CC:11:22:33`
- `AirportWiFi` -> `FF:EE:DD:44:55:66`

This is flagged as `Possible Fake Wi-Fi`.

## Notes
- Scanning uses native OS commands:
  - Windows: `netsh`
  - Linux: `nmcli`
  - macOS: `airport`
- Results depend on your Wi-Fi adapter and permissions.
