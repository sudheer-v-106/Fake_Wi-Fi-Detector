from datetime import datetime
from pathlib import Path
from typing import Dict, List


def _log_file_path() -> Path:
    data_dir = Path(__file__).resolve().parent / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir / "network_log.txt"


def timestamp_now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def append_network_log(networks: List[Dict[str, str]], suspicious: List[Dict[str, List[str]]]) -> None:
    log_path = _log_file_path()
    with log_path.open("a", encoding="utf-8") as file:
        file.write(f"\n=== Scan Time: {timestamp_now()} ===\n")
        for net in networks:
            file.write(
                f"SSID={net.get('ssid', '')} | "
                f"BSSID={net.get('bssid', '')} | "
                f"Signal={net.get('signal', '')} | "
                f"Security={net.get('security', '')}\n"
            )
        if suspicious:
            file.write("WARNING: Possible Fake Wi-Fi Detected\n")
            for item in suspicious:
                file.write(f"SSID={item['ssid']} | BSSIDs={', '.join(item['bssids'])}\n")
        else:
            file.write("No suspicious duplicate SSIDs found.\n")
