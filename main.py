import argparse
from typing import List, Dict

from detector import detect_suspicious_networks
from app_launcher import run_gui
from utils import append_network_log
from wifi_scanner import scan_networks


def _print_cli_table(networks: List[Dict[str, str]]) -> None:
    try:
        from prettytable import PrettyTable  # type: ignore

        table = PrettyTable()
        table.field_names = ["SSID", "BSSID", "Signal", "Security", "Status"]
        for net in networks:
            table.add_row(
                [
                    net.get("ssid", ""),
                    net.get("bssid", ""),
                    net.get("signal", ""),
                    net.get("security", ""),
                    net.get("status", "Safe"),
                ]
            )
        print(table)
    except Exception:
        header = f"{'SSID':25} {'BSSID':20} {'Signal':8} {'Security':18} {'Status':10}"
        print(header)
        print("-" * len(header))
        for net in networks:
            print(
                f"{net.get('ssid', ''):25} "
                f"{net.get('bssid', ''):20} "
                f"{net.get('signal', ''):8} "
                f"{net.get('security', ''):18} "
                f"{net.get('status', 'Safe'):10}"
            )


def run_cli() -> None:
    networks, error = scan_networks()
    suspicious = detect_suspicious_networks(networks)
    suspicious_ssids = {item["ssid"] for item in suspicious}

    for net in networks:
        net["status"] = "Suspicious" if net.get("ssid", "") in suspicious_ssids else "Safe"

    if error:
        print(f"[Scan Notice] {error}")

    if not networks:
        print("No networks found.")
        return

    _print_cli_table(networks)
    append_network_log(networks, suspicious)

    if suspicious:
        print("\nWARNING: Possible Fake Wi-Fi Detected")
        for item in suspicious:
            print(f"- SSID: {item['ssid']} | BSSIDs: {', '.join(item['bssids'])}")
    else:
        print("\nNo suspicious duplicate SSIDs found.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Fake Wi-Fi Detector")
    parser.add_argument("--cli", action="store_true", help="Run in terminal mode")
    args = parser.parse_args()

    if args.cli:
        run_cli()
    else:
        try:
            run_gui()
        except RuntimeError as exc:
            print(f"[UI Notice] {exc}")
            print("Falling back to CLI mode...\n")
            run_cli()


if __name__ == "__main__":
    main()
