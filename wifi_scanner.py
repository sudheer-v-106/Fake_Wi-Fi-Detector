import platform
import subprocess
from typing import Dict, List, Optional, Tuple


def _run_command(command: List[str]) -> Tuple[Optional[str], Optional[str]]:
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return result.stdout, None
    except FileNotFoundError:
        return None, f"Command not found: {' '.join(command)}"
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or "").strip()
        return None, detail or f"Command failed: {' '.join(command)}"
    except Exception as exc:
        return None, str(exc)


def _parse_windows_netsh(output: str) -> List[Dict[str, str]]:
    networks: List[Dict[str, str]] = []
    current_ssid = ""
    current_security = ""
    current_index: Optional[int] = None

    for raw_line in output.splitlines():
        line = raw_line.strip()
        lower_line = line.lower()

        if lower_line.startswith("ssid ") and "bssid" not in lower_line and " : " in line:
            current_ssid = line.split(" : ", 1)[1].strip()
            current_index = None
            continue

        if lower_line.startswith("authentication") and " : " in line:
            current_security = line.split(" : ", 1)[1].strip()
            continue

        if lower_line.startswith("bssid ") and " : " in line:
            bssid = line.split(" : ", 1)[1].strip()
            networks.append(
                {
                    "ssid": current_ssid,
                    "bssid": bssid,
                    "signal": "",
                    "security": current_security,
                }
            )
            current_index = len(networks) - 1
            continue

        if lower_line.startswith("signal") and " : " in line and current_index is not None:
            networks[current_index]["signal"] = line.split(" : ", 1)[1].strip()
            continue

    return [n for n in networks if n.get("ssid") or n.get("bssid")]


def _parse_linux_nmcli(output: str) -> List[Dict[str, str]]:
    networks: List[Dict[str, str]] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        parts = line.split("|")
        if len(parts) < 4:
            continue
        ssid, bssid, signal, security = [p.strip() for p in parts[:4]]
        networks.append(
            {
                "ssid": ssid,
                "bssid": bssid,
                "signal": f"{signal}%",
                "security": security or "OPEN",
            }
        )
    return networks


def _parse_macos_airport(output: str) -> List[Dict[str, str]]:
    networks: List[Dict[str, str]] = []
    lines = output.splitlines()
    if len(lines) <= 1:
        return networks

    for line in lines[1:]:
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        bssid_index = None
        for i, part in enumerate(parts):
            if part.count(":") == 5 and len(part) == 17:
                bssid_index = i
                break
        if bssid_index is None:
            continue
        ssid = " ".join(parts[:bssid_index])
        bssid = parts[bssid_index]
        signal = ""
        security = " ".join(parts[6:]) if len(parts) > 6 else ""
        if len(parts) > bssid_index + 2:
            signal = parts[bssid_index + 2]
        networks.append(
            {
                "ssid": ssid,
                "bssid": bssid,
                "signal": signal,
                "security": security or "UNKNOWN",
            }
        )
    return networks


def scan_networks() -> Tuple[List[Dict[str, str]], Optional[str]]:
    system = platform.system().lower()

    if "windows" in system:
        output, error = _run_command(["netsh", "wlan", "show", "networks", "mode=bssid"])
        if not output:
            base = "Could not run netsh scan command."
            if error:
                return [], f"{base} Details: {error}"
            return [], base
        return _parse_windows_netsh(output), None

    if "linux" in system:
        output, error = _run_command(
            ["nmcli", "-t", "--separator", "|", "-f", "SSID,BSSID,SIGNAL,SECURITY", "dev", "wifi", "list"]
        )
        if not output:
            base = "Could not run nmcli scan command."
            if error:
                return [], f"{base} Details: {error}"
            return [], base
        return _parse_linux_nmcli(output), None

    if "darwin" in system:
        airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
        output, error = _run_command([airport_path, "-s"])
        if not output:
            base = "Could not run airport scan command."
            if error:
                return [], f"{base} Details: {error}"
            return [], base
        return _parse_macos_airport(output), None

    return [], f"Unsupported operating system: {platform.system()}"
