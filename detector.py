from collections import defaultdict
from typing import Dict, List


def detect_suspicious_networks(networks: List[Dict[str, str]]) -> List[Dict[str, List[str]]]:
    grouped = defaultdict(set)

    for network in networks:
        ssid = (network.get("ssid") or "").strip()
        bssid = (network.get("bssid") or "").strip().upper()
        if not ssid or not bssid:
            continue
        grouped[ssid].add(bssid)

    suspicious = []
    for ssid, bssids in grouped.items():
        if len(bssids) > 1:
            suspicious.append({"ssid": ssid, "bssids": sorted(bssids)})

    return suspicious
