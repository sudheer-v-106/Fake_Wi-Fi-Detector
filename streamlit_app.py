from typing import Dict, List

import streamlit as st

from detector import detect_suspicious_networks
from utils import append_network_log
from wifi_scanner import scan_networks


def _prepare_rows(networks: List[Dict[str, str]], suspicious_ssids: set[str]) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for net in networks:
        ssid = net.get("ssid", "")
        rows.append(
            {
                "SSID": ssid,
                "BSSID": net.get("bssid", ""),
                "Signal": net.get("signal", ""),
                "Security": net.get("security", ""),
                "Status": "Suspicious" if ssid in suspicious_ssids else "Safe",
            }
        )
    return rows


def run_streamlit_app() -> None:
    st.set_page_config(page_title="Fake Wi-Fi Detector", page_icon="WiFi", layout="wide")
    st.title("Fake Wi-Fi Detector")
    st.write("Scan nearby Wi-Fi networks and detect possible Evil Twin access points.")

    if "rows" not in st.session_state:
        st.session_state.rows = []
        st.session_state.notice = ""
        st.session_state.notice_level = "info"
        st.session_state.warning = ""

    if st.button("Scan Networks", type="primary"):
        networks, error = scan_networks()
        suspicious = detect_suspicious_networks(networks)
        suspicious_ssids = {item["ssid"] for item in suspicious}
        rows = _prepare_rows(networks, suspicious_ssids)

        append_network_log(networks, suspicious)

        st.session_state.rows = rows
        if error:
            st.session_state.notice = error
            st.session_state.notice_level = "error"
            st.session_state.warning = ""
        else:
            st.session_state.notice = f"Scan completed. Networks found: {len(networks)}"
            st.session_state.notice_level = "info"

        if not error and suspicious:
            ssid_list = ", ".join(item["ssid"] for item in suspicious)
            st.session_state.warning = f"Possible Fake Wi-Fi detected for SSID(s): {ssid_list}"
        elif not error:
            st.session_state.warning = "No suspicious duplicate SSIDs found."

    if st.session_state.notice:
        if st.session_state.notice_level == "error":
            st.error(st.session_state.notice)
        else:
            st.info(st.session_state.notice)

    if st.session_state.rows:
        st.dataframe(st.session_state.rows, use_container_width=True, hide_index=True)
    else:
        st.write("No scan data yet. Click `Scan Networks` to start.")

    if st.session_state.warning:
        if st.session_state.warning.startswith("Possible Fake Wi-Fi"):
            st.error(st.session_state.warning)
        else:
            st.success(st.session_state.warning)


if __name__ == "__main__":
    run_streamlit_app()
