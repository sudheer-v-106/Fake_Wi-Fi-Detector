import os
import subprocess
import sys
from pathlib import Path
from typing import Dict


def run_gui() -> None:
    project_dir = Path(__file__).resolve().parent
    app_file = project_dir / "streamlit_app.py"
    local_home = project_dir / ".streamlit_home"
    local_config = local_home / ".streamlit"
    local_config.mkdir(parents=True, exist_ok=True)
    credentials_file = local_config / "credentials.toml"
    if not credentials_file.exists():
        credentials_file.write_text("[general]\nemail = \"\"\n", encoding="utf-8")

    env: Dict[str, str] = dict(**os.environ)
    env["HOME"] = str(local_home)
    env["USERPROFILE"] = str(local_home)
    env["STREAMLIT_CONFIG_DIR"] = str(local_config)

    command = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(app_file),
        "--server.address",
        "127.0.0.1",
        "--server.port",
        "8501",
    ]
    try:
        subprocess.run(command, check=True, env=env)
    except FileNotFoundError as exc:
        raise RuntimeError(
            "Python executable not found while launching Streamlit."
        ) from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            "Failed to launch Streamlit UI. Install it with: pip install streamlit"
        ) from exc
