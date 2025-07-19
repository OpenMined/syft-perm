"""Utility functions for filesystem editor."""

import json
import os
from pathlib import Path
from typing import Optional


def get_current_user_email() -> Optional[str]:
    """Get current user email from environment or local datasite."""

    # Try environment variable first

    user_email = os.environ.get("SYFTBOX_USER_EMAIL")

    # If not found, try to read from syftbox config

    if not user_email:

        try:

            config_path = Path(os.path.expanduser("~/.syftbox/config.json"))

            if config_path.exists():

                with open(config_path, "r") as f:

                    config = json.load(f)

                    user_email = config.get("email")

        except Exception:

            pass

    # If still not found, try to detect from local datasite

    if not user_email:

        datasites_path = Path(os.path.expanduser("~/SyftBox/datasites"))

        if datasites_path.exists():

            for datasite_dir in datasites_path.iterdir():

                if datasite_dir.is_dir() and "@" in datasite_dir.name:

                    yaml_files = list(datasite_dir.glob("**/syft.pub.yaml"))

                    if yaml_files:

                        user_email = datasite_dir.name

                        break

    return user_email
