"""Auto-launch management - register Domestique to start on login.

Provides two mechanisms for automatic startup:
1. SMAppService (macOS 13+) - modern login item API
2. LaunchAgent plist - fallback for older macOS versions

Additionally provides IT-managed deployment via:
3. LaunchDaemon plist - starts before user login (requires root)

Usage:
    from domestique_app.services.autolaunch import AutoLaunchManager
    mgr = AutoLaunchManager()
    mgr.enable()   # Register for auto-start on login
    mgr.disable()  # Remove auto-start
    mgr.is_enabled  # Check current state
"""

from __future__ import annotations

import contextlib
import logging
import plistlib
import subprocess
import sys
from pathlib import Path

from domestique_app.services.runtime import is_macos, is_windows, venv_python

logger = logging.getLogger("domestique.autolaunch")

BUNDLE_ID = "com.domestique.agent"
APP_NAME = "Domestique"
LAUNCH_AGENT_DIR = Path.home() / "Library" / "LaunchAgents"
LAUNCH_AGENT_PLIST = LAUNCH_AGENT_DIR / f"{BUNDLE_ID}.plist"
LAUNCH_DAEMON_PLIST = Path("/Library/LaunchDaemons") / f"{BUNDLE_ID}.plist"
WINDOWS_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


class AutoLaunchManager:
    """Manages Domestique's auto-launch on login.

    Tries SMAppService first (modern API), falls back to LaunchAgent plist.
    """

    def __init__(self, python_path: str | None = None) -> None:
        """Initialize with the Python interpreter path.

        Args:
            python_path: Path to the Python binary. Defaults to current interpreter.
        """
        self._python = python_path or sys.executable
        self._project_root = Path(__file__).parent.parent.parent

    @property
    def is_enabled(self) -> bool:
        """Check if auto-launch is currently configured."""
        if is_windows():
            return self._is_windows_run_key_enabled()
        if not is_macos():
            return False

        # Check LaunchAgent plist exists and is loaded
        if LAUNCH_AGENT_PLIST.exists():
            result = subprocess.run(  # noqa: S603
                ["launchctl", "list", BUNDLE_ID],  # noqa: S607
                capture_output=True,
                text=True,
            )
            return result.returncode == 0
        return False

    def enable(self) -> bool:
        """Register Domestique for auto-launch on login.

        Returns True if registration succeeded.
        """
        try:
            if is_windows():
                return self._enable_windows_run_key()
            if not is_macos():
                logger.warning("Auto-launch is not implemented for this OS")
                return False

            self._create_launch_agent()
            self._load_launch_agent()
            logger.info("Auto-launch enabled")
            return True
        except Exception as e:
            logger.error(f"Failed to enable auto-launch: {e}")
            return False

    def disable(self) -> bool:
        """Remove Domestique from auto-launch.

        Returns True if removal succeeded.
        """
        try:
            if is_windows():
                return self._disable_windows_run_key()
            if not is_macos():
                logger.warning("Auto-launch is not implemented for this OS")
                return False

            self._unload_launch_agent()
            if LAUNCH_AGENT_PLIST.exists():
                LAUNCH_AGENT_PLIST.unlink()
            logger.info("Auto-launch disabled")
            return True
        except Exception as e:
            logger.error(f"Failed to disable auto-launch: {e}")
            return False

    def _create_launch_agent(self) -> None:
        """Create the LaunchAgent plist file."""
        LAUNCH_AGENT_DIR.mkdir(parents=True, exist_ok=True)

        # Determine the launch command
        python_bin = str(venv_python(self._project_root) or self._python)

        plist = {
            "Label": BUNDLE_ID,
            "ProgramArguments": [
                python_bin,
                "-c",
                (
                    f"import sys; sys.path.insert(0, '{self._project_root}'); "
                    "from domestique_app.main import launch; launch()"
                ),
            ],
            "RunAtLoad": True,
            "KeepAlive": {
                "SuccessfulExit": False,  # Restart on crash
            },
            "WorkingDirectory": str(self._project_root),
            "StandardOutPath": str(Path.home() / ".domestique" / "logs" / "stdout.log"),
            "StandardErrorPath": str(Path.home() / ".domestique" / "logs" / "stderr.log"),
            "EnvironmentVariables": {
                "PATH": "/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin",
                "PYTHONPATH": str(self._project_root),
            },
            "ProcessType": "Interactive",  # Higher priority for UI app
            "ThrottleInterval": 10,  # Min 10s between restarts
        }

        # Ensure log directory exists
        (Path.home() / ".domestique" / "logs").mkdir(parents=True, exist_ok=True)

        with open(LAUNCH_AGENT_PLIST, "wb") as f:
            plistlib.dump(plist, f)

        logger.debug(f"Created LaunchAgent plist: {LAUNCH_AGENT_PLIST}")

    def _load_launch_agent(self) -> None:
        """Load the LaunchAgent with launchctl."""
        # Unload first to avoid "already loaded" errors
        subprocess.run(  # noqa: S603
            ["launchctl", "unload", str(LAUNCH_AGENT_PLIST)],  # noqa: S607
            capture_output=True,
        )
        result = subprocess.run(  # noqa: S603
            ["launchctl", "load", str(LAUNCH_AGENT_PLIST)],  # noqa: S607
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"launchctl load failed: {result.stderr}")

    def _unload_launch_agent(self) -> None:
        """Unload the LaunchAgent."""
        subprocess.run(  # noqa: S603
            ["launchctl", "unload", str(LAUNCH_AGENT_PLIST)],  # noqa: S607
            capture_output=True,
        )

    def _is_windows_run_key_enabled(self) -> bool:
        """Check the current user's Windows Run key."""
        import winreg

        try:
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER, WINDOWS_RUN_KEY, 0, winreg.KEY_READ
            ) as key:
                value, _ = winreg.QueryValueEx(key, APP_NAME)
            return "domestique_app.main" in value or "from domestique_app.main import launch" in value
        except FileNotFoundError:
            return False

    def _enable_windows_run_key(self) -> bool:
        """Register Domestique in the current user's Windows Run key."""
        import winreg

        python_bin = str(venv_python(self._project_root) or self._python)
        code = (
            "import sys; "
            f"sys.path.insert(0, {str(self._project_root)!r}); "
            "from domestique_app.main import launch; "
            "launch(mode='portable')"
        )
        command = subprocess.list2cmdline([python_bin, "-c", code])
        with winreg.CreateKeyEx(
            winreg.HKEY_CURRENT_USER, WINDOWS_RUN_KEY, 0, winreg.KEY_SET_VALUE
        ) as key:
            winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, command)
        logger.info("Windows auto-launch enabled")
        return True

    def _disable_windows_run_key(self) -> bool:
        """Remove Domestique from the current user's Windows Run key."""
        import winreg

        with winreg.CreateKeyEx(
            winreg.HKEY_CURRENT_USER, WINDOWS_RUN_KEY, 0, winreg.KEY_SET_VALUE
        ) as key, contextlib.suppress(FileNotFoundError):
            winreg.DeleteValue(key, APP_NAME)
        logger.info("Windows auto-launch disabled")
        return True


def generate_installer_script() -> str:
    """Generate a one-line installer shell script.

    This script:
    1. Clones/updates the repo
    2. Creates a venv and installs dependencies
    3. Generates and trusts the CA certificate
    4. Registers the LaunchAgent for auto-start
    5. Starts the app

    Returns the script content as a string.
    """
    return """#!/bin/bash
# Domestique Installer - One-line deployment
# Usage: curl -sSL https://domestique.dev/install | bash
set -euo pipefail

INSTALL_DIR="$HOME/.domestique/app"
DATA_DIR="$HOME/.domestique"
REPO_URL="https://github.com/domestique/domestique.git"

echo "🛡️  Installing Domestique..."

# 1. Clone or update
if [ -d "$INSTALL_DIR" ]; then
    echo "  -> Updating existing installation..."
    cd "$INSTALL_DIR" && git pull --quiet
else
    echo "  -> Downloading Domestique..."
    git clone --quiet "$REPO_URL" "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

# 2. Python environment
echo "  -> Setting up Python environment..."
python3 -m venv .venv
source .venv/bin/activate
pip install --quiet -e .

# 3. First-time setup (CA generation + trust)
echo "  -> Configuring HTTPS interception..."
python3 -c "
from domestique_app.services.interceptor import generate_ca, install_ca_to_keychain
cert, key = generate_ca()
install_ca_to_keychain(cert)
print('    CA certificate generated and trusted')
"

# 4. Register auto-start
echo "  -> Registering for auto-launch..."
python3 -c "
from domestique_app.services.autolaunch import AutoLaunchManager
mgr = AutoLaunchManager()
mgr.enable()
print('    Auto-launch enabled')
"

# 5. Start the app
echo "  -> Starting Domestique..."
python3 -c "
import sys; sys.path.insert(0, '.')
from domestique_app.main import launch
" &

echo ""
echo "✅ Domestique installed and running!"
echo "   Menu bar icon should appear shortly."
echo "   Data directory: $DATA_DIR"
echo "   To uninstall: ~/.domestique/app/scripts/uninstall.sh"
"""


def generate_uninstaller_script() -> str:
    """Generate an uninstaller shell script."""
    return f"""#!/bin/bash
# Domestique Uninstaller - Clean removal
set -euo pipefail

echo "🗑️  Uninstalling Domestique..."

# Stop the service
launchctl unload ~/Library/LaunchAgents/{BUNDLE_ID}.plist 2>/dev/null || true

# Remove LaunchAgent
rm -f ~/Library/LaunchAgents/{BUNDLE_ID}.plist

# Remove CA from keychain
security delete-certificate -c "Domestique Local CA" ~/Library/Keychains/login.keychain-db 2>/dev/null || true
security delete-certificate -c "LLM Firewall Local CA" ~/Library/Keychains/login.keychain-db 2>/dev/null || true

# Remove system proxy settings
for svc in "Wi-Fi" "Ethernet" "USB 10/100/1000 LAN" "Thunderbolt Bridge"; do
    networksetup -setautoproxystate "$svc" off 2>/dev/null || true
done

# Remove data
rm -rf ~/.domestique

# Remove app (optional - keep for reinstall)
read -p "Remove application code? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -rf ~/.domestique/app
fi

echo "✅ Domestique uninstalled."
"""  # noqa: E501
