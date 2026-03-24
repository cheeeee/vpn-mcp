"""Machine fingerprint for hardware-based user identification.

Collects a stable hardware identifier per platform and hashes it
to produce a deterministic fingerprint. Same machine always produces
the same fingerprint, preventing one person from farming multiple free accounts.
"""

import hashlib
import platform
import subprocess

_SALT = "vpn-mcp-fingerprint-v1"


def get_machine_fingerprint() -> str:
    """Return a SHA-256 hash of the machine's hardware identifier."""
    raw_id = _get_raw_machine_id()
    return hashlib.sha256(f"{raw_id}{_SALT}".encode()).hexdigest()


def _get_raw_machine_id() -> str:
    """Get a raw hardware identifier for the current platform."""
    system = platform.system()

    if system == "Darwin":
        return _get_macos_hardware_uuid()
    elif system == "Linux":
        return _get_linux_machine_id()
    elif system == "Windows":
        return _get_windows_machine_guid()
    else:
        # Fallback: use hostname + platform (weak but better than nothing)
        return f"{platform.node()}-{platform.machine()}-{platform.processor()}"


def _get_macos_hardware_uuid() -> str:
    """macOS: Hardware UUID from system_profiler (stable across reinstalls)."""
    try:
        result = subprocess.run(
            ["system_profiler", "SPHardwareDataType"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        for line in result.stdout.splitlines():
            if "Hardware UUID" in line:
                return line.split(":")[-1].strip()
    except (subprocess.SubprocessError, OSError):
        pass
    # Fallback to IOPlatformUUID
    try:
        result = subprocess.run(
            ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        for line in result.stdout.splitlines():
            if "IOPlatformUUID" in line:
                return line.split('"')[-2]
    except (subprocess.SubprocessError, OSError):
        pass
    return f"darwin-{platform.node()}"


def _get_linux_machine_id() -> str:
    """Linux: /etc/machine-id (systemd, stable across reboots)."""
    try:
        with open("/etc/machine-id") as f:
            machine_id = f.read().strip()
            if machine_id:
                return machine_id
    except OSError:
        pass
    # Fallback to DMI product UUID (requires root)
    try:
        with open("/sys/class/dmi/id/product_uuid") as f:
            return f.read().strip()
    except OSError:
        pass
    return f"linux-{platform.node()}"


def _get_windows_machine_guid() -> str:
    """Windows: MachineGuid from registry (stable, set at install)."""
    try:
        import winreg

        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography")
        value, _ = winreg.QueryValueEx(key, "MachineGuid")
        winreg.CloseKey(key)
        return value
    except (OSError, ImportError):
        pass
    # Fallback via wmic
    try:
        result = subprocess.run(
            ["wmic", "csproduct", "get", "UUID"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        lines = [line.strip() for line in result.stdout.splitlines() if line.strip() and line.strip() != "UUID"]
        if lines:
            return lines[0]
    except (subprocess.SubprocessError, OSError):
        pass
    return f"windows-{platform.node()}"
