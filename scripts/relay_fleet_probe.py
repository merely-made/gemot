# Copyright 2026 Mark Alan Boykin
# SPDX-License-Identifier: MPL-2.0
"""Private, bounded router preparation; never opens custody or starts a router."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import subprocess
import sys

OWNER = "moot-relay-pools-single-operator"


def machine_token():
    if os.name == "nt":
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as key:
            value = winreg.QueryValueEx(key, "MachineGuid")[0]
    else:
        marker = Path("/etc/machine-id")
        value = marker.read_text().strip() if marker.exists() else platform.node()
    return hashlib.sha256(value.encode()).hexdigest()


def router_config(root, port):
    # Tunnel hop counts are additionally set by the existing Rust session owner.
    return f"""# {OWNER}; private rehearsal only, no transit contribution.
log = file
loglevel = warn
logfile = {root.as_posix()}/router.log
ipv4 = true
ipv6 = false
notransit = true
floodfill = false
[ntcp2]
enabled = true
published = false
[ssu2]
enabled = true
published = false
[upnp]
enabled = false
[http]
enabled = false
[httpproxy]
enabled = false
[socksproxy]
enabled = false
[sam]
enabled = true
address = 127.0.0.1
port = {port}
[reseed]
verify = true
[addressbook]
enabled = false
"""


def stage(root, port):
    if not root.is_absolute() or root.is_symlink():
        raise ValueError("private absolute runtime root required")
    marker = root / "owner.txt"
    if root.exists():
        if not marker.is_file() or marker.is_symlink() or marker.read_text().strip() != OWNER:
            raise ValueError("existing runtime root has another owner")
    else:
        root.mkdir(parents=True, mode=0o700)
        with marker.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(OWNER + "\n")
    path = root / "i2pd.conf"
    expected = router_config(root, port)
    if path.is_symlink():
        raise ValueError("router config is an indirect path")
    if path.exists():
        if path.read_text(encoding="utf-8") != expected:
            raise ValueError("existing config differs; preserve it for review")
    else:
        with path.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(expected)
    # Never install binaries, generate keys, create data, or start a provider.
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", required=True, choices=["endpoints", "worker-a", "worker-b"])
    parser.add_argument("--sam-port", type=int, required=True)
    parser.add_argument("--runtime", required=True)
    parser.add_argument("--router-binary")
    parser.add_argument("--stage", action="store_true")
    args = parser.parse_args()
    if not 1024 <= args.sam_port <= 65535:
        raise ValueError("unprivileged SAM port required")
    root = Path(args.runtime).expanduser()
    config = stage(root, args.sam_port) if args.stage else root / "i2pd.conf"
    binary = args.router_binary or shutil.which("i2pd")
    if binary is None and Path("/usr/sbin/i2pd").is_file():
        binary = "/usr/sbin/i2pd"
    if binary:
        binary = str(Path(binary).expanduser())
        if not Path(binary).is_file():
            binary = None
    version_exit, version_line = None, None
    if binary:
        environment = os.environ.copy()
        if os.name != "nt":
            environment["LD_LIBRARY_PATH"] = str(root / "lib")
        version = subprocess.run([binary, "--version"], capture_output=True,
                                 timeout=5, env=environment)
        version_exit = version.returncode
        lines = (version.stdout + version.stderr).decode(errors="replace").splitlines()
        version_line = lines[0][:512] if lines else ""
    ready = False
    try:
        with socket.create_connection(("127.0.0.1", args.sam_port), timeout=2) as stream:
            stream.settimeout(2)
            stream.sendall(b"HELLO VERSION MIN=3.1 MAX=3.3\n")
            reply = bytearray()
            while len(reply) < 512 and b"\n" not in reply:
                part = stream.recv(512 - len(reply))
                if not part:
                    break
                reply.extend(part)
            ready = reply.startswith(b"HELLO REPLY RESULT=OK") and b"\n" in reply
    except OSError:
        pass
    result = {
        "role": args.role, "os": platform.system(), "arch": platform.machine(),
        "machine_token": machine_token(), "runtime": str(root),
        "config_staged": config.is_file(), "router_binary": binary,
        "config_sha256": hashlib.sha256(config.read_bytes()).hexdigest() if config.is_file() else None,
        "router_sha256": hashlib.sha256(Path(binary).read_bytes()).hexdigest() if binary else None,
        "router_version_exit": version_exit, "router_version_line": version_line,
        "runtime_bytes": sum(p.stat().st_size for p in root.rglob("*")
                             if p.is_file() and not p.is_symlink()) if root.is_dir() else 0,
        "sam_ready": ready, "sam_port": args.sam_port,
        "provider_started": False, "provider_config_verified_running": False,
        "custody": "not-probed", "group": "not-provisioned-by-this-tool",
        "qualification": "preparation-only",
    }
    print(json.dumps(result))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        print(json.dumps({"error": str(error), "qualification": "refused"}))
        sys.exit(1)
