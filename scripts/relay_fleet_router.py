# Copyright 2026 Mark Alan Boykin
# SPDX-License-Identifier: MPL-2.0
"""Own one private router child; stop on EOF, lost heartbeat, deadline or disk cap."""

import hashlib
import base64
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import threading
import time

OWNER = "moot-relay-pools-single-operator"


def retained_bytes(root):
    total = 0
    for path in root.rglob("*"):
        try:
            if path.is_file() and not path.is_symlink():
                total += path.stat().st_size
        except FileNotFoundError:
            pass  # The owned router may prune a netDb file while it is sampled.
    return total


def verified(request):
    root = Path(request["runtime"]).expanduser()
    binary = Path(request["binary"]).expanduser()
    config = root / "i2pd.conf"
    if not root.is_absolute() or root.is_symlink() or (root / "owner.txt").read_text().strip() != OWNER:
        raise ValueError("runtime ownership mismatch")
    if config.is_symlink() or binary.is_symlink():
        raise ValueError("indirect provider input")
    for path, key in [(binary, "binary_sha256"), (config, "config_sha256")]:
        if hashlib.sha256(path.read_bytes()).hexdigest() != request[key]:
            raise ValueError("provider input changed")
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,47}", request["run_id"]):
        raise ValueError("literal unique run identifier required")
    if not 10 <= request["seconds"] <= 2700 or not 1024 <= request["sam_port"] <= 65535:
        raise ValueError("provider bounds refused")
    if not retained_bytes(root) < request["max_runtime_bytes"] <= 40_000_000:
        raise ValueError("provider disk bound refused")
    # Refuse to attach to or replace an unowned listener.
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", request["sam_port"]))
    return root, binary, config


def stop(child):
    if child.poll() is None:
        child.terminate()
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=5)


def serve(request, control, emit):
    root, binary, config = verified(request)
    run = root / request["run_id"]
    run.mkdir(mode=0o700)  # A previous receipt/runtime is never overwritten.
    (run / "owner.txt").write_text(OWNER + "\n", encoding="utf-8")
    text = config.read_text(encoding="utf-8")
    old_log = "logfile = " + root.as_posix() + "/router.log"
    if text.count(old_log) != 1:
        raise ValueError("staged logfile binding differs")
    text = text.replace(old_log, "logfile = " + run.as_posix() + "/router.log")
    # Pin the bounded, loopback-only config before the child exists.
    for setting in ["notransit = true", "published = false", "address = 127.0.0.1",
                    "port = " + str(request["sam_port"]), "verify = true"]:
        if setting not in text:
            raise ValueError("privacy config differs")
    run_config = run / "i2pd.conf"
    with run_config.open("x", encoding="utf-8", newline="\n") as output:
        output.write(text)
    # These are the reviewed provider's public trust certificates, never keys.
    certificates = request["public_certificates"]
    if not isinstance(certificates, dict) or not 1 <= len(certificates) <= 128:
        raise ValueError("bounded public reseed certificate bundle required")
    for name, encoded in certificates.items():
        if not re.fullmatch(r"(?:reseed|family)/[A-Za-z0-9_.@-]+\.crt", name):
            raise ValueError("public certificate path refused")
        body = base64.b64decode(encoded, validate=True)
        if len(body) > 8192 or not body.startswith(b"-----BEGIN CERTIFICATE-----"):
            raise ValueError("public certificate content refused")
        path = run / "data/certificates" / name
        path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        with path.open("xb") as output:
            output.write(body)
    environment = os.environ.copy()
    if os.name != "nt":
        environment["LD_LIBRARY_PATH"] = str(root / "lib")
    lost = threading.Event()
    heartbeat = [time.monotonic()]

    def receive():
        try:
            for line in control:
                if line.strip() == "STOP":
                    break
                if line.strip() == "HEARTBEAT":
                    heartbeat[0] = time.monotonic()
        finally:
            lost.set()

    threading.Thread(target=receive, daemon=True).start()
    child = subprocess.Popen(
        [str(binary), "--conf=" + str(run_config), "--datadir=" + str(run / "data")],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env=environment, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    reason, started = "provider-exited", time.monotonic()
    peak = retained_bytes(root)
    try:
        emit({"state": "started", "pid": child.pid, "run_id": request["run_id"]})
        while child.poll() is None:
            size = retained_bytes(root)
            peak = max(peak, size)
            if size >= request["max_runtime_bytes"]:
                reason = "disk-cap"
                break
            if lost.is_set() or time.monotonic() - heartbeat[0] > 30:
                reason = "controller-lost"
                break
            if time.monotonic() - started >= request["seconds"]:
                reason = "deadline"
                break
            time.sleep(0.5)
    finally:
        stop(child)
        receipt = {"state": "stopped", "pid": child.pid, "reason": reason,
                   "exit": child.returncode, "peak_runtime_bytes": peak,
                   "retained_runtime_bytes": retained_bytes(root),
                   "owned_child_stopped": child.poll() is not None}
        with (run / "stopped.json").open("x", encoding="utf-8") as output:
            json.dump(receipt, output, indent=2)
        emit(receipt)


def main():
    request = json.loads(sys.stdin.readline(131073))
    serve(request, sys.stdin, lambda record: print(json.dumps(record), flush=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(json.dumps({"state": "refused", "error": str(error)}), flush=True)
        sys.exit(1)
