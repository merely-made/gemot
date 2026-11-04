# Copyright 2026 Mark Alan Boykin
# SPDX-License-Identifier: MPL-2.0
"""Run the prepared router-only rehearsal, with owned children and compact receipts."""

import argparse
import base64
from collections import deque
import concurrent.futures
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import queue
import shlex
import socket
import subprocess
import sys
import threading
import time

import relay_fleet
from relay_fleet_router import retained_bytes

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
HIDDEN = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def ssh(host, command):
    return ["ssh", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
            "-o", "ConnectTimeout=6", "-o", "ConnectionAttempts=1", host, command]


def compile_test(environment):
    args = ["cargo", "test", "-p", "gemot", "--lib", "--features", "relay-pool-i2p",
            "--frozen", "--no-run", "--message-format=json"]
    result = subprocess.run(args, cwd=REPO, env=environment, capture_output=True, timeout=300)
    if result.returncode:
        raise ValueError("rehearsal test compilation refused")
    binaries = []
    for line in result.stdout.splitlines():
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if record.get("reason") == "compiler-artifact" and record.get("executable"):
            if record["target"]["name"] == "gemot" and record["profile"]["test"]:
                binaries.append(Path(record["executable"]))
    if len(binaries) != 1 or not binaries[0].is_relative_to(Path(environment["CARGO_TARGET_DIR"])):
        raise ValueError("one receiving test binary in the stable target required")
    return binaries[0]


def helper(host, record):
    if host["local"]:
        return [sys.executable, "-B", "-u", str(HERE / "relay_fleet_router.py")]
    payload = (HERE / "relay_fleet_router.py").read_bytes()
    filename = "router-supervisor-" + hashlib.sha256(payload).hexdigest()[:16] + ".py"
    install = (
        "from pathlib import Path\n"
        f"root=Path({record['runtime']!r})\n"
        "assert not root.is_symlink()\n"
        "assert (root/'owner.txt').read_text().strip()=='moot-relay-pools-single-operator'\n"
        f"payload={payload!r}\n"
        f"path=root/{filename!r}\n"
        "assert not path.is_symlink()\n"
        "if path.exists(): assert path.read_bytes()==payload\n"
        "else:\n"
        " with path.open('xb') as output: output.write(payload)\n"
    )
    result = subprocess.run(ssh(host["host"], "python3 -"), input=install.encode(),
                            capture_output=True, timeout=20)
    if result.returncode:
        raise ValueError("owned supervisor staging refused")
    path = record["runtime"] + "/" + filename
    return ssh(host["host"], "python3 -B -u " + shlex.quote(path))


def read_lines(child, events, role):
    try:
        for line in child.stdout:
            if len(line) <= 16384:
                events.put((role, line.rstrip()))
    finally:
        events.put((role, None))


def sam(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1) as stream:
            stream.settimeout(1)
            stream.sendall(b"HELLO VERSION MIN=3.1 MAX=3.3\n")
            reply = bytearray()
            while len(reply) < 512 and b"\n" not in reply:
                block = stream.recv(512 - len(reply))
                if not block:
                    break
                reply.extend(block)
            return reply.startswith(b"HELLO REPLY RESULT=OK") and b"\n" in reply
    except OSError:
        return False


def terminate(child):
    if child.poll() is None:
        child.terminate()
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=5)


def certificates(data):
    directory = Path(data["public_certificates"]["directory"])
    files = {str(path.relative_to(directory)).replace("\\", "/"): path.read_bytes()
             for path in directory.rglob("*.crt")}
    hashes = {name: hashlib.sha256(body).hexdigest() for name, body in files.items()}
    digest = hashlib.sha256(json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if digest != data["public_certificates"]["sha256"]:
        raise ValueError("provider public certificate bundle changed")
    return {name: base64.b64encode(body).decode("ascii") for name, body in files.items()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    if args.report.exists() or not args.report.is_absolute() or not args.report.parent.is_dir():
        raise ValueError("new absolute private receipt path required")
    data = json.loads(args.manifest.read_text(encoding="utf-8-sig"))
    hosts = relay_fleet.validate(data)
    public_certificates = certificates(data)
    environment = os.environ.copy()
    environment.update(data["cargo_environment"])
    environment["CARGO_BUILD_JOBS"] = "1"
    environment.update(relay_fleet.instructions(hosts)["environment"])
    binary = compile_test(environment)  # No providers exist if compilation fails.
    print("REHEARSAL binary-ready", flush=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        records = list(pool.map(lambda host: relay_fleet.probe(host, True), hosts))
    if any(not r.get("ok") or r.get("sam_ready") or r.get("router_version_exit") != 0 for r in records):
        raise ValueError("three stopped, runnable owned providers required")
    if len({r["machine_token"] for r in records}) != 3:
        raise ValueError("three distinct router machines required")
    if any(record["router_sha256"] != host.get("router_sha256") for host, record in zip(hosts, records)):
        raise ValueError("provider binary differs from the reviewed artifact")
    local_bytes = sum(retained_bytes(Path(path)) for path in data["controller_receipt_roots"])
    before = local_bytes + sum(r["runtime_bytes"] for h, r in zip(hosts, records) if not h["local"])
    if before + 17_000_000 > data.get("retained_byte_cap_all_hosts", 20_000_000):
        raise ValueError("provider growth plus compact receipts exceed the retained budget")
    for host in hosts:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", host["forward_port"]))
    # Install helpers before any child exists; a staging failure leaves no routers.
    commands = [helper(host, record) for host, record in zip(hosts, records)]
    events, controls, forwards = queue.Queue(), {}, []
    readers = []
    provider_records, markers = [], []
    tail = deque(maxlen=40)
    done = threading.Event()
    test = None
    test_exit, failure = None, None
    started = time.monotonic()
    receipt = {
        "version": 1, "utc": datetime.now(timezone.utc).isoformat(), "run_id": args.run_id,
        "operator_count": 1, "application_hosts": 1, "router_hosts": 3,
        "custody_qualified": False, "independent_operator_qualified": False,
        "independent_uplink_qualified": False,
        "test_binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "manifest_sha256": hashlib.sha256(args.manifest.read_bytes()).hexdigest(),
        "router_supervisor_sha256": hashlib.sha256((HERE / "relay_fleet_router.py").read_bytes()).hexdigest(),
        "public_certificates_sha256": data["public_certificates"]["sha256"],
        "source": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO).decode().strip(),
        "retained_byte_cap_all_hosts": data.get("retained_byte_cap_all_hosts", 20_000_000),
        "retained_bytes_before_run": before, "reserved_runtime_growth_bytes": 15_000_000,
        "reserved_receipt_and_overshoot_bytes": 2_000_000,
    }

    def heartbeat():
        while not done.wait(5):
            for child in list(controls.values()):
                try:
                    child.stdin.write("HEARTBEAT\n")
                    child.stdin.flush()
                except (OSError, ValueError):
                    pass

    def consume():
        while True:
            try:
                role, line = events.get_nowait()
            except queue.Empty:
                break
            if role == "test":
                if line:
                    tail.append(line[:512])
                    if line.startswith("MURM_POOL_"):
                        if len(markers) < 1024:
                            markers.append(line[:2048])
                        print(line[:2048], flush=True)
            elif line:
                try:
                    record = json.loads(line)
                    provider_records.append({"role": role, **record})
                    print("REHEARSAL " + role + " " + record.get("state", "unknown"), flush=True)
                except ValueError:
                    pass

    try:
        for host, record, command in zip(hosts, records, commands):
            child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, text=True, encoding="utf-8",
                                     creationflags=HIDDEN)
            controls[host["role"]] = child
            reader = threading.Thread(target=read_lines, args=(child, events, host["role"]), daemon=True)
            reader.start()
            readers.append(reader)
            request = {"runtime": record["runtime"], "binary": record["router_binary"],
                       "binary_sha256": record["router_sha256"], "config_sha256": record["config_sha256"],
                       "sam_port": host["sam_port"], "run_id": args.run_id, "seconds": 2100,
                       "max_runtime_bytes": record["runtime_bytes"] + 5_000_000,
                       "public_certificates": public_certificates}
            child.stdin.write(json.dumps(request) + "\n")
            child.stdin.flush()
        threading.Thread(target=heartbeat, daemon=True).start()
        for command in relay_fleet.instructions(hosts)["ssh_forward_argv"]:
            forwards.append(subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                              creationflags=HIDDEN))
        while not all(sam(host["forward_port"]) for host in hosts):
            consume()
            if any(child.poll() is not None for child in [*controls.values(), *forwards]):
                raise ValueError("owned provider or loopback forward stopped during startup")
            if time.monotonic() - started > 90:
                raise ValueError("SAM readiness exceeded its bound")
            time.sleep(1)
        print("REHEARSAL three-sam-bridges-ready", flush=True)
        test = subprocess.Popen([str(binary), relay_fleet.REHEARSAL, "--ignored", "--nocapture", "--test-threads=1"],
                                cwd=REPO, env=environment, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, encoding="utf-8", errors="replace", creationflags=HIDDEN)
        reader = threading.Thread(target=read_lines, args=(test, events, "test"), daemon=True)
        reader.start()
        readers.append(reader)
        while test.poll() is None:
            consume()
            if any(child.poll() is not None for child in [*controls.values(), *forwards]):
                raise ValueError("owned provider or SSH forwarding was lost")
            if time.monotonic() - started > 2000:
                raise ValueError("rehearsal execution deadline")
            time.sleep(0.5)
        test_exit = test.returncode
        consume()
    except (OSError, ValueError, KeyboardInterrupt) as error:
        failure = str(error)
    finally:
        if test:
            terminate(test)
        for child in controls.values():
            try:
                child.stdin.write("STOP\n")
                child.stdin.flush()
                child.stdin.close()
            except (OSError, ValueError):
                pass
        for child in controls.values():
            try:
                child.wait(timeout=15)
            except subprocess.TimeoutExpired:
                terminate(child)  # EOF/heartbeat supervisor remains an independent stop guard.
        done.set()
        for child in forwards:
            terminate(child)
        for reader in readers:
            reader.join(timeout=2)
        consume()
        receipt.update({"test_exit": test_exit, "failure": failure, "markers": markers,
                        "private_test_tail": list(tail), "provider_events": provider_records,
                        "elapsed_seconds": round(time.monotonic() - started, 2),
                        "forward_children_stopped": all(child.poll() is not None for child in forwards),
                        "supervisors_stopped": all(child.poll() is not None for child in controls.values())})
        with args.report.open("x", encoding="utf-8", newline="\n") as output:
            json.dump(receipt, output, indent=2)
            output.write("\n")
    passed = test_exit == 0 and any('"two_workers":true' in marker for marker in markers)
    cleanup = sum(r.get("owned_child_stopped", False) for r in provider_records) == 3
    print(json.dumps({"rehearsal": "passed" if passed else "failed", "owned_routers_stopped": cleanup,
                      "qualification": "single-operator-router-rehearsal"}), flush=True)
    return 0 if passed and cleanup and failure is None else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
