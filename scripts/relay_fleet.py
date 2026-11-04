# Copyright 2026 Mark Alan Boykin
# SPDX-License-Identifier: MPL-2.0
"""Prepare a single-operator three-router rehearsal through strict SSH aliases.

Reports and the manifest are operator-private. Preparation stages inert router
configs only. It never starts providers, changes custody or provisions a Moot.

Use a private version-1 manifest with the three roles endpoints/worker-a/worker-b,
literal configured SSH aliases, explicit runtime paths, SAM and forward ports,
and optional router_binary paths. Run with --stage-routers to create owner-marked
configs; omit it for a read-only readiness check. --report must name a new file.
Private reports give exact forward/test argv and explicit qualification fields.
Install/stage providers through their existing owner, then verify --version and
the exact staged config before starting them. No automatic provider launch occurs.
The Rust rehearsal keeps all application workers and synthetic authority in one
controller process; it qualifies neither distributed custody nor physical worker
failure. I2P tunnel settings, recipient pins and fail-closed policy remain enforced
by the existing fixture. Operator SSH control traffic reveals control locators.
"""

import argparse
import concurrent.futures
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import sys
from datetime import datetime, timezone

ROLES = {"endpoints", "worker-a", "worker-b"}
HERE = Path(__file__).resolve().parent
REHEARSAL = "public_i2p_three_router_fleet_rehearsal"


def validate(data):
    if data.get("version") != 1 or data.get("operator_count") != 1:
        raise ValueError("version 1, single-operator manifest required")
    cargo = data.get("cargo_environment", {})
    if any(not isinstance(cargo.get(key), str) or not Path(cargo[key]).is_absolute()
           for key in ["CARGO_TARGET_DIR", "CARGO_BUILD_BUILD_DIR"]):
        raise ValueError("explicit absolute stable Cargo target and build paths required")
    if not Path(cargo["CARGO_BUILD_BUILD_DIR"]).is_relative_to(Path(cargo["CARGO_TARGET_DIR"])):
        raise ValueError("Cargo build directory must remain within its stable target")
    hosts = data.get("hosts", [])
    if len(hosts) != 3 or {h.get("role") for h in hosts} != ROLES:
        raise ValueError("one endpoint host and two router hosts required")
    if sum(h.get("local") is True for h in hosts) != 1:
        raise ValueError("one local endpoint host required")
    aliases, bridges = set(), set()
    for host in hosts:
        alias = host.get("host", "")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", alias) or alias in aliases:
            raise ValueError("distinct, literal SSH host aliases required")
        aliases.add(alias)
        if host.get("local") != (host["role"] == "endpoints"):
            raise ValueError("application endpoints must remain on the local controller")
        for field in ["sam_port", "forward_port"]:
            value = host.get(field)
            if type(value) is not int or not 1024 <= value <= 65535:
                raise ValueError("unprivileged SAM and forwarding ports required")
        if host["local"] and host["sam_port"] != host["forward_port"]:
            raise ValueError("local SAM port must equal its controller bridge")
        bridge = host["forward_port"]
        if bridge in bridges:
            raise ValueError("three distinct controller bridges required")
        bridges.add(bridge)
        if not isinstance(host.get("runtime"), str) or not host["runtime"]:
            raise ValueError("explicit private runtime paths required")
        # A future extension must not silently expose SAM on a LAN interface.
        if not ipaddress.ip_address(host.get("bind", "127.0.0.1")).is_loopback:
            raise ValueError("SAM and SSH forwarding must bind loopback")
    return hosts


def probe(host, stage):
    arguments = ["--role", host["role"], "--sam-port", str(host["sam_port"]),
                 "--runtime", host["runtime"]]
    if host.get("router_binary"):
        arguments += ["--router-binary", host["router_binary"]]
    if stage:
        arguments += ["--stage"]
    if host["local"]:
        command = [sys.executable, str(HERE / "relay_fleet_probe.py"), *arguments]
        payload = None
    else:
        # Remote command arguments cross a shell; quote every argument for POSIX.
        import shlex
        remote = "python3 - " + " ".join(shlex.quote(arg) for arg in arguments)
        command = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                   "-o", "ConnectTimeout=6", "-o", "ConnectionAttempts=1", host["host"], remote]
        payload = (HERE / "relay_fleet_probe.py").read_bytes()
    try:
        result = subprocess.run(command, input=payload, capture_output=True, timeout=20)
        if len(result.stdout) > 16384 or len(result.stderr) > 16384:
            raise ValueError("probe output exceeds receipt bound")
        record = json.loads(result.stdout)
        if result.returncode or record.get("role") != host["role"]:
            raise ValueError("remote preparation refused")
        return {"host": host["host"], "ok": True, **record}
    except (subprocess.TimeoutExpired, ValueError, OSError):
        # SSH diagnostics can contain direct addresses; keep them out of reports.
        return {"host": host["host"], "role": host["role"], "ok": False,
                "error": "bounded preparation failed; inspect the named host privately"}


def instructions(hosts):
    forwards = []
    for host in hosts:
        if not host["local"]:
            forwards.append(["ssh", "-N", "-o", "BatchMode=yes", "-o",
                             "StrictHostKeyChecking=yes", "-o", "ExitOnForwardFailure=yes",
                             "-L", f"127.0.0.1:{host['forward_port']}:127.0.0.1:{host['sam_port']}",
                             host["host"]])
    roles = {host["role"]: host for host in hosts}
    env = {}
    for role, name in [("endpoints", "MURM_RELAY_I2P_CLIENT_SAM"),
                       ("worker-a", "MURM_RELAY_I2P_WORKER_SAM"),
                       ("worker-b", "MURM_RELAY_I2P_WORKER_B_SAM")]:
        env[name] = "127.0.0.1:" + str(roles[role]["forward_port"])
    return {"ssh_forward_argv": forwards, "environment": env,
            "cargo_argv": ["cargo", "test", "-p", "gemot", "--lib", "--features",
                           "relay-pool-i2p", "--frozen", REHEARSAL, "--", "--ignored", "--nocapture",
                           "--test-threads=1"]}


def provider_instructions(results):
    providers = []
    for record in results:
        if not record.get("ok") or not record.get("router_binary"):
            continue
        root = record["runtime"].replace("\\", "/")
        providers.append({
            "host": record["host"], "role": record["role"],
            "argv": [record["router_binary"], "--conf=" + root + "/i2pd.conf",
                     "--datadir=" + root + "/data"],
            "environment": {"LD_LIBRARY_PATH": root + "/lib"} if record["os"] != "Windows" else {},
            "executed": False,
        })
    return providers


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--stage-routers", action="store_true")
    args = parser.parse_args()
    if not args.report.is_absolute() or args.report.exists() or not args.report.parent.is_dir():
        raise ValueError("new absolute report path under an existing private directory required")
    hosts = validate(json.loads(args.manifest.read_text(encoding="utf-8-sig")))
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(lambda host: probe(host, args.stage_routers), hosts))
    tokens = {r["machine_token"] for r in results if r.get("ok")}
    distinct = len(tokens) == 3
    report = {
        "version": 1, "utc": datetime.now(timezone.utc).isoformat(),
        "owner": "moot-relay-pools-single-operator", "operator_count": 1,
        "application_hosts": 1, "router_hosts_observed_distinct": distinct,
        "independent_operator_qualified": False, "independent_uplink_qualified": False,
        "custody_qualified": False, "traffic_qualified": False,
        "provider_started": False, "retained_byte_cap_all_hosts": 20_000_000,
        "manifest_sha256": hashlib.sha256(args.manifest.read_bytes()).hexdigest(),
        "probe_sha256": hashlib.sha256((HERE / "relay_fleet_probe.py").read_bytes()).hexdigest(),
        "manifest": json.loads(args.manifest.read_text(encoding="utf-8-sig")),
        "hosts": results, "manual_run": instructions(hosts),
    }
    report["manual_run"]["provider_launch"] = provider_instructions(results)
    report["manual_run"]["environment"].update(report["manifest"]["cargo_environment"])
    report["manual_run"]["environment"]["CARGO_BUILD_JOBS"] = "1"
    report["manual_run"]["required_checks"] = [
        "Verify each provider is the named owned process using the staged private config.",
        "Keep SAM and both SSH forward listeners on loopback.",
        "Stop only owned children/forwards after the test; preserve all prior receipts.",
        "Bound all retained rehearsal state across hosts to the shared 20 MB P3a cap.",
        "Do not count this fixture as distributed custody, worker-process or independent-uplink qualification.",
    ]
    with args.report.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    missing = [r["role"] for r in results if not r.get("ok") or not r.get("router_binary")]
    print(json.dumps({"preparation": "staged" if args.stage_routers else "checked",
                      "host_probes_ok": sum(r.get("ok", False) for r in results),
                      "distinct_router_hosts": distinct, "missing_router_binary": missing,
                      "runnable_router_binaries": sum(r.get("router_version_exit") == 0 for r in results),
                      "ready_sam_bridges": sum(r.get("sam_ready", False) for r in results),
                      "qualification": "not-run"}))
    return 0 if all(r.get("ok") for r in results) and distinct else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
