# Copyright 2026 Mark Alan Boykin
# SPDX-License-Identifier: MPL-2.0
"""Privacy and ownership controls for the fleet preparation tool."""

import copy
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import relay_fleet
import relay_fleet_probe


def manifest():
    return {"version": 1, "operator_count": 1,
            "cargo_environment": {"CARGO_TARGET_DIR": str(Path.cwd() / "unused"),
                                  "CARGO_BUILD_BUILD_DIR": str(Path.cwd() / "unused/build")},
            "hosts": [
        {"role": role, "host": host, "local": index == 0,
         "sam_port": 18000 if index else 38000, "forward_port": 38000 + index,
         "runtime": "~/private/router"}
        for index, (role, host) in enumerate([
            ("endpoints", "controller"), ("worker-a", "first"), ("worker-b", "second")])
    ]}


class PrivacyBoundaries(unittest.TestCase):
    def test_nonloopback_sam_and_duplicate_bridges_or_hosts_refuse(self):
        for change in [lambda d: d["hosts"][0].update(bind="0.0.0.0"),
                       lambda d: d["hosts"][1].update(forward_port=38000),
                       lambda d: d["hosts"][1].update(host="controller"),
                       lambda d: d["hosts"][1].update(host="-oProxyCommand=bad")]:
            data = copy.deepcopy(manifest())
            change(data)
            with self.assertRaises(ValueError):
                relay_fleet.validate(data)

    def test_instructions_keep_sam_in_explicit_loopback_ssh_forwards(self):
        prepared = relay_fleet.instructions(relay_fleet.validate(manifest()))
        self.assertEqual(len(prepared["ssh_forward_argv"]), 2)
        for argv in prepared["ssh_forward_argv"]:
            self.assertIn("StrictHostKeyChecking=yes", argv)
            self.assertIn("ExitOnForwardFailure=yes", argv)
            self.assertTrue(argv[argv.index("-L") + 1].startswith("127.0.0.1:"))
        self.assertIn("--ignored", prepared["cargo_argv"])
        self.assertEqual(len(set(prepared["environment"].values())), 3)

    def test_config_does_not_enable_transit_or_lan_sam(self):
        config = relay_fleet_probe.router_config(Path("/private/router"), 18000)
        self.assertIn("notransit = true", config)
        self.assertIn("address = 127.0.0.1", config)
        self.assertIn("verify = true", config)
        self.assertNotIn("published = true", config)

    def test_staging_preserves_foreign_and_changed_config(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "router"
            root.mkdir()
            (root / "existing.txt").write_text("preserve")
            with self.assertRaises(ValueError):
                relay_fleet_probe.stage(root, 18000)
            self.assertEqual((root / "existing.txt").read_text(), "preserve")
            owned = Path(temporary) / "owned"
            config = relay_fleet_probe.stage(owned, 18000)
            self.assertEqual(relay_fleet_probe.stage(owned, 18000), config)
            config.write_text("owner changed it")
            with self.assertRaises(ValueError):
                relay_fleet_probe.stage(owned, 18000)
            self.assertEqual(config.read_text(), "owner changed it")

    def test_ssh_diagnostics_do_not_escape_into_receipts(self):
        result = subprocess.CompletedProcess([], 255, b"", b"private direct locator")
        with patch("relay_fleet.subprocess.run", return_value=result):
            record = relay_fleet.probe(manifest()["hosts"][1], False)
        self.assertFalse(record["ok"])
        self.assertNotIn("private direct locator", str(record))


if __name__ == "__main__":
    unittest.main()
