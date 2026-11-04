# Copyright 2026 Mark Alan Boykin
# SPDX-License-Identifier: MPL-2.0
"""Executable ownership and stop controls; no network provider is started."""

import hashlib
import base64
import io
import json
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest.mock import patch

import relay_fleet_probe
import relay_fleet_router as router
import relay_fleet_run as runner


class Child:
    pid = 12345
    returncode = None

    def poll(self):
        return self.returncode

    def terminate(self):
        self.returncode = 0

    def wait(self, timeout):
        return self.returncode


class RouterControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "router"
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            self.port = listener.getsockname()[1]
        config = relay_fleet_probe.stage(self.root, self.port)
        binary = self.root / "fake-provider"
        binary.write_bytes(b"only a synthetic process fixture")
        self.request = {
            "runtime": str(self.root), "binary": str(binary), "run_id": "run-fixture",
            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "config_sha256": hashlib.sha256(config.read_bytes()).hexdigest(),
            "sam_port": self.port, "seconds": 60, "max_runtime_bytes": 1_000_000,
            "public_certificates": {"reseed/fixture.crt": base64.b64encode(
                b"-----BEGIN CERTIFICATE-----\nsynthetic public fixture\n-----END CERTIFICATE-----\n").decode()},
        }

    def test_eof_stops_only_the_owned_child_and_retains_a_receipt(self):
        records, child = [], Child()
        with patch.object(router.subprocess, "Popen", return_value=child):
            router.serve(self.request, io.StringIO(""), records.append)
        self.assertTrue(records[-1]["owned_child_stopped"])
        self.assertEqual(records[-1]["reason"], "controller-lost")
        self.assertTrue((self.root / "run-fixture/stopped.json").is_file())

    def test_disk_limit_stops_the_child_before_more_controller_work(self):
        records, child = [], Child()
        with patch.object(router.subprocess, "Popen", return_value=child), \
                patch.object(router, "retained_bytes", side_effect=[0, 0, 1_000_001, 1_000_001]):
            router.serve(self.request, io.StringIO(""), records.append)
        self.assertEqual(records[-1]["reason"], "disk-cap")
        self.assertTrue(records[-1]["owned_child_stopped"])

    def test_deadline_stops_a_child_even_with_an_open_controller(self):
        released = threading.Event()

        class OpenControl:
            def __iter__(self):
                released.wait(timeout=5)
                return iter([])

        records, child = [], Child()
        try:
            with patch.object(router.subprocess, "Popen", return_value=child), \
                    patch.object(router.time, "monotonic", side_effect=[0, 0, 1, 61]):
                router.serve(self.request, OpenControl(), records.append)
        finally:
            released.set()
        self.assertEqual(records[-1]["reason"], "deadline")

    def test_changed_artifacts_and_foreign_listener_refuse_before_spawn(self):
        changed = dict(self.request, binary_sha256="0" * 64)
        with patch.object(router.subprocess, "Popen") as spawn:
            with self.assertRaises(ValueError):
                router.serve(changed, io.StringIO(""), lambda _: None)
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", self.port))
                listener.listen()
                with self.assertRaises(OSError):
                    router.serve(self.request, io.StringIO(""), lambda _: None)
            spawn.assert_not_called()

    def test_certificate_traversal_refuses_before_any_child_exists(self):
        request = dict(self.request, public_certificates={"../outside.crt": "invalid"})
        with patch.object(router.subprocess, "Popen") as spawn:
            with self.assertRaises(ValueError):
                router.serve(request, io.StringIO(""), lambda _: None)
            spawn.assert_not_called()
        self.assertFalse((self.root / "outside.crt").exists())

    def test_public_trust_bundle_is_pinned_before_transfer(self):
        directory = self.root / "certificates"
        directory.mkdir()
        body = b"synthetic public certificate fixture"
        path = directory / "fixture.crt"
        path.write_bytes(body)
        hashes = {"fixture.crt": hashlib.sha256(body).hexdigest()}
        digest = hashlib.sha256(json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        data = {"public_certificates": {"directory": str(directory), "sha256": digest}}
        self.assertEqual(len(runner.certificates(data)), 1)
        path.write_bytes(b"changed")
        with self.assertRaises(ValueError):
            runner.certificates(data)


if __name__ == "__main__":
    unittest.main()
