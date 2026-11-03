#!/usr/bin/env python3
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Pure subprocess/pipe controls, never Kaname/API/public acceptance."""
import importlib.util
import os
from pathlib import Path
import selectors
import sys
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("rid_bridge_driver", Path(__file__).with_name("selftest_rid_native_bridge.py"))
DRIVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DRIVER)

PREFIX = "import os,sys,json,time; data=json.loads(sys.stdin.buffer.read()); os.write(1,b'OUT-before-ACK'); os.write(2,b'ERR-before-ACK'); "
BAD = PREFIX + "os.write(3,b'not-json'); os.close(3); os.read(4,64)"

class ProtocolAdapterControls(unittest.TestCase):
    def run_client(self, script, timeout=2, secrets=()):
        return DRIVER.run_protocol_client([sys.executable,"-c",script,"case"], {"runId":"run"}, dict(os.environ), timeout=timeout, audit_secrets=secrets)

    def assert_retained(self, error):
        self.assertIn(b"OUT-before-ACK", error.result.stdout)
        self.assertIn(b"ERR-before-ACK", error.result.stderr)
        self.assertTrue(error.audit["stdoutEOF"])
        self.assertTrue(error.audit["stderrEOF"])
        self.assertTrue(error.audit["reaped"])
        self.assertFalse(error.audit["permitSent"])
        self.assertEqual(error.audit["remainingFDs"], 0)

    def test_malformed_ack_retains_both_streams(self):
        with self.assertRaises(DRIVER.ProtocolClientFailure) as raised:
            self.run_client(BAD)
        self.assert_retained(raised.exception)
        self.assertIsNotNone(raised.exception.primary)

    def test_empty_ack_early_exit_retains_both_streams(self):
        with self.assertRaises(DRIVER.ProtocolClientFailure) as raised:
            self.run_client(PREFIX + "os.close(3); sys.exit(1)")
        self.assert_retained(raised.exception)

    def test_ack_timeout_retains_both_streams(self):
        with self.assertRaises(DRIVER.ProtocolClientFailure) as raised:
            self.run_client(PREFIX + "time.sleep(5)", timeout=0.1)
        self.assert_retained(raised.exception)

    def test_secret_audit_runs_on_invalid_ack(self):
        with self.assertRaises(DRIVER.ProtocolClientFailure) as raised:
            self.run_client(PREFIX + "os.write(1,b'unit-secret'); os.write(3,b'bad'); os.close(3); os.read(4,64)", secrets=(b"unit-secret",))
        self.assert_retained(raised.exception)
        self.assertTrue(raised.exception.audit["secretFound"])
        self.assertGreater(raised.exception.audit["secretChecks"], 0)

    def test_partial_pipe_allocation_closes_every_fd(self):
        allocated = []
        actual_pipe = os.pipe
        def allocate():
            if len(allocated) == 4:
                raise OSError("injected allocation failure")
            pair = actual_pipe()
            allocated.extend(pair)
            return pair
        with mock.patch.object(DRIVER.os, "pipe", side_effect=allocate):
            with self.assertRaises(DRIVER.ProtocolClientFailure) as raised:
                self.run_client(BAD)
        self.assertEqual(raised.exception.audit["remainingFDs"], 0)
        for fd in allocated:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_original_and_cleanup_errors_both_retained(self):
        actual_selector = selectors.DefaultSelector
        class CloseFailure:
            def __init__(self):
                self.inner = actual_selector()
            def __getattr__(self, name):
                return getattr(self.inner, name)
            def close(self):
                self.inner.close()
                raise OSError("injected selector cleanup failure")
        with mock.patch.object(DRIVER.selectors, "DefaultSelector", side_effect=CloseFailure):
            with self.assertRaises(DRIVER.ProtocolClientFailure) as raised:
                self.run_client(BAD)
        self.assert_retained(raised.exception)
        self.assertIsNotNone(raised.exception.primary)
        self.assertTrue(raised.exception.cleanup)

    def test_first_register_failure_after_spawn_closes_unused_ends(self):
        actual_selector = selectors.DefaultSelector
        actual_spawn = os.posix_spawn
        spawned = []
        allocated = []
        actual_pipe = os.pipe
        sentinel = OSError("injected first register failure")
        class FirstRegisterFailure:
            def __init__(self):
                self.inner = actual_selector()
            def __getattr__(self, name):
                return getattr(self.inner, name)
            def register(self, *args, **kwargs):
                raise sentinel
        def spawn(*args, **kwargs):
            pid = actual_spawn(*args, **kwargs)
            spawned.append(pid)
            return pid
        def pipe():
            pair = actual_pipe()
            allocated.extend(pair)
            return pair
        with mock.patch.object(DRIVER.selectors, "DefaultSelector", side_effect=FirstRegisterFailure), \
             mock.patch.object(DRIVER.os, "posix_spawn", side_effect=spawn), \
             mock.patch.object(DRIVER.os, "pipe", side_effect=pipe):
            with self.assertRaises(DRIVER.ProtocolClientFailure) as raised:
                self.run_client(BAD)
        error = raised.exception
        self.assertEqual(len(spawned), 1)
        self.assertIs(error.primary, sentinel)
        self.assertFalse(error.cleanup)
        self.assertTrue(error.audit["reaped"])
        self.assertTrue(error.audit["stdoutEOF"])
        self.assertTrue(error.audit["stderrEOF"])
        self.assertFalse(error.audit["ackValid"])
        self.assertFalse(error.audit["permitSent"])
        self.assertEqual(error.audit["remainingFDs"], 0)
        with self.assertRaises(ChildProcessError):
            os.waitpid(spawned[0], os.WNOHANG)
        for fd in allocated:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def assert_invalid_ack(self, changes=None, raw=None):
        script = PREFIX + "ack={'version':1,'pid':os.getpid(),'caseId':sys.argv[-1],'runId':data['runId']}; "
        if changes:
            script += changes + "; "
        script += "wire=" + (raw if raw else "json.dumps(ack)") + "; "
        script += "os.write(3,(wire+'\\n').encode()); os.close(3); os.read(4,64)"
        with self.assertRaises(DRIVER.ProtocolClientFailure) as raised:
            self.run_client(script, secrets=(b"unit-absent-secret",))
        self.assert_retained(raised.exception)
        self.assertFalse(raised.exception.audit["ackValid"])
        self.assertGreaterEqual(raised.exception.audit["secretChecks"], 2)
        self.assertIsNotNone(raised.exception.primary)

    def test_ack_boolean_version_rejected(self):
        self.assert_invalid_ack("ack['version']=True")

    def test_ack_float_version_rejected(self):
        self.assert_invalid_ack("ack['version']=1.0")

    def test_ack_float_pid_rejected(self):
        self.assert_invalid_ack("ack['pid']=float(os.getpid())")

    def test_ack_boolean_pid_rejected(self):
        self.assert_invalid_ack("ack['pid']=True")

    def test_ack_nonstring_case_rejected(self):
        self.assert_invalid_ack("ack['caseId']=1")

    def test_ack_nonstring_run_rejected(self):
        self.assert_invalid_ack("ack['runId']=1")

    def test_ack_extra_field_rejected(self):
        self.assert_invalid_ack("ack['extra']=1")

    def test_ack_duplicate_field_rejected(self):
        self.assert_invalid_ack(raw="json.dumps(ack)[:-1]+', \"version\": 1}'")

    def test_valid_ack_permit_and_both_streams(self):
        script = PREFIX + "os.write(3,(json.dumps({'version':1,'pid':os.getpid(),'caseId':sys.argv[-1],'runId':data['runId']})+'\\n').encode()); os.close(3); permit=b''; "
        script += "\nwhile True:\n chunk=os.read(4,64)\n if not chunk: break\n permit+=chunk\n"
        script += "assert permit==b'RID_NEWMAN_PERMIT_V1\\n'; os.write(1,b'OUT-after-permit'); os.write(2,b'ERR-after-permit')"
        result = self.run_client(script)
        self.assertEqual(result.returncode, 0)
        self.assertIn(b"OUT-after-permit", result.stdout)
        self.assertIn(b"ERR-after-permit", result.stderr)
        self.assertTrue(result.protocol_audit["ackValid"])
        self.assertTrue(result.protocol_audit["permitSent"])
        self.assertTrue(result.protocol_audit["stdoutEOF"])
        self.assertTrue(result.protocol_audit["stderrEOF"])
        self.assertEqual(result.protocol_audit["remainingFDs"], 0)

if __name__ == "__main__":
    unittest.main()
