#!/usr/bin/env python3
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Pure subprocess/pipe controls, never Kaname/API/public acceptance."""
import importlib.util
import json
import tempfile
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

class HostedDiffDiagnosticsControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location(
            "rid_hosted_driver", Path(__file__).resolve().parents[3] / ".github/scripts/run-rid-native.py")
        cls.hosted = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.hosted)

    def payload(self, rid):
        if rid == "03":
            return {"caseId": "registry-installation-rid03-S2-ROLE-DENIED-VERIFY",
                    "fields": ["operations", "raw"]}
        return {"missing": False, "columns": ["modified_at"], "beforeDone": "pending",
                "afterDone": "done", "kind": "service-account-key"}

    def diagnostics(self, rid, *, outputs=None, end="fail", source=None, before_run=False,
                    after_end=False, root_run=True, assertion=True, scan_suffix="", unknown=False):
        h = self.hosted
        root, predicates, _ = h.CASES["registry-installation-rid" + rid]
        leaf = root + "/" + sorted(h.RID_MATRIX_NESTED[root])[0]
        if unknown:
            leaf += "/unknown"
        kind = "RID03_READ_ONLY_DIFF" if rid == "03" else "RID05_OLD_OPERATION_DIFF"
        expected_source = h.DIFF_MARKER_SOURCES[kind]
        source = source or expected_source
        outputs = outputs if outputs is not None else [json.dumps(self.payload(rid))]
        marker_outputs = ["    " + Path(source).name + ":1: " + kind + " " + value + "\n"
                          for value in outputs]
        rows = []
        def add(action, name, output=None):
            row = {"Package": h.PACKAGE, "Test": name, "Action": action}
            if output is not None:
                row["Output"] = output
            rows.append(json.dumps(row) + "\n")
        if root_run:
            add("run", root)
        if before_run:
            for output in marker_outputs:
                add("output", leaf, output)
        add("run", leaf)
        if not before_run and not after_end:
            for output in marker_outputs:
                add("output", leaf, output)
        if assertion:
            add("output", leaf, "    Error Trace: " + str(h.ROOT / expected_source) + ":1\n")
        add(end, leaf)
        if after_end:
            for output in marker_outputs:
                add("output", leaf, output)
        add(end, root)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_text("".join(rows) + scan_suffix)
            return h.test_diagnostics(path, root, predicates), leaf

    def diagnose_role_markers(self, suite, outputs, *, trace, case=None, end="fail", active=True, suffix=""):
        h = self.hosted
        root, predicates, _ = h.CASES[suite]
        leaf = root + "/" + (case if case is not None else sorted(h.RID_MATRIX_NESTED[root])[0])
        rows = [{"Action": "run", "Test": root}]
        if active:
            rows.append({"Action": "run", "Test": leaf})
        rows += [{"Action": "output", "Test": leaf, "Output": value} for value in outputs]
        rows += [{"Action": "output", "Test": leaf, "Output": "    Error Trace: " + str(h.ROOT / trace) + ":1\n"},
                 {"Action": end, "Test": leaf}, {"Action": end, "Test": root}]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_text("".join(json.dumps(dict(row, Package=h.PACKAGE)) + "\n" for row in rows) + suffix)
            return h.test_diagnostics(path, root, predicates, timeout_seconds=1200)

    def check_role_readiness_marker(self, suite):
        source = "cmd/kaname/installation_whole_delivery_native_test.go"
        good = "    installation_whole_delivery_native_test.go:1: RID_ROLE_READINESS reason=deadline verbs=ready refs=failed\n"
        def diagnose(outputs, *, trace=source, **options):
            return self.diagnose_role_markers(suite, outputs, trace=trace, **options)
        for phase in ("initial-delivery", "restored-base", "unspecified"):
            with self.subTest(phase=phase):
                observed = diagnose([good.rstrip() + " phase=" + phase + "\n"])
                self.assertEqual(observed["roleReadiness"]["phase"], phase)
        self.assertEqual(diagnose([good])["roleReadiness"],
                         {"reason": "deadline", "verbs": "ready", "refs": "failed"})
        variants = [([good, good], {}), ([good.replace("deadline", "unit-secret")], {}),
                    ([good.replace("refs=failed", "refs=unit-secret")], {}),
                    ([good.rstrip() + " phase=unit-secret\n"], {}),
                    ([good.rstrip() + " secret=unit-secret\n"], {}),
                    ([good + "unit-secret\n"], {}), ([good], {"end": "pass"}),
                    ([good], {"end": "skip"}), ([good], {"active": False}),
                    ([good], {"trace": "cmd/kaname/installation_native_fixture_test.go"}),
                    ([good], {"suffix": "invalid-json"})]
        for outputs, options in variants:
            with self.subTest(outputs=outputs, options=options):
                result = diagnose(outputs, **options)
                self.assertNotIn("roleReadiness", result)
                self.assertNotIn("unit-secret", json.dumps(result))

    def test_failed_verb_census_keeps_closed_fields_and_consistent_counts(self):
        source = "cmd/kaname/installation_whole_delivery_native_test.go"
        record = ("    installation_whole_delivery_native_test.go:1: RID_ROLE_READINESS reason=deadline"
                  " verbs=failed refs=ready phase=initial-delivery examined=9 reseeded=7 failed=2"
                  " completed=true stage=replace-verbs class=deadlock\n")
        def diagnose(outputs):
            return self.diagnose_role_markers("registry-installation-rid11", outputs, trace=source)
        self.assertEqual(diagnose([record])["roleReadiness"]["verbCensus"], {
            "examined": 9, "reseeded": 7, "failed": 2, "completed": True,
            "firstFailureStage": "replace-verbs", "firstFailureClass": "deadlock"})
        partial = record.replace("examined=9", "examined=10").replace("completed=true", "completed=false")
        self.assertFalse(diagnose([partial])["roleReadiness"]["verbCensus"]["completed"])
        for before, after in (("examined=9", "examined=8"), ("examined=9", "examined=10"),
                              ("examined=9", "examined=1000000"), ("failed=2", "failed=0"),
                              ("verbs=failed", "verbs=ready"), ("replace-verbs", "fixture-secret"),
                              ("deadlock", "fixture-secret")):
            result = diagnose([record.replace(before, after)])
            self.assertNotIn("roleReadiness", result)
            self.assertNotIn("fixture-secret", json.dumps(result))
        self.assertNotIn("roleReadiness", diagnose([record, record]))
        for stage, cause in (("open-begin", "connection-open"), ("open-enter-v2", "sql-lock-unavailable"),
                             ("open-enter-v3", "sql-query-canceled"), ("open-abi-mismatch", "semantic-identity"),
                             ("open-input", "invalid-fence"), ("open-context", "Canceled"),
                             ("open-confirm-publication", "source-unconfirmed"),
                             ("open-confirm-publication", "sql-undefined-table")):
            with self.subTest(stage=stage, cause=cause):
                classified = record.replace("replace-verbs", stage).replace("deadlock", cause)
                census = diagnose([classified])["roleReadiness"]["verbCensus"]
                self.assertEqual((census["firstFailureStage"], census["firstFailureClass"]), (stage, cause))
        canceled = record.replace("stage=replace-verbs class=deadlock", "stage=open-enter-v2 class=sql-query-canceled").rstrip("\n")
        for reason, ctx, site in (("statement-timeout", "active", "global-coordinator"),
                                  ("user-request", "deadline", "consumer-admission"),
                                  ("other", "canceled", "unclassified")):
            with self.subTest(reason=reason, ctx=ctx, site=site):
                marker = f"{canceled} cancel={reason} context={ctx} site={site}\n"
                census = diagnose([marker])["roleReadiness"]["verbCensus"]
                self.assertEqual(census["firstFailureClass"], "sql-query-canceled")
                self.assertEqual(census["firstQueryCancel"], {"reason": reason, "context": ctx, "site": site})
        marker = canceled + " cancel=other context=active site=unclassified\n"
        for original, invalid in (("open-enter-v2", "commit"), ("sql-query-canceled", "deadlock"),
                                  ("cancel=other", "cancel=fixture-secret"), ("context=active", "context=fixture-secret"),
                                  ("site=unclassified", "site=fixture-secret"), (" context=active", "")):
            observed = diagnose([marker.replace(original, invalid)])
            self.assertNotIn("roleReadiness", observed)
            self.assertNotIn("fixture-secret", json.dumps(observed))
        open_record = record.replace("replace-verbs", "open-enter-v3")
        for unsafe_class in ("57014", "sql-secret-detail", "sql-query-canceled secret=value"):
            result = diagnose([open_record.replace("deadlock", unsafe_class)])
            self.assertNotIn("roleReadiness", result)
            self.assertNotIn(unsafe_class, json.dumps(result))

    def test_consumer_admission_observation_is_closed_and_matches_exact_failure(self):
        source = "cmd/kaname/installation_whole_delivery_native_test.go"
        prefix = (
            "    installation_whole_delivery_native_test.go:1: RID_ROLE_READINESS reason=deadline"
            " verbs=failed refs=ready phase=initial-delivery examined=56 reseeded=54 failed=2"
            " completed=true stage=open-enter-v2 class=sql-query-canceled"
            " cancel=statement-timeout context=active site=consumer-admission"
        )

        def diagnose(marker, **options):
            return self.diagnose_role_markers("registry-installation-rid11", [marker + "\n"], trace=source, **options)

        valid = prefix + " blocker=fixture waits=1 transaction-age=30s-to-60s"
        cases = (
            "every_accepted_result-table_input_authn_authority_backend_row_on_absent_and_ACTIVE_pair/census/S2/ACTIVE/negative",
            "each_fact-only_legal_twin_succeeds_and_converges;_missing_S1_A_before_writes/revoked-key/S1/ACTIVE/lawful-control",
        )
        for case in cases:
            with self.subTest(case=case):
                self.assertEqual(diagnose(valid, case=case)["roleReadiness"]["consumerAdmission"],
                                 {"blocker": "fixture", "waits": 1, "transactionAge": "30s-to-60s"})
                self.assertNotIn("roleReadiness", diagnose(valid, case=case, end="pass"))
        empty = prefix + " blocker=unknown waits=0 transaction-age=unknown"
        self.assertEqual(diagnose(empty)["roleReadiness"]["consumerAdmission"],
                         {"blocker": "unknown", "waits": 0, "transactionAge": "unknown"})
        self.assertNotIn("consumerAdmission", diagnose(prefix)["roleReadiness"])

        invalid = (
            ("blocker=fixture", "blocker=fixture-secret"),
            ("waits=1", "waits=65"),
            ("waits=1", "waits=0"),
            ("transaction-age=30s-to-60s", "transaction-age=fixture-secret"),
            ("phase=initial-delivery", "phase=restored-base"),
            ("stage=open-enter-v2", "stage=open-enter-v3"),
            ("cancel=statement-timeout", "cancel=user-request"),
            ("context=active", "context=deadline"),
            ("site=consumer-admission", "site=global-coordinator"),
        )
        for before, after in invalid:
            with self.subTest(before=before):
                observed = diagnose(valid.replace(before, after))
                self.assertNotIn("roleReadiness", observed)
                self.assertNotIn("fixture-secret", json.dumps(observed))

    def test_role_delta_on_matched_roles_projection_rejects_other_content(self):
        source = "cmd/kaname/installation_newman_retirement_test.go"
        prefix = "    installation_newman_whole_projection_test.go:1: "
        projection = prefix + ("RID_PROJECTION accounts=false service_accounts=false groups=false members=false "
                               "roles=true bindings=false delegations=false catalog=false materialization=false\n")
        delta = prefix + "RID_ROLE_DELTA fields=health,rule_states,updated_at\n"
        def diagnose(outputs, **options):
            return self.diagnose_role_markers("registry-installation-rid06", outputs, trace=source, **options)
        result = diagnose([projection, delta])
        self.assertEqual(result["changedProjectionFields"], ["roles"])
        self.assertEqual(result["changedRoleFields"], ["health", "rule_states", "updated_at"])
        for outputs in ([delta], [projection, delta, delta], [projection, delta.replace("health", "unit-secret")],
                        [projection, delta.replace("health", "updated_at")],
                        [projection.replace("roles=true", "roles=false"), delta]):
            result = diagnose(outputs)
            self.assertNotIn("changedRoleFields", result)
            self.assertNotIn("unit-secret", json.dumps(result))

    def test_role_readiness_keeps_only_closed_active_first_failure_marker(self):
        for suite in ("registry-installation-rid07", "registry-installation-rid11"):
            with self.subTest(suite=suite):
                self.check_role_readiness_marker(suite)

    def test_valid_red_markers_keep_only_safe_schema(self):
        for rid, field in (("03", "readOnlyDiffs"), ("05", "oldOperationDiffs")):
            with self.subTest(rid=rid):
                result, leaf = self.diagnostics(rid)
                self.assertEqual(result[field], [{"test": leaf, "diffs": [self.payload(rid)]}])

    def test_non_red_or_inactive_or_unrecognized_markers_are_omitted(self):
        variants = ({"end": "pass"}, {"end": "skip"}, {"before_run": True},
                    {"after_end": True}, {"root_run": False}, {"assertion": False},
                    {"unknown": True}, {"scan_suffix": "invalid-json"},
                    {"source": "cmd/kaname/installation_native_fixture_test.go"})
        for rid, field in (("03", "readOnlyDiffs"), ("05", "oldOperationDiffs")):
            for variant in variants:
                with self.subTest(rid=rid, variant=variant):
                    result, _ = self.diagnostics(rid, **variant)
                    self.assertNotIn(field, result)

    def test_duplicate_malformed_and_overflow_invalidate_leaf(self):
        for rid, field in (("03", "readOnlyDiffs"), ("05", "oldOperationDiffs")):
            good = json.dumps(self.payload(rid))
            for outputs in ([good, good], [good, "{}"], ["{}", good],
                            [good, good.replace("{", '{"extra":"secret",', 1)],
                            [good] * (self.hosted.RID03_OPERATION_MARKER_LIMIT + 1)):
                with self.subTest(rid=rid, outputs=outputs):
                    result, _ = self.diagnostics(rid, outputs=outputs)
                    self.assertNotIn(field, result)
                    self.assertNotIn("secret", json.dumps(result))

    def test_read_only_parser_rejects_unbounded_or_noncanonical_values(self):
        h = self.hosted
        good = self.payload("03")
        invalid = [dict(good, caseId="registry-installation-rid03-S3-ROLE-DENIED-VERIFY"),
                   dict(good, caseId="registry-installation-rid03-S2-UNKNOWN-VERIFY"),
                   dict(good, fields=[]), dict(good, fields=["raw", "operations"]),
                   dict(good, fields=["raw", "raw"]), dict(good, fields=["secret"]),
                   dict(good, fields=[{}]), dict(good, extra="secret")]
        prefix = "    installation_newman_delegated_grant_test.go:1: RID03_READ_ONLY_DIFF "
        for value in invalid:
            with self.subTest(value=value):
                self.assertIsNone(h.rid03_read_only_diff(prefix + json.dumps(value) + "\n", 1))
        raw = json.dumps(good)
        for output, limit in ((prefix + raw + "\n", 0), (prefix + raw, 1),
                              (prefix + raw + "\nextra\n", 1),
                              (prefix + raw.replace("{", '{"fields":[],', 1) + "\n", 1),
                              (prefix + " " * 2048 + raw + "\n", 1)):
            self.assertIsNone(h.rid03_read_only_diff(output, limit))

    def test_rid05_reuses_strict_old_operation_schema(self):
        h = self.hosted
        good = self.payload("05")
        prefix = "    installation_newman_deletion_delta_test.go:1: RID05_OLD_OPERATION_DIFF "
        for value in (dict(good, columns=["secret"]), dict(good, missing=1),
                      dict(good, beforeDone="secret"), dict(good, kind="secret"),
                      dict(good, columns=["modified_at", "modified_at"])):
            self.assertIsNone(h.rid03_old_operation_diff(
                prefix + json.dumps(value) + "\n", 1, marker="RID05_OLD_OPERATION_DIFF"))
        duplicate = json.dumps(good).replace("{", '{"missing":true,', 1)
        self.assertIsNone(h.rid03_old_operation_diff(
            prefix + duplicate + "\n", 1, marker="RID05_OLD_OPERATION_DIFF"))

    def test_original_rid03_old_operation_parser_is_preserved(self):
        h = self.hosted
        value = self.payload("05")
        output = "    installation_newman_delegated_grant_test.go:1: RID03_OLD_OPERATION_DIFF "
        self.assertEqual(h.rid03_old_operation_diff(output + json.dumps(value) + "\n", 1), value)

if __name__ == "__main__":
    unittest.main()
