#!/usr/bin/env python3
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Bounded real-Newman CLIENT premise, not Kaname/RID product acceptance.

Uses the real source generator, a local HTTPS endpoint with client certificates,
six phase reports and the actual collector/coverage judge. Synthetic identities
are deliberately not Kaname IDs. A rejected response echoes the fake bearer to
prove failure-message sanitization. No native RID count may be incremented here.
"""
import copy
import hashlib
import importlib.util
import json
import os
import ssl
import subprocess
import sys
import tempfile
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


HERE = Path(__file__).resolve().parent
SUITE = HERE.parent
STEM = "registry-installation-rid08"
PHASES = [
    ("FIRST-N3", "first-n3", 3, 5, 0),
    ("REPEAT-N4", "repeat-n4", 4, 5, 6),
    ("EMPTY-N0", "empty-n0", 0, 1, 0),
    ("LATE-FAULT-N0", "late-fault-n0", 0, 4, 0),
    ("FAULT-TWIN-N3", "fault-twin-n3", 3, 4, 0),
    ("RETRY-N3", "retry-n3", 3, 4, 6),
]


class PremiseFailure(Exception):
    pass


def check(value, message):
    if not value:
        raise PremiseFailure(message)


def expected(phase, n, count, previous):
    system = "fixture-SYS"
    tenants = ["fixture-A", "fixture-B", "fixture-system-tenant", "fixture-D"]
    accounts = sorted([system] + tenants[:count - 1])
    delegated = sorted(tenants[:n])
    sas = [{"id": i, "accountId": system, "name": name, "createdAt": "2000-01-01T00:00:00Z"}
           for i, name in [("fixture-stock-1", "stock1"), ("fixture-stock-2", "stock2"),
                           ("fixture-C", "creator"), ("fixture-I-first", "svc-ridfirst"),
                           ("fixture-I-second", "svc-ridsecond")]]
    ds = []
    for account in delegated:
        for module, suffix in [("ridfirst", "first"), ("ridsecond", "second")]:
            ds.append({"id": account + "-" + module, "accountId": account, "module": module,
                       "status": "ACTIVE", "createdAt": "2000-01-01T00:00:00Z",
                       "delegate": {"type": "SUBJECT_TYPE_SERVICE_ACCOUNT", "id": "fixture-I-" + suffix},
                       "delegatedBy": {"type": "service_account", "id": "fixture-C"},
                       "roleIds": ["fixture-role-" + module], "targetTypes": [module + ".objects"],
                       "subjectTypes": ["SUBJECT_TYPE_SERVICE_ACCOUNT"]})
    # Current first six rows in repeat are the exact first-N3 rows.
    old = [x for x in ds if x["accountId"] != "fixture-D"] if previous else []
    return {"phase": phase, "operatorId": "fixture-O", "creatorId": "fixture-C", "systemId": system,
            "accounts": accounts, "delegatedAccounts": delegated, "serviceAccounts": sas,
            "delegations": ds, "previousDelegations": old, "tenantNamedSystem": "fixture-system-tenant",
            "futureAccountId": "fixture-D"}


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def tool_tree(root):
    # Same bounded canonical record manifest as the Go parent and JS runner.
    root = root.resolve(strict=True)
    entries, files, total = [], 0, 0
    def visit(directory, depth):
        nonlocal files, total
        check(depth <= 128, "tool tree depth bound")
        with os.scandir(directory) as scan:
            for item in scan:
                check(len(entries) < 32768, "tool tree entry bound")
                absolute = Path(item.path)
                relative = absolute.relative_to(root).as_posix()
                check(len(relative) <= 4096 and all(32 <= ord(c) <= 126 for c in relative), "tool path alphabet")
                stat = item.stat(follow_symlinks=False)
                mode = format(stat.st_mode & 0o777, "03o")
                if item.is_symlink():
                    target = absolute.resolve(strict=True)
                    check(target.is_relative_to(root), "tool symlink escape")
                    value = target.relative_to(root).as_posix()
                    check(all(32 <= ord(c) <= 126 for c in value), "tool symlink alphabet")
                    kind = "S"
                elif item.is_dir(follow_symlinks=False):
                    kind, value = "D", "-"
                elif item.is_file(follow_symlinks=False):
                    total += stat.st_size
                    check(stat.st_size <= 32 * 1048576 and total <= 256 * 1048576, "tool bytes bound")
                    digest, seen = hashlib.sha256(), 0
                    with absolute.open("rb") as source:
                        while chunk := source.read(65536):
                            seen += len(chunk)
                            check(seen <= 32 * 1048576, "tool file bound")
                            digest.update(chunk)
                    check(seen == stat.st_size, "tool file changed")
                    kind, value = "F", digest.hexdigest()
                    files += 1
                else:
                    raise PremiseFailure("tool special file")
                entries.append(kind + "\t" + relative + "\t" + mode + "\t" + value + "\n")
                if kind == "D":
                    visit(absolute, depth + 1)
    visit(root, 0)
    check(files > 0, "tool tree empty")
    return hashlib.sha256("".join(sorted(entries)).encode("ascii")).hexdigest()


def main():
    node = Path(os.environ.get("KANAME_RID_NODE_BINARY", ""))
    package = Path(os.environ.get("KANAME_RID_NEWMAN_MODULE", ""))
    check(node.is_absolute() and node.is_file() and package.is_absolute() and package.is_dir(),
          "explicit actual Newman tool prerequisite missing")
    # In an overlay, locate the real binding in the enclosing authoritative repo.
    root = next((p for p in HERE.parents if (p / "cmd/kaname/installation_delegations.go").is_file()), None)
    check(root is not None, "repository binding unavailable")
    sys.path.insert(0, str(root / "tests/newman/scripts"))
    import gen
    import gen_shared
    cases = gen._RUN.load(SUITE / "cases" / (STEM + ".py")).CASES
    collection = gen_shared.build_collection(gen._EMIT, STEM, cases)
    collector = load_module("rid_client_premise_collector", HERE / "collect-rid-native.py")
    with tempfile.TemporaryDirectory(prefix="kaname-rid-client-premise-") as tmp:
        out = Path(tmp)
        collection_path = out / (STEM + ".postman_collection.json")
        collection_path.write_text(json.dumps(collection, ensure_ascii=False, indent=2) + "\n")
        cert, key = out / "ca.crt", out / "ca.key"
        minted = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                                "-keyout", str(key), "-out", str(cert), "-days", "1",
                                "-subj", "/CN=localhost", "-addext", "basicConstraints=critical,CA:TRUE",
                                "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
                               capture_output=True, timeout=15)
        check(minted.returncode == 0, "private premise PKI unavailable")
        key.chmod(0o600)
        secret = "fixture-client-token-" + uuid.uuid4().hex
        state = {"expected": None, "bad": False, "badGet": False, "answered": 0, "authFailures": 0}
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass
            def do_GET(self):
                if self.headers.get("Authorization") != "Bearer " + secret:
                    state["authFailures"] += 1
                    self.send(401, {"code": 16, "message": "invalid client"})
                    return
                e = state["expected"]
                u = urlsplit(self.path)
                qs = parse_qs(u.query, keep_blank_values=True)
                if u.path == "/iam/v1/me":
                    self.send(200, {"subject": "user:" + e["operatorId"],
                                    "userId": secret if state["bad"] else e["operatorId"]})
                elif u.path == "/iam/v1/accounts":
                    self.page("accounts", [{"id": a} for a in e["accounts"]], qs)
                elif u.path == "/iam/v1/serviceAccounts":
                    self.page("serviceAccounts", e["serviceAccounts"], qs)
                elif u.path.startswith("/iam/v1/serviceAccounts/"):
                    selected = [a for a in e["serviceAccounts"] if a["id"] == u.path.rsplit("/", 1)[1]]
                    body = copy.deepcopy(selected[0]) if selected else {"code": 5}
                    if selected and state["badGet"]:
                        body["name"] = "Get-only-corrupt-name"
                    self.send(200 if selected else 404, body)
                elif u.path == "/iam/v1/grantDelegations":
                    account = qs.get("accountId", [""])[0]
                    self.page("grantDelegations", [d for d in e["delegations"] if d["accountId"] == account], qs)
                elif u.path.startswith("/iam/v1/grantDelegations/"):
                    selected = [d for d in e["delegations"] if d["id"] == u.path.rsplit("/", 1)[1]]
                    self.send(200 if selected else 404, selected[0] if selected else {"code": 5})
                elif u.path == "/iam/v1/accounts/fixture-deleted-A":
                    self.send(404, {"code": 5, "message": "not found"})
                else:
                    self.send(404, {"code": 5})
            def page(self, field, rows, qs):
                check(qs.get("pageSize") == ["2"], "premise requires actual pageSize2")
                offset = int(qs.get("pageToken", ["0"])[0] or "0")
                body = {field: rows[offset:offset + 2]}
                if offset + 2 < len(rows):
                    body["nextPageToken"] = str(offset + 2)
                self.send(200, body)
            def send(self, code, data):
                raw = json.dumps(data).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
                state["answered"] += 1
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
        tls.load_verify_locations(cert)
        tls.verify_mode = ssl.CERT_REQUIRED
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        run_id = "client-premise-" + uuid.uuid4().hex
        executable_sha = hashlib.sha256(b"CLIENT PREMISE ONLY; no Kaname executable").hexdigest()
        identities = {"nodeSHA256": hashlib.sha256(node.read_bytes()).hexdigest(),
                      "runnerSHA256": hashlib.sha256((HERE / "run-rid-native.cjs").read_bytes()).hexdigest(),
                      "toolTreeSHA256": tool_tree(package),
                      "collectionSHA256": hashlib.sha256(collection_path.read_bytes()).hexdigest(),
                      "testExecutableSHA256": executable_sha}
        reports = []
        origin = "https://localhost:" + str(server.server_port)
        def run(case_id, e, name, good=True):
            state["expected"] = e
            payload = {"ownRestBaseUrl": origin, "variables": {"rid08Expected": e,
                       "ridSystemId": e["systemId"], "ridDeletedAccountId": "fixture-deleted-A",
                       "jwtRIDOperator": secret}, "runId": run_id, "testExecutableSHA256": executable_sha, "expectedIdentities": identities}
            proc = subprocess.run([str(node), str(HERE / "run-rid-native.cjs"), str(collection_path),
                                   str(package), str(cert), str(cert), str(key), case_id],
                                  input=json.dumps(payload).encode(), capture_output=True, timeout=100,
                                  env={"HOME": str(out), "PATH": str(node.parent) + ":/usr/bin:/bin",
                                       "NODE_OPTIONS": "--max-old-space-size=256", "NO_PROXY": "localhost,127.0.0.1"})
            for material in (secret.encode(), key.read_bytes(), b"-----BEGIN PRIVATE KEY-----"):
                check(material not in proc.stdout + proc.stderr, "client output leaked private material")
            doc = json.loads(proc.stdout)
            check((proc.returncode == 0 and doc.get("ok") is True) == good,
                  "actual client verdict differs from expected premise")
            check(not proc.stderr, "unexpected client stderr")
            path = out / name
            path.write_bytes(proc.stdout)
            return path, doc
        try:
            for cid, phase, n, count, old in PHASES:
                path, _ = run(STEM + "-" + cid, expected(phase, n, count, old), cid + ".json")
                reports.append(path)
            merged = collector.combine(collection_path, reports, run_id, executable_sha, identities)
            check(len(merged["sources"]) == 6, "complete six-phase premise not observed")
            report_dir = out / "reports"
            report_dir.mkdir()
            (report_dir / (STEM + ".json")).write_text(json.dumps(merged))
            judged = subprocess.run([sys.executable, str(root / "tests/newman/scripts/exec-coverage.py"),
                                     "--collections-glob", str(collection_path), "--out-dir", str(report_dir)],
                                    capture_output=True, timeout=30)
            check(judged.returncode == 0, "actual shared coverage judge rejected complete report")
            rejected = 0
            for mutate in ("missing-phase", "different-invocation", "different-executable", "different-collection", "different-node", "different-runner", "different-tree", "one-phase-tool-drift"):
                args = [collection_path, reports, run_id, executable_sha, copy.deepcopy(identities)]
                if mutate == "missing-phase": args[1] = reports[:-1]
                elif mutate == "different-invocation": args[2] = "client-premise-" + uuid.uuid4().hex
                elif mutate == "different-executable": args[3] = "0" * 64
                elif mutate == "one-phase-tool-drift":
                    changed = out / "one-phase-tool-drift.json"
                    doc = json.loads(reports[0].read_bytes())
                    doc["toolTreeSHA256"] = "0" * 64
                    changed.write_text(json.dumps(doc))
                    args[1] = [changed] + reports[1:]
                elif mutate.startswith("different-") and mutate.split("-")[1] in ("node", "runner", "tree"):
                    identity_key = {"node": "nodeSHA256", "runner": "runnerSHA256", "tree": "toolTreeSHA256"}[mutate.split("-")[1]]
                    args[4][identity_key] = "0" * 64
                else:
                    drift = copy.deepcopy(collection)
                    drift["item"][0]["item"][0]["name"] += "-drift"
                    changed = out / "drift" / collection_path.name
                    changed.parent.mkdir()
                    changed.write_text(json.dumps(drift))
                    args[0] = changed
                try:
                    collector.combine(*args)
                except collector.InvalidEvidence:
                    rejected += 1
                else:
                    raise AssertionError("collector accepted incompatible actual phase evidence")
            state["bad"] = True
            _, bad = run(STEM + "-FIRST-N3", expected("first-n3", 3, 5, 0), "failed.json", good=False)
            check(bad["counts"]["failed"] > 0, "negative client premise never failed an assertion")
            state["bad"] = False
            state["badGet"] = True
            _, bad_get = run(STEM + "-FIRST-N3", expected("first-n3", 3, 5, 0), "failed-SA-Get-only.json", good=False)
            check(bad_get["counts"]["failed"] > 0, "correct List/corrupt SA Get was accepted")
            check(tool_tree(package) == identities["toolTreeSHA256"], "premise tool tree changed")
            check(state["answered"] > 0 and state["authFailures"] == 0, "HTTPS/auth request premise missing")
            print(json.dumps({"kind": "CLIENT_PREMISE_ONLY_NOT_KANAME_ACCEPTANCE", "ok": True,
                              "phases": 6, "actualRequests": merged["run"]["stats"]["requests"]["total"],
                              "assertions": merged["run"]["stats"]["assertions"]["total"],
                              "collectorInjectionsRejected": rejected, "echoedBearerFailureSanitized": True, "correctListCorruptSAGetRejected": True,
                              "nativeRIDAcceptedIncrement": 0}))
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=3)
            check(not worker.is_alive(), "premise server did not stop")


if __name__ == "__main__":
    try:
        main()
    except (PremiseFailure, AssertionError, ValueError, OSError, subprocess.SubprocessError) as exc:
        # Never print arbitrary mock response/runner errors or private material.
        print(json.dumps({"kind": "CLIENT_PREMISE_ONLY_NOT_KANAME_ACCEPTANCE", "ok": False,
                          "failure": str(exc) if isinstance(exc, PremiseFailure) else "client-generation-execution-collector-or-redaction-premise"}))
        sys.exit(1)
