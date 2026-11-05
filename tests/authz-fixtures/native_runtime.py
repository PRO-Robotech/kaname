#!/usr/bin/env python3
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Native process holder for the existing own-stand public delegation fixture.

Called only inside the leased bounded job. PostgreSQL ownership/TLS setup belongs
to the Go integration holder. No SQL seeding, consumer, Docker service, build,
policy override or identity injection is performed here. Logs stay private.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import ssl
import subprocess
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
PORTS = (9090, 9091, 9095, 9096, 9097, 9098, 9099, 9100)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--evidence", type=Path, required=True)
    ap.add_argument("--pg-port", type=int, required=True)
    ap.add_argument("--binary", type=Path, required=True)
    ap.add_argument("--migrator", type=Path, required=True)
    args = ap.parse_args()
    os.umask(0o077)
    evidence = args.evidence.resolve()
    pki = evidence / "pki"
    mode = os.environ.get("KANAME_NATIVE_MODE", "base")
    if mode not in {"base", "public-matrix"}:
        raise ValueError("unknown native acceptance mode")
    env = {key: os.environ[key] for key in ("HOME", "PATH", "GOMAXPROCS", "GOMEMLIMIT") if key in os.environ}
    env.update(json.loads((evidence / "run/native-environment.json").read_text()))
    env["KANAME_DB_PORT"] = str(args.pg_port)
    for key, port in {
        "ENDPOINT": 9090, "INTERNAL_ENDPOINT": 9091, "METRICS_ENDPOINT": 9095,
        "REGISTRY_TOKEN__ENDPOINT": 9096, "JWKS_PROXY__ENDPOINT": 9097,
        "REST_ENDPOINT": 9098, "INTERNAL_REST_ENDPOINT": 9099, "LOGIN_LANE_ENDPOINT": 9100,
    }.items():
        env["KANAME_API_SERVER__" + key] = f"tcp://127.0.0.1:{port}"
    # Явный пустой YAML и точное окружение стенда; унаследованной конфигурации нет.
    config = evidence / "config.yaml"
    config.write_text("{}\n")
    env["KANAME_CONFIG_PATH"] = str(config)
    processes = []
    files = []
    results = {"mode": mode, "steps": [], "ports": list(PORTS), "cleanup": []}
    results["binaries"] = {name: hashlib.sha256(path.read_bytes()).hexdigest()
                           for name, path in (("kaname", args.binary), ("migrator", args.migrator))}

    def start(name, command):
        log = (evidence / (name + ".log")).open("xb")
        files.append(log)
        proc = subprocess.Popen(command, cwd=ROOT, env=env, stdout=log,
                                stderr=subprocess.STDOUT, start_new_session=True)
        processes.append((name, proc))
        (evidence / "child-processes.json").write_text(json.dumps(
            [{"name": n, "pid": p.pid, "pgid": p.pid} for n, p in processes]) + "\n")
        return proc

    def step(name, command, timeout=120):
        done = start(name, command)
        try:
            done.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(done.pid, signal.SIGKILL)
            done.wait(timeout=5)
            raise RuntimeError(f"{name} timed out") from None
        results["steps"].append({"name": name, "rc": done.returncode})
        if done.returncode:
            raise RuntimeError(f"{name} failed with rc={done.returncode}; see private log")

    def alive():
        for name, proc in processes:
            if name in {"kaname", "mailbox"} and proc.poll() is not None:
                raise RuntimeError(f"{name} exited before readiness: {proc.returncode}")

    def wait_probe(probe):
        deadline = time.monotonic() + 60
        while True:
            alive()
            try:
                probe()
                return
            except (OSError, ValueError):
                if time.monotonic() >= deadline:
                    raise RuntimeError("native listener/application probe timed out") from None
                time.sleep(0.2)

    def owned_loopback_listeners(proc, expected):
        inodes = set()
        for fd in Path(f"/proc/{proc.pid}/fd").iterdir():
            try:
                target = fd.readlink().as_posix()
            except FileNotFoundError:
                continue
            if target.startswith("socket:["):
                inodes.add(target[8:-1])
        found = set()
        for family in ("tcp", "tcp6"):
            for line in Path(f"/proc/{proc.pid}/net/{family}").read_text().splitlines()[1:]:
                fields = line.split()
                if fields[3] != "0A" or fields[9] not in inodes:
                    continue
                address, port = fields[1].split(":")
                if family != "tcp" or address != "0100007F":
                    raise RuntimeError("owned native listener is not IPv4 loopback")
                found.add(int(port, 16))
        if found != set(expected):
            raise RuntimeError("native listener ownership/port census differs from the fixture")

    success = False
    owned_environment = None
    newman_started = False
    def stop_requested(signum, _frame):
        raise RuntimeError(f"native job cancelled by signal {signum}")
    signal.signal(signal.SIGTERM, stop_requested)
    signal.signal(signal.SIGINT, stop_requested)
    try:
        for port in (*PORTS, 14465, 18025):
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", port))
        step("migrate", [str(args.migrator), "up"])
        mailbox = start("mailbox", ["python3", str(ROOT / ".github/scripts/stand-mailbox.py"), "serve",
                          "--host", "127.0.0.1", "--smtp-port", "14465", "--http-port", "18025",
                          "--cert", str(pki / "srv.crt"), "--key", str(pki / "srv.key")])
        def mailbox_probe():
            with urllib.request.urlopen("http://127.0.0.1:18025/healthz", timeout=2) as response:
                if response.status != 200:
                    raise ValueError("mailbox not ready")
        wait_probe(mailbox_probe)
        owned_loopback_listeners(mailbox, {14465, 18025})
        service = start("kaname", [str(args.binary), "serve"])
        tls = ssl.create_default_context(cafile=str(pki / "ca.crt"))
        tls.load_cert_chain(pki / "srv.crt", pki / "srv.key")
        def listeners_probe():
            for port in PORTS:
                with socket.create_connection(("127.0.0.1", port), timeout=2) as conn:
                    with tls.wrap_socket(conn, server_hostname="localhost"):
                        pass
        wait_probe(listeners_probe)
        # Настоящий собственный публичный протокол приложения (не утверждение по PID/журналу запуска).
        def jwks_probe():
            with urllib.request.urlopen("https://localhost:9097/.well-known/kaname/jwks.json", context=tls, timeout=2) as response:
                doc = json.load(response)
                if response.status != 200 or not isinstance(doc.get("keys"), list) or not doc["keys"]:
                    raise ValueError("signing keys not published")
        wait_probe(jwks_probe)
        owned_loopback_listeners(service, PORTS)
        results["steps"].append({"name": "all-listeners-tls-and-jwks", "rc": 0})
        if mode == "public-matrix":
            for tool in ("newman", "grpcurl", "jq", "openssl"):
                if not shutil.which(tool, path=env["PATH"]):
                    raise RuntimeError(f"required existing tool unavailable: {tool}")
            owned_environment = ROOT / "tests/newman/environments/local.postman_environment.json"
            if owned_environment.exists():
                owned_environment = None
                raise RuntimeError("public matrix requires a fresh environment; existing file preserved")
            step("seed-own", ["python3", "tests/authz-fixtures/seed_own_stand.py", "--pki", str(pki)], timeout=240)
            step("seed-resource", ["python3", "tests/authz-fixtures/seed_registry_resource.py", "--pki", str(pki),
                                   "--ledger", str(evidence / "registry-intent.json")])
            # Эта матрица использует обычных машинных делегатов; слоты человеческой
            # церемонии относятся к своей отдельной волне приёмки.
            step("seed-delegates", ["python3", "tests/authz-fixtures/seed_delegation.py", "--pki", str(pki),
                                    "--ledger", str(evidence / "delegation-subjects.json")])
            step("remint-bootstrap", ["python3", "tests/authz-fixtures/seed_own_stand.py", "--remint-bootstrap", "--pki", str(pki)])
            newman_started = True
            step("newman", ["bash", "tests/newman/scripts/run.sh", "--service", "iam-grant-delegation",
                            "--ssl-client-cert", str(pki / "srv.crt"), "--ssl-client-key", str(pki / "srv.key"),
                            "--ssl-extra-ca-certs", str(pki / "ca.crt"),
                            "--internal-front-client-cert", str(pki / "edge.crt"),
                            "--internal-front-client-key", str(pki / "edge.key")], timeout=360)
            report = json.loads((ROOT / "tests/newman/out/iam-grant-delegation.json").read_text())
            run = report["run"]
            if run["failures"] or run["stats"]["assertions"]["failed"] or not run["stats"]["assertions"]["total"]:
                raise RuntimeError("Newman report has missing or failed assertions")
            executed = [item["item"]["name"] for item in run["executions"]]
            def request_names(items):
                return [name for item in items for name in
                        (request_names(item["item"]) if "item" in item else [item["name"]])]
            collection = json.loads((ROOT / "tests/newman/collections/iam-grant-delegation.postman_collection.json").read_text())
            expected = request_names(collection["item"])
            missing = sorted(set(expected) - set(executed))
            skipped = sum(bool(assertion.get("skipped")) for execution in run["executions"]
                          for assertion in execution.get("assertions", []))
            if missing or skipped:
                raise RuntimeError(f"public matrix incomplete: missing requests={len(missing)} skipped assertions={skipped}")
            for case in range(1, 6):
                if not any(name.startswith(f"IAM-GD-E{case}-") for name in executed):
                    raise RuntimeError(f"GD-E{case} was not executed")
            for case in ("IAM-GD-1011-GROUP-CONTAINS-DELEGATE-DENIED", "IAM-GD-1011-GROUP-WITHOUT-DELEGATE-ALLOWED"):
                if not any(name.startswith(case + " ::") and "-grant-group" in name for name in executed):
                    raise RuntimeError(case + " was not executed")
            results["newmanStats"] = run["stats"]
            results["newmanCoverage"] = {"expectedRequests": len(expected), "executedRequests": len(executed),
                                        "missingRequests": missing, "skippedAssertions": skipped}
        success = True
    finally:
        for name, proc in reversed(processes):
            forced = False
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    forced = True
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait(timeout=5)
            results["cleanup"].append({"name": name, "pid": proc.pid, "rc": proc.returncode, "forced": forced})
            if forced or (name == "kaname" and proc.returncode != 0):
                success = False
        for log in files:
            log.close()
        if newman_started and (ROOT / "tests/newman/out").exists():
            shutil.copytree(ROOT / "tests/newman/out", evidence / "newman")
        if owned_environment is not None and owned_environment.exists():
            shutil.copyfile(owned_environment, evidence / "private.postman_environment.json")
            owned_environment.unlink()
        results["success"] = success
        (evidence / "native-result.json").write_text(json.dumps(results, indent=2) + "\n")
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
