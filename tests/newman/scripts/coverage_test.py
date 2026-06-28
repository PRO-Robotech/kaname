# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""Test coverage.py against synthetic proto + collection."""
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent
COVERAGE = HERE / "coverage.py"


def _write_proto(d: Path, content: str) -> Path:
    p = d / "test_service.proto"
    p.write_text(content)
    return p


def _write_collection(d: Path, items: list) -> Path:
    p = d / "test.postman_collection.json"
    p.write_text(json.dumps({"info": {"name": "test"}, "item": items}))
    return p


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(COVERAGE), *args],
        capture_output=True, text=True, timeout=30,
    )


def test_full_coverage_passes_min_100(tmp_path):
    proto_dir = tmp_path / "proto"; proto_dir.mkdir()
    _write_proto(proto_dir, """
syntax = "proto3";
package kacho.cloud.iam.v1;
service FooService {
  rpc Bar (BarRequest) returns (BarResponse);
}
""")
    col_dir = tmp_path / "collections"; col_dir.mkdir()
    _write_collection(col_dir, [
        {"name": "FOO-BAR-OK",
         "request": {"method": "POST", "url": {"raw": "{{baseUrl}}/iam/v1/foos:bar"}}}
    ])
    r = _run("--proto-glob", str(proto_dir / "*.proto"),
             "--collections-glob", str(col_dir / "*.json"),
             "--min", "100")
    assert r.returncode == 0, r.stderr
    assert "100%" in r.stdout


def test_partial_coverage_fails_min_100(tmp_path):
    proto_dir = tmp_path / "proto"; proto_dir.mkdir()
    _write_proto(proto_dir, """
syntax = "proto3";
package kacho.cloud.iam.v1;
service FooService {
  rpc Bar (BarRequest) returns (BarResponse);
  rpc Baz (BazRequest) returns (BazResponse);
}
""")
    col_dir = tmp_path / "collections"; col_dir.mkdir()
    _write_collection(col_dir, [])
    r = _run("--proto-glob", str(proto_dir / "*.proto"),
             "--collections-glob", str(col_dir / "*.json"),
             "--min", "100")
    assert r.returncode != 0
    assert "0%" in r.stdout or "0 of 2" in r.stdout


def test_http_annotation_overrides_heuristic(tmp_path):
    """The proto's google.api.http annotation is the authoritative URL mapping."""
    proto_dir = tmp_path / "proto"; proto_dir.mkdir()
    _write_proto(proto_dir, """
syntax = "proto3";
package kacho.cloud.iam.v1;
import "google/api/annotations.proto";
service AccountService {
  rpc Create (CreateAccountRequest) returns (Operation) {
    option (google.api.http) = {
      post: "/iam/v1/accounts"
      body: "*"
    };
  }
}
""")
    col_dir = tmp_path / "collections"; col_dir.mkdir()
    _write_collection(col_dir, [
        {"name": "ACC-CR-OK",
         "request": {"method": "POST", "url": {"raw": "{{baseUrl}}/iam/v1/accounts"}}}
    ])
    r = _run("--proto-glob", str(proto_dir / "*.proto"),
             "--collections-glob", str(col_dir / "*.json"),
             "--min", "100")
    assert r.returncode == 0, r.stderr
    assert "100%" in r.stdout


def test_path_param_template_matches_concrete_url(tmp_path):
    """`/iam/v1/accounts/{account_id}` template matches a concrete `…/accounts/abc-123`."""
    proto_dir = tmp_path / "proto"; proto_dir.mkdir()
    _write_proto(proto_dir, """
syntax = "proto3";
package kacho.cloud.iam.v1;
import "google/api/annotations.proto";
service AccountService {
  rpc Get (GetAccountRequest) returns (Account) {
    option (google.api.http) = { get: "/iam/v1/accounts/{account_id}" };
  }
}
""")
    col_dir = tmp_path / "collections"; col_dir.mkdir()
    _write_collection(col_dir, [
        {"name": "ACC-GT-OK",
         "request": {"method": "GET", "url": {"raw": "{{baseUrl}}/iam/v1/accounts/acc-abc123"}}}
    ])
    r = _run("--proto-glob", str(proto_dir / "*.proto"),
             "--collections-glob", str(col_dir / "*.json"),
             "--min", "100")
    assert r.returncode == 0, r.stderr


def test_commented_out_rpc_not_counted(tmp_path):
    """// rpc Foo (...) returns (...); inside a service body must NOT be counted."""
    proto_dir = tmp_path / "proto"
    proto_dir.mkdir()
    _write_proto(proto_dir, """
syntax = "proto3";
package kacho.cloud.iam.v1;
service FooService {
  // rpc CommentedOut (X) returns (Y);
  /* rpc AlsoCommented (X) returns (Y); */
  rpc Real (Req) returns (Resp);
}
// service WholeServiceCommented { rpc Foo (X) returns (Y); }
""")
    col_dir = tmp_path / "collections"
    col_dir.mkdir()
    _write_collection(col_dir, [
        {"name": "FOO-REAL-OK",
         "request": {"method": "POST", "url": {"raw": "{{baseUrl}}/iam/v1/foos:real"}}}
    ])
    r = _run("--proto-glob", str(proto_dir / "*.proto"),
             "--collections-glob", str(col_dir / "*.json"),
             "--min", "100")
    # If commented RPCs were counted, this would be 1 of 3 (or 1 of 4) and fail --min 100.
    assert r.returncode == 0, r.stderr
    assert "1 of 1" in r.stdout or "100%" in r.stdout
