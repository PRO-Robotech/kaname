#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""
coverage.py — newman RPC→case-id coverage gate for kacho-iam.

Parses kacho-proto IAM .proto files for `service X { rpc Y(...) ... }` blocks
and their `option (google.api.http) = { <verb>: "<path>" … };` annotations,
then walks Postman collection JSON files in tests/newman/collections/ to compute
which proto RPCs have at least one matching newman case.

Output:
    Coverage: N of M RPCs (P%)
    Missing RPCs:
      - ServiceName.RpcName (METHOD /path/template)
      ...

Exit codes:
    0 — pct >= --min
    1 — pct <  --min
    2 — no RPCs discovered (likely bad --proto-glob)
"""
from __future__ import annotations

import argparse
import glob
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Proto parsing
# ---------------------------------------------------------------------------

# `service Foo {`  →  capture name + body up to matching `}` (depth-tracked manually).
_SERVICE_RE = re.compile(r"service\s+(\w+)\s*\{", re.MULTILINE)

# `rpc Name (Req) returns (Resp)` — header only; body is extracted with a depth-
# tracked, string-aware scanner because RPC bodies frequently contain `{` and `}`
# inside double-quoted URL templates (e.g. `get: "/iam/v1/accounts/{account_id}"`),
# which a naive regex would miscount.
_RPC_HEADER_RE = re.compile(
    r"rpc\s+(\w+)\s*\([^)]*\)\s*returns\s*\([^)]*\)\s*",
    re.MULTILINE | re.DOTALL,
)

# HTTP annotation: `<verb>: "<path>"` inside `(google.api.http)` block.
# We don't try to match the whole `option (google.api.http) = { ... }` envelope —
# instead, inside an RPC body block, we look for any `(get|post|put|patch|delete): "..."`.
_HTTP_RE = re.compile(
    r"(get|post|put|patch|delete)\s*:\s*\"([^\"]+)\"",
    re.IGNORECASE,
)

def _strip_proto_comments(text: str) -> str:
    """Strip // line comments and /* … */ block comments from .proto text."""
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    text = re.sub(r"//[^\n]*", "", text)
    return text


# A simple snake_case helper for plural derivation in the REST-path heuristic.
def _camel_to_snake(name: str) -> str:
    s = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s).lower()


def _pluralize(snake: str) -> str:
    # Trivial English pluralization: y→ies, s/x/z/ch/sh → +es, else +s.
    if snake.endswith("y") and not snake.endswith(("ay", "ey", "iy", "oy", "uy")):
        return snake[:-1] + "ies"
    if snake.endswith(("s", "x", "z")) or snake.endswith(("ch", "sh")):
        return snake + "es"
    return snake + "s"


def _service_resource(service_name: str) -> str:
    """
    AccountService → accounts
    NetworkInterfaceService → network_interfaces
    """
    # Strip trailing "Service".
    base = service_name
    if base.endswith("Service"):
        base = base[: -len("Service")]
    return _pluralize(_camel_to_snake(base))


def _heuristic_path(service_name: str, rpc_name: str) -> str:
    """Convention-based fallback when no google.api.http annotation is present."""
    return f"/iam/v1/{_service_resource(service_name)}:{_camel_to_snake(rpc_name)}"


class Rpc:
    __slots__ = ("service", "name", "method", "path", "template_re")

    def __init__(self, service: str, name: str, method: str, path: str):
        self.service = service
        self.name = name
        self.method = method.upper()
        self.path = path
        self.template_re = _path_to_regex(path)

    def fqn(self) -> str:
        return f"{self.service}.{self.name}"


def _path_to_regex(template: str) -> re.Pattern:
    """`/iam/v1/accounts/{account_id}` → ^/iam/v1/accounts/[^/]+$ ."""
    # Escape regex meta, then turn `\{name\}` (or `\{name=…\}`) into `[^/]+`.
    escaped = re.escape(template)
    # `re.escape` turns `{` → `\{`, `}` → `\}` (or leaves `{`/`}` literal depending on Py
    # version). Handle both.
    pattern = re.sub(r"\\\{[^{}]+\\\}", r"[^/]+", escaped)
    pattern = re.sub(r"\{[^{}]+\}", r"[^/]+", pattern)
    return re.compile("^" + pattern + "$")


def _extract_braced_body(text: str, start: int) -> Tuple[str, int]:
    """
    Given index of the opening `{` in `text`, return (body_without_outer_braces, index_after_closing_brace).

    String-aware: skips `{` and `}` inside `"..."` (handling backslash escapes).
    Comment-aware: skips `//…\n` and `/* … */`.
    """
    assert text[start] == "{"
    depth = 1
    i = start + 1
    n = len(text)
    while i < n and depth > 0:
        c = text[i]
        # Single-line comment.
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            nl = text.find("\n", i + 2)
            i = n if nl < 0 else nl + 1
            continue
        # Block comment.
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
            continue
        # String literal — consume until unescaped closing quote.
        if c == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\" and j + 1 < n:
                    j += 2
                    continue
                if text[j] == '"':
                    j += 1
                    break
                j += 1
            i = j
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
        i += 1
    return text[start + 1 : i - 1], i


def parse_proto_file(path: Path) -> List[Rpc]:
    text = path.read_text(encoding="utf-8", errors="replace")
    # Strip comments BEFORE any regex parsing so that `// rpc Foo(...) returns(...);`
    # or `/* service X { … } */` inside the source doesn't inflate the RPC count.
    text = _strip_proto_comments(text)
    rpcs: List[Rpc] = []
    for sm in _SERVICE_RE.finditer(text):
        service_name = sm.group(1)
        brace_pos = sm.end() - 1  # position of `{`
        service_body, _ = _extract_braced_body(text, brace_pos)
        # Walk rpc headers; for each, decide between `;`-terminated and `{...}`-bodied form,
        # extracting the body with the depth/string-aware scanner.
        pos = 0
        n = len(service_body)
        while pos < n:
            m = _RPC_HEADER_RE.search(service_body, pos)
            if not m:
                break
            rpc_name = m.group(1)
            end = m.end()
            # Skip whitespace.
            while end < n and service_body[end] in " \t\r\n":
                end += 1
            rpc_body = ""
            if end < n and service_body[end] == ";":
                pos = end + 1
            elif end < n and service_body[end] == "{":
                rpc_body, after = _extract_braced_body(service_body, end)
                pos = after
            else:
                # Malformed — advance past the header to avoid infinite loop.
                pos = m.end()
                continue
            http_match = _HTTP_RE.search(rpc_body) if rpc_body else None
            if http_match:
                method, route = http_match.group(1).upper(), http_match.group(2)
                rpcs.append(Rpc(service_name, rpc_name, method, route))
            else:
                rpcs.append(
                    Rpc(service_name, rpc_name, "POST",
                        _heuristic_path(service_name, rpc_name))
                )
    return rpcs


# ---------------------------------------------------------------------------
# Collection parsing
# ---------------------------------------------------------------------------

# Strip `{{baseUrl}}` (or any leading `{{var}}/`) and any query string.
_BASE_URL_RE = re.compile(r"^\{\{[^}]+\}\}")


def _strip_base(raw: str) -> str:
    s = _BASE_URL_RE.sub("", raw)
    # Drop query string.
    q = s.find("?")
    if q >= 0:
        s = s[:q]
    return s


def _iter_items(items: list):
    """Postman items can be nested (folders). Yield leaves with `.request`."""
    for it in items:
        if "request" in it:
            yield it
        if "item" in it:
            yield from _iter_items(it["item"])


def parse_collection_file(path: Path) -> List[Tuple[str, str]]:
    """Return list of (METHOD, stripped_path) for each request item."""
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError) as e:
        print(f"WARNING: skipping malformed collection {path}: {e}", file=sys.stderr)
        return []
    out: List[Tuple[str, str]] = []
    for item in _iter_items(data.get("item", [])):
        req = item.get("request") or {}
        method = (req.get("method") or "GET").upper()
        url = req.get("url")
        if isinstance(url, dict):
            raw = url.get("raw") or ""
        elif isinstance(url, str):
            raw = url
        else:
            raw = ""
        if not raw:
            continue
        out.append((method, _strip_base(raw)))
    return out


# ---------------------------------------------------------------------------
# Coverage computation
# ---------------------------------------------------------------------------

def compute_coverage(rpcs: List[Rpc], cases: List[Tuple[str, str]]) -> Dict[str, bool]:
    covered: Dict[str, bool] = {rpc.fqn(): False for rpc in rpcs}
    for rpc in rpcs:
        for method, path in cases:
            if method != rpc.method:
                continue
            if rpc.template_re.match(path):
                covered[rpc.fqn()] = True
                break
    return covered


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--proto-glob", required=True,
                   help="glob for .proto files (e.g. '../kacho-proto/proto/kacho/cloud/iam/v1/*.proto')")
    p.add_argument("--collections-glob", required=True,
                   help="glob for Postman collection JSON files")
    p.add_argument("--min", type=float, default=0.0,
                   help="minimum coverage percent required to exit 0")
    args = p.parse_args(argv)

    rpcs: List[Rpc] = []
    for f in sorted(glob.glob(args.proto_glob)):
        rpcs.extend(parse_proto_file(Path(f)))

    if not rpcs:
        print("ERROR: no RPCs discovered (check --proto-glob)", file=sys.stderr)
        return 2

    cases: List[Tuple[str, str]] = []
    for f in sorted(glob.glob(args.collections_glob)):
        cases.extend(parse_collection_file(Path(f)))

    covered = compute_coverage(rpcs, cases)
    n_total = len(covered)
    n_covered = sum(1 for v in covered.values() if v)
    pct = (100.0 * n_covered / n_total) if n_total else 0.0

    print(f"Coverage: {n_covered} of {n_total} RPCs ({pct:.0f}%)")

    missing = [fqn for fqn, ok in covered.items() if not ok]
    if missing:
        print("Missing RPCs:")
        rpc_by_fqn = {r.fqn(): r for r in rpcs}
        for fqn in missing:
            r = rpc_by_fqn[fqn]
            print(f"  - {fqn} ({r.method} {r.path})")

    return 0 if pct >= args.min else 1


if __name__ == "__main__":
    sys.exit(main())
