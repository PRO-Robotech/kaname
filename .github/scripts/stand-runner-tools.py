#!/usr/bin/env python3
"""Объявления инструментов e2e workflow для существующего stand-own runner."""
import argparse
import hashlib
import json
import platform
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import struct
import sys

import yaml


def manifest(root):
    path = root / ".github/workflows/e2e-newman.yml"
    document = yaml.safe_load(path.read_text())
    entries, checks, images, setups = {}, {}, {}, {}
    inspected = 0

    def add(kind, name, spec, source):
        key = (kind, name)
        prior = entries.get(key)
        if prior and prior["spec"] != spec:
            raise ValueError(f"{source}: конфликт версии {name}: {prior['spec']} / {spec}")
        if prior:
            prior["sources"].append(source)
        else:
            entries[key] = {"kind": kind, "name": name, "spec": spec, "sources": [source]}

    for job, data in document["jobs"].items():
        container = data.get("container")
        images[job] = container.get("image") if isinstance(container, dict) else container or data.get("runs-on")
        for index, step in enumerate(data.get("steps", [])):
            inspected += 1
            source = f"{path.name}:{job}/steps/{index}"
            action = str(step.get("uses", ""))
            settings = step.get("with", {})
            if action.startswith("actions/setup-go@"):
                if "go-version-file" in settings:
                    text = (root / settings["go-version-file"]).read_text()
                    version = re.search(r"^toolchain go(\d+\.\d+\.\d+)$", text, re.M) or re.search(r"^go (\d+\.\d+\.\d+)$", text, re.M)
                    if not version:
                        raise ValueError(f"{source}: версия Go не объявлена файлом")
                    version = version[1]
                else:
                    version = str(settings.get("go-version", ""))
                if not re.fullmatch(r"\d+\.\d+\.\d+", version):
                    raise ValueError(f"{source}: неподдержанная форма Go pin {version!r}")
                if setups.get("go", version) != version:
                    raise ValueError(f"{source}: setup-go версии расходятся")
                setups["go"] = version
            elif action.startswith("actions/setup-node@"):
                version = str(settings.get("node-version", ""))
                if version and not re.fullmatch(r"\d+(?:\.\d+\.\d+)?", version):
                    raise ValueError(f"{source}: неподдержанная форма Node pin {version!r}")
                if version:
                    if setups.get("node", version) != version:
                        raise ValueError(f"{source}: setup-node версии расходятся")
                    setups["node"] = version
            elif "setup-helm@" in action:
                version = str(settings.get("version", ""))
                if not re.fullmatch(r"v?\d+\.\d+\.\d+", version):
                    raise ValueError(f"{source}: неподдержанная форма Helm pin {version!r}")
                setups["helm"] = version
            for line in str(step.get("run", "")).splitlines():
                install = re.match(r"\s*(go install |npm install -g |python3 -m pip install )", line)
                if install:
                    words = shlex.split(line, comments=True)
                    if words[:2] == ["go", "install"]:
                        spec = words[2]
                        if not re.fullmatch(r"[A-Za-z0-9._/-]+@v[0-9][A-Za-z0-9.+-]*", spec):
                            raise ValueError(f"{source}: неподдержанная форма go install {spec!r}")
                        add("go", spec.split("@", 1)[0].rsplit("/", 1)[-1], spec, source)
                    elif words[:3] == ["npm", "install", "-g"]:
                        spec = words[3]
                        if not re.fullmatch(r"(?:@[A-Za-z0-9._-]+/)?[A-Za-z0-9._-]+@[0-9][A-Za-z0-9.+-]*", spec):
                            raise ValueError(f"{source}: неподдержанная форма npm pin {spec!r}")
                        add("npm", spec.rsplit("@", 1)[0], spec, source)
                    else:
                        for word in words[4:]:
                            if word == "||" or word.startswith("rc="):
                                break
                            if word.startswith("-"):
                                continue
                            if not re.fullmatch(r"[A-Za-z0-9._-]+(?:==[A-Za-z0-9.+-]+)?", word):
                                raise ValueError(f"{source}: неподдержанная форма pip install {word!r}")
                            add("pip", word.split("==", 1)[0], word, source)
                check = re.match(r"\s*for tool in (.+?); do", line)
                if check:
                    for name in shlex.split(check[1]):
                        if not re.fullmatch(r"[A-Za-z0-9._-]+", name):
                            raise ValueError(f"{source}: имя инструмента не статично: {name!r}")
                        checks.setdefault(name, []).append(source)
    if not inspected or not entries or not checks:
        raise ValueError("workflow tools: пустое входное замыкание")
    return {"source": str(path), "jobs": len(images), "steps": inspected, "images": images,
            "setup": setups, "install": list(entries.values()), "checks": checks}


def installer(data, work, root):
    quote = shlex.quote
    lines = ["set -uo pipefail", f'export PATH="$(go env GOPATH)/bin:{quote(str(work / "bin"))}:$PATH"',
             f"mkdir -p {quote(str(work / 'python-tools'))} || return 1",
             f"export PYTHONPATH={quote(str(work / 'python-tools'))}${{PYTHONPATH:+:$PYTHONPATH}}"]
    for entry in data["install"]:
        spec = quote(entry["spec"])
        if entry["kind"] == "go":
            lines.append(f"go install {spec} || return 1")
        elif entry["kind"] == "npm":
            lines.append(f"npm install -g {spec} || return 1")
        else:
            lines.append(f"python3 -m pip install --quiet --target {quote(str(work / 'python-tools'))} {spec} || return 1")
    lines.append('missing=""')
    for name in data["checks"]:
        lines.append(f"command -v {quote(name)} >/dev/null 2>&1 || python3 {quote(str(root / '.github/scripts/stand-runner-tools.py'))} --root {quote(str(root))} --work {quote(str(work))} --provide-ship {quote(name)} || return 1")
        lines.append(f"command -v {quote(name)} >/dev/null 2>&1 || missing=\"$missing {name}\"")
    lines.append('[ -z "$missing" ] || { printf "workflow tools: base-image provider отсутствует:%s\\n" "$missing" >&2; return 1; }')
    return "\n".join(lines) + "\n"


def version_arguments(name):
    return {"helm": ["version", "--short"], "kubectl": ["version", "--client", "-o", "json"],
            "openssl": ["version"], "go": ["version"]}.get(name, ["--version"])


def provide_ship(data, work, name):
    if name not in data["checks"]:
        raise ValueError(f"missing-provider: undeclared tool {name}")
    source = work / "ship" / name
    if not source.is_file() or source.is_symlink():
        raise ValueError(f"missing-provider: {name}; source={data['checks'][name]}; supply an ABI-compatible CLI with --ship")
    content = source.read_bytes()
    machine = {"x86_64": 62, "aarch64": 183}.get(platform.machine())
    if len(content) < 20 or content[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", content, 18)[0] != machine:
        raise ValueError(f"missing-provider: {name}; shipped CLI ELF/ABI mismatch")
    target = work / "bin" / name
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    target.chmod(0o755)
    if target.read_bytes() != content:
        raise ValueError(f"missing-provider: {name}; shipped bytes changed")
    probe = subprocess.run([str(target), *version_arguments(name)], capture_output=True, text=True, timeout=30)
    if probe.returncode != 0:
        raise ValueError(f"missing-provider: {name}; shipped CLI runtime probe rc={probe.returncode}")
    print(f"workflow tools: provided {name} from --ship sha256={hashlib.sha256(content).hexdigest()}")


def observe(data, work):
    # Форматы version argv — протокол CLI, состав целей берётся только из workflow.
    result = {"inherited_ci_version_parity": "unresolved", "images": data["images"], "tools": {}}
    for name in data["checks"]:
        binary = shutil.which(name)
        if not binary:
            raise ValueError(f"missing-provider: {name}, source={data['checks'][name]}")
        file = Path(binary).resolve()
        run = subprocess.run([str(file), *version_arguments(name)], capture_output=True, text=True, timeout=30)
        result["tools"][name] = {"path": str(file), "sha256": hashlib.sha256(file.read_bytes()).hexdigest(),
                                 "version_rc": run.returncode, "version_output": (run.stdout + run.stderr).strip(),
                                 "source_steps": data["checks"][name], "ci_version_equality": "not-asserted"}
    for entry in data["install"]:
        if entry["kind"] != "go":
            continue
        binary = shutil.which(entry["name"])
        if not binary:
            raise ValueError(f"missing-provider: pinned {entry['name']}")
        module, pin = entry["spec"].rsplit("@", 1)
        run = subprocess.run(["go", "version", "-m", binary], capture_output=True, text=True, timeout=30)
        rows = [line.strip().split() for line in run.stdout.splitlines()]
        path_ok = any(row == ["path", module] for row in rows)
        mod_ok = any(len(row) >= 3 and row[0] == "mod" and row[2] == pin and (module == row[1] or module.startswith(row[1] + "/")) for row in rows)
        if run.returncode or not path_ok or not mod_ok:
            raise ValueError(f"pinned tool build metadata disagrees: {entry['name']} expected={entry['spec']} actual={run.stdout!r}")
        result["tools"][entry["name"]]["go_build_metadata"] = run.stdout
        result["tools"][entry["name"]]["declared_pin"] = entry["spec"]
    for entry in data["install"]:
        if entry["kind"] != "npm":
            continue
        expected = entry["spec"].rsplit("@", 1)[1]
        actual = result["tools"].get(entry["name"], {})
        if actual.get("version_rc") != 0 or actual.get("version_output", "").strip().lstrip("v") != expected:
            raise ValueError(f"npm tool runtime version disagrees: {entry['name']} expected={expected}")
        actual["declared_pin"] = entry["spec"]
    if data["setup"].get("go"):
        run = subprocess.run(["go", "env", "GOVERSION"], capture_output=True, text=True, timeout=30)
        if run.returncode or run.stdout.strip() != "go" + data["setup"]["go"]:
            raise ValueError("setup-go provider не совпал с объявленной версией")
    for name in ("node", "helm"):
        if name in data["setup"]:
            actual = result["tools"].get(name, {}).get("version_output", "").lstrip("v")
            wanted = data["setup"][name].lstrip("v")
            if not re.match(re.escape(wanted) + r"(?:[.\s+]|$)", actual):
                raise ValueError(f"setup-{name} runtime provider не совпал с declared pin {wanted}")
    (work / "runtime-tools.json").write_text(json.dumps(result, ensure_ascii=False, sort_keys=True))
    print("workflow tools: declared pins verified; inherited CI version parity unresolved")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--observe", action="store_true")
    parser.add_argument("--provide-ship")
    args = parser.parse_args()
    args.work.mkdir(parents=True, exist_ok=True)
    try:
        data = manifest(args.root)
        if args.provide_ship:
            provide_ship(data, args.work, args.provide_ship)
        elif args.observe:
            observe(data, args.work)
        else:
            (args.work / "workflow-tools.json").write_text(json.dumps(data, ensure_ascii=False, sort_keys=True))
            (args.work / "workflow-tools.sh").write_text(installer(data, args.work, args.root))
            print(f"workflow tools: jobs={data['jobs']} steps={data['steps']} installs={len(data['install'])} checks={len(data['checks'])}")
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        out = args.work / "out"
        out.mkdir(parents=True, exist_ok=True)
        (out / "tool-condition.json").write_text(json.dumps({"stage": "setup", "code": 125, "kind": "workflow_tools_unmet", "reason": str(error)}, ensure_ascii=False))
        raise ValueError(str(error)) from error


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError) as error:
        print(f"workflow tools: {error}", file=sys.stderr)
        sys.exit(1)
