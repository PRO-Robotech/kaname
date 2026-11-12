#!/usr/bin/env python3
"""Объявления инструментов e2e workflow для существующего stand-own runner."""
import argparse
import hashlib
import json
import platform
import os
import importlib.metadata
import ssl
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
    provider = {k: str(v) for k, v in document.get("env", {}).items() if k.startswith("KANAME_RUNNER_")}
    required = ("IMAGE", "OS", "SNAPSHOT", "RELEASES", "APT", "SYSTEM_CLI", "NODE", "NPM", "HELM", "KUBECTL", "DOCKER", "DOCKER_SHA256", "PIP", "PYYAML")
    if set(provider) != {"KANAME_RUNNER_" + name for name in required}:
        raise ValueError("workflow provider: missing/unknown declaration")
    if provider["KANAME_RUNNER_OS"] != "ubuntu/24.04" or provider["KANAME_RUNNER_IMAGE"] != "ubuntu:24.04":
        raise ValueError("workflow provider: unsupported OS/image")
    if not re.fullmatch(r"https://snapshot\.ubuntu\.com/ubuntu/[0-9]{8}T[0-9]{6}Z/", provider["KANAME_RUNNER_SNAPSHOT"]):
        raise ValueError("workflow provider: immutable snapshot required")
    for name in ("NODE", "NPM", "HELM", "KUBECTL", "DOCKER", "PIP", "PYYAML"):
        if not re.fullmatch(r"v?\d+\.\d+\.\d+", provider["KANAME_RUNNER_" + name]):
            raise ValueError("workflow provider: exact version required: " + name)
    if not re.fullmatch(r"[a-f0-9]{64}", provider["KANAME_RUNNER_DOCKER_SHA256"]):
        raise ValueError("workflow provider: Docker release digest required")
    releases = {}
    for line in provider["KANAME_RUNNER_RELEASES"].splitlines():
        fields = line.split()
        if len(fields) != 2 or not re.fullmatch(r"[a-f0-9]{64}", fields[0]) or fields[1] not in ("noble", "noble-updates", "noble-security") or fields[1] in releases:
            raise ValueError("workflow provider: exact signed release hashes required")
        releases[fields[1]] = fields[0]
    if set(releases) != {"noble", "noble-updates", "noble-security"}:
        raise ValueError("workflow provider: incomplete signed release hashes")
    packages = {}
    for spec in provider["KANAME_RUNNER_APT"].split():
        if not re.fullmatch(r"[a-z0-9.+-]+=[A-Za-z0-9:~.+-]+", spec):
            raise ValueError("workflow provider: exact apt spec required")
        name, version = spec.split("=", 1)
        if name in packages:
            raise ValueError("workflow provider: duplicate apt spec " + name)
        packages[name] = version
    if not packages:
        raise ValueError("workflow provider: empty apt closure")
    system_cli = json.loads(provider["KANAME_RUNNER_SYSTEM_CLI"])
    if set(system_cli) != {"git", "openssl", "jq", "python3"} or any(not isinstance(v, str) or not re.fullmatch(r"\d+\.\d+(?:\.\d+)?", v) for v in system_cli.values()):
        raise ValueError("workflow provider: exact system CLI declarations required")
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
                            if "==" not in word:
                                raise ValueError(f"{source}: unpinned Python package {word}")
                            add("pip", word.split("==", 1)[0], word, source)
                check = re.match(r"\s*for tool in (.+?); do", line)
                if check:
                    for name in shlex.split(check[1]):
                        if not re.fullmatch(r"[A-Za-z0-9._-]+", name):
                            raise ValueError(f"{source}: имя инструмента не статично: {name!r}")
                        checks.setdefault(name, []).append(source)
    if not inspected or not entries or not checks:
        raise ValueError("workflow tools: пустое входное замыкание")
    yaml_pin = next((entry["spec"].split("==", 1)[1] for entry in entries.values() if entry["kind"] == "pip" and entry["name"].lower() == "pyyaml"), None)
    if yaml_pin != provider["KANAME_RUNNER_PYYAML"]:
        raise ValueError("workflow bootstrap/install PyYAML pins disagree")
    provider["KANAME_RUNNER_GO"] = setups["go"]
    for name, pin in setups.items():
        if name != "go" and pin.lstrip("v") != provider["KANAME_RUNNER_" + name.upper()].lstrip("v"):
            raise ValueError("workflow setup/provider disagreement: " + name)
    return {"provider": provider, "system_cli": system_cli, "apt": packages, "source": str(path), "jobs": len(images), "steps": inspected, "images": images,
            "setup": setups, "install": list(entries.values()), "checks": checks}


def installer(data, work, root):
    quote = shlex.quote
    # Поставленные запасные файлы не должны затенять только что подготовленного точного поставщика.
    # Оставляем их обнаруживаемыми только после путей поставщика/системы.
    lines = ["set -uo pipefail", f'export PATH="$(go env GOPATH)/bin:$PATH:{quote(str(work / "bin"))}"',
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
    """Measure used CLIs and their runtime closure, rejecting inherited PATH tools."""
    provider = data["provider"]
    def pin(name):
        return provider["KANAME_RUNNER_" + name.upper()].lstrip("v")
    def run(argv):
        result = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise ValueError(f"provider probe failed rc={result.returncode}: {argv}")
        return result.stdout.strip() or result.stderr.strip()
    result = {"declared_provider_versions": "verified", "hosted_runtime_comparison": "not-observed", "provider": provider, "images": data["images"], "tools": {}, "packages": {}}
    for name, expected in data["apt"].items():
        actual = run(["dpkg-query", "-W", "-f=${Version}", name])
        if actual != expected:
            raise ValueError(f"apt package version disagrees: {name}: {actual} != {expected}")
        result["packages"][name] = actual
    # Пин пакета дистрибутива не равен протоколу версии исполняемого файла:
    # закреплённый пакет Ubuntu jq 1.7.1 сообщает jq-1.7 в сохранённом нативном отказе.
    versions = {"go": pin("go"), "node": pin("node"), "helm": pin("helm"),
                "kubectl": pin("kubectl"), "docker": pin("docker"), **data["system_cli"]}
    for entry in data["install"]:
        if entry["kind"] in ("npm", "go"):
            versions[entry["name"]] = entry["spec"].rsplit("@", 1)[1].lstrip("v")
    targets = dict(data["checks"])
    targets.setdefault("npm", [data["source"] + "/env/KANAME_RUNNER_NPM"])
    gopath = Path(run(["go", "env", "GOPATH"])) / "bin"
    for name, sources in targets.items():
        binary = shutil.which(name)
        if not binary:
            raise ValueError(f"missing-provider: {name}, source={sources}")
        file = Path(binary).resolve()
        if name in ("git", "openssl", "jq", "python3"):
            permitted = file.parent == Path("/usr/bin")
        elif name in ("kind", "grpcurl"):
            permitted = file.parent == gopath.resolve()
        else:
            permitted = file.is_relative_to((work / "provider").resolve())
        if not permitted:
            raise ValueError(f"PATH shadowing: {name}: {file}")
        output = run([str(file), *version_arguments(name)])
        if name == "kubectl":
            actual = json.loads(output)["clientVersion"]["gitVersion"].lstrip("v")
        elif name == "go":
            actual = run(["go", "env", "GOVERSION"]).removeprefix("go")
        elif name == "helm":
            match = re.search(r'Version:"v([^"+]+)', output)
            actual = match[1] if match else output.lstrip("v").split("+", 1)[0]
        else:
            match = re.search(r"(?<![0-9.])v?(\d+\.\d+(?:\.\d+)?)", output)
            actual = match[1] if match else output.lstrip("v")
        expected = pin("npm") if name == "npm" else versions.get(name)
        # go install часто встраивает '(devel)' в вывод версии. Метаданные сборки
        # ниже — канонический источник версии этих модульных команд.
        go_entry = next((e for e in data["install"] if e["kind"] == "go" and e["name"] == name), None)
        if go_entry:
            module, expected_mod = go_entry["spec"].rsplit("@", 1)
            metadata = run(["go", "version", "-m", str(file)])
            rows = [line.strip().split() for line in metadata.splitlines()]
            if not any(row == ["path", module] for row in rows) or not any(len(row) >= 3 and row[0] == "mod" and row[2] == expected_mod and (module == row[1] or module.startswith(row[1] + "/")) for row in rows):
                raise ValueError(f"pinned tool build metadata disagrees: {name}: {metadata}")
            actual = expected_mod.lstrip("v")
        if expected is None or actual != expected:
            raise ValueError(f"CLI version disagrees: {name}: {actual!r} != {expected!r}")
        result["tools"][name] = {"path": str(file), "sha256": hashlib.sha256(file.read_bytes()).hexdigest(),
            "version": actual, "expected": expected, "version_output": output,
            "source_steps": sources, "declared_version_equality": "verified"}
        if go_entry:
            result["tools"][name]["go_build_metadata"] = metadata
    # Функциональные пробы stdlib/ABI включают модули, пропущенные при поставке одного ELF.
    import lzma, sqlite3, venv, hashlib as hash_probe
    if ".".join(map(str, sys.version_info[:3])) != data["system_cli"]["python3"]:
        raise ValueError("Python runtime disagrees with apt provider")
    if ssl.OPENSSL_VERSION.split()[1] != data["system_cli"]["openssl"]:
        raise ValueError("Python OpenSSL ABI disagrees with provider")
    if lzma.decompress(lzma.compress(b"runner")) != b"runner" or sqlite3.connect(":memory:").execute("select 42").fetchone() != (42,):
        raise ValueError("Python stdlib functional probe failed")
    result["python_runtime"] = {"executable": sys.executable, "version": sys.version, "openssl": ssl.OPENSSL_VERSION}
    expected_packages = {"pip": pin("pip")}
    for entry in data["install"]:
        if entry["kind"] == "pip":
            name, expected = entry["spec"].split("==", 1)
            expected_packages[name] = expected
    for name, expected in expected_packages.items():
        actual = importlib.metadata.version(name)
        if actual != expected:
            raise ValueError(f"Python package version disagrees: {name}: {actual} != {expected}")
        result["packages"]["python:" + name] = actual
    helpers = Path(run(["git", "--exec-path"]))
    if helpers != Path("/usr/lib/git-core") or not (helpers / "git-remote-https").is_file():
        raise ValueError("Git helper closure missing or shadowed")
    run([str(helpers / "git-sh-i18n--envsubst"), "--variables", "$RUNNER"])
    helper = subprocess.run([str(helpers / "git-remote-https")], capture_output=True, text=True, timeout=30)
    if helper.returncode != 1 or "remote-curl: usage: git remote-curl" not in helper.stderr:
        raise ValueError("Git HTTPS helper cannot load its runtime/ABI closure")
    result["git_https_helper"] = {"path": str((helpers / "git-remote-https").resolve()), "startup_rc": helper.returncode}
    result["git_exec_path"] = str(helpers)
    (work / "runtime-tools.json").write_text(json.dumps(result, ensure_ascii=False, sort_keys=True))
    print("workflow tools: exact CLI/package pins and runtime closure verified")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--observe", action="store_true")
    parser.add_argument("--provide-ship")
    parser.add_argument("--provider-json", action="store_true")
    args = parser.parse_args()
    args.work.mkdir(parents=True, exist_ok=True)
    try:
        data = manifest(args.root)
        if args.provider_json:
            print(json.dumps([{"name": k, "value": v} for k, v in data["provider"].items()]))
        elif args.provide_ship:
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
