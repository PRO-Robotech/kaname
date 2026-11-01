#!/usr/bin/env python3
"""Самопроба реального текста payload: установки, пролог и граница shell-step."""
import hashlib
import io
import json
import os
import platform
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile

import yaml


def declarations(root):
    """Состав и пины берутся из исполняемых install/check steps всех jobs workflow."""
    path = root / ".github/workflows/e2e-newman.yml"
    workflow = yaml.safe_load(path.read_text())
    installs, checks, blocks, inspected = {}, set(), [], 0
    for job, body in workflow["jobs"].items():
        for index, step in enumerate(body.get("steps", [])):
            inspected += 1
            if str(step.get("uses", "")).startswith("actions/setup-go@"):
                version_file = step.get("with", {}).get("go-version-file")
                assert version_file, (job, index, "setup-go без go-version-file")
                mod = (root / version_file).read_text()
                match = re.search(r"^toolchain go(\d+\.\d+\.\d+)$", mod, re.M) or re.search(r"^go (\d+\.\d+\.\d+)$", mod, re.M)
                assert match, "setup-go source не называет версию"
                installs["go"] = (match[1], f"{job}/steps/{index}/with/{version_file}")
            run = step.get("run", "")
            found = False
            for line in run.splitlines():
                words = shlex.split(line, comments=True) if re.match(r"\s*(go install |npm install -g |python3 -m pip install )", line) else []
                if words[:2] == ["go", "install"]:
                    spec = words[2]
                    module, version = spec.rsplit("@", 1)
                    name = module.rsplit("/", 1)[-1]
                    previous = installs.get(name)
                    assert previous is None or previous[0] == version, (name, previous, version)
                    installs[name] = (version, f"{job}/steps/{index}")
                    found = True
                elif words[:3] == ["npm", "install", "-g"]:
                    spec = words[3]
                    name, version = spec.rsplit("@", 1)
                    previous = installs.get(name)
                    assert previous is None or previous[0] == version, (name, previous, version)
                    installs[name] = (version, f"{job}/steps/{index}")
                    found = True
                elif words[:4] == ["python3", "-m", "pip", "install"]:
                    # Незакреплённая версия остаётся незакреплённой и в ожидании пробы.
                    for spec in words[4:]:
                        if spec.startswith("-"):
                            continue
                        if spec in ("||", ">", "2>") or spec.startswith("rc="):
                            break
                        name, _, version = spec.partition("==")
                        installs[f"python:{name}"] = (version, f"{job}/steps/{index}")
                    found = True
                match = re.match(r"\s*for tool in (.+?); do", line)
                if match:
                    checks.update(shlex.split(match[1]))
            if found:
                blocks.append(run)
    assert inspected and installs and blocks, "пустой обход workflow tools"
    print(f"PARITY-CENSUS workflow jobs={len(workflow['jobs'])} steps={inspected} installs={len(installs)} checks={len(checks)}", flush=True)
    for name, (version, coordinate) in sorted(installs.items()):
        print(f"PARITY-DECL {coordinate} {name} version={version or 'workflow-unpinned'}", flush=True)
    return installs, checks, blocks


def executable(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(0o755)


class World:
    """Изолированные пути и install peers; исполняется сам RUNNER_POD_SH."""
    def __init__(self, base, payload, env=None, ships=None):
        self.base = base
        self.payload = payload
        self.work = base / "work"
        self.src = base / "src"
        self.prefix = base / "usr/local"
        self.bin = base / "fixture-bin"
        for directory in (self.work / "out", self.work / "ship", self.work / "bin", self.src / "sub", self.prefix / "bin", self.bin):
            directory.mkdir(parents=True, exist_ok=True)
        (self.work / ".go").touch()
        (self.work / ".fetched").touch()
        (self.src / "root-sentinel").write_text("root\n")
        if ships:
            for file in ships.iterdir():
                if file.is_file():
                    shutil.copyfile(file, self.work / "ship" / file.name)
        self.env = dict(os.environ)
        self.env.update(env or {})
        self.env.update(HOME=str(base / "home"), PATH=f"{self.bin}:{self.prefix}/bin:/usr/bin:/bin",
                        RUNNER_SHA="fixture-source", RUNNER_REPO="PRO-Robotech/kaname",
                        RUNNER_NODE="20", RUNNER_KUBECTL="v1.31.2", RUNNER_GO=self.env.get("RUNNER_GO", "1.26.10"),
                        RUNNER_GH_SH="#!/bin/sh\nexit 4\n", GITHUB_PATH=str(self.work / "github-path"),
                        FIXTURE_WORLD=str(base), FIXTURE_PY=sys.executable,
                        KANAME_STAND_IN_POD="inherited-after-world-cleanup", KEEP_SENTINEL="retained",
                        GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_SYSTEM="/dev/null")
        executable(self.bin / "apt-get", '#!/bin/sh\nprintf "%s\\n" "$*" >> "$FIXTURE_WORLD/apt-argv"\n')
        executable(self.work / "bin/kubectl", '#!/bin/sh\necho "Client Version: v1.31.2"\n')
        # Необъявленные пины образа не сочиняются: эти base-image tools лишь присутствуют.
        for tool in ("helm", "docker"):
            executable(self.bin / tool, '#!/bin/sh\necho "fixture-base-image-tool"\n')
        installer = '''#!/usr/bin/env python3
import json, os, pathlib, sys
root=pathlib.Path(os.environ["FIXTURE_WORLD"])
name=pathlib.Path(sys.argv[0]).name
args=sys.argv[1:]
if name == "go":
    if args == ["env", "GOVERSION"]: print("go"+os.environ["RUNNER_GO"]); sys.exit(0)
    if args == ["env", "GOPATH"]: print(root/"go"); sys.exit(0)
    if args == ["version"]: print("go version go"+os.environ["RUNNER_GO"]+" linux/amd64"); sys.exit(0)
    if args[:1] != ["install"]: sys.exit(71)
    module, version=args[1].rsplit("@",1); tool=module.rsplit("/",1)[-1]; target=root/"go/bin"/tool
elif name == "npm":
    if args == ["--version"]: print("10.0.0"); sys.exit(0)
    if args[:2] != ["install", "-g"]: sys.exit(72)
    tool, version=args[2].rsplit("@",1); target=root/"usr/local/bin"/tool
else: sys.exit(73)
with (root/"install-argv").open("a") as out: out.write(json.dumps([name,*args])+"\\n")
target.parent.mkdir(parents=True,exist_ok=True)
target.write_text("#!/bin/sh\\nprintf '%s\\n' "+repr(version)+"\\n")
target.chmod(0o755)
'''
        executable(self.bin / "go", installer)
        # Python остаётся настоящим; только сетевой install peer заменён контролируемым.
        executable(self.bin / "python3", '''#!/bin/sh
if [ "$1 $2 $3" = '-m pip install' ]; then
  printf '%s\\n' "$*" >> "$FIXTURE_WORLD/python-install-argv"
  exit 0
fi
exec "$FIXTURE_PY" "$@"
''')
        archive = self.work / "node-fixture.tar.xz"
        arch = {"x86_64": "x64", "aarch64": "arm64"}[platform.machine()]
        self.env["FIXTURE_NODE_ARCH"] = arch
        with tarfile.open(archive, "w:xz") as tar:
            for name, body in {"node": '#!/bin/sh\necho v20.0.0\n', "npm": installer}.items():
                data = body.encode()
                info = tarfile.TarInfo(f"node-v20.0.0-linux-{arch}/bin/{name}")
                info.size = len(data)
                info.mode = 0o755
                tar.addfile(info, io.BytesIO(data))
        self.env["FIXTURE_NODE_ARCHIVE"] = str(archive)
        executable(self.bin / "curl", '''#!/usr/bin/env python3
import hashlib, os, pathlib, shutil, sys
a=sys.argv[1:]; archive=pathlib.Path(os.environ["FIXTURE_NODE_ARCHIVE"])
if a[-1].endswith("/SHASUMS256.txt"):
 print(hashlib.sha256(archive.read_bytes()).hexdigest()+"  node-v20.0.0-linux-"+os.environ["FIXTURE_NODE_ARCH"]+".tar.xz")
elif "-o" in a:
 shutil.copyfile(archive,a[a.index("-o")+1])
else: sys.exit(74)
''')

    def run(self, command, extra_install="", payload=None):
        text = self.payload if payload is None else payload
        if extra_install:
            anchor = 'say "команда: $RUNNER_CMD"\n'
            assert text.count(anchor) == 1, "граница producer payload не найдена"
            text = text.replace(anchor, extra_install + "\n" + anchor)
        # Перенос адресов, не переписывание решения. Другие байты producer сохраняются.
        for old, new in (("/usr/local", self.prefix), ("/work", self.work), ("/src", self.src)):
            text = text.replace(old, str(new))
        env = dict(self.env)
        for key, value in env.items():
            if key.startswith("RUNNER_"):
                env[key] = value.replace("/work/", str(self.work) + "/").replace("/src/", str(self.src) + "/")
        env["RUNNER_CMD"] = command.replace("/work/", str(self.work) + "/").replace("/src/", str(self.src) + "/")
        print("PARITY-PRODUCER sha256=" + hashlib.sha256(self.payload.encode()).hexdigest(), flush=True)
        result = subprocess.run(["bash", "-c", text], env=env, cwd=self.src, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=45)
        stage = (self.work / ".rc").read_text().strip() if (self.work / ".rc").exists() else "missing"
        print(f"PARITY-PAYLOAD rc={result.returncode} stage={stage}", flush=True)
        if not stage.startswith("command "):
            print(result.stdout, flush=True)
            raise RuntimeError("payload fixture не дошла до команды: " + stage)
        return result


def payload_checks(root, payload):
    installs, checks, blocks = declarations(root)
    failures = 0
    with tempfile.TemporaryDirectory(prefix="stand-parity-") as temp:
        base = Path(temp)
        control = World(base / "control", payload)
        assert control.run("true").returncode == 0, "законный opaque control не исполнился"
        probe = '''import importlib, json, pathlib, shutil, subprocess, sys
data=json.loads(pathlib.Path(sys.argv[1]).read_text()); failures=[]
for name, version in data.items():
 if name.startswith('python:'):
  importlib.import_module(name.split(':',1)[1].replace('pyyaml','yaml')); continue
 actual=shutil.which(name)
 if not actual: failures.append(name+': отсутствует'); continue
 if version:
  r=subprocess.run([actual,'version' if name=='go' else '--version'],capture_output=True,text=True)
  if version not in r.stdout+r.stderr: failures.append(name+': ожидалось '+version+', получено '+r.stdout+r.stderr)
print('TOOL-RESULT '+json.dumps(failures,ensure_ascii=False)); sys.exit(bool(failures))
'''
        for label, install in (("actual", ""), ("workflow-lawful", "\n".join(blocks))):
            world = World(base / label, payload)
            (world.work / "ship/tools.py").write_text(probe)
            expected = {name: spec[0] for name, spec in installs.items()}
            expected.update({name: expected.get(name, "") for name in checks})
            (world.work / "ship/tools.json").write_text(json.dumps(expected))
            result = world.run("python3 /work/ship/tools.py /work/ship/tools.json", install)
            print(result.stdout, flush=True)
            trace = world.base / "install-argv"
            print("PARITY-INSTALL " + label + " " + (trace.read_text() if trace.exists() else "no-go-or-npm-install"), flush=True)
            if label == "actual":
                print(f"PARITY-AXIS tools rc={result.returncode}", flush=True)
                failures += result.returncode != 0
            else:
                assert result.returncode == 0, "workflow lawful install twin не исполнился"
        command = "python3 -c " + shlex.quote("import os,json; print(json.dumps({'present': 'KANAME_STAND_IN_POD' in os.environ, 'keep':os.environ.get('KEEP_SENTINEL')}))")
        for label, code in (("actual", payload), ("unset-lawful", payload.replace("unset KUBECONFIG\n", "unset KUBECONFIG KANAME_STAND_IN_POD\n", 1))):
            world = World(base / (label + "-env"), payload)
            result = world.run(command, payload=code)
            rows = [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{"present":')]
            assert len(rows) == 1 and rows[0]["keep"] == "retained", "env fixture не исполнилась"
            good = rows[0]["present"] is False
            print(f"PARITY-AXIS prologue {label} absent={good}", flush=True)
            if label == "actual": failures += not good
            else: assert good, "lawful unset twin не подавил унаследованную переменную"
        world = World(base / "opaque-cwd", payload)
        result = world.run("cd sub; test \"$PWD\" = \"$(dirname \"$PWD\")/sub\"")
        assert result.returncode == 0, "законный cd внутри opaque payload потерян"
        print("PARITY-OPAQUE cwd сохраняется внутри одной команды: PASS", flush=True)
    return int(bool(failures))


def step_checks(objects, ships):
    data = json.loads(objects.read_text())
    pod = next(item for item in data["items"] if item["kind"] == "Pod")
    container = next(item for item in pod["spec"]["containers"] if item["name"] == "run")
    env = {entry["name"]: entry["value"] for entry in container["env"]}
    payload = container["command"][2]
    with tempfile.TemporaryDirectory(prefix="stand-parity-steps-") as temp:
        world = World(Path(temp), payload, env=env, ships=ships)
        result = world.run(env.get("RUNNER_CMD", ""))
        print(result.stdout, flush=True)
        if result.returncode != 0 or not (world.src / "step-file").is_file():
            print("PARITY-AXIS steps: отдельные оболочки/root cwd/files не подтверждены", flush=True)
            return 1
        print("PARITY-AXIS steps: actual producer payload исполнен, root cwd и files сохранены", flush=True)
    return 0


if __name__ == "__main__":
    try:
        if sys.argv[1] == "--steps":
            sys.exit(step_checks(Path(sys.argv[2]), Path(sys.argv[3])))
        sys.exit(payload_checks(Path(sys.argv[1]), Path(sys.argv[2]).read_text()))
    except Exception as error:
        print(f"PARITY-INVALID: {type(error).__name__}: {error}", flush=True)
        sys.exit(2)
