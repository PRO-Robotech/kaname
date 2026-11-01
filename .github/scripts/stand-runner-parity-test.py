#!/usr/bin/env python3
"""Самопроба реального текста payload: установки, пролог и граница shell-step."""
import hashlib
import ast
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


def remap_roots(text, roots):
    """Один проход по исходным root tokens; вставленные байты не разбираются заново."""
    return re.sub(r"/(?:usr/local|work|src)(?=/|[\s\"'`;)]|$)", lambda match: str(roots[match[0]]), text)


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
        source_root = Path(__file__).resolve().parents[2]
        for relative in ("go.mod", ".github/workflows/e2e-newman.yml", ".github/scripts/stand-runner-tools.py", ".github/scripts/stand-runner-bootstrap.sh"):
            destination = self.src / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source_root / relative, destination)
        if ships:
            for file in ships.iterdir():
                if file.is_file():
                    shutil.copyfile(file, self.work / "ship" / file.name)
        self.provider = {k: str(v) for k, v in yaml.safe_load((source_root / ".github/workflows/e2e-newman.yml").read_text())["env"].items()}
        self.env = dict(os.environ)
        self.env.update(self.provider)
        self.env["KANAME_RUNNER_GO"] = declarations(source_root)[0]["go"][0]
        self.env["FIXTURE_NPM"] = self.provider["KANAME_RUNNER_NPM"]
        self.env["FIXTURE_REAL_GOROOT"] = os.environ["GOROOT"]
        self.env.update(env or {})
        self.env.update(HOME=str(base / "home"), PATH=f"{self.bin}:{self.prefix}/bin:/usr/bin:/bin",
                        RUNNER_SHA="fixture-source", RUNNER_REPO="PRO-Robotech/kaname",
                        RUNNER_NODE=self.provider["KANAME_RUNNER_NODE"], RUNNER_KUBECTL=self.provider["KANAME_RUNNER_KUBECTL"], RUNNER_GO=self.env["KANAME_RUNNER_GO"],
                        RUNNER_GH_SH="#!/bin/sh\nexit 4\n", GITHUB_PATH=str(self.work / "github-path"), GITHUB_ENV=str(self.work / "github-env"),
                        FIXTURE_WORLD=str(base), FIXTURE_PY=sys.executable,
                        KANAME_STAND_IN_POD="inherited-after-world-cleanup", KEEP_SENTINEL="retained",
                        GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_SYSTEM="/dev/null")
        # Операционный envelope payload/export, отдельно от expected workflow toolset.
        # Это настоящие capabilities base-fixture, не успешные ответы apt peer.
        operational = ("bash", "cat", "chmod", "cut", "date", "find", "git", "grep", "gzip", "head",
                       "install", "jq", "mkdir", "mv", "openssl", "rm", "seq", "sha256sum", "sh",
                       "sleep", "sort", "stat", "tar", "tail", "uname")
        manifest = {}
        for name in operational:
            source = shutil.which(name, path=os.environ["PATH"])
            assert source, f"base-fixture operational dependency отсутствует: {name}"
            original = Path(source).resolve()
            assert original.is_file() and os.access(original, os.X_OK), (name, original)
            digest = hashlib.sha256(original.read_bytes()).hexdigest()
            target = self.bin / name
            if name == "jq":
                target.symlink_to(original)
                target.chmod(0o755)
                assert hashlib.sha256(target.read_bytes()).hexdigest() == digest, "jq bytes не совпали"
            else:
                target.symlink_to(original)
            manifest[name] = {"source": str(original), "sha256": digest, "provider": "base-fixture/native"}
        lawful_jq = subprocess.run([str(self.bin / "jq"), "-nc", "{proof:(6*7)}"], env=self.env,
                                  capture_output=True, text=True, timeout=5)
        bad_jq = subprocess.run([str(self.bin / "jq"), "-n", "{"], env=self.env,
                               capture_output=True, text=True, timeout=5)
        assert lawful_jq.returncode == 0 and json.loads(lawful_jq.stdout) == {"proof": 42}, "jq не вычислил lawful input"
        assert bad_jq.returncode != 0, "jq проглотил ошибочный фильтр"
        (base / "operational-closure.json").write_text(json.dumps(manifest, sort_keys=True))
        if base.name == "control":
            print("PARITY-OPERATIONAL " + json.dumps(manifest, sort_keys=True), flush=True)
        print("PARITY-READY operational=" + ",".join(operational) + " jq=real-bytes/evaluation-and-refusal", flush=True)
        executable(self.bin / "apt-get", '#!/bin/sh\nprintf "%s\\n" "$*" >> "$FIXTURE_WORLD/apt-argv"\n')
        executable(self.work / "bin/kubectl", '#!/bin/sh\necho "Client Version: v1.31.2"\n')
        # Необъявленные пины образа не сочиняются: эти base-image tools лишь присутствуют.
        for tool in ("helm", "docker"):
            executable(self.bin / tool, '#!/bin/sh\necho "fixture-base-image-tool"\n')
        installer = '''#!/usr/bin/env python3
import json, os, pathlib, subprocess, sys
root=pathlib.Path(os.environ["FIXTURE_WORLD"])
name=pathlib.Path(sys.argv[0]).name
args=sys.argv[1:]
if name == "go":
    if args == ["env", "GOVERSION"]: print("go"+os.environ["RUNNER_GO"]); sys.exit(0)
    if args == ["env", "GOPATH"]: print(root/"go"); sys.exit(0)
    if args == ["version"]: print("go version go"+os.environ["RUNNER_GO"]+" linux/amd64"); sys.exit(0)
    if args[:2] == ["version", "-m"]:
        target=pathlib.Path(args[2])
        real=os.environ.get("FIXTURE_REAL_GO")
        if real and target.read_bytes().startswith(b"\\x7fELF"):
            sys.exit(subprocess.run([real,*args],env=dict(os.environ, GOROOT=os.environ["FIXTURE_REAL_GOROOT"])).returncode)
        specs=json.loads((root/"go-install-specs.json").read_text())
        module, version=specs[str(target)].rsplit("@",1)
        print(str(target)+": go"+os.environ["RUNNER_GO"])
        print("\\tpath\\t"+module)
        print("\\tmod\\t"+module.split("/cmd/",1)[0]+"\\t"+version+"\\th1:controlled-fixture")
        sys.exit(0)
    if args[:1] != ["install"]: sys.exit(71)
    module, version=args[1].rsplit("@",1); tool=module.rsplit("/",1)[-1]; target=root/"go/bin"/tool
    records=root/"go-install-specs.json"
    specs=json.loads(records.read_text()) if records.exists() else {}
    specs[str(target)]=args[1]; records.write_text(json.dumps(specs))
    if os.environ.get("FIXTURE_REAL_GO") and tool == "grpcurl":
        target.parent.mkdir(parents=True,exist_ok=True)
        environment=dict(os.environ, GOBIN=str(target.parent), GOROOT=os.environ["FIXTURE_REAL_GOROOT"])
        sys.exit(subprocess.run([os.environ["FIXTURE_REAL_GO"],*args],env=environment).returncode)
elif name == "npm":
    if args == ["--version"]: print(os.environ["FIXTURE_NPM"]); sys.exit(0)
    if args[:2] != ["install", "-g"]: sys.exit(72)
    tool, version=args[2].rsplit("@",1); target=root/"work/provider/node/bin"/tool
else: sys.exit(73)
with (root/"install-argv").open("a") as out: out.write(json.dumps([name,*args])+"\\n")
target.parent.mkdir(parents=True,exist_ok=True)
target.write_text("#!/bin/sh\\nprintf '%s\\n' "+repr(version)+"\\n")
target.chmod(0o755)
'''
        executable(self.bin / "go", installer)
        # Python остаётся настоящим; только сетевой install peer заменён контролируемым.
        executable(self.bin / "python3", '''#!/bin/sh
if [ "$1 $2" = '-m venv' ]; then
  for last; do :; done
  "$FIXTURE_PY" "$@" || exit $?
  for site in "$last"/lib/python*/site-packages; do
    printf '%s\n' "$FIXTURE_SITE_PATHS" > "$site/fixture-parent.pth"
  done
  exit 0
fi
if [ "$1 $2 $3" = '-m pip install' ]; then
  printf '%s\\n' "$*" >> "$FIXTURE_WORLD/python-install-argv"
  exit 0
fi
exec "$FIXTURE_PY" "$@"
''')
        # Операционная возможность base-fixture, не доказательство настоящего apt install:
        # tar получает реальный декодер байтов stdlib lzma. Apt peer остаётся явно
        # подставным; неизвестный argv и испорченный архив не дают успешного status.
        executable(self.bin / "xz", '''#!/usr/bin/env python3
import lzma, sys
if not sys.argv[1:] or any(arg not in ("-d", "--decompress", "-c", "--stdout") for arg in sys.argv[1:]):
 print("fixture xz: unsupported argv", file=sys.stderr); sys.exit(75)
sys.stdout.buffer.write(lzma.decompress(sys.stdin.buffer.read()))
''')
        import lzma
        sample = b"fixture-xz-byte-control\x00\n"
        decoder = [str(self.bin / "xz"), "-d"]
        lawful = subprocess.run(decoder, env=self.env, input=lzma.compress(sample), capture_output=True, timeout=5)
        broken = subprocess.run(decoder, env=self.env, input=b"invalid-xz-archive", capture_output=True, timeout=5)
        assert lawful.returncode == 0 and lawful.stdout == sample, "base-fixture xz не декодировал exact bytes"
        assert broken.returncode != 0, "base-fixture xz принял испорченный архив"
        print("PARITY-READY xz source=base-fixture/stdlib-lzma lawful=exact-bytes bad-archive=refused", flush=True)
        peers = self.base / "python-peers"
        (peers / "pip").mkdir(parents=True)
        (peers / "pip/__init__.py").write_text("")
        (peers / "pip/__main__.py").write_text("import os,sys,pathlib\nassert sys.argv[1] == 'install'\nwith (pathlib.Path(os.environ['FIXTURE_WORLD'])/'python-install-argv').open('a') as out: out.write(repr(sys.argv[1:])+'\\n')\n")
        self.env["PYTHONPATH"] = str(peers) + os.pathsep + os.environ.get("PYTHONPATH", "")
        self.env["FIXTURE_SITE_PATHS"] = "\n".join(p for p in sys.path if "site-packages" in p or "dist-packages" in p)
        # Controlled peers provide synthetic Go/Node/Helm archives. The production
        # bootstrap still verifies their bytes; the Docker workflow digest requires
        # the real parent provider archive. The outer native run proves real CLIs.
        outer_work = Path(os.environ["KANAME_RUNNER_WORK"])
        self.env["FIXTURE_DOCKER_ARCHIVE"] = str(outer_work / "docker.tgz")
        node = self.provider["KANAME_RUNNER_NODE"]
        helm = self.provider["KANAME_RUNNER_HELM"]
        kubectl = self.provider["KANAME_RUNNER_KUBECTL"]
        files = {
            "node": {f"node-v{node}-linux-x64/bin/node": f"#!/bin/sh\necho v{node}\n", f"node-v{node}-linux-x64/bin/npm": installer},
            "go": {"go/bin/go": installer},
            "helm": {"linux-amd64/helm": f"#!/bin/sh\necho {helm}\n"},
        }
        for name, contents in files.items():
            archive = self.work / (name + "-fixture.tar" + (".xz" if name == "node" else ".gz"))
            with tarfile.open(archive, "w:xz" if name == "node" else "w:gz") as tar:
                for filename, body in contents.items():
                    raw = body.encode(); info = tarfile.TarInfo(filename); info.size = len(raw); info.mode = 0o755
                    tar.addfile(info, io.BytesIO(raw))
        (self.work / "kubectl-fixture").write_text("#!/bin/sh\necho " + shlex.quote(json.dumps({"clientVersion": {"gitVersion": kubectl}})) + "\n")
        # These peers must remain available after bootstrap deliberately clears PATH.
        provider_bin = self.work / "provider/bin"
        provider_bin.mkdir(parents=True)
        for name in ("python3",):
            (provider_bin / name).symlink_to(self.bin / name)
        executable(provider_bin / "curl", r'''#!/usr/bin/env python3
import hashlib, os, pathlib, shutil, sys
a=sys.argv[1:]; url=next(x for x in a if x.startswith("https://")); work=pathlib.Path(os.environ["FIXTURE_WORLD"])/"work"
if "go.dev/dl/?mode=json" in url:
 import json
 pin=os.environ["KANAME_RUNNER_GO"]
 content=[{"version":"go"+pin,"files":[{"filename":"go"+pin+".linux-amd64.tar.gz","sha256":hashlib.sha256((work/"go-fixture.tar.gz").read_bytes()).hexdigest()}]}]
 pathlib.Path(a[a.index("-o")+1]).write_text(json.dumps(content));sys.exit(0)
if "nodejs.org" in url:
 file=work/"node-fixture.tar.xz"
elif "go.dev" in url:
 file=work/"go-fixture.tar.gz"
elif "get.helm.sh" in url:
 file=work/"helm-fixture.tar.gz"
elif "dl.k8s.io" in url:
 file=work/"kubectl-fixture"
elif "download.docker.com" in url:
 file=pathlib.Path(os.environ["FIXTURE_DOCKER_ARCHIVE"])
else:
 print("unknown download peer",file=sys.stderr);sys.exit(74)
if os.environ.get("FIXTURE_FETCH_FAIL"):
 print("controlled provider fetch failure",file=sys.stderr);sys.exit(75)
if url.endswith("/SHASUMS256.txt"):
 print(hashlib.sha256(file.read_bytes()).hexdigest()+"  node-v"+os.environ["KANAME_RUNNER_NODE"]+"-linux-x64.tar.xz")
elif url.endswith((".sha256", ".sha256sum")):
 print(hashlib.sha256(file.read_bytes()).hexdigest())
elif "-o" in a:
 shutil.copyfile(file,a[a.index("-o")+1])
else: sys.exit(74)
''')
        # The first download occurs after the controlled PATH is installed.

    def run(self, command, extra_install="", payload=None, expected_stage="command"):
        text = self.payload if payload is None else payload
        if extra_install:
            anchor = 'say "команда: $RUNNER_CMD"\n'
            assert text.count(anchor) == 1, "граница producer payload не найдена"
            text = text.replace(anchor, extra_install + "\n" + anchor)
        # Перенос адресов, не переписывание решения. Другие байты producer сохраняются.
        roots = {"/usr/local": self.prefix, "/work": self.work, "/src": self.src}
        text = remap_roots(text, roots)
        env = dict(self.env)
        for key, value in env.items():
            if key.startswith("RUNNER_"):
                env[key] = remap_roots(value, roots)
        env["RUNNER_CMD"] = remap_roots(command, roots)
        print("PARITY-PRODUCER world=" + self.base.name + " sha256=" + hashlib.sha256(self.payload.encode()).hexdigest(), flush=True)
        result = subprocess.run(["bash", "-c", text], env=env, cwd=self.src, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300 if self.env.get("FIXTURE_REAL_GO") else 90)
        stage = (self.work / ".rc").read_text().strip() if (self.work / ".rc").exists() else "missing"
        print(f"PARITY-PAYLOAD rc={result.returncode} stage={stage}", flush=True)
        if not stage.startswith(expected_stage + " "):
            print(result.stdout, flush=True)
            raise RuntimeError("payload fixture не дошла до команды: " + stage)
        return result


def payload_checks(root, payload, axis="all"):
    installs, checks, blocks = declarations(root)
    failures = 0
    with tempfile.TemporaryDirectory(prefix="stand-parity-") as temp:
        base = Path(temp)
        roots = {"/usr/local": base / "workflow-lawful/usr/local", "/work": base / "workflow-lawful/work", "/src": base / "workflow-lawful/src"}
        sample = "'/usr/local/bin/kubectl' /work/out /src/root /workflow-lawful/bin"
        expected = f"'{roots['/usr/local']}/bin/kubectl' {roots['/work']}/out {roots['/src']}/root /workflow-lawful/bin"
        assert remap_roots(sample, roots) == expected, "remap lawful boundary не сохранена"
        mutant = sample
        for old, new in roots.items():
            mutant = mutant.replace(old, str(new))
        assert mutant != expected, "remap control не отличает прежнюю повторную замену"
        print("PARITY-READY remap=single-pass/original-boundaries workflow-lawful=preserved old-mutant=rejected", flush=True)
        control = World(base / "control", payload)
        assert control.run("true").returncode == 0, "законный opaque control не исполнился"
        probe = '''import importlib, json, pathlib, shutil, subprocess, sys
data=json.loads(pathlib.Path(sys.argv[1]).read_text()); failures=[]
for name, version in data.items():
 if name.startswith('python:'):
  package=name.split(':',1)[1]
  importlib.import_module(package.replace('pyyaml','yaml'))
  from importlib.metadata import version as package_version
  if package_version(package) != version: failures.append(name+': package version mismatch')
  continue
 actual=shutil.which(name)
 if not actual: failures.append(name+': отсутствует'); continue
 if version:
  r=subprocess.run([actual,'version' if name=='go' else '--version'],capture_output=True,text=True)
  if version not in r.stdout+r.stderr: failures.append(name+': ожидалось '+version+', получено '+r.stdout+r.stderr)
print('TOOL-RESULT '+json.dumps(failures,ensure_ascii=False)); sys.exit(bool(failures))
'''
        tool_worlds = (("actual", ""), ("workflow-lawful", "\n".join(blocks)), ("pin-mutant", "")) if axis in ("all", "tools") else ()
        for label, install in tool_worlds:
            # Один и тот же root/layout: меняется только факт workflow install.
            pair_root = base / "workflow-lawful"
            shutil.rmtree(pair_root, ignore_errors=True)
            world = World(pair_root, payload)
            if label == "pin-mutant":
                helper = world.src / ".github/scripts/stand-runner-tools.py"
                text = helper.read_text()
                statements = [node for node in ast.walk(ast.parse(text)) if isinstance(node, ast.Assign) and ast.get_source_segment(text, node) == "spec = words[2]"]
                assert len(statements) == 1, "нет единственного producer Go spec"
                node = statements[0]
                lines = text.splitlines(keepends=True)
                start = sum(map(len, lines[:node.lineno-1])) + node.col_offset
                end = sum(map(len, lines[:node.end_lineno-1])) + node.end_col_offset
                replacement = "spec = words[2].replace(" + repr("@" + installs["grpcurl"][0]) + ", '@v0.0.1042')"
                helper.write_text(text[:start] + replacement + text[end:])
            print("PARITY-CASE tools " + label, flush=True)
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
            elif label == "workflow-lawful":
                assert result.returncode == 0, "workflow lawful install twin не исполнился"
            else:
                assert result.returncode != 0, "tools self-test не увидел однофактный wrong-pin mutant"
                print("PARITY-MUTANT tools rejected=wrong-pin command-stage", flush=True)
        if axis in ("all", "tools"):
            # Existing wrong portable tools are replaced, rather than accepted by
            # command -v. The lawful pair uses the same full production bootstrap.
            existing = World(base / "wrong-existing", payload)
            executable(existing.work / "provider/node/bin/node", "#!/bin/sh\necho v0.0.1042\n")
            repaired = existing.run("node --version")
            assert repaired.returncode == 0 and ("v" + existing.provider["KANAME_RUNNER_NODE"]) in repaired.stdout
            print("PARITY-MUTANT existing-version repaired=exact-workflow-pin", flush=True)
            controls = ("fetch-failure", "PATH-shadowing", "python-package-version", "missing-stdlib", "missing-git-helper")
            for label in controls:
                world = World(base / label, payload)
                if label == "fetch-failure":
                    world.env["FIXTURE_FETCH_FAIL"] = "1"
                elif label == "PATH-shadowing":
                    executable(world.work / "provider/node/bin/git", "#!/bin/sh\necho git version 0.0.1042\n")
                elif label == "python-package-version":
                    pins = declarations(Path(__file__).resolve().parents[2])[0]
                    package = next(name.split(":", 1)[1] for name in pins if name.startswith("python:") and name.split(":", 1)[1] != "pyyaml")
                    fake = world.work / "python-tools" / (package + "-0.0.1042.dist-info")
                    fake.mkdir(parents=True)
                    (fake / "METADATA").write_text("Metadata-Version: 2.1\nName: " + package + "\nVersion: 0.0.1042\n")
                elif label == "missing-stdlib":
                    (world.base / "python-peers/lzma.py").write_text("raise ImportError('controlled missing stdlib')\n")
                elif label == "missing-git-helper":
                    world.env["GIT_EXEC_PATH"] = str(world.base / "absent-git-helpers")
                rejected = world.run("touch /work/out/should-not-run", expected_stage="setup")
                assert rejected.returncode == 125 and not (world.work / "out/should-not-run").exists(), label
                reasons = {"fetch-failure": "controlled provider fetch failure", "PATH-shadowing": "PATH shadowing: git",
                           "python-package-version": "Python package version disagrees:", "missing-stdlib": "controlled missing stdlib",
                           "missing-git-helper": "Git helper closure missing or shadowed"}
                assert reasons[label] in rejected.stdout, (label, rejected.stdout)
                print("PARITY-MUTANT provider rejected=" + label + " stage=setup code=125 payload=not-run", flush=True)
        command = "python3 -c " + shlex.quote("import os,json; print(json.dumps({'present': 'KANAME_STAND_IN_POD' in os.environ, 'keep':os.environ.get('KEEP_SENTINEL')}))")
        env_worlds = (("actual", payload), ("unset-mutant", payload.replace("unset KUBECONFIG KANAME_STAND_IN_POD\n", "unset KUBECONFIG\n", 1))) if axis in ("all", "prologue") else ()
        for label, code in env_worlds:
            pair_root = base / "prologue-world"
            shutil.rmtree(pair_root, ignore_errors=True)
            world = World(pair_root, payload)
            result = world.run(command, payload=code)
            rows = [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{"present":')]
            assert len(rows) == 1 and rows[0]["keep"] == "retained", "env fixture не исполнилась"
            good = rows[0]["present"] is False
            print(f"PARITY-AXIS prologue {label} absent={good}", flush=True)
            if label == "actual": failures += not good
            else:
                assert not good, "prologue self-test не увидел mutant без unset"
                print("PARITY-MUTANT prologue rejected=missing-unset", flush=True)
        if axis in ("all", "opaque"):
            world = World(base / "opaque-cwd", payload)
            result = world.run("cd sub; test \"$PWD\" = \"$(dirname \"$PWD\")/sub\"")
            assert result.returncode == 0, "законный cd внутри opaque payload потерян"
            print("PARITY-OPAQUE cwd сохраняется внутри одной команды: PASS", flush=True)
        if axis == "real-tool":
            world = World(base / "real-grpcurl", payload)
            real_go = shutil.which("go", path=os.environ["PATH"])
            assert real_go, "реальный Go отсутствует"
            world.env["FIXTURE_REAL_GO"] = str(Path(real_go).resolve())
            result = world.run("grpcurl --version")
            assert result.returncode == 0, result.stdout
            record = json.loads((world.work / "runtime-tools.json").read_text())["tools"]["grpcurl"]
            binary = Path(record["path"])
            assert binary.read_bytes().startswith(b"\x7fELF"), "grpcurl не реальный ELF binary"
            metadata = subprocess.run([real_go, "version", "-m", str(binary)], capture_output=True, text=True, check=True)
            rows = [line.strip().split() for line in metadata.stdout.splitlines()]
            assert any(len(row) >= 3 and row[0] == "mod" and row[2] == installs["grpcurl"][0] for row in rows), metadata.stdout
            print("PARITY-REAL grpcurl workflow-pin=" + installs["grpcurl"][0] + " path=" + str(binary) + " sha256=" + hashlib.sha256(binary.read_bytes()).hexdigest(), flush=True)
            print(metadata.stdout + result.stdout, flush=True)
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
        anchor = '( cd /src && bash -- "/work/ship/$step" )'
        assert payload.count(anchor) == 1, "граница step cwd не единственна"
        mutant = World(Path(temp) / "cwd-mutant", payload, env=env, ships=ships)
        bad = mutant.run(env.get("RUNNER_CMD", ""), payload=payload.replace(anchor, '( cd /src/sub && bash -- "/work/ship/$step" )', 1))
        assert bad.returncode != 0, "steps self-test не увидел wrong-cwd mutant"
        print("PARITY-MUTANT steps rejected=wrong-cwd", flush=True)
        failure_ships = Path(temp) / "failure-ships"
        failure_ships.mkdir()
        (failure_ships / "first.sh").write_text('printf "failure nonce=1042\\n" > "$PARITY_OUT/summary.txt"\nexit 23\n')
        (failure_ships / "second.sh").write_text('touch "$PARITY_OUT/not-run"\n')
        failed = World(Path(temp) / "first-failure", payload, env=env, ships=failure_ships)
        failed.env["PARITY_OUT"] = str(failed.work / "out")
        outcome = failed.run(env.get("RUNNER_CMD", ""))
        assert outcome.returncode == 23 and not (failed.work / "out/not-run").exists(), "первый код/остановка steps не сохранены"
        receiver = failed.base / "receiver"
        receiver.mkdir()
        exported = dict(failed.env, RUNNER_ROOT=str(failed.base), RUNNER_WORK=str(failed.work),
                        RUNNER_GLOBS=os.environ["PARITY_EXPORT_GLOBS"], RUNNER_MANIFEST_SH=os.environ["PARITY_EXPORT_MANIFEST"],
                        RUNNER_TAR_SH=os.environ["PARITY_EXPORT_TAR"])
        code = "set -uo pipefail\n" + os.environ["PARITY_EXPORT_FUNCTIONS"] + '\nrunner_exec() { shift; "$@"; }\nrunner_fetch fixture "$1"\n'
        fetch = subprocess.run(["bash", "-c", code, "fetch", str(receiver)], env=exported, capture_output=True, text=True, timeout=30)
        print(fetch.stdout + fetch.stderr, flush=True)
        assert fetch.returncode == 0 and (receiver / "work/out/summary.txt").read_bytes() == b"failure nonce=1042\n", "summary после реальной ошибки шага не экспортирован"
        print("PARITY-STEP-FAILURE code=23 following=not-run summary=exported-exact-bytes", flush=True)
    return 0


if __name__ == "__main__":
    try:
        if sys.argv[1] == "--steps":
            sys.exit(step_checks(Path(sys.argv[2]), Path(sys.argv[3])))
        if sys.argv[1] == "--axis":
            assert sys.argv[2] in ("tools", "prologue", "opaque", "real-tool"), "неизвестная ось fixture"
            sys.exit(payload_checks(Path(sys.argv[3]), Path(sys.argv[4]).read_text(), sys.argv[2]))
        sys.exit(payload_checks(Path(sys.argv[1]), Path(sys.argv[2]).read_text()))
    except Exception as error:
        print(f"PARITY-INVALID: {type(error).__name__}: {error}", flush=True)
        sys.exit(2)
