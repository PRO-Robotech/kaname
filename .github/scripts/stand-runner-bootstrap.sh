#!/usr/bin/env bash
# Shared provider. All version and package literals belong to e2e-newman.yml.
# Source this file so the measured environment also becomes the payload environment.
runner_provider_command() {
  local log="$1" stage="$2" seconds="$3" rc log_rc
  shift 3
  printf 'RUNNER-PROVIDER stage=%s begin utc=%s\n' "$stage" "$(date -u +%FT%TZ)"
  timeout --signal=TERM --kill-after=5 "$seconds" "$@" 2>&1 | tee -a "$log"
  local -a codes=("${PIPESTATUS[@]}")
  rc="${codes[0]}"; log_rc="${codes[1]}"
  printf 'RUNNER-PROVIDER stage=%s rc=%s log_rc=%s utc=%s\n' "$stage" "$rc" "$log_rc" "$(date -u +%FT%TZ)"
  [ "$rc" = 0 ] && [ "$log_rc" = 0 ]
}

runner_bootstrap() {
  local root="$1" work="$2" mode="${3:-all}" aptdir cadir package spec url file sum arch nodearch
  [ "$(uname -m)" = x86_64 ] || { echo 'runner provider: only verified amd64 is supported' >&2; return 125; }
  . /etc/os-release
  [ "$ID/$VERSION_ID" = "$KANAME_RUNNER_OS" ] || { echo 'runner provider: OS declaration mismatch' >&2; return 125; }
  mkdir -p "$work" "$work/out" || return 125
  export KANAME_RUNNER_WORK="$work" DEBIAN_FRONTEND=noninteractive
  if [ "$(id -u)" != 0 ]; then
    sudo --preserve-env=KANAME_RUNNER_OS,KANAME_RUNNER_SNAPSHOT,KANAME_RUNNER_APT \
      bash -c '. "$1"; runner_bootstrap "$2" "$3" apt-only' bootstrap "$root/.github/scripts/stand-runner-bootstrap.sh" "$root" "$work" || return 125
    [ "$mode" != apt-only ] || return 0
    mode=portable
  fi
  if [ "$mode" != portable ]; then
  aptdir="$work/apt-provider"
  mkdir -p "$aptdir/lists/partial" "$aptdir/archives/partial" || return 125
  printf 'deb [check-valid-until=no] %s noble main universe\ndeb [check-valid-until=no] %s noble-updates main universe\ndeb [check-valid-until=no] %s noble-security main universe\n' \
    "$KANAME_RUNNER_SNAPSHOT" "$KANAME_RUNNER_SNAPSHOT" "$KANAME_RUNNER_SNAPSHOT" > "$aptdir/sources.list"
  # The stock image has the Ubuntu archive keyring, but no TLS CA bundle.
  # Bootstrap transport trust from signed Ubuntu main only, with isolated lists
  # and archives so stock image sources cannot expand this preliminary update.
  if [ ! -s /etc/ssl/certs/ca-certificates.crt ]; then
    cadir="$aptdir/ca-bootstrap"
    mkdir -p "$cadir/lists/partial" "$cadir/archives/partial" || return 125
    printf 'deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] http://archive.ubuntu.com/ubuntu noble main\ndeb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] http://archive.ubuntu.com/ubuntu noble-updates main\ndeb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] http://security.ubuntu.com/ubuntu noble-security main\n' > "$cadir/sources.list" || return 125
    local -a caapt=(apt-get -o APT::Update::Error-Mode=any -o Acquire::Languages=none -o Acquire::http::Timeout=15 -o Acquire::https::Timeout=15 -o Acquire::Retries=0
      -o "Dir::Etc::sourcelist=$cadir/sources.list" -o Dir::Etc::sourceparts=-
      -o "Dir::State::lists=$cadir/lists" -o "Dir::Cache::archives=$cadir/archives" -o APT::Get::List-Cleanup=0)
    runner_provider_command "$work/out/step-provider-install.log" ca-index 60 \
      "${caapt[@]}" update -q &&
    runner_provider_command "$work/out/step-provider-install.log" ca-install 60 \
      "${caapt[@]}" install -y -q --no-install-recommends --no-remove ca-certificates || return 125
  fi
  local -a apt=(apt-get -o APT::Update::Error-Mode=any -o Acquire::Languages=none -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 -o Acquire::Retries=0 -o "Dir::Etc::sourcelist=$aptdir/sources.list" -o Dir::Etc::sourceparts=-
    -o "Dir::State::lists=$aptdir/lists" -o "Dir::Cache::archives=$aptdir/archives" -o APT::Get::List-Cleanup=0)
  export DEBIAN_FRONTEND=noninteractive
  runner_provider_command "$work/out/step-provider-install.log" snapshot-index 170 "${apt[@]}" update -q || return 125
  local -a packages=()
  for spec in $KANAME_RUNNER_APT; do
    [[ "$spec" =~ ^[a-z0-9.+-]+=[a-zA-Z0-9:~.+-]+$ ]] || return 125
    packages+=("$spec")
  done
  [ "${#packages[@]}" -gt 0 ] || return 125
  runner_provider_command "$work/out/step-provider-install.log" exact-install 300 "${apt[@]}" install -y -q --no-install-recommends --allow-downgrades --no-remove \
    "${packages[@]}" ca-certificates curl tar gzip xz-utils procps python3-venv python3-cryptography || return 125
  for spec in "${packages[@]}"; do
    package="${spec%%=*}"
    [ "$(dpkg-query -W -f='${Version}' "$package")" = "${spec#*=}" ] || return 125
  done
  printf 'RUNNER-PROVIDER apt exact closure verified snapshot=%s packages=%s\n' "$KANAME_RUNNER_SNAPSHOT" "${#packages[@]}"
  [ "$mode" != apt-only ] || return 0
  fi
  mkdir -p "$work/provider/bin" || return 125
  export PATH="$work/provider/bin:/usr/bin:/bin"
  arch=amd64; nodearch=x64
  # Upstream release checksums are read only from the declared exact release URL.
  printf 'RUNNER-PROVIDER artifact=go version=%s\n' "$KANAME_RUNNER_GO"
  url="https://go.dev/dl/go${KANAME_RUNNER_GO}.linux-$arch.tar.gz"
  curl -fsSL --retry 1 --connect-timeout 20 --max-time 180 "$url" -o "$work/go.tar.gz" || return 125
  curl -fsSL --retry 1 --connect-timeout 20 --max-time 60 'https://go.dev/dl/?mode=json&include=all' -o "$work/go-releases.json" || return 125
  sum="$(python3 -c 'import json,sys; rows=json.load(open(sys.argv[1])); found=[f["sha256"] for row in rows if row["version"]=="go"+sys.argv[2] for f in row["files"] if f["filename"]=="go"+sys.argv[2]+".linux-"+sys.argv[3]+".tar.gz"]; assert len(found)==1; print(found[0])' "$work/go-releases.json" "$KANAME_RUNNER_GO" "$arch")" || return 125
  printf '%s  %s\n' "$sum" "$work/go.tar.gz" | sha256sum -c --status || return 125
  mkdir -p "$work/provider/go" || return 125
  tar -xz --strip-components=1 -C "$work/provider/go" -f "$work/go.tar.gz" || return 125
  export GOROOT="$work/provider/go" GOTOOLCHAIN=local
  export PATH="$GOROOT/bin:$PATH"
  printf 'RUNNER-PROVIDER artifact=node version=%s\n' "$KANAME_RUNNER_NODE"
  file="node-v$KANAME_RUNNER_NODE-linux-$nodearch.tar.xz"
  url="https://nodejs.org/dist/v$KANAME_RUNNER_NODE"
  sum="$(curl -fsSL --retry 1 --connect-timeout 20 --max-time 60 "$url/SHASUMS256.txt" | awk -v n="$file" '$2 == n {print $1}')" || return 125
  [[ "$sum" =~ ^[0-9a-f]{64}$ ]] || return 125
  curl -fsSL --retry 1 --connect-timeout 20 --max-time 180 "$url/$file" -o "$work/node.tar.xz" || return 125
  printf '%s  %s\n' "$sum" "$work/node.tar.xz" | sha256sum -c --status || return 125
  mkdir -p "$work/provider/node" || return 125
  tar -xJ --strip-components=1 -C "$work/provider/node" -f "$work/node.tar.xz" || return 125
  export NPM_CONFIG_PREFIX="$work/provider/node"
  export PATH="$NPM_CONFIG_PREFIX/bin:$PATH"
  url="https://dl.k8s.io/release/$KANAME_RUNNER_KUBECTL/bin/linux/$arch/kubectl"
  curl -fsSL --retry 1 --connect-timeout 20 --max-time 180 "$url" -o "$work/provider/bin/kubectl" || return 125
  sum="$(curl -fsSL --retry 1 --connect-timeout 20 --max-time 60 "$url.sha256")" || return 125
  printf '%s  %s\n' "$sum" "$work/provider/bin/kubectl" | sha256sum -c --status || return 125
  url="https://get.helm.sh/helm-$KANAME_RUNNER_HELM-linux-$arch.tar.gz"
  curl -fsSL --retry 1 --connect-timeout 20 --max-time 180 "$url" -o "$work/helm.tar.gz" || return 125
  sum="$(curl -fsSL --retry 1 --connect-timeout 20 --max-time 60 "$url.sha256sum" | cut -d' ' -f1)" || return 125
  printf '%s  %s\n' "$sum" "$work/helm.tar.gz" | sha256sum -c --status || return 125
  tar -xz -C "$work" -f "$work/helm.tar.gz" "linux-$arch/helm" || return 125
  cp "$work/linux-$arch/helm" "$work/provider/bin/helm" || return 125
  curl -fsSL --retry 1 --connect-timeout 20 --max-time 180 "https://download.docker.com/linux/static/stable/x86_64/docker-$KANAME_RUNNER_DOCKER.tgz" -o "$work/docker.tgz" || return 125
  printf '%s  %s\n' "$KANAME_RUNNER_DOCKER_SHA256" "$work/docker.tgz" | sha256sum -c --status || return 125
  tar -xz -C "$work" -f "$work/docker.tgz" docker/docker || return 125
  cp "$work/docker/docker" "$work/provider/bin/docker" || return 125
  chmod 0755 "$work/provider/bin/"* || return 125
  python3 -m venv --clear "$work/provider/python" || return 125
  export PATH="$work/provider/python/bin:$PATH"
  python3 -m pip install --quiet "pip==$KANAME_RUNNER_PIP" "PyYAML==$KANAME_RUNNER_PYYAML" || return 125
  # Expose only the signing distribution supplied by the signed apt snapshot,
  # not all system site-packages. Keep pip/PyYAML and the venv isolation intact.
  python3 - <<'PY' || return 125
import importlib.metadata
from email.parser import Parser
from pathlib import Path
import subprocess
import sysconfig

source = Path('/usr/lib/python3/dist-packages')
target = Path(sysconfig.get_path('purelib'))
files = subprocess.check_output(['dpkg-query', '-L', 'python3-cryptography', 'python3-cffi-backend'], text=True).splitlines()
names = {Path(path).relative_to(source).parts[0] for path in files
         if Path(path).is_relative_to(source) and Path(path) != source}
metadata = {name for name in names if name.startswith('cryptography') and name.endswith(('.dist-info', '.egg-info'))}
backend = {name for name in names if name.startswith('_cffi_backend.') and name.endswith('.so')}
formats = {suffix: sorted(name for name in metadata if name.endswith(suffix))
           for suffix in ('.dist-info', '.egg-info')}
if 'cryptography' not in names or not metadata or any(len(items) > 1 for items in formats.values()) or len(backend) != 1:
    raise RuntimeError('signing apt distribution closure missing or ambiguous')
versions = set()
for name in metadata:
    record = source / name / ('METADATA' if name.endswith('.dist-info') else 'PKG-INFO')
    if str(record) not in files:
        raise RuntimeError('signing metadata record not owned by apt')
    headers = Parser().parsestr(record.read_text())
    if headers.get_all('Name') != ['cryptography'] or len(headers.get_all('Version', [])) != 1 or not headers['Version']:
        raise RuntimeError('signing metadata identity invalid')
    versions.add(headers['Version'])
if len(versions) != 1:
    raise RuntimeError('signing metadata versions disagree')
expected_version = next(iter(versions))
canonical_metadata = (formats['.dist-info'] or formats['.egg-info'])[0]
for name in {'cryptography', canonical_metadata} | backend:
    origin = source / name
    if not origin.exists():
        raise RuntimeError('signing apt distribution file missing: ' + str(origin))
    (target / name).symlink_to(origin, target_is_directory=origin.is_dir())

import cryptography, _cffi_backend
if Path(cryptography.__file__).resolve() != (source / 'cryptography/__init__.py').resolve() or Path(_cffi_backend.__file__).resolve() != (source / next(iter(backend))).resolve():
    raise RuntimeError('signing apt distribution shadowed')
if cryptography.__version__ != expected_version or importlib.metadata.version('cryptography') != expected_version:
    raise RuntimeError('signing module/metadata version disagrees with apt')
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
key = ec.generate_private_key(ec.SECP256R1())
pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
key = serialization.load_pem_private_key(pem, password=None)
message = b'runner-signing-closure'
signature = key.sign(message, ec.ECDSA(hashes.SHA256()))
r, s = utils.decode_dss_signature(signature)
signature = utils.encode_dss_signature(r, s)
key.public_key().verify(signature, message, ec.ECDSA(hashes.SHA256()))
try:
    key.public_key().verify(signature, message + b'-changed', ec.ECDSA(hashes.SHA256()))
except InvalidSignature:
    pass
else:
    raise RuntimeError('signing closure accepted a changed message')
print('RUNNER-PROVIDER signing ES256 verified cryptography=' + importlib.metadata.version('cryptography'))
PY
  python3 "$root/.github/scripts/stand-runner-tools.py" --root "$root" --work "$work" || return 125
  . "$work/workflow-tools.sh" || return 125
  python3 "$root/.github/scripts/stand-runner-tools.py" --root "$root" --work "$work" --observe || return 125
  if [ -n "${GITHUB_PATH:-}" ]; then
    printf '%s\n' "$work/provider/python/bin" "$work/provider/node/bin" "$work/provider/go/bin" "$work/provider/bin" "$work/bin" "$(go env GOPATH)/bin" >> "$GITHUB_PATH" || return 125
    printf 'PYTHONPATH=%s\nKANAME_RUNNER_WORK=%s\nGOROOT=%s\nGOTOOLCHAIN=local\nNPM_CONFIG_PREFIX=%s\n' "$PYTHONPATH" "$work" "$GOROOT" "$NPM_CONFIG_PREFIX" >> "$GITHUB_ENV" || return 125
  fi
}
