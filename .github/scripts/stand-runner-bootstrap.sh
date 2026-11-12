#!/usr/bin/env bash
# Общий поставщик. Все литералы версий и пакетов принадлежат e2e-newman.yml.
# Подключайте этот файл через source, чтобы измеренное окружение стало окружением полезной нагрузки.
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


# Кэш не является источником доверия: InRelease закреплён суммой workflow,
# а APT повторно проверяет подпись и хэши Packages из локального зеркала.
runner_apt_cache_key() {
  printf '%s\0' 'apt-cache-v1' "$KANAME_RUNNER_OS" "$KANAME_RUNNER_SNAPSHOT" "$KANAME_RUNNER_APT" "$KANAME_RUNNER_RELEASES" | sha256sum | cut -d' ' -f1
}

# Восстановленный архив содержит только данные. Root никогда не использует его
# каталоги как рабочие пути APT и не следует его ссылкам.
runner_apt_import_cache() {
  local cache="$1" aptdir="$2" file directory
  [ -d "$cache" ] && [ ! -L "$cache" ] || return 1
  for directory in lists archives; do
    [ -d "$cache/$directory" ] && [ ! -L "$cache/$directory" ] || return 1
  done
  [ -f "$cache/verified-cache" ] && [ ! -L "$cache/verified-cache" ] && [ "$(stat -c %h "$cache/verified-cache")" = 1 ] || return 1
  cp -- "$cache/verified-cache" "$aptdir/verified-cache" || return 1
  for directory in lists archives; do
    for file in "$cache/$directory/"*; do
      [ -e "$file" ] || continue
      [ -f "$file" ] && [ ! -L "$file" ] && [ "$(stat -c %h "$file")" = 1 ] || return 1
      case "$directory/${file##*/}" in
        lists/*_InRelease|lists/*_binary-amd64_Packages|lists/*_binary-amd64_Packages.lz4|lists/*_binary-amd64_Packages.xz|archives/*.deb) ;;
        *) return 1;;
      esac
      cp -- "$file" "$aptdir/$directory/${file##*/}" || return 1
    done
  done
}

runner_apt_archive_hashes() {
  local work="$1" aptdir="$2" file name wanted="$1/apt-archives.wanted" checks="$1/apt-archives.sha256"
  : > "$wanted" || return 1
  for file in "$aptdir/archives/"*.deb; do
    [ -e "$file" ] || continue
    name="${file##*/}"
    [[ "$name" =~ ^[a-z0-9][a-z0-9+.-]*_[a-zA-Z0-9%:~+.-]+_(amd64|all)\.deb$ ]] && [ -f "$file" ] && [ ! -L "$file" ] || return 1
    printf '%s\n' "$name" >> "$wanted" || return 1
  done
  [ -s "$wanted" ] || return 0
  # Packages здесь уже удостоверены signed file-only apt update. Сверяем САМИ
  # байты deb, не полагаясь на доверие APT к собственному root-owned archive cache.
  awk -v wanted="$wanted" '
    BEGIN { while ((getline n < wanted)>0) { k=n; gsub(/%3A/,"%3a",k); gsub(/:/,"%3a",k); if (k in names) bad=1; names[k]=n }; close(wanted); RS=""; FS="\n" }
    { package=version=arch=sha="";
      for (i=1;i<=NF;i++) {
        if ($i ~ /^Package: /) package=substr($i,10);
        else if ($i ~ /^Version: /) version=substr($i,10);
        else if ($i ~ /^Architecture: /) arch=substr($i,15);
        else if ($i ~ /^SHA256: /) sha=substr($i,9);
      }
      gsub(/:/,"%3a",version); key=package "_" version "_" arch ".deb";
      if (key in names) {
        if (sha !~ /^[a-f0-9]+$/ || length(sha)!=64 || ((key in hashes) && hashes[key]!=sha)) bad=1;
        hashes[key]=sha
      }
    }
    END { for (key in names) { if (!(key in hashes)) bad=1; else print hashes[key] "  " names[key] }; if (bad) exit 1 }
  ' "$work/apt-offline/dists/"*/main/binary-amd64/Packages "$work/apt-offline/dists/"*/universe/binary-amd64/Packages > "$checks" || return 1
  (cd "$aptdir/archives" && sha256sum --strict --check "$checks") || return 1
}

runner_apt_export_cache() {
  local work="$1" aptdir="$2" cache="$1/apt-cache" next="$1/apt-cache.next" file directory
  rm -rf -- "$next" || return 1
  mkdir -m 0755 -p "$next/lists" "$next/archives" || return 1
  cp -- "$aptdir/verified-cache" "$next/verified-cache" || return 1
  for directory in lists archives; do
    for file in "$aptdir/$directory/"*; do
      [ -f "$file" ] && [ ! -L "$file" ] || continue
      case "$directory/${file##*/}" in
        lists/*_InRelease|lists/*_binary-amd64_Packages|lists/*_binary-amd64_Packages.lz4|lists/*_binary-amd64_Packages.xz|archives/*.deb)
          cp -- "$file" "$next/$directory/${file##*/}" || return 1;;
      esac
    done
  done
  # locks/partial/CA state не публикуются; обычный UID cache action читает всё.
  chmod 0644 "$next/verified-cache" "$next/lists/"* || return 1
  for file in "$next/archives/"*.deb; do [ ! -e "$file" ] || chmod 0644 "$file" || return 1; done
  rm -rf -- "$cache" || return 1
  mv -- "$next" "$cache" || return 1
}

runner_apt_cached_snapshot() {
  local work="$1" aptdir="$2" prefix suite sum extra component input offline="$1/apt-offline" count=0
  local -A seen=()
  prefix="${KANAME_RUNNER_SNAPSHOT#https://}"; prefix="${prefix//\//_}"
  rm -rf -- "$offline" || return 1
  mkdir -p "$offline/dists" || return 1
  while read -r sum suite extra; do
    [ -n "$sum$suite$extra" ] || continue
    [[ "$sum" =~ ^[a-f0-9]{64}$ && "$suite" =~ ^noble(-updates|-security)?$ && -z "$extra" && -z "${seen[$suite]:-}" ]] || return 1
    seen[$suite]=1; count=$((count+1))
    input="$aptdir/lists/${prefix}dists_${suite}_InRelease"
    [ -f "$input" ] && [ ! -L "$input" ] || return 1
    printf '%s  %s\n' "$sum" "$input" | sha256sum --check --status || return 1
    mkdir -p "$offline/dists/$suite" || return 1
    cp -- "$input" "$offline/dists/$suite/InRelease" || return 1
    for component in main universe; do
      local -a indices=("$aptdir/lists/${prefix}dists_${suite}_${component}_binary-amd64_Packages"*)
      [ "${#indices[@]}" = 1 ] && [ -f "${indices[0]}" ] && [ ! -L "${indices[0]}" ] || return 1
      mkdir -p "$offline/dists/$suite/$component/binary-amd64" || return 1
      /usr/lib/apt/apt-helper cat-file "${indices[0]}" > "$offline/dists/$suite/$component/binary-amd64/Packages" || return 1
    done
  done <<< "$KANAME_RUNNER_RELEASES"
  [ "$count" = 3 ] && [ -n "${seen[noble]:-}" ] && [ -n "${seen[noble-updates]:-}" ] && [ -n "${seen[noble-security]:-}" ]
}

runner_apt_from_cache() {
  local work="$1" aptdir="$2" key="$3"; shift 3
  [ -f "$aptdir/verified-cache" ] && [ ! -L "$aptdir/verified-cache" ] && [ "$(cat "$aptdir/verified-cache")" = "$key" ] || return 1
  runner_apt_cached_snapshot "$work" "$aptdir" || return 1
  local offline="$work/apt-offline" lists="$work/apt-offline-lists" sources="$work/apt-offline.sources.list" suite
  rm -rf -- "$lists" || return 1
  mkdir -p "$lists/partial" || return 1
  : > "$sources" || return 1
  for suite in noble noble-updates noble-security; do
    printf 'deb [arch=amd64 check-valid-until=no signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] file:%s %s main universe\n' "$offline" "$suite" >> "$sources" || return 1
  done
  local -a apt=(apt-get -o APT::Update::Error-Mode=any -o APT::Architecture=amd64 -o APT::Architectures=amd64
    -o Acquire::Languages=none -o Acquire::By-Hash=false -o Acquire::CompressionTypes::Order=uncompressed
    -o Acquire::IndexTargets::deb::CNF::DefaultEnabled=false -o Acquire::IndexTargets::deb::DEP-11::DefaultEnabled=false
    -o "Dir::Etc::sourcelist=$sources" -o Dir::Etc::sourceparts=- -o "Dir::State::lists=$lists"
    -o "Dir::Cache::archives=$aptdir/archives" -o Binary::apt-get::APT::Keep-Downloaded-Packages=true -o APT::Keep-Downloaded-Packages=true -o APT::Get::List-Cleanup=0)
  runner_provider_command "$work/out/step-provider-install.log" cached-signed-index 60 "${apt[@]}" update -q || return 1
  runner_apt_archive_hashes "$work" "$aptdir" || return 1
  # --no-download вместе с --download-only может вернуть 0 при недостающем deb.
  # Просим APT только перечислить загрузки: непустой список означает cache miss,
  # до dpkg и без попытки получить пакет из сети или локального зеркала.
  local closure_log="$work/out/step-provider-closure.log" line
  : > "$closure_log" || return 1
  runner_provider_command "$closure_log" cached-closure 60 "${apt[@]}" install --print-uris --download-only -y -q --no-install-recommends --allow-downgrades --no-remove "$@" || return 1
  while IFS= read -r line; do [[ "$line" != \'* ]] || return 1; done < "$closure_log"
  # Ошибка самой установки не становится cache miss и не маскируется повтором.
  runner_provider_command "$work/out/step-provider-install.log" cached-exact-install 300 "${apt[@]}" install --no-download -y -q --no-install-recommends --allow-downgrades --no-remove "$@" || return 2
  printf 'RUNNER-PROVIDER apt cache=verified-offline\n'
}

runner_bootstrap() {
  local root="$1" work="$2" mode="${3:-all}" aptdir cadir package spec url file sum arch nodearch
  [ "$(uname -m)" = x86_64 ] || { echo 'runner provider: only verified amd64 is supported' >&2; return 125; }
  . /etc/os-release
  [ "$ID/$VERSION_ID" = "$KANAME_RUNNER_OS" ] || { echo 'runner provider: OS declaration mismatch' >&2; return 125; }
  mkdir -p "$work" "$work/out" || return 125
  export KANAME_RUNNER_WORK="$work" DEBIAN_FRONTEND=noninteractive
  if [ "$(id -u)" != 0 ]; then
    sudo --preserve-env=KANAME_RUNNER_OS,KANAME_RUNNER_SNAPSHOT,KANAME_RUNNER_APT,KANAME_RUNNER_RELEASES \
      bash -c '. "$1"; runner_bootstrap "$2" "$3" apt-only' bootstrap "$root/.github/scripts/stand-runner-bootstrap.sh" "$root" "$work" || return 125
    [ "$mode" != apt-only ] || return 0
    mode=portable
  fi
  if [ "$mode" != portable ]; then
  aptdir="$work/apt-provider"
  rm -rf -- "$aptdir" || return 125
  mkdir -p "$aptdir/lists/partial" "$aptdir/archives/partial" || return 125
  runner_apt_import_cache "$work/apt-cache" "$aptdir" || true
  local -a packages=()
  for spec in $KANAME_RUNNER_APT; do
    [[ "$spec" =~ ^[a-z0-9.+-]+=[a-zA-Z0-9:~.+-]+$ ]] || return 125
    packages+=("$spec")
  done
  [ "${#packages[@]}" -gt 0 ] || return 125
  local -a closure=("${packages[@]}" ca-certificates curl tar gzip xz-utils procps python3-venv python3-cryptography)
  local cache_rc=0 cache_key
  cache_key="$(runner_apt_cache_key)" || return 125
  runner_apt_from_cache "$work" "$aptdir" "$cache_key" "${closure[@]}" || cache_rc=$?
  [ "$cache_rc" != 2 ] || return 125
  if [ "$cache_rc" != 0 ]; then
    printf 'RUNNER-PROVIDER apt cache=miss-or-invalid; signed snapshot required\n'
    # Холодный путь не наследует ни одного байта отвергнутого кэша.
    rm -rf -- "$aptdir" || return 125
    mkdir -p "$aptdir/lists/partial" "$aptdir/archives/partial" || return 125
    # Без валидного кэша начальное доверие TLS ставится из подписанного Ubuntu main.
    if [ ! -s /etc/ssl/certs/ca-certificates.crt ]; then
      cadir="$aptdir/ca-bootstrap"
      mkdir -p "$cadir/lists/partial" "$cadir/archives/partial" || return 125
      printf 'deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] http://archive.ubuntu.com/ubuntu noble main\ndeb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] http://archive.ubuntu.com/ubuntu noble-updates main\ndeb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] http://security.ubuntu.com/ubuntu noble-security main\n' > "$cadir/sources.list" || return 125
      local -a caapt=(apt-get -o APT::Update::Error-Mode=any -o Acquire::Languages=none -o Acquire::IndexTargets::deb::CNF::DefaultEnabled=false -o Acquire::http::Timeout=15 -o Acquire::https::Timeout=15 -o Acquire::Retries=0
        -o "Dir::Etc::sourcelist=$cadir/sources.list" -o Dir::Etc::sourceparts=-
        -o "Dir::State::lists=$cadir/lists" -o "Dir::Cache::archives=$cadir/archives" -o APT::Get::List-Cleanup=0)
      runner_provider_command "$work/out/step-provider-install.log" ca-index 60 "${caapt[@]}" update -q &&
      runner_provider_command "$work/out/step-provider-install.log" ca-install 60 "${caapt[@]}" install -y -q --no-install-recommends --no-remove ca-certificates || return 125
    fi
    : > "$aptdir/sources.list" || return 125
    for suite in noble noble-updates noble-security; do
      printf 'deb [arch=amd64 check-valid-until=no signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] %s %s main universe\n' "$KANAME_RUNNER_SNAPSHOT" "$suite" >> "$aptdir/sources.list" || return 125
    done
    local -a apt=(apt-get -o APT::Update::Error-Mode=any -o APT::Architecture=amd64 -o APT::Architectures=amd64
      -o Acquire::Languages=none -o Acquire::IndexTargets::deb::CNF::DefaultEnabled=false -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 -o Acquire::Retries=2
      -o "Dir::Etc::sourcelist=$aptdir/sources.list" -o Dir::Etc::sourceparts=- -o "Dir::State::lists=$aptdir/lists"
      -o "Dir::Cache::archives=$aptdir/archives" -o Binary::apt-get::APT::Keep-Downloaded-Packages=true -o APT::Keep-Downloaded-Packages=true -o APT::Get::List-Cleanup=0)
    runner_provider_command "$work/out/step-provider-install.log" snapshot-index 420 "${apt[@]}" update -q || return 125
    runner_apt_cached_snapshot "$work" "$aptdir" || return 125
    runner_provider_command "$work/out/step-provider-install.log" exact-install 300 "${apt[@]}" install -y -q --no-install-recommends --allow-downgrades --no-remove "${closure[@]}" || return 125
  fi
  for spec in "${packages[@]}"; do
    package="${spec%%=*}"
    [ "$(dpkg-query -W -f='${Version}' "$package")" = "${spec#*=}" ] || return 125
  done
  printf '%s\n' "$cache_key" > "$aptdir/verified-cache" || return 125
  runner_apt_export_cache "$work" "$aptdir" || printf '::warning::проверенные инструменты установлены, но APT-кэш не опубликован\n'
  printf 'RUNNER-PROVIDER apt exact closure verified snapshot=%s packages=%s\n' "$KANAME_RUNNER_SNAPSHOT" "${#packages[@]}"
  [ "$mode" != apt-only ] || return 0
  fi
  mkdir -p "$work/provider/bin" || return 125
  export PATH="$work/provider/bin:/usr/bin:/bin"
  arch=amd64; nodearch=x64
  # Контрольные суммы релиза upstream читаются только с объявленного URL точного релиза.
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
  # Открываем только signing-distribution из подписанного снимка apt,
  # не все системные site-packages. Сохраняем изоляцию pip/PyYAML и venv.
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
