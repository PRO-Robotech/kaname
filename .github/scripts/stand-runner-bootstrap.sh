#!/usr/bin/env bash
# Shared provider. All version and package literals belong to e2e-newman.yml.
# Source this file so the measured environment also becomes the payload environment.
runner_bootstrap() {
  local root="$1" work="$2" mode="${3:-all}" aptdir package spec url file sum arch nodearch
  [ "$(uname -m)" = x86_64 ] || { echo 'runner provider: only verified amd64 is supported' >&2; return 125; }
  . /etc/os-release
  [ "$ID/$VERSION_ID" = "$KANAME_RUNNER_OS" ] || { echo 'runner provider: OS declaration mismatch' >&2; return 125; }
  mkdir -p "$work" || return 125
  aptdir="$work/apt-provider"
  mkdir -p "$aptdir/lists/partial" "$aptdir/archives/partial" || return 125
  printf 'deb [check-valid-until=no] %s noble main universe\ndeb [check-valid-until=no] %s noble-updates main universe\ndeb [check-valid-until=no] %s noble-security main universe\n' \
    "$KANAME_RUNNER_SNAPSHOT" "$KANAME_RUNNER_SNAPSHOT" "$KANAME_RUNNER_SNAPSHOT" > "$aptdir/sources.list"
  # apt's transport bootstrap is distinct from measured tools. The clean image has
  # no CA bundle; use the same signed archive over HTTP until ca-certificates exists.
  if [ ! -s /etc/ssl/certs/ca-certificates.crt ]; then
    sed -i 's|https://|http://|g' "$aptdir/sources.list" || return 125
  fi
  local -a apt=(apt-get -o "Dir::Etc::sourcelist=$aptdir/sources.list" -o Dir::Etc::sourceparts=-
    -o "Dir::State::lists=$aptdir/lists" -o "Dir::Cache::archives=$aptdir/archives" -o APT::Get::List-Cleanup=0)
  export DEBIAN_FRONTEND=noninteractive
  "${apt[@]}" update -q || return 125
  local -a packages=()
  for spec in $KANAME_RUNNER_APT; do
    [[ "$spec" =~ ^[a-z0-9.+-]+=[a-zA-Z0-9:~.+-]+$ ]] || return 125
    packages+=("$spec")
  done
  [ "${#packages[@]}" -gt 0 ] || return 125
  "${apt[@]}" install -y -q --no-install-recommends --allow-downgrades --no-remove \
    "${packages[@]}" ca-certificates curl tar gzip xz-utils procps python3-venv python3-cryptography || return 125
  for spec in "${packages[@]}"; do
    package="${spec%%=*}"
    [ "$(dpkg-query -W -f='${Version}' "$package")" = "${spec#*=}" ] || return 125
  done
  printf 'RUNNER-PROVIDER apt exact closure verified snapshot=%s packages=%s\n' "$KANAME_RUNNER_SNAPSHOT" "${#packages[@]}"
  [ "$mode" != apt-only ] || return 0
  mkdir -p "$work/provider/bin" || return 125
  export PATH="$work/provider/bin:/usr/bin:/bin"
  arch=amd64; nodearch=x64
  # Upstream release checksums are read only from the declared exact release URL.
  url="https://go.dev/dl/go${KANAME_RUNNER_GO}.linux-$arch.tar.gz"
  curl -fsSL --retry 3 --max-time 300 "$url" -o "$work/go.tar.gz" || return 125
  sum="$(curl -fsSL --retry 3 --max-time 60 "$url.sha256")" || return 125
  printf '%s  %s\n' "$sum" "$work/go.tar.gz" | sha256sum -c --status || return 125
  mkdir -p "$work/provider/go" || return 125
  tar -xz --strip-components=1 -C "$work/provider/go" -f "$work/go.tar.gz" || return 125
  export PATH="$work/provider/go/bin:$PATH"
  file="node-v$KANAME_RUNNER_NODE-linux-$nodearch.tar.xz"
  url="https://nodejs.org/dist/v$KANAME_RUNNER_NODE"
  sum="$(curl -fsSL --retry 3 --max-time 60 "$url/SHASUMS256.txt" | awk -v n="$file" '$2 == n {print $1}')" || return 125
  [[ "$sum" =~ ^[0-9a-f]{64}$ ]] || return 125
  curl -fsSL --retry 3 --max-time 300 "$url/$file" -o "$work/node.tar.xz" || return 125
  printf '%s  %s\n' "$sum" "$work/node.tar.xz" | sha256sum -c --status || return 125
  mkdir -p "$work/provider/node" || return 125
  tar -xJ --strip-components=1 -C "$work/provider/node" -f "$work/node.tar.xz" || return 125
  export PATH="$work/provider/node/bin:$PATH"
  url="https://dl.k8s.io/release/$KANAME_RUNNER_KUBECTL/bin/linux/$arch/kubectl"
  curl -fsSL --retry 3 --max-time 300 "$url" -o "$work/provider/bin/kubectl" || return 125
  sum="$(curl -fsSL --retry 3 --max-time 60 "$url.sha256")" || return 125
  printf '%s  %s\n' "$sum" "$work/provider/bin/kubectl" | sha256sum -c --status || return 125
  url="https://get.helm.sh/helm-$KANAME_RUNNER_HELM-linux-$arch.tar.gz"
  curl -fsSL --retry 3 --max-time 300 "$url" -o "$work/helm.tar.gz" || return 125
  sum="$(curl -fsSL --retry 3 --max-time 60 "$url.sha256sum" | cut -d' ' -f1)" || return 125
  printf '%s  %s\n' "$sum" "$work/helm.tar.gz" | sha256sum -c --status || return 125
  tar -xz -C "$work" -f "$work/helm.tar.gz" "linux-$arch/helm" || return 125
  cp "$work/linux-$arch/helm" "$work/provider/bin/helm" || return 125
  curl -fsSL --retry 3 --max-time 300 "https://download.docker.com/linux/static/stable/x86_64/docker-$KANAME_RUNNER_DOCKER.tgz" -o "$work/docker.tgz" || return 125
  printf '%s  %s\n' "$KANAME_RUNNER_DOCKER_SHA256" "$work/docker.tgz" | sha256sum -c --status || return 125
  tar -xz -C "$work" -f "$work/docker.tgz" docker/docker || return 125
  cp "$work/docker/docker" "$work/provider/bin/docker" || return 125
  chmod 0755 "$work/provider/bin/"* || return 125
  python3 -m venv --clear "$work/provider/python" || return 125
  export PATH="$work/provider/python/bin:$PATH"
  python3 -m pip install --quiet "pip==$KANAME_RUNNER_PIP" "PyYAML==$KANAME_RUNNER_PYYAML" || return 125
  python3 "$root/.github/scripts/stand-runner-tools.py" --root "$root" --work "$work" || return 125
  . "$work/workflow-tools.sh" || return 125
  python3 "$root/.github/scripts/stand-runner-tools.py" --root "$root" --work "$work" --observe || return 125
  if [ -n "${GITHUB_PATH:-}" ]; then
    printf '%s\n' "$work/provider/python/bin" "$work/provider/node/bin" "$work/provider/go/bin" "$work/provider/bin" "$work/bin" "$(go env GOPATH)/bin" >> "$GITHUB_PATH" || return 125
    printf 'PYTHONPATH=%s\nKANAME_RUNNER_WORK=%s\n' "$PYTHONPATH" "$work" >> "$GITHUB_ENV" || return 125
  fi
}
