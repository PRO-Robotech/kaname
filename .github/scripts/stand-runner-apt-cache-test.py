#!/usr/bin/env python3
"""Проверка настоящего APT в одноразовом Ubuntu без сети и без изменения хоста."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import lzma
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def run(argv, **kwargs):
    return subprocess.run(argv, check=True, **kwargs)


def prepare(root):
    home = root / "gpg"
    home.mkdir(mode=0o700)
    gpg = ["gpg", "--homedir", str(home), "--batch", "--pinentry-mode", "loopback", "--passphrase", ""]
    run(gpg + ["--quick-generate-key", "APT cache test <cache@example.invalid>", "rsa2048", "sign", "0"], stdout=subprocess.DEVNULL)
    with (root / "test-keyring.gpg").open("wb") as out:
        run(gpg + ["--export"], stdout=out)
    archives = root / "seed/archives"
    lists = root / "seed/lists"
    archives.mkdir(parents=True)
    lists.mkdir()
    records = []
    for name, dependency in (("kaname-cache-fixture", ""), ("kaname-cache-dependent", "Depends: kaname-cache-fixture (= 1:1.0)\n")):
        package = root / name
        (package / "DEBIAN").mkdir(parents=True)
        (package / "DEBIAN/control").write_text(
            f"Package: {name}\nVersion: 1:1.0\nArchitecture: all\nMaintainer: Test <cache@example.invalid>\n"
            + dependency + "Description: disposable APT cache test\n")
        target = package / "usr/share" / name
        target.mkdir(parents=True)
        (target / "proof").write_text(name + "\n")
        archive = archives / (name + "_1%3a1.0_all.deb")
        run(["dpkg-deb", "--build", "--root-owner-group", str(package), str(archive)], stdout=subprocess.DEVNULL)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        records.append(f"Package: {name}\nVersion: 1:1.0\nArchitecture: all\n{dependency}"
                       f"Filename: pool/{archive.name}\nSize: {archive.stat().st_size}\nSHA256: {digest}\nDescription: disposable test\n\n")
    pins = []
    prefix = "snapshot.ubuntu.com_ubuntu_20261025T000000Z_"
    for suite in ("noble", "noble-updates", "noble-security"):
        files = {}
        for component in ("main", "universe"):
            data = ("".join(records) if suite == "noble" and component == "main" else "").encode()
            files[component + "/binary-amd64/Packages"] = data
            # Ubuntu публикует также сжатый индекс. Локальное зеркало кэша
            # содержит только распакованный: порядок APT обязан выбрать его.
            files[component + "/binary-amd64/Packages.xz"] = lzma.compress(data)
            (lists / (prefix + "dists_" + suite + "_" + component + "_binary-amd64_Packages")).write_bytes(data)
        release = root / (suite + ".Release")
        release.write_text(f"Origin: Cache fixture\nLabel: Cache fixture\nSuite: {suite}\nCodename: {suite}\n"
                           + "Date: " + datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")
                           + "\nArchitectures: amd64\nComponents: main universe\nSHA256:\n"
                           + "".join(f" {hashlib.sha256(data).hexdigest()} {len(data):16d} {name}\n" for name, data in files.items()))
        signed = lists / (prefix + "dists_" + suite + "_InRelease")
        run(gpg + ["--digest-algo", "SHA256", "--output", str(signed), "--clearsign", str(release)])
        pins.append(hashlib.sha256(signed.read_bytes()).hexdigest() + " " + suite)
    (root / "releases").write_text("\n".join(pins) + "\n")


INSIDE = r'''
set -euo pipefail
test -f /.dockerenv
# У hosted runner уже может быть свой порядок: добавление элемента списка
# командной строкой не ставит его перед существующим предпочтением xz.
printf 'Acquire::CompressionTypes::Order { "xz"; };\n' > /etc/apt/apt.conf.d/99-cache-test-order
. /src/.github/scripts/stand-runner-bootstrap.sh
export KANAME_RUNNER_OS=ubuntu/24.04
export KANAME_RUNNER_SNAPSHOT=https://snapshot.ubuntu.com/ubuntu/20261025T000000Z/
export KANAME_RUNNER_APT='kaname-cache-fixture=1:1.0'
export KANAME_RUNNER_RELEASES="$(cat /fixture/releases)"
key=$(runner_apt_cache_key)
prefix=snapshot.ubuntu.com_ubuntu_20261025T000000Z_dists_
count=0
fresh() {
  rm -rf /case
  mkdir -m 0755 -p /case/out /case/apt-provider/lists/partial /case/apt-provider/archives/partial
  cp -a /fixture/seed /case/apt-cache
  printf '%s\n' "$key" > /case/apt-cache/verified-cache
}
check() {
  local expected=$1 name=$2 rc=0; shift 2
  "$@" > /case/out/result.log 2>&1 || rc=$?
  if [ "$rc" != "$expected" ]; then
    cat /case/out/result.log
    echo "APT-CACHE FAIL $name expected=$expected actual=$rc"; exit 1
  fi
  count=$((count+1)); echo "APT-CACHE PASS $name rc=$rc"
}
attempt() {
  runner_apt_import_cache /case/apt-cache /case/apt-provider || return 1
  runner_apt_from_cache /case /case/apt-provider "$key" "${@:-kaname-cache-fixture=1:1.0}"
}
fresh; rm /case/apt-cache/verified-cache
check 1 missing-marker attempt
fresh; echo changed > /case/apt-cache/verified-cache
check 1 wrong-marker attempt
fresh; echo changed >> "/case/apt-cache/lists/${prefix}noble_InRelease"
check 1 changed-release attempt
fresh; original_releases="$KANAME_RUNNER_RELEASES"; original_key="$key"
sed -i 's/Origin: Cache fixture/Origin: Changed fixture/' "/case/apt-cache/lists/${prefix}noble_InRelease"
bad_sum=$(sha256sum "/case/apt-cache/lists/${prefix}noble_InRelease"); bad_sum=${bad_sum%% *}
KANAME_RUNNER_RELEASES="$bad_sum noble$(printf '%s\n' "$original_releases" | tail -n +2 | sed '1s/^/\n/')"
key=$(runner_apt_cache_key); printf '%s\n' "$key" > /case/apt-cache/verified-cache
check 1 matching-hash-invalid-signature attempt
KANAME_RUNNER_RELEASES="$original_releases"; key="$original_key"
fresh; echo changed >> "/case/apt-cache/lists/${prefix}noble_main_binary-amd64_Packages"
check 1 changed-signed-packages attempt
fresh; truncate -s 12 '/case/apt-cache/archives/kaname-cache-fixture_1%3a1.0_all.deb'
check 1 truncated-deb attempt
fresh; printf X | dd of='/case/apt-cache/archives/kaname-cache-fixture_1%3a1.0_all.deb' bs=1 seek=20 conv=notrunc status=none
check 1 same-size-changed-deb attempt
fresh; cp '/case/apt-cache/archives/kaname-cache-fixture_1%3a1.0_all.deb' '/case/apt-cache/archives/kaname-cache-fixture_1:1.0_all.deb'
printf X | dd of='/case/apt-cache/archives/kaname-cache-fixture_1%3a1.0_all.deb' bs=1 seek=20 conv=notrunc status=none
check 1 epoch-alias-collision attempt
fresh; cp '/case/apt-cache/archives/kaname-cache-fixture_1%3a1.0_all.deb' '/case/apt-cache/archives/kaname-cache-fixture_1%3A1.0_all.deb'
check 1 epoch-case-collision attempt
fresh; rm '/case/apt-cache/archives/kaname-cache-fixture_1%3a1.0_all.deb'
check 1 incomplete-dependency-closure attempt kaname-cache-dependent=1:1.0
test ! -e /usr/share/kaname-cache-dependent/proof
for target in lists archives; do
  fresh; mkdir /case/outside; echo unchanged > /case/outside/proof
  rm -r "/case/apt-cache/$target"; ln -s /case/outside "/case/apt-cache/$target"
  check 1 "symlink-directory-$target" attempt
  test "$(cat /case/outside/proof)" = unchanged
done
fresh; echo unchanged > /case/outside
ln -s /case/outside /case/apt-cache/lists/unexpected_InRelease
check 1 symlink-file attempt; test "$(cat /case/outside)" = unchanged
fresh; echo unchanged > /case/outside
ln /case/outside /case/apt-cache/lists/unexpected_InRelease
check 1 hardlink-file attempt; test "$(cat /case/outside)" = unchanged
fresh; echo unchanged > /case/outside
ln -s /case/outside /case/apt-cache/sources.list
# Неизвестный верхний файл не используется и не копируется в root workspace.
check 0 valid-signed-offline-install attempt
test "$(cat /case/outside)" = unchanged
test "$(dpkg-query -W -f='${Version}' kaname-cache-fixture)" = 1:1.0
test "$(cat /usr/share/kaname-cache-fixture/proof)" = kaname-cache-fixture
dpkg --purge kaname-cache-fixture >/dev/null
# Данные из рабочей области экспортируются без частных каталогов/locks.
mkdir -m 0700 -p /case/apt-provider/lists/partial /case/apt-provider/archives/partial
touch /case/apt-provider/lists/lock /case/apt-provider/archives/lock
check 0 export-data-only runner_apt_export_cache /case /case/apt-provider
test ! -e /case/apt-cache/lists/partial; test ! -e /case/apt-cache/archives/lock
check 0 ordinary-uid-can-archive setpriv --reuid=65534 --regid=65534 --clear-groups tar -cf /dev/null -C /case apt-cache
mv /case/apt-cache /exported
fresh; rm -r /case/apt-cache; cp -a /exported /case/apt-cache
check 0 exported-cache-fresh-import-offline-install attempt
dpkg --purge kaname-cache-fixture >/dev/null
# Холодный producer уже имеет dependency из отдельного bootstrap archive.
# Его main archives сначала непригоден для действительно свежего consumer.
fresh
rm '/case/apt-cache/archives/kaname-cache-fixture_1%3a1.0_all.deb'
check 1 cold-export-before-fill-fresh-consumer-misses attempt kaname-cache-dependent=1:1.0
test ! -e /usr/share/kaname-cache-dependent/proof
test ! -e /usr/share/kaname-cache-fixture/proof
test ! -e '/case/apt-provider/archives/kaname-cache-fixture_1%3a1.0_all.deb'
# Отдельный bootstrap archive не входит ни в main archives, ни в export.
mkdir -p /case/apt-provider/ca-bootstrap/archives
cp '/fixture/seed/archives/kaname-cache-fixture_1%3a1.0_all.deb' /case/apt-provider/ca-bootstrap/archives/
dpkg -i '/case/apt-provider/ca-bootstrap/archives/kaname-cache-fixture_1%3a1.0_all.deb' >/dev/null
test "$(dpkg-query -W -f='${Version}' kaname-cache-fixture)" = 1:1.0
test ! -e /usr/share/kaname-cache-dependent/proof
# Настоящий signed file-only mirror содержит исходные deb, но main archive
# получает недостающую dependency только через production download helper.
mkdir -p /case/apt-offline/pool
cp /fixture/seed/archives/*.deb /case/apt-offline/pool/
: > /case/apt-provider/sources.list
for suite in noble noble-updates noble-security; do
  printf 'deb [arch=amd64 check-valid-until=no signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] file:/case/apt-offline %s main universe\n' "$suite" >> /case/apt-provider/sources.list
done
apt-get -o APT::Update::Error-Mode=any -o APT::Architecture=amd64 -o APT::Architectures=amd64 \
  -o Acquire::Languages=none -o Acquire::By-Hash=false \
  -o Acquire::IndexTargets::deb::Packages::CompressionTypes=uncompressed \
  -o Acquire::IndexTargets::deb::Packages::KeepCompressed=false \
  -o Acquire::IndexTargets::deb::CNF::DefaultEnabled=false \
  -o Acquire::IndexTargets::deb::DEP-11::DefaultEnabled=false \
  -o Dir::Etc::sourcelist=/case/apt-provider/sources.list -o Dir::Etc::sourceparts=- \
  -o Dir::State::lists=/case/apt-provider/lists -o Dir::Cache::archives=/case/apt-provider/archives \
  -o APT::Get::List-Cleanup=0 update -q > /case/out/cold-signed-index.log 2>&1 || {
    cat /case/out/cold-signed-index.log; exit 1;
  }
fill_preinstalled_dependency() {
  local status_before status_after
  status_before=$(sha256sum /var/lib/dpkg/status) || return 1
  runner_apt_fill_cache /case /case/apt-provider kaname-cache-dependent=1:1.0 || return 1
  status_after=$(sha256sum /var/lib/dpkg/status) || return 1
  [ "$status_before" = "$status_after" ] || return 1
  [ "$(dpkg-query -W -f='${Version}' kaname-cache-fixture)" = 1:1.0 ] || return 1
  [ ! -e /usr/share/kaname-cache-dependent/proof ] || return 1
  [ -f '/case/apt-provider/archives/kaname-cache-fixture_1%3a1.0_all.deb' ] || return 1
  [ -f '/case/apt-provider/archives/kaname-cache-dependent_1%3a1.0_all.deb' ] || return 1
  runner_apt_archive_hashes /case /case/apt-provider
}
check 0 cold-preinstalled-dependency-filled-without-dpkg-mutation fill_preinstalled_dependency
check 0 cold-full-closure-export runner_apt_export_cache /case /case/apt-provider
test ! -e /case/apt-cache/ca-bootstrap
mv /case/apt-cache /cold-exported
# Удаляем producer state, bootstrap archive и mirror; остаётся только export.
dpkg --purge kaname-cache-fixture >/dev/null
fresh
rm -r /case/apt-cache
cp -a /cold-exported /case/apt-cache
check 0 cold-full-export-fresh-consumer-offline-install attempt kaname-cache-dependent=1:1.0
test "$(dpkg-query -W -f='${Version}' kaname-cache-fixture)" = 1:1.0
test "$(dpkg-query -W -f='${Version}' kaname-cache-dependent)" = 1:1.0
test "$(cat /usr/share/kaname-cache-fixture/proof)" = kaname-cache-fixture
test "$(cat /usr/share/kaname-cache-dependent/proof)" = kaname-cache-dependent
dpkg --purge kaname-cache-dependent kaname-cache-fixture >/dev/null
# Последний отрицательный случай: после успешной проверки closure ошибка dpkg
# должна остаться fatal=2; это не cache miss и не повод повторять online install.
fresh; mkdir /case/bin
cat > /case/bin/apt-get <<'EOF'
#!/usr/bin/env bash
if [[ " $* " == *' install '* && " $* " != *' --download-only '* ]]; then
  touch /case/install-refused
  exit 23
fi
exec /usr/bin/apt-get "$@"
EOF
chmod 0755 /case/bin/apt-get
PATH=/case/bin:$PATH check 2 actual-install-refusal-is-fatal attempt
test -f /case/install-refused
test ! -e /usr/share/kaname-cache-fixture/proof
echo "APT-CACHE TOTAL=$count PASS=$count network=none real-apt=true"
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="ubuntu:24.04")
    parser.add_argument("--cgroup-parent", default="")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    with tempfile.TemporaryDirectory(prefix="kaname-apt-cache-") as temp:
        fixture = Path(temp)
        prepare(fixture)
        name = "kaname-apt-cache-test-" + str(os.getpid())
        argv = ["docker", "run", "--name", name, "--network", "none", "--memory", "768m", "--memory-swap", "768m",
                "--cpus", "1", "--pids-limit", "128", "--security-opt", "no-new-privileges=true",
                "--mount", f"type=bind,src={repo},dst=/src,readonly",
                "--mount", f"type=bind,src={fixture},dst=/fixture,readonly",
                "--mount", f"type=bind,src={fixture / 'test-keyring.gpg'},dst=/usr/share/keyrings/ubuntu-archive-keyring.gpg,readonly"]
        if args.cgroup_parent:
            argv += ["--cgroup-parent", args.cgroup_parent]
        argv += [args.image, "bash", "-c", INSIDE]
        try:
            outcome = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=240, text=True)
            state = json.loads(subprocess.check_output(["docker", "inspect", name], text=True))[0]
            print(outcome.stdout, end="", flush=True)
            summary = {"returncode": outcome.returncode, "state": state["State"], "image": state["Image"],
                       "memory": state["HostConfig"]["Memory"], "memorySwap": state["HostConfig"]["MemorySwap"],
                       "networkMode": state["HostConfig"]["NetworkMode"]}
            if args.out:
                args.out.mkdir(parents=True, exist_ok=True)
                (args.out / "apt-cache.original.raw").write_text(outcome.stdout)
                (args.out / "apt-cache.actual.json").write_text(json.dumps(summary, indent=2) + "\n")
            if outcome.returncode or state["State"]["OOMKilled"]:
                raise RuntimeError("APT cache integration failed: " + json.dumps(summary))
        finally:
            run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
