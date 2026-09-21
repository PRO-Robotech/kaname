#!/usr/bin/env bash
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# install.sh — провязать хук отправки этого клона и сказать, провязан ли он.
# Зовётся целями `make install-hooks` / `make check-hooks`; руками — тоже можно.
#
# ЭКЗЕМПЛЯР ЭТОГО МЕХАНИЗМА — СВОЙ, А НЕ СКОПИРОВАННЫЙ. У соседнего продукта
# (PRO-Robotech/kacho) стоит та же ИДЕЯ переходника в scripts/hooks/install.sh —
# и она НЕ перенесена сюда файлом: копия одного и того же отслеживаемого пути
# в двух стволах запрещена (ban20-copy-ban), а Kaname — отдельный продукт со
# своим Makefile, своим набором целей (`vet`, `lint`, `test-short`) и без общей
# точки сборки с kacho. Расхождение с оригиналом объявлено, а не спрятано:
#
#   у kacho                                   здесь            почему
#   ──────────────────────────────────────────────────────────────────────────
#   несколько хуков (pre-push, + чужой         один (pre-push)  предмета для
#     pre-commit, не через этот механизм)                       второго нет —
#                                                                своей проверки
#                                                                идентичности
#                                                                у Kaname не
#                                                                заведено
#   группы прогона по составу диффа           нет               дерево много
#     (proto/go/terraform/helm/ui)                                меньше, один
#                                                                  Go-модуль —
#                                                                  делить нечего
#   ci-local.sh отдельным файлом              команды `make`    цели уже есть
#                                              напрямую в хуке   и обслуживают
#                                                                 пин линтера
#
# ПОЧЕМУ НЕ `core.hooksPath` — тот же довод, что у соседа, и он не зависит от
# продукта: git начинает искать хуки ТОЛЬКО по указанному пути, и всё, что уже
# лежит в `.git/hooks`, перестаёт исполняться молча. Лекарство обязано быть
# проверено на то, что оно сохраняет, поэтому в `.git/hooks` кладётся
# ПЕРЕХОДНИК — короткий файл, который находит рабочую копию и исполняет
# отслеживаемый скрипт из неё:
#
#   · посторонний хук под другим именем не трогается НИКОГДА (отказ, не
#     перезапись);
#   · переходник берёт скрипт из ТОЙ рабочей копии, из которой идёт отправка;
#   · путей машины в переходнике нет — переезд клона его не ломает;
#   · цена: новый отслеживаемый хук требует повторного `make install-hooks`,
#     и эта цена наблюдаемая — её называет `make check-hooks`, а не молчание.
#
# ХУКОМ СЧИТАЕТСЯ отслеживаемый файл в scripts/hooks, в имени которого нет
# точки (расширения `.sh` у самого install.sh — потому оно хуком не станет).
set -uo pipefail

mode="${1:-install}"

die() { printf '%s\n' "$@" >&2; exit 1; }

root="$(git rev-parse --show-toplevel 2>/dev/null)" ||
    die "install-hooks: это не рабочая копия git — провязывать не во что."
common="$(git rev-parse --git-common-dir 2>/dev/null)" ||
    die "install-hooks: git не назвал общий каталог репозитория."
case "$common" in /*) ;; *) common="$root/$common" ;; esac

src="$root/scripts/hooks"
dst="$common/hooks"

hooks=()
while IFS= read -r rel; do
    base="${rel##*/}"
    case "$base" in *.*) continue ;; esac
    hooks+=("$base")
done < <(git -C "$root" ls-files scripts/hooks)

[ "${#hooks[@]}" -gt 0 ] ||
    die "install-hooks: в scripts/hooks нет НИ ОДНОГО отслеживаемого хука." \
        "Пустой обход здесь означал бы зелёный вывод при непровязанном клоне."

marker="kaname-hook-stub v1"

configured="$(git config --get core.hooksPath 2>/dev/null || true)"
if [ -n "$configured" ]; then
    abs="$configured"
    case "$abs" in /*) ;; *) abs="$root/$abs" ;; esac
    if [ ! -d "$abs" ]; then
        die "ОТКАЗ: core.hooksPath = «$configured» — каталога по этому пути НЕТ." \
            "  git config --unset core.hooksPath   # затем: make install-hooks"
    fi
    real_cfg="$(cd "$abs" && pwd -P)"
    if [ "$real_cfg" != "$(cd "$src" && pwd -P)" ]; then
        die "ОТКАЗ: core.hooksPath = «$configured» ведёт в $real_cfg." \
            "git будет искать хуки ТАМ, провязка в $dst не исполнится ни разу." \
            "  git config --unset core.hooksPath   # затем: make install-hooks"
    fi
    echo "core.hooksPath = «$configured» — хуки исполняются НАПРЯМУЮ из $src."
    echo "отслеживаемых хуков: ${#hooks[@]}; исполняются напрямую"
    exit 0
fi

mkdir -p "$dst" || die "install-hooks: не создать $dst"

stub_for() {
    cat <<STUB
#!/usr/bin/env bash
# СГЕНЕРИРОВАН \`make install-hooks\` — правится НЕ здесь, а в scripts/hooks/$1.
# $marker
set -uo pipefail
top="\$(git rev-parse --show-toplevel 2>/dev/null)" || top=""
[ -n "\$top" ] || top="\$PWD"
real="\$top/scripts/hooks/$1"
if [ ! -x "\$real" ]; then
    echo "$1: в этой рабочей копии нет \$real — проверок НЕ БЫЛО" >&2
    exit 0
fi
exec "\$real" "\$@"
STUB
}

wired=0
missing=()
foreign=()
for name in "${hooks[@]}"; do
    target="$dst/$name"
    if [ ! -e "$target" ]; then
        missing+=("$name")
        continue
    fi
    if grep -qF "$marker" "$target" 2>/dev/null; then
        if [ -x "$target" ]; then wired=$((wired + 1)); else missing+=("$name"); fi
        continue
    fi
    foreign+=("$name")
done

kept=()
for f in "$dst"/*; do
    [ -e "$f" ] || continue
    b="${f##*/}"
    case "$b" in *.sample) continue ;; esac
    ours=0
    for name in "${hooks[@]}"; do [ "$b" = "$name" ] && ours=1; done
    [ "$ours" = 1 ] || kept+=("$b")
done

report() {
    echo "хуки: провязано $wired из ${#hooks[@]} ($dst)"
    [ "${#kept[@]}" -eq 0 ] ||
        printf 'посторонних хуков оставлено нетронутыми: %s\n' "${kept[*]}"
}

case "$mode" in
check)
    report
    if [ "${#foreign[@]}" -gt 0 ]; then
        echo "ОТКАЗ: под именем хука лежит ЧУЖОЙ файл: ${foreign[*]}" >&2
        exit 1
    fi
    if [ "${#missing[@]}" -gt 0 ]; then
        echo "ОТКАЗ: не провязаны: ${missing[*]}" >&2
        echo "Отправка ветки НЕ проверяется локально: конвейер станет первым читателем." >&2
        echo "  make install-hooks" >&2
        exit 1
    fi
    exit 0
    ;;
notice)
    if [ "${#missing[@]}" -gt 0 ] || [ "${#foreign[@]}" -gt 0 ]; then
        echo "ВНИМАНИЕ: хуки git не провязаны (${#missing[@]} не провязано, ${#foreign[@]} занято чужим)." >&2
        echo "  Отправка ветки НЕ будет проверена локально — «make install-hooks» это чинит." >&2
    fi
    exit 0
    ;;
install) ;;
*) die "install-hooks: неизвестный режим «$mode» (install | check | notice)" ;;
esac

if [ "${#foreign[@]}" -gt 0 ]; then
    die "ОТКАЗ: под именем хука уже лежит ЧУЖОЙ файл: ${foreign[*]}" \
        "Он НЕ перезаписывается: уберите его сами либо слейте со scripts/hooks/<имя>."
fi

installed=()
for name in "${hooks[@]}"; do
    target="$dst/$name"
    stub_for "$name" > "$target" || die "install-hooks: не записать $target"
    chmod +x "$target" || die "install-hooks: не сделать исполняемым $target"
    installed+=("$name")
done

wired=${#installed[@]}
report
printf 'провязаны переходниками: %s\n' "${installed[*]}"
echo "проверить в любой момент: make check-hooks"
