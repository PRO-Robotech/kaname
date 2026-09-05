// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// operator_docs_exit_code_test.go — обёртка `tools/operator-docs.sh` ПРОПУСКАЕТ
// код возврата программы, а не подменяет его своим.
//
// # Что ловится, и это НЕ гипотеза
//
// Первая редакция обёртки звала `go run`. Он на любом ненулевом коде программы
// отдаёт СВОЙ код 1 и печатает `exit status 3` строкой в поток ошибок. Четыре
// объявленных исхода схлопывались в два, и «без предмета» становилось
// неотличимо от находки — то есть отсутствие предмета читалось бы вызывающим
// как вердикт о дереве. Измерено прогоном, а не выведено чтением.
//
// # Почему подставной сборщик, а не настоящий прогон
//
// Настоящий прогон на этом дереве отдаёт 0, поэтому доказать им можно ровно
// один исход из четырёх. Здесь на PATH кладётся подставной `go`, чья сборка
// производит программу с ЗАДАННЫМ кодом, — и обёртка проверяется на каждом
// исходе, включая те, которых на здоровом дереве не бывает.
//
// Подделка структурно неспособна дать ложное зелёное: она не читает дерева
// вовсе и печатает только то, что ей велено, поэтому «обёртка вернула 0»
// доказывает пропуск нуля, а не исправность разбора.
package tools_regression

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// stubGo кладёт на PATH подставной `go`, чья `build -C … -o <bin> …` создаёт
// программу, выходящую кодом want.
func stubGo(t *testing.T, want int) string {
	t.Helper()
	dir := t.TempDir()

	// Подставной сборщик разбирает только то, что ему передаёт обёртка: ключ
	// `-o` и путь. Обход остальных аргументов делает пробу нечувствительной к
	// их порядку.
	body := `#!/usr/bin/env bash
set -euo pipefail
out=""
prev=""
for a in "$@"; do
  if [[ "$prev" == "-o" ]]; then out="$a"; fi
  prev="$a"
done
if [[ -z "$out" ]]; then echo "подставной сборщик: ключ -o не передан" >&2; exit 97; fi
printf '#!/usr/bin/env bash\nexit ` + itoa(want) + `\n' > "$out"
chmod +x "$out"
`
	path := filepath.Join(dir, "go")
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestOperatorDocsWrapper_PropagatesEveryDeclaredExitCode(t *testing.T) {
	script, err := filepath.Abs("operator-docs.sh")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("обёртки нет: %v — доказывать нечего", err)
	}

	// Четыре исхода объявлены шапкой самой обёртки. Проверяются ВСЕ: исход,
	// оставшийся вне прогона, унёс бы с собой доказательство своего пропуска.
	for _, want := range []int{0, 1, 2, 3} {
		t.Run(strings.TrimSpace(itoa(want)), func(t *testing.T) {
			cmd := exec.Command("bash", script)
			cmd.Env = append(os.Environ(), "PATH="+stubGo(t, want)+string(os.PathListSeparator)+os.Getenv("PATH"))
			out, _ := cmd.CombinedOutput()

			got := cmd.ProcessState.ExitCode()
			if got != want {
				t.Fatalf("программа вышла кодом %d, обёртка отдала %d — четыре объявленных исхода "+
					"схлопнулись, и «без предмета» станет неотличимо от находки.\nвывод:\n%s",
					want, got, out)
			}
		})
	}
}
