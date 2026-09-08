// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package tools_regression

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/gitenv"
)

// void_message_names_the_walk_root_test.go — сообщение о ТРЕТЬЕЙ категории исхода
// называет КОРЕНЬ ОБХОДА в себе самом (задача PRO-Robotech/kacho#1897).
//
// # Предмет
//
// У обеих целей манифеста исход VOID («проверять нечего») говорит словами, а не
// только кодом. Пока манифестов в дереве не было, слова объясняли исход
// РАСПИСАНИЕМ: «предмет появится вместе с первым манифестом модуля». Манифесты
// приехали (#1091), объяснение пережило свой предмет, и единственная действующая
// причина VOID стала иной: обход не дошёл до манифестов — назван не тот корень.
//
// Текст приведён к дереву и посылает читателя к корню обхода. Здесь проверяется,
// что посылать ЕСТЬ КУДА: корень обязан стоять в самом сообщении.
//
// # Почему stderr ОТДЕЛЬНО от stdout, а не объединённый вывод
//
// Перепись и строка «корень обхода: …» идут в stdout, сообщение об исходе — в
// stderr. Объединённый вывод сделал бы утверждение тривиально истинным: корень
// нашёлся бы в переписи, о которой это сообщение ничего не знает. Читатель же
// видит их порознь — оболочка конвейера снимает stderr отдельной строкой, — и
// «смотрите корень обхода» без корня посылает в пустоту.
//
// # Чем эта проба НЕ является
//
// Она не судит ИСТИННОСТЬ объяснения: правдивость прозы машинного предиката не
// имеет (`writing.md` §10). Она locks ДЕЙСТВЕННУЮ половину — что названный
// читателю следующий шаг у него есть.

// runSplit зовёт обёртку и возвращает код возврата, stdout и stderr ПОРОЗНЬ.
func runSplit(t *testing.T, script string, args ...string) (int, string, string) {
	t.Helper()
	p := filepath.Join(serviceRoot(t), "tools", script)
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("исполнителя %s в дереве нет (%v): цель никем не зовётся", script, err)
	}
	cmd := exec.Command("bash", append([]string{p}, args...)...) // #nosec G204 -- путь из дерева проб
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	code := 0
	if err := cmd.Run(); err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("обёртка %s не запустилась: %v\n%s", script, err, errb.String())
		}
		code = ee.ExitCode()
	}
	return code, out.String(), errb.String()
}

// emptyRepo — дерево, на котором проверка ФОРМЫ даёт ИМЕННО VOID: репозиторий
// без единого манифеста.
//
// Репозиторий, а не голый временный каталог: полоса дерева берёт перечень путей
// у ИНДЕКСА (задача PRO-Robotech/kacho#2041), и каталог без индекса даёт НАХОДКУ
// «перечень взять неоткуда», а не «проверять нечего». Предпосылка пробы требует
// ровно VOID — значит индекс обязан быть, и обязан быть пустым.
func emptyRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	// gitenv, а не exec напрямую: `cmd.Dir` НЕ выбирает репозиторий, когда в
	// окружении стоит GIT_DIR — переменная сильнее рабочего каталога, и фикстура
	// завела бы индекс ТОЙ копии, из которой запущен прогон.
	cmd := gitenv.Command(root, "init", "-q")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init в %s: %v\n%s", root, err, out)
	}
	return root
}

// voidCanonTree — дерево, на котором сверка канона даёт ИМЕННО VOID: канон несёт
// только типы вне закрытого набора модулей, а манифесты всех шести модулей
// ресурсов не объявляют. Тогда находок нет (каждый модуль манифест несёт) и
// сверять при этом нечего — блоков, принадлежащих модулям, ноль.
func voidCanonTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "proto", "kaname", "cloud", "iam", "v1")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("каталог канона: %v", err)
	}
	// Тип, которого НЕТ в посевном каталоге: принадлежность блока модулю решает
	// каталог (`TypesOutsideModules`), а не имя каталога дерева. Блок вне всякого
	// модуля не рождает ни находки «канон сверх порождённого», ни сверки, — и это
	// единственный вход, дающий ровно VOID.
	const canon = `model
  schema 1.1

type synthetic_type_outside_every_module
  relations
    define anchor: [anchor]
`
	if err := os.WriteFile(filepath.Join(dir, "fga_model.fga"), []byte(canon), 0o600); err != nil {
		t.Fatalf("запись канона: %v", err)
	}
	for _, m := range []string{"iam", "vpc", "compute", "loadbalancer", "registry", "storage"} {
		d := filepath.Join(root, "services", m)
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatalf("каталог модуля %s: %v", m, err)
		}
		body := "apiVersion: iam/v1\nmodule: " + m + "\nresources: []\n"
		if err := os.WriteFile(filepath.Join(d, "manifest.yaml"), []byte(body), 0o600); err != nil {
			t.Fatalf("манифест %s: %v", m, err)
		}
	}
	return root
}

// TestManifestVoidMessagesNameTheWalkRootInThemselves — обе цели, обе стороны.
func TestManifestVoidMessagesNameTheWalkRootInThemselves(t *testing.T) {
	cases := []struct {
		name   string
		script string
		root   func(*testing.T) string
	}{
		{"форма манифеста", "module-manifest-check.sh", emptyRepo},
		{"сверка канона", "model-canon-check.sh", voidCanonTree},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := c.root(t)
			code, stdout, stderr := runSplit(t, c.script, "-root="+root)
			if code != 2 {
				t.Fatalf("исход %d, ожидался 2 (VOID): предпосылка пробы не выполнена — "+
					"утверждение о сообщении VOID было бы вакуумным\nstdout:\n%s\nstderr:\n%s",
					code, stdout, stderr)
			}
			if !strings.Contains(stderr, root) {
				t.Errorf("сообщение об исходе VOID не называет корень обхода %q — оно посылает "+
					"читателя «смотрите корень обхода», а корень стоит в другом потоке, "+
					"которого он может не видеть\nstderr:\n%s", root, stderr)
			}
		})
	}
}

// TestManifestVoidMessagesAreNotEmittedWhenThereIsSomethingToCheck — положительный
// контроль: на дереве продукта исхода VOID нет, значит проба выше не зеленеет от
// того, что сообщение печатается всегда.
func TestManifestVoidMessagesAreNotEmittedWhenThereIsSomethingToCheck(t *testing.T) {
	for _, script := range []string{"module-manifest-check.sh", "model-canon-check.sh"} {
		code, _, stderr := runSplit(t, script)
		if code == 2 {
			t.Fatalf("%s: дерево продукта дало VOID — манифесты отслеживаются деревом, "+
				"и пустой обход здесь означает, что до них не дошли\nstderr:\n%s", script, stderr)
		}
	}
}
