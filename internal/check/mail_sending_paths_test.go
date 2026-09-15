// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// mail_sending_paths_test.go — MAIL-47 приёмки ID-MAIL-1 по дереву службы.
//
// Предмет, зеркало и граница гейта — в шапке `mail_sending_paths.go`; здесь
// только ОБХОД дерева, перепись и порог беспредметности. Способность упасть и
// смолчать доказана инъекцией — mail_sending_paths_injection_test.go.
package check_test

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// mailSendingGoFloor — не-тестовых исходников Go, ниже которого обход
// беспредметен.
//
// Не «больше нуля»: ноль ловит только полностью сорванный обход, а обход,
// сузившийся до десятка файлов (сменилась раскладка, отсёкся суффикс), выглядел
// бы обычным зелёным — и «путей отправки ноль» читалось бы как находка «вид без
// производителя» там, где не прочитано ничего. Величина НИЖЕ фактической с
// запасом (на ревизии заведения — 846): она признак беспредметности, а не
// перепись.
const mailSendingGoFloor = 500

// ownModulePath — путь модуля ИЗ go.mod, а не выписанный литералом: пакеты
// своего модуля с «mail» в имени (очередь писем, её писатель) — наш код, и
// разбор судит их содержимое, а не имя импорта.
func ownModulePath(t *testing.T, root string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "go.mod")) // #nosec G304 -- корень модуля этого дерева
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: go.mod модуля не читается: %v", err)
	}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if rest, ok := strings.CutPrefix(line, "module "); ok {
			if p := strings.TrimSpace(rest); p != "" {
				return p
			}
		}
	}
	t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: в go.mod нет строки `module` — свой модуль " +
		"не отличить от чужого импорта")
	return ""
}

// TestMAIL47OneMailSendingPathAndItSendsOnlyTheInvitation — MAIL-47 на дереве
// службы: путей, кладущих письмо в отправку, РОВНО ОДИН, и отправляет он
// только приглашение; путей чужих видов — ноль.
func TestMAIL47OneMailSendingPathAndItSendsOnlyTheInvitation(t *testing.T) {
	t.Parallel()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: рабочий каталог не установлен: %v", err)
	}
	root, err := platformtree.ModuleRootFrom(wd)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не найден: %v", err)
	}
	module := ownModulePath(t, root)

	files, err := treecorpus.UnderWithSuffix(root, ".go")
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: состав дерева: %v — без переписи "+
			"«ноль находок» неотличимо от «ноль прочитанного»", err)
	}

	var (
		parsed, imports, literals int
		unparsed                  []string
		facts                     []check.MailSendingFacts
	)
	for _, abs := range files {
		if strings.HasSuffix(abs, "_test.go") {
			// Пробы вправе поднимать подставной узел и говорить с ним: предмет
			// гейта — отправка ПРОДУКТОМ, а не фикстурой.
			continue
		}
		rel, rerr := filepath.Rel(root, abs)
		if rerr != nil {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: относительный путь для %s: %v", abs, rerr)
		}
		rel = filepath.ToSlash(rel)
		src, rderr := os.ReadFile(abs) // #nosec G304 -- путь из индекса git ЭТОГО дерева
		if rderr != nil {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: чтение %s: %v", rel, rderr)
		}
		f, serr := check.ScanMailSending(rel, src, module)
		if serr != nil {
			// Неразбираемый исходник не собирается — об этом скажет сборка. Но
			// перепись не имеет права засчитать его прочитанным.
			unparsed = append(unparsed, rel)
			continue
		}
		parsed++
		imports += f.Imports
		literals += f.Literals
		facts = append(facts, f)
	}

	v := check.JudgeMailSending(facts)
	kinds := make([]string, 0, len(v.Kinds))
	for _, k := range v.Kinds {
		kinds = append(kinds, string(k))
	}
	sort.Strings(kinds)

	t.Logf("перепись: исходников Go (не тестовых) разобрано %d · не разобралось %d %v · "+
		"импортов прочитано %d · строковых литералов прочитано %d · "+
		"путей отправки найдено %d · видов письма, которые они отправляют, %d %v · находок %d",
		parsed, len(unparsed), unparsed, imports, literals, v.Paths, len(kinds), kinds, len(v.Findings))

	if parsed < mailSendingGoFloor {
		t.Fatalf("разобрано %d не-тестовых исходников Go при пороге %d — перепись "+
			"беспредметна, и «путей отправки ноль» означало бы «ноль прочитанного»",
			parsed, mailSendingGoFloor)
	}
	if imports == 0 || literals == 0 {
		t.Fatalf("при непустом обходе прочитано импортов %d и литералов %d — разбор "+
			"перестал доходить до узлов, и молчание гейта ничего не означает", imports, literals)
	}

	for _, f := range v.Findings {
		t.Error(f)
	}
}
