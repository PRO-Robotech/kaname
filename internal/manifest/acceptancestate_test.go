// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// acceptancestate_test.go — колонка «Состояние» §6 приёмки договора о посеве
// манифестов ОБЯЗАНА совпадать с деревом: строка, объявляющая проверку
// незаведённой, не вправе называть сценарий, чья проба посажена.
//
// # Что стережётся
//
// Утверждение, пережившее свой предмет. Документ APPROVED, его колонка
// состояния читается как действующая — и говорит «держателя нет» ровно там, где
// держатель есть и зелёный. Следствия наблюдаемы оба: читатель заводит второй
// держатель поверх существующего либо считает требование неудержанным и не идёт
// за ним в код.
//
// # Судится в ОБЕ стороны, и это несущее
//
// Односторонний предикат («ни одна строка не объявляет незаведённым посаженное»)
// зеленел бы на вычеркнутой колонке. Поэтому вторая ось: строка, назвавшая
// держателем сценарий, чьей пробы в дереве НЕТ, — тоже находка.
//
// # Чего гейт НЕ судит, и это граница, а не пропуск
//
// Он не судит, ПРАВДУ ли говорит проза требования и покрывает ли проба сценарий
// по существу: «покрывает» машинного предиката не имеет. Он судит совпадение
// двух перечислимых множеств — сценариев, названных строкой, и сценариев,
// посаженных в пакете.
package manifest_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

const (
	// seedContractDoc — приёмка договора о посеве манифестов.
	seedContractDoc = "../../docs/engineering/acceptance/module-manifest-seed-contract.md"
	// seedContractProbeDir — каталог, где живут пробы MOD-MF.
	seedContractProbeDir = "."
)

var (
	// scenarioRe — идентификатор сценария в полной форме.
	scenarioRe = regexp.MustCompile(`MOD-MF-(\d{2})`)
	// bareScenarioRe — сценарий, записанный ГОЛЫМ числом. Форма законная и в §6
	// преобладающая: «MOD-MF-01, 05, 06», «MOD-MF-13, 14, 15 + контроль 16» —
	// второй и следующие идентификаторы перечня стоят без префикса. Распознаватель,
	// знающий только полную форму, видел бы 12 ссылок из 25, и тринадцать строк
	// оставались бы вне наблюдения — не нарушением, а невидимостью.
	bareScenarioRe = regexp.MustCompile(`\b(\d{2})\b`)
	// probeRe — объявление посаженной пробы сценария.
	probeRe = regexp.MustCompile(`(?m)^func TestMODMF(\d{2})`)
	// awaitedRe — состояние «держателя нет, он заказан». Две формы: длинная в
	// колонке состояния и короткая («проба заказана») — обе означают одно.
	awaitedRe = regexp.MustCompile(`проверки нет — заказана|роба \*\*заказана\*\*|роба заказана`)
)

// landedScenarios — сценарии, чьи пробы объявлены в каталоге.
func landedScenarios(dir string) (map[string]string, int, error) {
	found := make(map[string]string)
	files, err := filepath.Glob(filepath.Join(dir, "*_test.go"))
	if err != nil {
		return nil, 0, err
	}
	read := 0
	for _, f := range files {
		body, err := os.ReadFile(f)
		if err != nil {
			return nil, read, err
		}
		read++
		for _, m := range probeRe.FindAllStringSubmatch(string(body), -1) {
			found[m[1]] = filepath.Base(f)
		}
	}
	return found, read, nil
}

// namedScenarios — сценарии, названные колонкой «Держится», во ВСЕХ законных
// формах записи. Голое число считается идентификатором только там, где колонка
// уже назвала хотя бы один сценарий полной формой: иначе номер задачи или ссылка
// на раздел прошли бы за сценарий.
func namedScenarios(holder string) []string {
	full := scenarioRe.FindAllStringSubmatch(holder, -1)
	if len(full) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(full))
	out := make([]string, 0, len(full))
	for _, m := range bareScenarioRe.FindAllStringSubmatch(holder, -1) {
		if seen[m[1]] {
			continue
		}
		seen[m[1]] = true
		out = append(out, m[1])
	}
	return out
}

// sectionSix вырезает §6 документа: от заголовка раздела до следующего.
func sectionSix(text string) string {
	lines := strings.Split(text, "\n")
	start := -1
	for i, ln := range lines {
		if strings.HasPrefix(ln, "## 6.") {
			start = i
			break
		}
		_ = ln
	}
	if start < 0 {
		return ""
	}
	for i := start + 1; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], "## ") {
			return strings.Join(lines[start:i], "\n")
		}
	}
	return strings.Join(lines[start:], "\n")
}

// auditAcceptanceState разбирает §6 и ВОЗВРАЩАЕТ находки. Разбор не обращается
// к *testing.T: проба способности падать иначе роняла бы саму себя.
func auditAcceptanceState(docPath, probeDir string) (findings []string, rows, refs, probes int) {
	landed, filesRead, err := landedScenarios(probeDir)
	if err != nil {
		return []string{"пробы не прочитаны: " + err.Error()}, 0, 0, 0
	}
	probes = len(landed)

	body, err := os.ReadFile(docPath)
	if err != nil {
		return []string{"приёмка не прочитана: " + err.Error()}, 0, 0, probes
	}
	section := sectionSix(string(body))
	if strings.TrimSpace(section) == "" {
		return []string{"§6 приёмки не найден — гейт судил бы о непрочитанном"}, 0, 0, probes
	}

	for _, ln := range strings.Split(section, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(ln), "|") {
			continue
		}
		cols := strings.Split(strings.Trim(strings.TrimSpace(ln), "|"), "|")
		if len(cols) < 3 {
			continue
		}
		requirement := strings.TrimSpace(cols[0])
		if requirement == "Требование" || strings.HasPrefix(requirement, "---") {
			continue
		}
		rows++
		holder, state := cols[1], cols[2]
		named := namedScenarios(holder)
		awaited := awaitedRe.MatchString(state)
		for _, id := range named {
			refs++
			file, ok := landed[id]
			switch {
			case awaited && ok:
				findings = append(findings, "строка «"+requirement+"» объявляет проверку незаведённой, "+
					"а MOD-MF-"+id+" посажен: "+file+
					"\n    состояние пережило свой предмет: читатель заведёт второй держатель поверх существующего")
			case !awaited && !ok:
				findings = append(findings, "строка «"+requirement+"» называет держателем MOD-MF-"+id+
					", чьей пробы в дереве НЕТ"+
					"\n    держатель выдан авансом: строка обещает проверку, за которой никого нет")
			}
		}
	}

	if rows == 0 {
		findings = append(findings, "обход пуст: строк таблицы §6 не прочитано ни одной — "+
			"«находок 0» неотличимо от «прочитано 0»")
	}
	if filesRead == 0 {
		findings = append(findings, "обход пуст: файлов проб не прочитано ни одного")
	}
	return findings, rows, refs, probes
}

func TestSeedContractSectionSixStateMatchesTheTree(t *testing.T) {
	findings, rows, refs, probes := auditAcceptanceState(seedContractDoc, seedContractProbeDir)
	for _, f := range findings {
		t.Error(f)
	}
	if rows == 0 || probes == 0 {
		t.Fatal("обход пуст — гейт судил бы о непрочитанном")
	}
	sorted := make([]string, 0, probes)
	for id := range mustLanded(t) {
		sorted = append(sorted, id)
	}
	sort.Strings(sorted)
	t.Logf("перепись: строк §6 прочитано %d · ссылок на сценарии %d · проб MOD-MF в пакете %d (%s) · находок %d",
		rows, refs, probes, strings.Join(sorted, ","), len(findings))
}

func mustLanded(t *testing.T) map[string]string {
	t.Helper()
	landed, _, err := landedScenarios(seedContractProbeDir)
	if err != nil {
		t.Fatal(err)
	}
	return landed
}

// ─────────────────────────────────────────────────────────────────────────────
// Доказательство способности упасть. Инъекция идёт по КОПИИ: правка настоящей
// приёмки ради пробы оборвала бы соседнюю сессию в том же дереве.

// copySeedContract кладёт приёмку и подставной каталог проб во временный
// каталог и возвращает пути к ним.
func copySeedContract(t *testing.T, doc, probes string) (string, string) {
	t.Helper()
	root := t.TempDir()
	docPath := filepath.Join(root, "acceptance.md")
	if err := os.WriteFile(docPath, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	probeDir := filepath.Join(root, "probes")
	if err := os.MkdirAll(probeDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if probes != "" {
		if err := os.WriteFile(filepath.Join(probeDir, "landed_test.go"), []byte(probes), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return docPath, probeDir
}

const (
	// injDoc — §6 из двух строк: у первой держатель посажен, у второй его нет и
	// строка это признаёт. Законный близнец обязан молчать на обеих.
	injDoc = "## 5. Сценарии\n\nпрочее\n\n" +
		"## 6. Чем держится каждое требование\n\n" +
		"| Требование | Держится | Состояние |\n|---|---|---|\n" +
		"| ключ описан | MOD-MF-01, 05 | **посажено**: `landed_test.go` |\n" +
		"| цель существует | MOD-MF-20 | **проверки нет — заказана** |\n\n" +
		"## 7. Дальше\n"
	// injProbes — посажены 01 и 05; 20 не посажен намеренно.
	injProbes = "package probes\n\nfunc TestMODMF01(t *testing.T) {}\nfunc TestMODMF05(t *testing.T) {}\n"
)

func TestSeedContractSectionSixState_CanFailAndStaysSilent(t *testing.T) {
	cases := []struct {
		name   string
		doc    string
		probes string
		want   string
		why    string
	}{
		{
			name:   "законный близнец: состояние сходится с деревом",
			doc:    injDoc,
			probes: injProbes,
			why: "положительный контроль: без него всякое красное ниже могло бы приходить от самого разбора, " +
				"а не от инъекции",
		},
		{
			name: "строка объявляет незаведённым посаженное",
			doc: strings.Replace(injDoc, "| ключ описан | MOD-MF-01, 05 | **посажено**: `landed_test.go` |",
				"| ключ описан | MOD-MF-01, 05 | **проверки нет — заказана** |", 1),
			probes: injProbes,
			want:   "объявляет проверку незаведённой, а MOD-MF-01 посажен",
			why:    "ровно предмет #1826: колонка пережила посадку и говорит «держателя нет» там, где он есть",
		},
		{
			name: "голая форма второго идентификатора перечня не теряется",
			doc: strings.Replace(injDoc, "| ключ описан | MOD-MF-01, 05 | **посажено**: `landed_test.go` |",
				"| ключ описан | MOD-MF-20, 05 | **проверки нет — заказана** |", 1),
			probes: injProbes,
			want:   "MOD-MF-05 посажен",
			why: "распознаватель обязан знать ОБЕ формы записи: полную и голым числом. Знай он одну — " +
				"тринадцать ссылок §6 остались бы вне наблюдения",
		},
		{
			name: "строка называет держателя, которого нет",
			doc: strings.Replace(injDoc, "| цель существует | MOD-MF-20 | **проверки нет — заказана** |",
				"| цель существует | MOD-MF-20 | **посажено**: `landed_test.go` |", 1),
			probes: injProbes,
			want:   "называет держателем MOD-MF-20, чьей пробы в дереве НЕТ",
			why: "вторая ось: без неё предикат зеленел бы на вычеркнутой колонке — достаточно объявить " +
				"держателем что угодно",
		},
		{
			name:   "раздела §6 в документе нет",
			doc:    "## 5. Сценарии\n\nпрочее\n",
			probes: injProbes,
			want:   "§6 приёмки не найден",
			why:    "переименование раздела обязано краснеть, а не давать «находок 0» на непрочитанном",
		},
		{
			name:   "проб в каталоге нет вовсе",
			doc:    injDoc,
			probes: "",
			want:   "обход пуст",
			why: "«находок 0» обязано быть отличимо от «прочитано 0»: пустой каталог проб сделал бы " +
				"всякую строку «посажено» находкой, а всякую «заказана» — тишиной",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			docPath, probeDir := copySeedContract(t, tc.doc, tc.probes)
			findings, rows, refs, probes := auditAcceptanceState(docPath, probeDir)

			if tc.want == "" {
				if len(findings) != 0 {
					t.Fatalf("разбор нашёл на законной копии то, чего в ней нет — первое же ложное "+
						"срабатывание снимает гейт.\nнаходки:\n  %s", strings.Join(findings, "\n  "))
				}
				if rows == 0 || refs == 0 || probes == 0 {
					t.Fatalf("контроль ничего не доказывает: строк %d · ссылок %d · проб %d", rows, refs, probes)
				}
				return
			}
			if len(findings) == 0 {
				t.Fatalf("разбор смолчал на инъекции — он НЕ способен упасть по этой оси.\n"+
					"что должно было ловиться: %s", tc.why)
			}
			joined := strings.Join(findings, "\n  ")
			if !strings.Contains(joined, tc.want) {
				t.Fatalf("разбор покраснел не на том: ждали %q.\nчто должно было ловиться: %s\nнаходки:\n  %s",
					tc.want, tc.why, joined)
			}
		})
	}
}
