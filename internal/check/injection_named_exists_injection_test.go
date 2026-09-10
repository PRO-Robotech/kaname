// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// injection_named_exists_injection_test.go — доказательство того, что разбор
// обещаний СПОСОБЕН упасть, и падает на своём предмете (#2479).
//
// Инъекция роняет ТОЛЬКО проверяемое: разбор принимает корень обхода доводом,
// поэтому каждый мир живёт во временном каталоге и настоящего дерева не
// касается вовсе. Соседние гейты пакета его не видят.
//
// Каждый мир отличается от своего законного близнеца ОДНИМ фактом — наличием
// одного файла либо одной строкой комментария.
package check_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// injTree кладёт синтетическое дерево (путь → содержимое) и отдаёт его корень.
func injTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, body := range files {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatalf("каталог %s не создан: %v", rel, err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("файл %s не записан: %v", rel, err)
		}
	}
	return root
}

// namingProbe — исходник пробы, чья шапка называет доказательство.
func namingProbe(coord string) string {
	return "// Способность упасть доказана инъекцией — " + coord + ".\npackage p\n"
}

// injAudit — разбор с общей проверкой предпосылки.
func injAudit(t *testing.T, root string) ([]check.InjectionFinding, check.InjectionCensus) {
	t.Helper()
	findings, census, err := check.AuditNamedInjections(root)
	if err != nil {
		t.Fatalf("обход синтетического дерева не состоялся: %v", err)
	}
	return findings, census
}

// TestNamedInjectionInjection_LawfulTwinStaysSilent — ЗАКОННЫЙ БЛИЗНЕЦ, первым.
//
// Без него красное ниже приходило бы от чего угодно — например от разбора,
// объявляющего находкой всякое упоминание.
func TestNamedInjectionInjection_LawfulTwinStaysSilent(t *testing.T) {
	root := injTree(t, map[string]string{
		"pkg/a/a_test.go":           namingProbe("a_injection_test.go"),
		"pkg/a/a_injection_test.go": "package p\n",
	})
	findings, census := injAudit(t, root)
	if len(findings) != 0 {
		t.Fatalf("обещание С предметом объявлено находкой: %v", findings)
	}
	if census.InComments != 1 || census.Resolved != 1 {
		t.Fatalf("перепись не сошлась: упоминаний %d, резолвится %d — ожидалось 1 и 1",
			census.InComments, census.Resolved)
	}
}

// TestNamedInjectionInjection_PromiseWithoutSubjectIsCaught — обещание без
// предмета названо, и находка называет ОБЕ координаты: кто обещал и что.
func TestNamedInjectionInjection_PromiseWithoutSubjectIsCaught(t *testing.T) {
	root := injTree(t, map[string]string{
		"pkg/a/a_test.go": namingProbe("a_injection_test.go"),
	})
	findings, census := injAudit(t, root)
	if len(findings) != 1 {
		t.Fatalf("обещание без предмета дало находок %d, ожидалась 1: %v", len(findings), findings)
	}
	if findings[0].NamedBy != "pkg/a/a_test.go" {
		t.Errorf("находка не называет обещавшего: %q", findings[0].NamedBy)
	}
	if findings[0].Coordinate != "a_injection_test.go" {
		t.Errorf("находка не называет обещанного: %q", findings[0].Coordinate)
	}
	if census.Resolved != 0 {
		t.Errorf("нерезолвящееся упоминание зачтено резолвнутым: %d", census.Resolved)
	}
}

// TestNamedInjectionInjection_KnowsAllThreeLawfulForms — распознаватель знает
// ВСЕ три законные формы координаты.
//
// Ось названа замером, а не вкусом: наивный резолвер («только сосед») дал по
// этому дереву четыре непопадания, и все четыре оказались законными формами.
// Форма, о которой резолвер не знает, даёт не красное и не зелёное, а молчание —
// и молчит она ровно о тех пробах, которые доказательство ИМЕЮТ.
func TestNamedInjectionInjection_KnowsAllThreeLawfulForms(t *testing.T) {
	for _, c := range []struct {
		name  string
		files map[string]string
	}{
		{"сосед", map[string]string{
			"pkg/a/a_test.go":           namingProbe("a_injection_test.go"),
			"pkg/a/a_injection_test.go": "package p\n",
		}},
		{"по модулю — доказательство в другом пакете", map[string]string{
			"pkg/a/a_test.go":           namingProbe("b_injection_test.go"),
			"pkg/b/b_injection_test.go": "package q\n",
		}},
		{"координатой от корня модуля", map[string]string{
			"pkg/a/a_test.go":                namingProbe("internal/b/c_injection_test.go"),
			"internal/b/c_injection_test.go": "package q\n",
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			findings, census := injAudit(t, injTree(t, c.files))
			if len(findings) != 0 {
				t.Fatalf("законная форма координаты объявлена находкой: %v", findings)
			}
			if census.Resolved != 1 {
				t.Fatalf("резолвится %d, ожидалось 1 — форма не узнана, и молчание неотличимо "+
					"от отсутствия обещания", census.Resolved)
			}
		})
	}
}

// TestNamedInjectionInjection_CoordinateOutsideTheModuleIsNotResolved —
// координата от корня МОНОРЕПО, а не модуля, предметом не резолвится.
//
// Половина, без которой предыдущая проба ничего не доказывает: резолвер,
// принимающий любой путь, зеленел бы на всём.
func TestNamedInjectionInjection_CoordinateOutsideTheModuleIsNotResolved(t *testing.T) {
	findings, _ := injAudit(t, injTree(t, map[string]string{
		"pkg/a/a_test.go":                namingProbe("services/iam/internal/b/c_injection_test.go"),
		"internal/b/c_injection_test.go": "package q\n",
	}))
	if len(findings) != 1 {
		t.Fatalf("путь с чужой приставкой резолвнут: находок %d, ожидалась 1 — в самостоятельном "+
			"клоне такая координата указывает наружу дерева, и обещание её не имеет предмета",
			len(findings))
	}
}

// TestNamedInjectionInjection_StringLiteralIsCountedButNotJudged — упоминание в
// СТРОКОВОМ литерале не судится и при этом считается.
//
// Обе половины несущие. Не судится — потому что синтетические имена инъекций
// живут именно в литералах, и разбор краснел бы на чужой фикстуре, то есть на
// собственном доказательстве. Считается — потому что молчание о целом виде
// вхождений неотличимо от их отсутствия.
func TestNamedInjectionInjection_StringLiteralIsCountedButNotJudged(t *testing.T) {
	findings, census := injAudit(t, injTree(t, map[string]string{
		"pkg/a/a_test.go": "package p\n\nvar x = \"nowhere_injection_test.go\"\n",
	}))
	if len(findings) != 0 {
		t.Fatalf("имя из строкового литерала объявлено обещанием: %v", findings)
	}
	if census.InStrings != 1 {
		t.Fatalf("упоминаний в литералах насчитано %d, ожидалось 1 — целый вид вхождений "+
			"невидим переписи", census.InStrings)
	}
	if census.InComments != 0 {
		t.Fatalf("литерал зачтён комментарием: упоминаний в комментариях %d", census.InComments)
	}
}

// TestNamedInjectionInjection_PlaceholderIsNotACoordinate — образец с угловыми
// скобками координатой НЕ считается.
//
// Иначе разбор краснел бы на собственном объяснении: перечень законных форм
// стоит в его шапке, и записанный именами он был бы четырьмя обещаниями без
// предмета.
func TestNamedInjectionInjection_PlaceholderIsNotACoordinate(t *testing.T) {
	findings, census := injAudit(t, injTree(t, map[string]string{
		"pkg/a/a_test.go": "// форма координаты: <имя>_injection_test.go\npackage p\n",
	}))
	if len(findings) != 0 {
		t.Fatalf("образец принят за координату: %v", findings)
	}
	if census.InComments != 0 {
		t.Fatalf("образец зачтён упоминанием: %d", census.InComments)
	}
}

// TestNamedInjectionInjection_DirectoryIsNotAProof — каталог с именем
// доказательства доказательством не является.
func TestNamedInjectionInjection_DirectoryIsNotAProof(t *testing.T) {
	root := injTree(t, map[string]string{
		"pkg/a/a_test.go": namingProbe("a_injection_test.go"),
		"pkg/a/a_injection_test.go/внутри/x.txt": "не исходник\n",
	})
	findings, _ := injAudit(t, root)
	if len(findings) != 1 {
		t.Fatalf("каталог зачтён доказательством: находок %d, ожидалась 1", len(findings))
	}
}

// TestNamedInjectionInjection_EmptyWalkIsAFinding — пустое дерево даёт НОЛЬ по
// обеим осям переписи, по которым гейт и объявляет вердикт беспредметным.
//
// Утверждаются числа, а не исход гейта: его `t.Fatal` живёт в теле пробы и
// инъекции не поддаётся.
func TestNamedInjectionInjection_EmptyWalkIsAFinding(t *testing.T) {
	findings, census := injAudit(t, injTree(t, map[string]string{"README.md": "не Go\n"}))
	if len(findings) != 0 {
		t.Fatalf("на дереве без исходников найдены обещания: %v", findings)
	}
	if census.GoFiles != 0 || census.InComments != 0 {
		t.Fatalf("предпосылка неверна: исходников %d, упоминаний %d — ожидалось 0 и 0",
			census.GoFiles, census.InComments)
	}
}

// TestNamedInjectionInjection_UnparsableSourceIsNotCounted — неразбираемый
// исходник в перепись не попадает: о нём высказывается компилятор, а перепись
// обязана недосчитать его вслух, а не выдать за прочитанный.
func TestNamedInjectionInjection_UnparsableSourceIsNotCounted(t *testing.T) {
	_, census := injAudit(t, injTree(t, map[string]string{
		"pkg/a/broken.go": "это не Go\n",
		"pkg/a/a_test.go": "package p\n",
	}))
	if census.GoFiles != 1 {
		t.Fatalf("исходников разобрано %d, ожидался 1 — неразбираемый зачтён прочитанным",
			census.GoFiles)
	}
}

// TestNamedInjectionInjection_FindingsAreDeterministic — порядок находок
// детерминирован: текст, меняющийся от прогона к прогону, читают один раз.
func TestNamedInjectionInjection_FindingsAreDeterministic(t *testing.T) {
	root := injTree(t, map[string]string{
		"pkg/b/b_test.go": namingProbe("b_injection_test.go"),
		"pkg/a/a_test.go": namingProbe("a_injection_test.go"),
	})
	var first string
	for i := range 5 {
		findings, _ := injAudit(t, root)
		var names []string
		for _, f := range findings {
			names = append(names, f.NamedBy)
		}
		got := strings.Join(names, ",")
		if i == 0 {
			first = got
			continue
		}
		if got != first {
			t.Fatalf("порядок находок непостоянен: %q против %q", got, first)
		}
	}
	if first != "pkg/a/a_test.go,pkg/b/b_test.go" {
		t.Fatalf("порядок находок не отсортирован: %q", first)
	}
}
