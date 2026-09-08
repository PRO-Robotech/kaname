// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// ids_fixture_form_injection_test.go — ДОКАЗАТЕЛЬСТВО того, что гейт формы
// фикстурного идентификатора способен упасть и способен смолчать.
//
// Инъекция идёт в ОБЕ стороны по каждой оси: обрезанный литерал обязан
// находиться И называть координату, законный близнец ТОЙ ЖЕ формы записи обязан
// молчать. Без второй половины гейт ловил бы форму записи, а не существо, и
// первый же ложный срабат его отключил бы.
//
// Пробы зовут ТО ЖЕ тело (inspectFixtureForm), что исполняется на дереве, и оно
// выносит вердикт настоящей `shared.ValidateResourceID`. Своя копия предиката
// разошлась бы с продуктом молча — и доказательство перестало бы относиться к
// тому, что стоит на дереве.
//
// ОТДЕЛЬНЫЕ ОСИ, каждая со своим контролем:
//
//   - четыре формы записи позиции — поле · объявление · присваивание ·
//     приведение. Форма, о которой распознаватель не знает, была бы не
//     редкостью, а слепой зоной (testing.md §«Гейт на класс», п. 7);
//   - предикат, УЖЕ проваливший контроль: обычное слово, начинающееся с
//     префикса, и сама константа префикса обязаны молчать. Ради этого гейт и
//     переписан с поиска по имени на разбор по позиции;
//   - охват ВЫВЕДЕН из продукта: тот же дефект в пакете, чей прод форму не
//     судит, находкой не становится — но считается отдельным числом, иначе
//     «вне охвата» было бы неотличимо от «нет»;
//   - пометка намеренно негодной формы: гасит находку и САМА ИСТЕКАЕТ, стоя на
//     годном литерале;
//   - ведомость остатка: расхождение в ОБЕ стороны и запись, которой нечего
//     исключать.
package shared_test

import (
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

const (
	// injServiceDir — корень синтетического сервиса: координаты находок
	// печатаются относительно него.
	injServiceDir = "svc"
	// injScopedPkg — пакет, чей прод зовёт строгую проверку ⇒ он в охвате.
	injScopedPkg = "internal/apps/kaname/api/x"
	// injUnscopedPkg — пакет БЕЗ такого вызова ⇒ вне охвата.
	injUnscopedPkg = "internal/apps/kaname/api/y"

	// injWellFormed / injTruncated — пара, различающаяся РОВНО одним символом:
	// вердикт по ней говорит об оси длины и ни о чём другом.
	injWellFormed = "usr00000000000000001"
	injTruncated  = "usr0000000000000001"
)

// injProdCall — прод-файл, вводящий пакет в охват. Отдельная ось: сам факт
// охвата обязан ВЫВОДИТЬСЯ из этого файла, а не быть выписан списком.
const injProdCall = `package x

import "` + sharedImport + `"

func f(id string) error { return shared.ValidateResourceID(id, "usr", "user") }
`

// synthTests разбирает фикстуры проб в тот же вид, в каком гейт видит дерево, —
// С КОММЕНТАРИЯМИ: пометка живёт в комментарии, и без них ось пометки была бы
// недоказуема.
func synthTests(t *testing.T, sources map[string]string) []testFile {
	t.Helper()
	out := make([]testFile, 0, len(sources))
	for path, src := range sources {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, src, parser.ParseComments|parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("фикстура %s не разобрана: %v", path, err)
		}
		out = append(out, testFile{Path: path, AST: f, FSet: fset})
	}
	return out
}

// scene собирает сцену: собственный domain + прод, вводящий пакет в охват, +
// поданные файлы проб.
func scene(t *testing.T, tests map[string]string) ([]sourceFile, []testFile) {
	t.Helper()
	prod := syntheticTree(t, map[string]string{
		injServiceDir + "/internal/domain/constants.go": domainFixture,
		injServiceDir + "/" + injScopedPkg + "/call.go": injProdCall,
	})
	full := make(map[string]string, len(tests))
	for p, src := range tests {
		full[injServiceDir+"/"+p] = src
	}
	return prod, synthTests(t, full)
}

// runScene — единственная точка вызова тела гейта в этом файле.
func runScene(t *testing.T, ledger map[string]int, tests map[string]string) fixtureFormCensus {
	t.Helper()
	prod, parsed := scene(t, tests)
	c := inspectFixtureForm(prod, parsed, injServiceDir, ledger)
	if len(c.ScopePkgs) != 1 || c.ScopePkgs[0] != injScopedPkg {
		t.Fatalf("охват выведен неверно: %v — дальнейший вердикт был бы про другое", c.ScopePkgs)
	}
	return c
}

// scopedTest кладёт тело в файл проб пакета, находящегося В охвате.
func scopedTest(body string) map[string]string {
	return map[string]string{injScopedPkg + "/x_test.go": "package x\n\n" + body}
}

// requireFinding требует ровно одну находку, называющую координату и значение.
func requireFinding(t *testing.T, c fixtureFormCensus, wantValue string) {
	t.Helper()
	if len(c.Findings) != 1 {
		t.Fatalf("ожидалась одна находка, получено %d: %v", len(c.Findings), c.Findings)
	}
	got := c.Findings[0]
	if !strings.Contains(got, injScopedPkg+"/x_test.go:") {
		t.Fatalf("находка не называет координату: %q", got)
	}
	if !strings.Contains(got, wantValue) {
		t.Fatalf("находка не называет значение %q: %q", wantValue, got)
	}
}

// requireSilence требует молчания по всем трём осям вердикта: находки, устаревшие
// пометки и ведомость.
func requireSilence(t *testing.T, c fixtureFormCensus) {
	t.Helper()
	if len(c.Findings) != 0 || len(c.StaleMarks) != 0 || len(c.LedgerErrors) != 0 {
		t.Fatalf("ожидалось молчание, получено: находки=%v пометки=%v ведомость=%v",
			c.Findings, c.StaleMarks, c.LedgerErrors)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Ось 1 — четыре формы записи позиции собственного идентификатора.

func TestInjection_FixtureForm_TruncatedIsFoundInEveryWriteForm(t *testing.T) {
	forms := map[string]string{
		"поле": `import "svc/internal/domain"

var _ = domain.In{UserID: "` + injTruncated + `"}
`,
		"объявление": `const userID = "` + injTruncated + `"
`,
		"присваивание": `func f(in *struct{ UserID string }) { in.UserID = "` + injTruncated + `" }
`,
		"приведение": `import "svc/internal/domain"

var _ = domain.UserID("` + injTruncated + `")
`,
	}
	for name, body := range forms {
		t.Run(name, func(t *testing.T) {
			c := runScene(t, nil, scopedTest(body))
			requireFinding(t, c, injTruncated)
		})
	}
}

func TestInjection_FixtureForm_WellFormedTwinIsSilentInEveryWriteForm(t *testing.T) {
	forms := map[string]string{
		"поле": `import "svc/internal/domain"

var _ = domain.In{UserID: "` + injWellFormed + `"}
`,
		"объявление": `const userID = "` + injWellFormed + `"
`,
		"присваивание": `func f(in *struct{ UserID string }) { in.UserID = "` + injWellFormed + `" }
`,
		"приведение": `import "svc/internal/domain"

var _ = domain.UserID("` + injWellFormed + `")
`,
	}
	for name, body := range forms {
		t.Run(name, func(t *testing.T) {
			c := runScene(t, nil, scopedTest(body))
			requireSilence(t, c)
			if c.Claims != 1 {
				t.Fatalf("законный близнец обязан быть ОСМОТРЕН, а не пропущен: заявок %d", c.Claims)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Ось 2 — предикат, уже проваливший контроль. Обе формы обязаны молчать.

// Обычное слово, начинающееся с префикса, стоящее НЕ в позиции идентификатора,
// — 524 таких «попадания» и погубили поиск по имени.
func TestInjection_FixtureForm_OrdinaryWordOutsideAnIDPositionIsSilent(t *testing.T) {
	c := runScene(t, nil, scopedTest(`import "svc/internal/domain"

var _ = domain.In{ResourceType: "account", Name: "accounting", Note: "usr_alice"}
`))
	requireSilence(t, c)
	if c.Claims != 0 {
		t.Fatalf("вне позиции идентификатора заявок быть не может: %d", c.Claims)
	}
}

// Сама константа префикса — 47 таких «попаданий». Заявкой считается префикс
// ПЛЮС хоть один символ, поэтому голый префикс молчит даже в позиции id.
func TestInjection_FixtureForm_BarePrefixInIDPositionIsSilent(t *testing.T) {
	c := runScene(t, nil, scopedTest(`const userID = "usr"
`))
	requireSilence(t, c)
	if c.IDPositions != 1 {
		t.Fatalf("позиция обязана быть ОСМОТРЕНА: позиций %d", c.IDPositions)
	}
	if c.Claims != 0 {
		t.Fatalf("голый префикс идентификатором не притворяется: заявок %d", c.Claims)
	}
}

// Чужой префикс в позиции идентификатора — не наш предмет: тип чужого решает
// его владелец (api-conventions.md §By-lane code-split).
func TestInjection_FixtureForm_ForeignPrefixIsSilent(t *testing.T) {
	c := runScene(t, nil, scopedTest(`const subnetID = "net0000000000000001"
`))
	requireSilence(t, c)
	if c.Claims != 0 {
		t.Fatalf("чужой префикс собственным идентификатором не заявляется: %d", c.Claims)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Ось 3 — охват ВЫВЕДЕН из продукта.

func TestInjection_FixtureForm_SameDefectOutsideScopeIsCountedNotAccused(t *testing.T) {
	c := runScene(t, nil, map[string]string{
		injUnscopedPkg + "/y_test.go": "package y\n\nconst userID = \"" + injTruncated + "\"\n",
	})
	requireSilence(t, c)
	if c.OutOfBad != 1 {
		t.Fatalf("негодное ВНЕ охвата обязано быть сосчитано — иначе «вне охвата» "+
			"неотличимо от «нет»: сосчитано %d", c.OutOfBad)
	}
	if c.InScopeBad != 0 {
		t.Fatalf("пакет вне охвата не обвиняется: в охвате насчитано %d", c.InScopeBad)
	}
}

// Контроль к предыдущему: тот же файл, тот же дефект — но пакет стал судить
// форму, и охват вырос САМ, без правки списка.
func TestInjection_FixtureForm_ScopeGrowsWithTheProduct(t *testing.T) {
	prod := syntheticTree(t, map[string]string{
		injServiceDir + "/internal/domain/constants.go":   domainFixture,
		injServiceDir + "/" + injScopedPkg + "/call.go":   injProdCall,
		injServiceDir + "/" + injUnscopedPkg + "/call.go": strings.Replace(injProdCall, "package x", "package y", 1),
	})
	tests := synthTests(t, map[string]string{
		injServiceDir + "/" + injUnscopedPkg + "/y_test.go": "package y\n\nconst userID = \"" + injTruncated + "\"\n",
	})
	c := inspectFixtureForm(prod, tests, injServiceDir, nil)
	if len(c.ScopePkgs) != 2 {
		t.Fatalf("охват обязан вырасти вместе с продуктом: %v", c.ScopePkgs)
	}
	if len(c.Findings) != 1 || !strings.Contains(c.Findings[0], injUnscopedPkg) {
		t.Fatalf("пакет, начавший судить форму, приводит с собой требование к своим "+
			"фикстурам: %v", c.Findings)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Ось 4 — пометка намеренно негодной формы гасит находку и истекает сама.

func TestInjection_FixtureForm_MarkSilencesTheDeliberateDefect(t *testing.T) {
	c := runScene(t, nil, scopedTest(`// `+deliberateBadFormMark+`: проба утверждает отказ по длине.
const userID = "`+injTruncated+`"
`))
	requireSilence(t, c)
	if c.Marked != 1 {
		t.Fatalf("пометка обязана быть сосчитана: помечено %d", c.Marked)
	}
}

func TestInjection_FixtureForm_MarkOnAWellFormedLiteralIsStale(t *testing.T) {
	c := runScene(t, nil, scopedTest(`// `+deliberateBadFormMark+`: причина пережила свой предмет.
const userID = "`+injWellFormed+`"
`))
	if len(c.StaleMarks) != 1 {
		t.Fatalf("пометке нечего исключать — это находка: %v", c.StaleMarks)
	}
	if !strings.Contains(c.StaleMarks[0], injWellFormed) {
		t.Fatalf("устаревшая пометка обязана называть координату и значение: %q", c.StaleMarks[0])
	}
	if len(c.Findings) != 0 {
		t.Fatalf("годный литерал находкой быть не может: %v", c.Findings)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Ось 5 — ведомость остатка: расхождение в ОБЕ стороны и пустая запись.

func TestInjection_FixtureForm_LedgerHoldsTheExactCount(t *testing.T) {
	// Второе значение обязано быть НЕГОДНЫМ самостоятельно: приписка символа к
	// обрезанному даёт полную длину, и остаток стал бы единицей вместо двойки.
	body := scopedTest(`const aID = "` + injTruncated + `"
const bID = "usr00000000000002"
`)

	t.Run("точное число молчит", func(t *testing.T) {
		requireSilence(t, runScene(t, map[string]int{injScopedPkg: 2}, body))
	})

	t.Run("рост — находка", func(t *testing.T) {
		c := runScene(t, map[string]int{injScopedPkg: 1}, body)
		if len(c.LedgerErrors) != 1 || !strings.Contains(c.LedgerErrors[0], "найдено 2") {
			t.Fatalf("новая негодная фикстура обязана находиться: %v", c.LedgerErrors)
		}
	})

	t.Run("потолок не годится: убыль тоже находка", func(t *testing.T) {
		c := runScene(t, map[string]int{injScopedPkg: 5}, body)
		if len(c.LedgerErrors) != 1 || !strings.Contains(c.LedgerErrors[0], "называет 5") {
			t.Fatalf("ведомость обязана истекать по мере починки: %v", c.LedgerErrors)
		}
	})
}

func TestInjection_FixtureForm_LedgerEntryWithNothingToExcludeIsAFinding(t *testing.T) {
	c := runScene(t, map[string]int{injScopedPkg: 3}, scopedTest(`const userID = "`+injWellFormed+`"
`))
	if len(c.LedgerErrors) != 1 || !strings.Contains(c.LedgerErrors[0], "нечего исключать") {
		t.Fatalf("запись, которой нечего исключать, обязана находиться: %v", c.LedgerErrors)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Ось 6 — предпосылки гейта. Пустой обход не имеет права выглядеть чистым.

func TestInjection_FixtureForm_EmptyWalkIsNotCleanliness(t *testing.T) {
	prod := syntheticTree(t, map[string]string{
		injServiceDir + "/internal/domain/constants.go": domainFixture,
		injServiceDir + "/" + injScopedPkg + "/call.go": injProdCall,
	})
	c := inspectFixtureForm(prod, nil, injServiceDir, nil)
	if c.TestFiles != 0 || c.Claims != 0 {
		t.Fatalf("сцена собрана неверно: файлов %d заявок %d", c.TestFiles, c.Claims)
	}
	// Вердикт по пустому обходу выносит сам гейт (t.Fatal в TestFixtureIdentifiers…);
	// здесь доказывается, что перепись это состояние ОТЛИЧАЕТ от чистого дерева.
	if len(c.Findings) != 0 {
		t.Fatalf("пустой обход не производит находок — он производит НОЛЬ ПРОЧИТАННОГО: %v", c.Findings)
	}
}

func TestInjection_FixtureForm_PrefixesComeFromTheTreeNotFromAList(t *testing.T) {
	prod := syntheticTree(t, map[string]string{
		injServiceDir + "/internal/domain/constants.go": "package domain\n\nconst ShortIDLen = 20\n",
		injServiceDir + "/" + injScopedPkg + "/call.go": injProdCall,
	})
	tests := synthTests(t, map[string]string{
		injServiceDir + "/" + injScopedPkg + "/x_test.go": "package x\n\nconst userID = \"" + injTruncated + "\"\n",
	})
	c := inspectFixtureForm(prod, tests, injServiceDir, nil)
	if len(c.Prefixes) != 0 {
		t.Fatalf("префиксы обязаны выводиться из дерева: %v", c.Prefixes)
	}
	if len(c.Findings) != 0 {
		t.Fatalf("без объявленных префиксов заявок не бывает — и это ловит проверка "+
			"предпосылки, а не молчаливое согласие: %v", c.Findings)
	}
}
