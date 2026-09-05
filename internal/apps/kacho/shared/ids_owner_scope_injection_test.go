// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// ids_owner_scope_injection_test.go — ДОКАЗАТЕЛЬСТВО того, что гейт границы
// владения способен упасть и способен смолчать.
//
// Инъекция идёт в ОБЕ стороны по каждой оси: дефект обязан находиться, законный
// близнец ТОЙ ЖЕ формы обязан молчать. Без второй половины гейт ловил бы форму
// записи, а не существо, и первый же ложный срабат его отключил бы.
//
// Пробы зовут ТО ЖЕ тело (inspectOwnerScope), что исполняется на дереве. Своя
// копия предиката разошлась бы с настоящим гейтом молча — и доказательство
// перестало бы относиться к нему.
//
// Отдельная ось — РАЗРЕШЕНИЕ ПЕРЕМЕННОЙ. Оно обязано быть проверкой, а не
// печатью: производитель, возвращающий чужой префикс, обязан находиться так же,
// как чужой префикс, поставленный в вызов напрямую. Без этой пробы разрешение
// переменной было бы дырой ровно того размера, какую оно открывает.
package shared_test

import (
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// ownDomainImport / sharedImport — пути, по которым распознаватель узнаёт
// СВОЙ пакет domain и пакет строгой проверки.
const (
	ownDomainImport = "github.com/PRO-Robotech/kacho-iam/internal/domain"
	sharedImport    = "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/shared"
	foreignImport   = "github.com/PRO-Robotech/kacho/pkg/ids"
)

// domainFixture — собственный пакет domain: источник, из которого гейт ВЫВОДИТ
// владение. Перечня имён у гейта нет, поэтому фикстура обязана его нести.
const domainFixture = `package domain

const (
	PrefixAccount = "acc"
	PrefixGroup   = "grp"
	PrefixUser    = "usr"
)
`

// syntheticTree разбирает фикстуры в тот же вид, в каком гейт видит дерево.
func syntheticTree(t *testing.T, sources map[string]string) []sourceFile {
	t.Helper()
	fset := token.NewFileSet()
	out := make([]sourceFile, 0, len(sources))
	for path, src := range sources {
		f, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("фикстура %s не разобрана: %v", path, err)
		}
		out = append(out, sourceFile{Path: path, AST: f})
	}
	return out
}

// withDomain добавляет к фикстурам собственный пакет domain.
func withDomain(callSite string) map[string]string {
	return map[string]string{
		"internal/domain/constants.go":      domainFixture,
		"internal/apps/kacho/api/x/call.go": callSite,
	}
}

// callSiteSource собирает файл вызова с нужным импортом и телом.
func callSiteSource(extraImport, body string) string {
	imports := "\t\"" + sharedImport + "\"\n"
	if extraImport != "" {
		imports += "\t\"" + extraImport + "\"\n"
	}
	return "package x\n\nimport (\n" + imports + ")\n\n" + body
}

// ─────────────────────────────────────────────────────────────────────────────
// Ось 1 — префикс поставлен в вызов НАПРЯМУЮ.

// Дефект: чужой префикс. Обязано находиться — это утверждение о типе чужого
// идентификатора, которое конвенция запрещает потребителю.
func TestInjection_ForeignPrefixIsFound(t *testing.T) {
	files := syntheticTree(t, withDomain(callSiteSource(foreignImport, `
func f(id string) error { return shared.ValidateResourceID(id, ids.PrefixNetwork, "network") }
`)))
	c := inspectOwnerScope(files)
	if c.Calls != 1 {
		t.Fatalf("распознаватель не увидел вызов: вызовов %d", c.Calls)
	}
	if len(c.Findings) != 1 {
		t.Fatalf("чужой префикс не найден: находок %d", len(c.Findings))
	}
	if !strings.Contains(c.Findings[0], "call.go") {
		t.Fatalf("находка не назвала координату: %q", c.Findings[0])
	}
}

// Дефект: префикс литералом — каталог обойдён, владение никем не заявлено.
func TestInjection_LiteralPrefixIsFound(t *testing.T) {
	files := syntheticTree(t, withDomain(callSiteSource("", `
func f(id string) error { return shared.ValidateResourceID(id, "zzz", "thing") }
`)))
	c := inspectOwnerScope(files)
	if len(c.Findings) != 1 {
		t.Fatalf("литерал не найден: находок %d", len(c.Findings))
	}
}

// ЗАКОННЫЙ БЛИЗНЕЦ: та же форма, идентификатор СВОЙ. Гейт обязан молчать.
func TestInjection_OwnPrefixStaysSilent(t *testing.T) {
	files := syntheticTree(t, withDomain(callSiteSource(ownDomainImport, `
func f(id string) error { return shared.ValidateResourceID(id, domain.PrefixAccount, "account") }
`)))
	c := inspectOwnerScope(files)
	if len(c.Findings) != 0 {
		t.Fatalf("гейт краснеет на законном вызове: %v", c.Findings)
	}
	if c.OwnedSelector != 1 {
		t.Fatalf("перепись не зачла законный вызов: константой %d", c.OwnedSelector)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Ось 2 — префикс пришёл ПЕРЕМЕННОЙ. Разрешение обязано быть проверкой.

// ЗАКОННЫЙ БЛИЗНЕЦ: производитель возвращает только свои префиксы (и пустую
// строку на полосе отказа) — молчание.
func TestInjection_VariableFromOwnProducerStaysSilent(t *testing.T) {
	files := syntheticTree(t, withDomain(callSiteSource(ownDomainImport, `
func producer(k string) (string, string, error) {
	if k == "user" {
		return domain.PrefixUser, "user", nil
	}
	return "", "", nil
}

func f(k, id string) error {
	p, n, err := producer(k)
	if err != nil {
		return err
	}
	return shared.ValidateResourceID(id, p, n)
}
`)))
	c := inspectOwnerScope(files)
	if len(c.Findings) != 0 {
		t.Fatalf("гейт краснеет на законном разрешении переменной: %v", c.Findings)
	}
	if c.ResolvedIdent != 1 {
		t.Fatalf("перепись не зачла разрешение переменной: переменной %d", c.ResolvedIdent)
	}
}

// ДЕФЕКТ ТОЙ ЖЕ ФОРМЫ: производитель возвращает ЧУЖОЙ префикс. Обязано
// находиться — иначе разрешение переменной было бы печатью, а не проверкой, и
// чужой идентификатор проезжал бы под видом своего.
func TestInjection_VariableFromForeignProducerIsFound(t *testing.T) {
	src := "package x\n\nimport (\n\t\"" + sharedImport + "\"\n\t\"" + foreignImport + "\"\n)\n" + `
func producer(k string) (string, string, error) {
	return ids.PrefixNetwork, "network", nil
}

func f(k, id string) error {
	p, n, err := producer(k)
	if err != nil {
		return err
	}
	return shared.ValidateResourceID(id, p, n)
}
`
	files := syntheticTree(t, withDomain(src))
	c := inspectOwnerScope(files)
	if len(c.Findings) != 1 {
		t.Fatalf("чужой префикс, пришедший переменной, НЕ найден: находок %d, разрешено переменной %d",
			len(c.Findings), c.ResolvedIdent)
	}
}

// ДЕФЕКТ: переменная, источник которой в этом пакете не находится. Гейт
// закрывается наглухо — неразрешимое есть находка, а не послабление.
func TestInjection_UnresolvableVariableIsFound(t *testing.T) {
	files := syntheticTree(t, withDomain(callSiteSource("", `
func f(id string, p, n string) error { return shared.ValidateResourceID(id, p, n) }
`)))
	c := inspectOwnerScope(files)
	if len(c.Findings) != 1 {
		t.Fatalf("неразрешимая переменная не найдена: находок %d", len(c.Findings))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Ось 3 — ПРЕДПОСЫЛКА гейта. Она обязана быть наблюдаемой, а не подразумеваться.

// Собственный пакет domain исчез: владение выводить неоткуда. Перепись обязана
// показать ноль объявленных префиксов — на дереве по этому признаку гейт падает,
// и «не с чем сверять» не выдаётся за «сверено, чисто».
func TestInjection_MissingOwnDomainIsVisibleInTheCensus(t *testing.T) {
	files := syntheticTree(t, map[string]string{
		"internal/apps/kacho/api/x/call.go": callSiteSource(ownDomainImport, `
func f(id string) error { return shared.ValidateResourceID(id, domain.PrefixAccount, "account") }
`),
	})
	c := inspectOwnerScope(files)
	if len(c.OwnedPrefixes) != 0 {
		t.Fatalf("предпосылка не измеряется: объявлено префиксов %d", len(c.OwnedPrefixes))
	}
	if len(c.Findings) == 0 {
		t.Fatal("без собственного каталога владения вызов обязан стать находкой, а не пройти молча")
	}
}

// Обход пуст — перепись обязана это показать; на дереве гейт по этому признаку
// падает, потому что «ноль находок» и «ноль прочитанного» суть разные вердикты.
func TestInjection_EmptyWalkIsVisibleInTheCensus(t *testing.T) {
	c := inspectOwnerScope(nil)
	if c.FilesWalked != 0 || c.Calls != 0 {
		t.Fatalf("перепись пустого обхода лжёт: файлов %d, вызовов %d", c.FilesWalked, c.Calls)
	}
}
