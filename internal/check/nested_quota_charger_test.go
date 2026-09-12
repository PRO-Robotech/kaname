// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// nested_quota_charger_test.go — вложенный вид, объявленный в каталоге,
// обязан ИМЕТЬ СПИСАНИЕ (задача продукта `PRO-Robotech/kacho#353`).
//
// Порт с монорепо (`internal/repohygiene/nestedquotacharger_test.go`, снят
// вынесением службы — `kacho#2597`). Дословно: предикат, перечень
// освобождений, обе пробы. Изменилось: пакет (`repohygiene_test` →
// `check_test`), обход дерева.
//
// # ПРЕДМЕТ — КРОСС-СЕРВИСНЫЙ, и это несущее для порта
//
// Каталог видов (`countableKinds`) живёт у владельца величин — этой службы
// (`internal/domain/limit.go`). Списывающий триггер живёт у владельца
// РЕСУРСА — в миграциях СОСЕДНИХ сервисов (`vpc`, `nlb`, `storage`,
// `registry`, …), которых в дереве kaname НЕТ и не будет: это архитектурное
// решение (`data-integrity.md` §«Счётчик потолка живёт РЯДОМ С РЕСУРСОМ, а
// величина — у владельца величин»), а не пробел переноса.
//
// Отсюда форма порта: гейт требует ДЕРЕВО ПЛАТФОРМЫ целиком
// (`platformtree.Require`, ровно тот случай из её же годка — «манифесты
// соседних модулей» здесь читается как «миграции соседних модулей»). В
// самостоятельном клоне службы — ЗАКОННЫЙ пропуск с названной предпосылкой,
// а не находка: предмета для сверки здесь нет ни у одной из двух сторон.
// Гейт вооружается сам, когда модуль встаёт локально рядом с платформой
// (`polyrepo.md` §«Локальная кросс-репо разработка» — `go.work`).
package check_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"

	"go/ast"
	"go/parser"
	"go/token"
)

// nestedKindsWithoutAChargerYet — виды, у которых списания ещё НЕТ, с
// причиной и предметом. Пуст — и это цель, а не поломка (см. монорепо).
var nestedKindsWithoutAChargerYet = map[string]string{}

// TestNestedChargerExemptionsStillHaveSubject — освобождение живёт, пока у
// него есть предмет.
func TestNestedChargerExemptionsStillHaveSubject(t *testing.T) {
	root := platformtree.Require(t)
	ownDir := filepath.Join(root, filepath.FromSlash(platformtree.ModuleDirInPlatform()))

	declared := nestedKindsOfCatalogue(t, ownDir)
	charged, _, _ := nestedKindChargers(t, root)

	declaredSet := map[string]bool{}
	for _, k := range declared {
		declaredSet[k] = true
	}
	for kind, why := range nestedKindsWithoutAChargerYet {
		if why == "" {
			t.Errorf("освобождение %q обязано нести причину", kind)
		}
		if !declaredSet[kind] {
			t.Errorf("освобождению %q больше нечего освобождать: каталог такого вида не объявляет", kind)
		}
		if _, isCharged := charged[kind]; isCharged {
			t.Errorf("вид %q УЖЕ списывается — освобождение пережило свой предмет и обязано "+
				"уйти вместе с ним", kind)
		}
	}
	t.Logf("перепись: освобождений прочитано %d, все с предметом", len(nestedKindsWithoutAChargerYet))
}

// TestEveryNestedQuotaKindHasACharger — сам гейт.
func TestEveryNestedQuotaKindHasACharger(t *testing.T) {
	root := platformtree.Require(t)
	ownDir := filepath.Join(root, filepath.FromSlash(platformtree.ModuleDirInPlatform()))

	declared := nestedKindsOfCatalogue(t, ownDir)
	if len(declared) == 0 {
		t.Fatal("вложенных видов в каталоге не найдено — предпосылка гейта сломана, и его " +
			"молчание не отличимо от согласия")
	}

	charged, lifecycle, sqlSeen := nestedKindChargers(t, root)

	if len(charged) == 0 {
		t.Fatalf("предикат не нашёл НИ ОДНОГО списания по носителю-родителю на %d миграциях — "+
			"он мерит форму записи, а не факт", sqlSeen)
	}
	if len(lifecycle) == 0 {
		t.Fatal("предикат не нашёл НИ ОДНОЙ строки учёта родителя: без неё списывать нечего, " +
			"и «списание есть» было бы утверждением ни о чём")
	}

	var findings []string
	for _, kind := range declared {
		if _, exempt := nestedKindsWithoutAChargerYet[kind]; exempt {
			continue
		}
		_, hasCharge := charged[kind]
		_, hasRow := lifecycle[kind]
		switch {
		case !hasCharge && !hasRow:
			findings = append(findings, kind+
				" — величина задаётся администратором и не делает НИЧЕГО: ни строки учёта "+
				"родителя, ни списания. Предел объявлен и не применяется ни при каких условиях")
		case !hasCharge:
			findings = append(findings, kind+
				" — строка учёта родителя заводится, но её никто не списывает: счётчик "+
				"стоит на нуле вечно, и потолок не наступает никогда")
		case !hasRow:
			findings = append(findings, kind+
				" — списание есть, а строки учёта родителя никто не заводит: списывать "+
				"нечего, и КАЖДАЯ вставка ребёнка отвергается «потолок не назван»")
		}
	}

	declaredSet := map[string]bool{}
	for _, k := range declared {
		declaredSet[k] = true
	}
	for kind, where := range charged {
		if strings.Count(kind, ".") != 2 {
			continue
		}
		if !declaredSet[kind] {
			findings = append(findings, kind+
				" — списывается ("+where+"), но каталог такого вложенного вида не объявляет: "+
				"величины у него нет, и отказ наступит на первой же вставке ребёнка")
		}
	}
	sort.Strings(findings)

	chargedNested, rowNested := 0, 0
	for _, k := range declared {
		if _, ok := charged[k]; ok {
			chargedNested++
		}
		if _, ok := lifecycle[k]; ok {
			rowNested++
		}
	}
	t.Logf("перепись: миграций осмотрено %d; вложенных видов каталога %d (%s); "+
		"из них со списанием %d, со строкой учёта родителя %d; освобождений %d",
		sqlSeen, len(declared), strings.Join(declared, ", "), chargedNested, rowNested,
		len(nestedKindsWithoutAChargerYet))

	if len(findings) != 0 {
		t.Fatalf("вложенный потолок, который задаётся и не действует, — обещание, за которое "+
			"никто не отвечает: администратор меняет число, ответ успешен, предел не "+
			"наступает:\n%s", strings.Join(findings, "\n"))
	}
}

// nestedKindsOfCatalogue читает вложенные виды из ТАБЛИЦЫ КАТАЛОГА разбором
// AST. ownDir — каталог СВОЕГО модуля (не платформы).
func nestedKindsOfCatalogue(t *testing.T, ownDir string) []string {
	t.Helper()

	path := filepath.Join(ownDir, "internal", "domain", "limit.go")
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("разбор каталога видов %s: %v", path, err)
	}

	rootByName := map[string]bool{}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Names) == 0 || len(vs.Values) == 0 {
				continue
			}
			if !strings.HasPrefix(vs.Names[0].Name, "Carrier") {
				continue
			}
			if lit, ok := vs.Values[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
				if _, err := strconv.Unquote(lit.Value); err == nil {
					rootByName[vs.Names[0].Name] = true
				}
			}
		}
	}
	if len(rootByName) == 0 {
		t.Fatal("корней аренды в каталоге не найдено — без них «вложенный» неотличим от «корневого»")
	}

	var nested []string
	ast.Inspect(file, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok || len(vs.Names) == 0 || vs.Names[0].Name != "countableKinds" {
			return true
		}
		lit, ok := vs.Values[0].(*ast.CompositeLit)
		if !ok {
			return true
		}
		for _, el := range lit.Elts {
			entry, ok := el.(*ast.CompositeLit)
			if !ok || len(entry.Elts) != 2 {
				continue
			}
			kind, kok := nestedQuotaStringOf(entry.Elts[0])
			if !kok {
				continue
			}
			if ident, isIdent := entry.Elts[1].(*ast.Ident); isIdent {
				if !rootByName[ident.Name] {
					t.Fatalf("носитель %q вида %q — идентификатор, но не объявленная константа "+
						"корня: гейт не знает, корневой он или родительский, и молчать здесь "+
						"нельзя", ident.Name, kind)
				}
				continue
			}
			if _, isLit := nestedQuotaStringOf(entry.Elts[1]); !isLit {
				continue
			}
			nested = append(nested, kind)
		}
		return false
	})
	sort.Strings(nested)
	return nested
}

func nestedQuotaStringOf(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	v, err := strconv.Unquote(lit.Value)
	return v, err == nil
}

// nestedKindChargers отдаёт виды, по которым списывает триггер, и виды, у
// которых заводится строка учёта родителя. root — корень ПЛАТФОРМЫ.
func nestedKindChargers(t *testing.T, root string) (charged, lifecycle map[string]string, sqlSeen int) {
	t.Helper()

	files, err := treecorpus.UnderWithSuffix(filepath.Join(root, "services"), ".sql")
	if err != nil {
		t.Fatalf("перечень миграций берётся у индекса дерева, а не обходом диска: %v", err)
	}

	charged, lifecycle = map[string]string{}, map[string]string{}
	chargeRe := regexp.MustCompile(`kacho_quota_count\(([^)]*)\)`)
	lifeRe := regexp.MustCompile(`kacho_quota_carrier_lifecycle\(([^)]*)\)`)
	argRe := regexp.MustCompile(`'([^']*)'`)
	space := regexp.MustCompile(`\s+`)

	for _, path := range files {
		if !strings.Contains(path, "/internal/migrations/") {
			continue
		}
		raw, rerr := os.ReadFile(path)
		if rerr != nil {
			t.Fatalf("чтение %s: %v", path, rerr)
		}
		sqlSeen++
		body := space.ReplaceAllString(string(raw), " ")

		rel := path
		if i := strings.Index(path, "/services/"); i >= 0 {
			rel = path[i+1:]
		}
		for _, m := range chargeRe.FindAllStringSubmatch(body, -1) {
			for _, a := range argRe.FindAllStringSubmatch(m[1], -1) {
				if a[1] == "" {
					continue
				}
				charged[a[1]] = rel
			}
		}
		for _, m := range lifeRe.FindAllStringSubmatch(body, -1) {
			for _, a := range argRe.FindAllStringSubmatch(m[1], -1) {
				if a[1] == "" {
					continue
				}
				lifecycle[a[1]] = rel
			}
		}
	}
	return charged, lifecycle, sqlSeen
}
