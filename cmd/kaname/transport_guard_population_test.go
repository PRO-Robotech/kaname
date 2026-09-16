// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// transport_guard_population_test.go — КАЖДАЯ не-gRPC поверхность судится
// стражем транспорта, и число судимых ВЫВОДИТСЯ из дерева (задача #2641).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Перечень `iamHTTPEdges` называет рёбра, чей транспорт судит
// `requireHTTPEdgeTLS`. Перечень этот ВТОРОЙ по отношению к тому, из чего
// поверхности строятся, и потому опасен ровно тем же, чем опасен всякий
// рукописный список: отстань он на одно ребро — страж судил бы посадку не
// целиком, а проба осталась бы зелёной.
//
// До этой пробы длина перечня сверялась САМА С СОБОЙ: перепись боевого профиля
// печатала «HTTP-рёбер в перечне 5, из них с объявленным адресом 5». Утверждение
// верное и пустое — оно не могло покраснеть НИ ПРИ КАКОМ составе дерева, потому
// что оба числа приходят из одного источника. Форма без содержания.
//
// Заведут седьмую поверхность — её транспорт не будет судим ничем, и ни одна
// проба этого не скажет. Именно это здесь и закрывается: число рёбер сверяется с
// числом, ВЫВЕДЕННЫМ разбором корня.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ РАВЕНСТВО, А НЕ «НЕ МЕНЬШЕ»
//
// Популяция закрыта: поверхность либо судится общим перечнем, либо названа
// ведомостью как судимая ОТДЕЛЬНЫМ стражем. Неравенство в обе стороны — находка:
// меньше — поверхность без суждения; больше — ребро, под которым нет
// поверхности, то есть страж, судящий то, чего корень не поднимает.
//
// ─────────────────────────────────────────────────────────────────────────────
// ВЕДОМОСТЬ САМОИСТЕКАЕТ, И ПРОВЕРЯЕТСЯ ОНА УЗЛОМ, А НЕ СЛОВОМ
//
// Поверхность выдачи докерного токена судит свой страж со своим текстом отказа —
// это РЕШЕНИЕ, а не дрейф (довод — шапка `httpedgetls.go`). Такая поверхность
// обязана быть названа ИМЕНЕМ и причиной, и запись обязана истекать: исчезнет
// отдельный страж — запись становится находкой, потому что исключать ей больше
// нечего.
//
// Существование стража проверяется ОБЪЯВЛЕНИЕМ ФУНКЦИИ (узел `FuncDecl`), а не
// поиском имени: имя `requireRegistryTokenTLS` стоит в дереве и в комментариях —
// в шапке `httpedgetls.go`, объясняющей, почему страж отдельный, и в самом
// `serve.go`. Проверка по подстроке зеленела бы на СОБСТВЕННОМ объяснении
// ведомости — ровно тот класс, который `testing.md` §«Гейт на класс» п. 4
// называет чтением текста вместо исполняемой части.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
)

// httpEdgeRosterFunc — функция, отдающая перечень судимых рёбер.
const httpEdgeRosterFunc = "iamHTTPEdges"

// separatelyGuardedSurface — поверхность, судимая НЕ общим перечнем.
//
// Запись заводится ПО ФАКТУ, а не с запасом: ведомость, записанная шире
// предмета, прощает то, чего уже нет, и следующая настоящая находка уедет под
// неё незамеченной.
type separatelyGuardedSurface struct {
	// Surface — как поверхность зовётся у человека.
	Surface string
	// Guard — ОБЪЯВЛЕНИЕ стража. Исчезнет оно — запись истекает.
	Guard string
	// Why — почему страж отдельный. Без причины запись неотличима от недосмотра.
	Why string
}

// separatelyGuardedSurfaces — ВЕДОМОСТЬ. Две записи, каждая названа решением.
var separatelyGuardedSurfaces = []separatelyGuardedSurface{{
	Surface: "выдача докерного токена",
	Guard:   "requireRegistryTokenTLS",
	Why: "по этой ноге едет ПРИВАТНЫЙ КЛЮЧ ключа служебной учётки, у которого нет " +
		"ни срока, ни ротации: ущерб не ограничен ничем, в отличие от короткоживущего " +
		"предъявителя. Свести стража с общим значило бы либо потерять этот довод, либо " +
		"повторить его вторым местом об одном предмете",
}, {
	Surface: "полоса входа паролем",
	Guard:   "requireLoginLaneTLS",
	Why: "общий страж судит ТОЛЬКО транспорт («TLS есть»), а полосе входа этого мало: " +
		"вызывающего она опознаёт SAN проверенного КЛИЕНТСКОГО сертификата, поэтому " +
		"условие старта — режим `mutual`, и он есть только у этого стража (Ф3-44 в). " +
		"Сверх того полоса поднимается ПОСАДКОЙ (`own`), а не адресом: под `external` " +
		"её нет, и общий перечень судил бы ребро, которого на этой посадке не поднимают",
}}

// transportGuardCensus — объём осмотренного и выведенные числа.
type transportGuardCensus struct {
	Files          int
	Parsed         int
	SurfacesBuilt  int
	EdgesInRoster  int
	LedgerEntries  int
	LedgerResolved []string
	LedgerExpired  []string
}

func (c transportGuardCensus) Summary() string {
	resolved := "нет"
	if len(c.LedgerResolved) > 0 {
		resolved = strings.Join(c.LedgerResolved, ", ")
	}
	return fmt.Sprintf(
		"прод-файлов корня %d · разобрано %d · не-gRPC поверхностей построено %d · "+
			"судится перечнем рёбер %d · судится отдельным стражем %d (%s) · "+
			"записей ведомости %d",
		c.Files, c.Parsed, c.SurfacesBuilt, c.EdgesInRoster,
		len(c.LedgerResolved), resolved, c.LedgerEntries)
}

// countTransportGuardPopulations разбирает корень и выводит числа.
//
// Состав приходит ПАРАМЕТРОМ: в живом дереве его даёт обход корня, инъекция
// подаёт синтетический.
func countTransportGuardPopulations(files []string, ledger []separatelyGuardedSurface) (transportGuardCensus, error) {
	c := transportGuardCensus{LedgerEntries: len(ledger)}
	fset := token.NewFileSet()
	declared := map[string]bool{}

	for _, path := range files {
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			continue
		}
		c.Files++
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return c, fmt.Errorf("разобрать %s: %w", path, err)
		}
		c.Parsed++

		ast.Inspect(file, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.FuncDecl:
				// Объявление стража — УЗЕЛ, а не слово: имя стоит и в
				// комментариях, объясняющих, почему он отдельный.
				if v.Recv == nil && v.Name != nil {
					declared[v.Name.Name] = true
				}
				if v.Name != nil && v.Name.Name == httpEdgeRosterFunc {
					c.EdgesInRoster += rosterElementsIn(v)
				}
			case *ast.CallExpr:
				if id, ok := v.Fun.(*ast.Ident); ok && id.Name == "iamHTTPSurface" {
					c.SurfacesBuilt++
				}
			}
			return true
		})
	}

	for _, e := range ledger {
		if declared[e.Guard] {
			c.LedgerResolved = append(c.LedgerResolved, e.Surface)
			continue
		}
		c.LedgerExpired = append(c.LedgerExpired, e.Surface+" ("+e.Guard+")")
	}
	sort.Strings(c.LedgerResolved)
	sort.Strings(c.LedgerExpired)
	return c, nil
}

// rosterElementsIn — сколько элементов в перечне, который функция возвращает.
func rosterElementsIn(fn *ast.FuncDecl) int {
	n := 0
	ast.Inspect(fn, func(node ast.Node) bool {
		ret, ok := node.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		for _, r := range ret.Results {
			if lit, ok := r.(*ast.CompositeLit); ok {
				n += len(lit.Elts)
			}
		}
		return true
	})
	return n
}

// TestIAM2641_EveryNonGRPCSurfaceIsJudgedByATransportGuard — перепись в два
// числа: поверхностей не-gRPC N · судится транспортом M, и N == M с учётом
// ведомости.
func TestIAM2641_EveryNonGRPCSurfaceIsJudgedByATransportGuard(t *testing.T) {
	root := iamServiceRoot(t)
	files, err := treecorpus.UnderWithSuffix(filepath.Join(root, "cmd"), ".go")
	if err != nil {
		t.Fatalf("перечень файлов композиционного корня: %v", err)
	}
	census, err := countTransportGuardPopulations(files, separatelyGuardedSurfaces)
	if err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("%s", census.Summary())

	if census.Parsed == 0 {
		t.Fatalf("обход не разобрал НИ ОДНОГО прод-файла корня — вердикт беспредметен: "+
			"«ноль находок» неотличимо от «ноль прочитанного» (корень %s)", root)
	}
	if census.SurfacesBuilt == 0 {
		t.Fatalf("поверхностей выведено НУЛЬ — распознаватель построения мёртв: он ищет " +
			"вызовы `iamHTTPSurface`. Ноль здесь означает отказ РАЗБОРА, а не пустую " +
			"популяцию: корень без поверхностей не поднимается")
	}
	if census.EdgesInRoster == 0 {
		t.Fatalf("перечень рёбер выведен НУЛЁМ — распознаватель перечня мёртв: он ищет "+
			"элементы литерала, который возвращает `%s`", httpEdgeRosterFunc)
	}

	// САМОИСТЕЧЕНИЕ: записи, которой больше нечего исключать, быть не должно.
	if len(census.LedgerExpired) > 0 {
		t.Errorf("ВЕДОМОСТЬ БЕЗ ПРЕДМЕТА (%d): %s — объявления стража в дереве нет, "+
			"значит поверхность либо судится теперь общим перечнем, либо снята. Запись "+
			"снимается ТЕМ ЖЕ изменением: послабление, которому нечего исключать, "+
			"достаётся следующему читателю и прощает уже другое",
			len(census.LedgerExpired), strings.Join(census.LedgerExpired, ", "))
	}

	judged := census.EdgesInRoster + len(census.LedgerResolved)
	if census.SurfacesBuilt != judged {
		t.Fatalf("не-gRPC поверхностей построено %d, судится транспортом %d "+
			"(перечнем рёбер %d + отдельным стражем %d). Равенство несущее в ОБЕ стороны: "+
			"меньше — поверхность, чей транспорт не судит НИЧТО, и ни одна проба этого не "+
			"скажет (страж пропускает то, чего ему не дали); больше — ребро, под которым "+
			"корень поверхности не поднимает. Исходов два: внести поверхность в `%s` либо "+
			"назвать её ведомостью `separatelyGuardedSurfaces` — ИМЕНЕМ стража и причиной",
			census.SurfacesBuilt, judged, census.EdgesInRoster, len(census.LedgerResolved),
			httpEdgeRosterFunc)
	}
}
