// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// catalog_parity_anchor_wiring_test.go — ОПОРА стража паритета приходит из
// ДОСТАВКИ, а не из образа (задача продукта #1861).
//
// # Зачем гейт, если предмет уже закрыт пробой самого стража
//
// Проба стража (`seed/catalog_parity_anchor_test.go`) утверждает, что страж
// УМЕЕТ судить против опоры «образ ∪ доставка». Она ничего не говорит о том, что
// композиционный корень ЭТУ опору ему подаёт: `seed.ImageAnchor()` третьим
// аргументом собирается молча и возвращает поведение ровно к тому, ради снятия
// которого задача заведена. Умение без вызывающего есть мёртвый страж — тот же
// класс, что `AuthMode`, объявленный и не читаемый.
//
// # Гейт судит УЗЕЛ, а не подстроку
//
// Имена `AnchorOfDelivery` и `ImageAnchor` стоят в этом дереве и в комментариях —
// в том числе в объяснении самого гейта. Проверка по подстроке краснела бы на
// собственном объяснении и зеленела бы на файле, где нет ни одного вызова.
// Поэтому обход идёт по узлам вызова и по связыванию идентификатора.
//
// # Что утверждается, и каждое — в паре с инъекцией
//
//	опора ВЫВОДИТСЯ из доставки          есть вызов `AnchorOfDelivery`
//	страж получает ИМЕННО ЕЁ             третий аргумент — тот же идентификатор
//	опора строится ДО первой записи      её вызов раньше применителя и стража

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"testing"
)

// anchorWiring — то, что обход прочитал о потоке опоры.
type anchorWiring struct {
	// bound — имя, которым связан результат `AnchorOfDelivery`; пусто, если
	// производителя опоры не звали вовсе.
	bound    string
	anchorAt token.Pos
	// guardArg — третий аргумент стража, как он записан; пусто, если стража не
	// звали.
	guardArg string
	// guardArgIsIdent — аргумент есть голый идентификатор (а не вызов вроде
	// `seed.ImageAnchor()`).
	guardArgIsIdent bool
	guardAt         token.Pos
	applyAt         token.Pos
	// callsSeen — ОБЪЁМ ОСМОТРЕННОГО. Ноль означает «ничего не прочитано», и это
	// отказ, а не согласие.
	callsSeen int
}

// readAnchorWiring — обход исходника: производитель опоры, страж и применитель.
func readAnchorWiring(t *testing.T, name string, src any) anchorWiring {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, name, src, parser.ParseComments)
	if err != nil {
		t.Fatalf("%s не разобран: %v — непрочитанное есть НАХОДКА, а не согласие", name, err)
	}

	var w anchorWiring
	ast.Inspect(file, func(n ast.Node) bool {
		// Связывание `x, err := …AnchorOfDelivery(…)` — берётся ПЕРВОЕ, потому
		// что второй производитель опоры в одном корне сам по себе находка.
		if as, ok := n.(*ast.AssignStmt); ok && w.bound == "" {
			for _, rhs := range as.Rhs {
				call, isCall := rhs.(*ast.CallExpr)
				if !isCall {
					continue
				}
				sel, isSel := call.Fun.(*ast.SelectorExpr)
				if !isSel || sel.Sel.Name != "AnchorOfDelivery" {
					continue
				}
				if len(as.Lhs) > 0 {
					if id, isIdent := as.Lhs[0].(*ast.Ident); isIdent {
						w.bound = id.Name
						w.anchorAt = call.Pos()
					}
				}
			}
		}

		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		w.callsSeen++
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			if fn.Name == "applyDeliveredManifests" && !w.applyAt.IsValid() {
				w.applyAt = call.Pos()
			}
		case *ast.SelectorExpr:
			if fn.Sel.Name == "AssertCatalogParity" && !w.guardAt.IsValid() {
				w.guardAt = call.Pos()
				if len(call.Args) >= 3 {
					var buf bytes.Buffer
					if perr := printer.Fprint(&buf, fset, call.Args[2]); perr == nil {
						w.guardArg = buf.String()
					}
					_, w.guardArgIsIdent = call.Args[2].(*ast.Ident)
				}
			}
		}
		return true
	})
	return w
}

// judgeAnchorWiring — вердикт над прочитанным. Отдан отдельной функцией, чтобы
// живой гейт и инъекция судили ОДНИМ предикатом: два судьи об одном предмете
// разошлись бы молча.
func judgeAnchorWiring(w anchorWiring) []string {
	var findings []string
	if w.callsSeen == 0 {
		return []string{"обход не нашёл ни одного вызова — вердикт беспредметен"}
	}
	if w.bound == "" {
		findings = append(findings, "опора паритета не выводится из доставки: вызова "+
			"AnchorOfDelivery нет — страж судит один образ, и модуль, объявленный "+
			"манифестом оператора, отказал бы в пуске")
	}
	if !w.guardAt.IsValid() {
		findings = append(findings, "AssertCatalogParity не зовётся — предпосылка о потоке "+
			"опоры исчезла, и судить больше нечего")
		return findings
	}
	if w.guardArg == "" {
		findings = append(findings, "страж позван без третьего аргумента — опора не подана вовсе")
	} else if !w.guardArgIsIdent || (w.bound != "" && w.guardArg != w.bound) {
		findings = append(findings, "страж получает опору ["+w.guardArg+"], а доставка "+
			"связана как ["+w.bound+"]: опора, выведенная из доставки, до стража НЕ доезжает")
	}
	if w.bound != "" && w.anchorAt.IsValid() {
		if w.anchorAt > w.guardAt {
			findings = append(findings, "опора строится ПОСЛЕ стража — страж успевает "+
				"отказать по образу прежде, чем доставка её расширит")
		}
		if w.applyAt.IsValid() && w.anchorAt > w.applyAt {
			findings = append(findings, "опора строится ПОСЛЕ применителя — доставка, "+
				"переопределяющая строку образа, была бы отвергнута уже ПОСЛЕ записи")
		}
	}
	return findings
}

// TestServeFeedsTheParityGuardTheDeliveredAnchor — ЖИВОЙ гейт над serve.go.
func TestServeFeedsTheParityGuardTheDeliveredAnchor(t *testing.T) {
	if _, err := os.Stat("serve.go"); err != nil {
		t.Fatalf("serve.go не прочитан: %v", err)
	}
	w := readAnchorWiring(t, "serve.go", nil)
	t.Logf("осмотрено вызовов в serve.go: %d; опора связана как %q; страж получает %q",
		w.callsSeen, w.bound, w.guardArg)
	for _, f := range judgeAnchorWiring(w) {
		t.Errorf("%s", f)
	}
}

// ── Инъекция: гейт СПОСОБЕН упасть и СПОСОБЕН смолчать ──────────────────────

const anchorWiringLive = `package main

func serve() error {
	deliveredManifests, mErr := loadDeliveredManifests(logger, cfg.Manifests)
	if mErr != nil {
		return mErr
	}
	catalogAnchor, anErr := modulecatalog.AnchorOfDelivery(deliveredManifests)
	if anErr != nil {
		return anErr
	}
	if aErr := applyDeliveredManifests(ctx, logger, catalogApplier, deliveredManifests); aErr != nil {
		return aErr
	}
	_, catErr := seed.AssertCatalogParity(ctx, catalogRepo, catalogAnchor)
	return catErr
}
`

// anchorWiringImageOnly — ДЕФЕКТ, ради снятия которого задача заведена: опора
// строится и не доезжает, страж судит образ.
const anchorWiringImageOnly = `package main

func serve() error {
	deliveredManifests, mErr := loadDeliveredManifests(logger, cfg.Manifests)
	if mErr != nil {
		return mErr
	}
	catalogAnchor, anErr := modulecatalog.AnchorOfDelivery(deliveredManifests)
	if anErr != nil {
		return anErr
	}
	use(catalogAnchor)
	_, catErr := seed.AssertCatalogParity(ctx, catalogRepo, seed.ImageAnchor())
	return catErr
}
`

const anchorWiringNoProducer = `package main

func serve() error {
	deliveredManifests, mErr := loadDeliveredManifests(logger, cfg.Manifests)
	if mErr != nil {
		return mErr
	}
	use(deliveredManifests)
	_, catErr := seed.AssertCatalogParity(ctx, catalogRepo, seed.ImageAnchor())
	return catErr
}
`

const anchorWiringBuiltAfterGuard = `package main

func serve() error {
	_, catErr := seed.AssertCatalogParity(ctx, catalogRepo, catalogAnchor)
	if catErr != nil {
		return catErr
	}
	catalogAnchor, anErr := modulecatalog.AnchorOfDelivery(deliveredManifests)
	return anErr
}
`

const anchorWiringBuiltAfterApply = `package main

func serve() error {
	if aErr := applyDeliveredManifests(ctx, logger, catalogApplier, deliveredManifests); aErr != nil {
		return aErr
	}
	catalogAnchor, anErr := modulecatalog.AnchorOfDelivery(deliveredManifests)
	if anErr != nil {
		return anErr
	}
	_, catErr := seed.AssertCatalogParity(ctx, catalogRepo, catalogAnchor)
	return catErr
}
`

// anchorWiringOnlyInComments — оба имени названы ПРОЗОЙ и ни одно не позвано.
const anchorWiringOnlyInComments = `package main

// serve — путь старта.
//
// Опора: modulecatalog.AnchorOfDelivery, затем seed.AssertCatalogParity с
// catalogAnchor, и никогда seed.ImageAnchor(). Здесь ничего не зовётся.
func serve() error { return nil }
`

func TestIAM1861_InjectionRedsTheAnchorWiringAndKeepsQuietOnTheLiveOne(t *testing.T) {
	cases := []struct {
		name        string
		src         string
		wantFinding bool
		wantInText  string
	}{
		{
			// ЗАКОННЫЙ БЛИЗНЕЦ. Без него всё, что ниже, зеленело бы на гейте,
			// который отвергает любой вход.
			name: "живая раскладка — гейт молчит",
			src:  anchorWiringLive,
		},
		{
			name:        "опора построена и НЕ доезжает — страж судит образ",
			src:         anchorWiringImageOnly,
			wantFinding: true,
			wantInText:  "до стража НЕ доезжает",
		},
		{
			name:        "производителя опоры нет вовсе",
			src:         anchorWiringNoProducer,
			wantFinding: true,
			wantInText:  "не выводится из доставки",
		},
		{
			name:        "опора построена ПОСЛЕ стража",
			src:         anchorWiringBuiltAfterGuard,
			wantFinding: true,
			wantInText:  "ПОСЛЕ стража",
		},
		{
			name:        "опора построена ПОСЛЕ применителя — отказ уже после записи",
			src:         anchorWiringBuiltAfterApply,
			wantFinding: true,
			wantInText:  "ПОСЛЕ применителя",
		},
		{
			name:        "оба имени только в комментариях — вызовов нет",
			src:         anchorWiringOnlyInComments,
			wantFinding: true,
			wantInText:  "беспредметен",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := readAnchorWiring(t, "synthetic.go", tc.src)
			findings := judgeAnchorWiring(w)
			t.Logf("осмотрено вызовов %d; опора %q; аргумент стража %q; находок %d: %v",
				w.callsSeen, w.bound, w.guardArg, len(findings), findings)
			if tc.wantFinding && len(findings) == 0 {
				t.Fatalf("инъекция не покраснела: гейт не способен упасть на этом входе")
			}
			if !tc.wantFinding && len(findings) != 0 {
				t.Fatalf("законный близнец покраснел: %v", findings)
			}
			if tc.wantInText != "" {
				var joined string
				for _, f := range findings {
					joined += f + " | "
				}
				if !bytes.Contains([]byte(joined), []byte(tc.wantInText)) {
					t.Fatalf("находка не называет %q: %v", tc.wantInText, findings)
				}
			}
		})
	}
}
