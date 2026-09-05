// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package module

// anchor_wiring_test.go — опора паритета полосы ГЛАГОЛА приходит из ТОЙ ЖЕ
// доставки, которой взят манифест (задача продукта #1861).
//
// # Что здесь предмет
//
// Сборка требует, чтобы опора была ПОДАНА, — она параметр. Сборка НЕ различает
// поданную опору доставки от `seed.ImageAnchor()`, а различие это и есть предмет
// задачи: оставь глаголу образ, и `iamctl module plan/apply` отвергал бы ровно
// тот модуль, который старт этого же процесса принимает.
//
// Второй предмет — ОТКУДА взята доставка. Построй опору вторым чтением каталога
// доставки, и манифест был бы выбран по одному составу, а опора построена по
// другому; разошлось бы это молча, потому что оба чтения законны по отдельности.
//
// # Гейт судит УЗЕЛ, а не подстроку
//
// Имена `AnchorOfDelivery` и `ImageAnchor` стоят в этом дереве и в комментариях,
// в том числе в объяснении выше. Проверка по подстроке краснела бы на
// собственном объяснении.

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"testing"
)

// verbAnchorWiring — что обход прочитал о потоке опоры в одном файле.
type verbAnchorWiring struct {
	// deliveryBound — имя, которым связана ВСЯ доставка (второй результат
	// `manifestFromDelivery`).
	deliveryBound string
	// anchorBound — имя, которым связан результат `AnchorOfDelivery`.
	anchorBound string
	// anchorArg — аргумент, поданный `AnchorOfDelivery`.
	anchorArg string
	// consumerArg — то, что уехало потребителю опоры (`PlanAgainstAnchor`
	// четвёртым аргументом либо поле `Anchor:` запроса).
	consumerArg string
	callsSeen   int
}

func readVerbAnchorWiring(t *testing.T, name string, src any) verbAnchorWiring {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, name, src, parser.ParseComments)
	if err != nil {
		t.Fatalf("%s не разобран: %v — непрочитанное есть НАХОДКА", name, err)
	}
	render := func(n ast.Node) string {
		var buf bytes.Buffer
		if perr := printer.Fprint(&buf, fset, n); perr != nil {
			return ""
		}
		return buf.String()
	}

	var w verbAnchorWiring
	ast.Inspect(file, func(n ast.Node) bool {
		if as, ok := n.(*ast.AssignStmt); ok {
			for _, rhs := range as.Rhs {
				call, isCall := rhs.(*ast.CallExpr)
				if !isCall {
					continue
				}
				switch fn := call.Fun.(type) {
				case *ast.Ident:
					// `m, delivery, err := manifestFromDelivery(…)` — ВСЯ
					// доставка вторым результатом.
					if fn.Name == "manifestFromDelivery" && w.deliveryBound == "" && len(as.Lhs) >= 2 {
						if id, isIdent := as.Lhs[1].(*ast.Ident); isIdent {
							w.deliveryBound = id.Name
						}
					}
				case *ast.SelectorExpr:
					if fn.Sel.Name == "AnchorOfDelivery" && w.anchorBound == "" {
						if len(as.Lhs) > 0 {
							if id, isIdent := as.Lhs[0].(*ast.Ident); isIdent {
								w.anchorBound = id.Name
							}
						}
						if len(call.Args) > 0 {
							w.anchorArg = render(call.Args[0])
						}
					}
				}
			}
		}

		// Поле `Anchor:` составного литерала запроса — потребитель у применителя.
		if kv, ok := n.(*ast.KeyValueExpr); ok && w.consumerArg == "" {
			if key, isIdent := kv.Key.(*ast.Ident); isIdent && key.Name == "Anchor" {
				w.consumerArg = render(kv.Value)
			}
		}

		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		w.callsSeen++
		if sel, isSel := call.Fun.(*ast.SelectorExpr); isSel &&
			sel.Sel.Name == "PlanAgainstAnchor" && w.consumerArg == "" && len(call.Args) >= 4 {
			w.consumerArg = render(call.Args[3])
		}
		return true
	})
	return w
}

// judgeVerbAnchorWiring — ОДИН предикат для живого гейта и для инъекции.
func judgeVerbAnchorWiring(w verbAnchorWiring) []string {
	var findings []string
	if w.callsSeen == 0 {
		return []string{"обход не нашёл ни одного вызова — вердикт беспредметен"}
	}
	if w.consumerArg == "" {
		return []string{"потребителя опоры нет: ни PlanAgainstAnchor, ни поля Anchor " +
			"запроса — предпосылка о потоке опоры исчезла"}
	}
	if w.anchorBound == "" {
		findings = append(findings, "опора не выводится из доставки: вызова AnchorOfDelivery "+
			"нет — глагол судит один образ и отвергнет модуль, который старт принимает")
	} else if w.consumerArg != w.anchorBound {
		findings = append(findings, "потребитель получает опору ["+w.consumerArg+"], а доставка "+
			"связана как ["+w.anchorBound+"]: опора доставки до потребителя НЕ доезжает")
	}
	if w.anchorBound != "" {
		switch {
		case w.deliveryBound == "":
			findings = append(findings, "доставка не связана вторым результатом "+
				"manifestFromDelivery: опора строится не тем чтением, которым взят манифест")
		case w.anchorArg != w.deliveryBound:
			findings = append(findings, "опора строится из ["+w.anchorArg+"], а манифест взят "+
				"из доставки ["+w.deliveryBound+"]: два чтения об одном предмете")
		}
	}
	return findings
}

// TestVerbLaneFeedsTheDeliveredAnchor — ЖИВОЙ гейт над обоими файлами полосы.
func TestVerbLaneFeedsTheDeliveredAnchor(t *testing.T) {
	for _, name := range []string{"plan.go", "apply.go"} {
		t.Run(name, func(t *testing.T) {
			w := readVerbAnchorWiring(t, name, nil)
			t.Logf("осмотрено вызовов %d; доставка %q; опора %q из %q; потребитель получает %q",
				w.callsSeen, w.deliveryBound, w.anchorBound, w.anchorArg, w.consumerArg)
			for _, f := range judgeVerbAnchorWiring(w) {
				t.Errorf("%s", f)
			}
		})
	}
}

// ── Инъекция ────────────────────────────────────────────────────────────────

const verbAnchorLive = `package module

func Execute() error {
	m, delivery, err := manifestFromDelivery(ctx, uc.delivery, module)
	if err != nil {
		return err
	}
	deliveredAnchor, aerr := modulecatalog.AnchorOfDelivery(delivery)
	if aerr != nil {
		return aerr
	}
	req := modulecatalog.Request{Manifest: m, Anchor: deliveredAnchor}
	return apply(req)
}
`

const verbAnchorImageOnly = `package module

func Execute() error {
	m, delivery, err := manifestFromDelivery(ctx, uc.delivery, module)
	if err != nil {
		return err
	}
	deliveredAnchor, aerr := modulecatalog.AnchorOfDelivery(delivery)
	if aerr != nil {
		return aerr
	}
	use(deliveredAnchor)
	req := modulecatalog.Request{Manifest: m, Anchor: seed.ImageAnchor()}
	return apply(req)
}
`

const verbAnchorNoProducer = `package module

func Execute() error {
	m, delivery, err := manifestFromDelivery(ctx, uc.delivery, module)
	if err != nil {
		return err
	}
	use(delivery)
	req := modulecatalog.Request{Manifest: m, Anchor: seed.ImageAnchor()}
	return apply(req)
}
`

// verbAnchorSecondRead — опора построена ВТОРЫМ чтением доставки: манифест взят
// одним составом, опора — другим.
const verbAnchorSecondRead = `package module

func Execute() error {
	m, delivery, err := manifestFromDelivery(ctx, uc.delivery, module)
	if err != nil {
		return err
	}
	use(delivery)
	second, rerr := uc.delivery.Read(ctx)
	if rerr != nil {
		return rerr
	}
	deliveredAnchor, aerr := modulecatalog.AnchorOfDelivery(second.Manifests)
	if aerr != nil {
		return aerr
	}
	req := modulecatalog.Request{Manifest: m, Anchor: deliveredAnchor}
	return apply(req)
}
`

const verbAnchorOnlyInComments = `package module

// Execute — путь глагола.
//
// Опора: modulecatalog.AnchorOfDelivery(delivery), затем Request{Anchor: …},
// и никогда seed.ImageAnchor(). Здесь ничего не зовётся.
func Execute() error { return nil }
`

func TestIAM1861_InjectionRedsTheVerbAnchorWiring(t *testing.T) {
	cases := []struct {
		name        string
		src         string
		wantFinding bool
		wantInText  string
	}{
		// ЗАКОННЫЙ БЛИЗНЕЦ идёт первым: без него всё ниже зеленело бы на гейте,
		// который отвергает любой вход.
		{name: "живая раскладка — гейт молчит", src: verbAnchorLive},
		{
			name: "опора построена и НЕ доезжает", src: verbAnchorImageOnly,
			wantFinding: true, wantInText: "НЕ доезжает",
		},
		{
			name: "производителя опоры нет вовсе", src: verbAnchorNoProducer,
			wantFinding: true, wantInText: "не выводится из доставки",
		},
		{
			name: "опора построена ВТОРЫМ чтением доставки", src: verbAnchorSecondRead,
			wantFinding: true, wantInText: "два чтения об одном предмете",
		},
		{
			name: "имена только в комментариях — вызовов нет", src: verbAnchorOnlyInComments,
			wantFinding: true, wantInText: "беспредметен",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := readVerbAnchorWiring(t, "synthetic.go", tc.src)
			findings := judgeVerbAnchorWiring(w)
			t.Logf("осмотрено вызовов %d; доставка %q; опора %q из %q; потребитель %q; находок %d: %v",
				w.callsSeen, w.deliveryBound, w.anchorBound, w.anchorArg, w.consumerArg,
				len(findings), findings)
			if tc.wantFinding && len(findings) == 0 {
				t.Fatal("инъекция не покраснела: гейт не способен упасть на этом входе")
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
