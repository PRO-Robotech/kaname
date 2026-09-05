// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kacho/pkg/authz"
)

// Вторая ступень цепочки отзыва — пересчёт производного пообъектного доступа у
// владельца прав. Её величина назначается ручкой посадки и до этой пробы не
// судилась ничем: оператор был вправе объявить обход раз в час, и отозванная
// выдача действовала бы час.
//
// Пары намеренно двусторонние: отрицание без положительного контроля зеленело бы
// на страже, отвергающем любую величину.

func msEnv(d time.Duration) string {
	return strconv.FormatInt(int64(d/time.Millisecond), 10)
}

func TestSweepAboveTheCeilingRefusesStart(t *testing.T) {
	t.Setenv(reconcileSweepKnob, msEnv(authz.RevocationPolicy.MaterializationCeiling+time.Second))

	err := readReconcileWindows().validate(authz.RevocationPolicy.MaterializationCeiling)
	if err == nil {
		t.Fatalf("обход шире потолка %v принят: величина второй ступени назначается посадкой и не судится",
			authz.RevocationPolicy.MaterializationCeiling)
	}
	for _, want := range []string{
		reconcileSweepKnob,
		authz.RevocationPolicy.MaterializationCeiling.String(),
		"refuse to start",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("текст отказа не называет %q: %v", want, err)
		}
	}
}

func TestDrainAboveTheCeilingRefusesStart(t *testing.T) {
	t.Setenv(reconcileDrainKnob, msEnv(authz.RevocationPolicy.MaterializationCeiling+time.Second))

	err := readReconcileWindows().validate(authz.RevocationPolicy.MaterializationCeiling)
	if err == nil {
		t.Fatalf("дренаж шире потолка %v принят", authz.RevocationPolicy.MaterializationCeiling)
	}
	if !strings.Contains(err.Error(), reconcileDrainKnob) {
		t.Errorf("текст отказа не называет ручку дренажа: %v", err)
	}
}

// Положительный контроль. Без него отрицания выше зеленели бы на страже,
// отвергающем всё, — в том числе умолчания, на которых сегодня работает каждая
// посадка дерева.
func TestDeclaredDefaultsStartSilently(t *testing.T) {
	w := readReconcileWindows()
	if err := w.validate(authz.RevocationPolicy.MaterializationCeiling); err != nil {
		t.Fatalf("умолчания второй ступени (обход %v, дренаж %v) отвергнуты: %v",
			w.Sweep, w.Drain, err)
	}
	if w.Sweep != 30*time.Second || w.Drain != time.Second {
		t.Fatalf("умолчания сдвинулись: обход %v, дренаж %v — сумма цепочки посчитана "+
			"из других слагаемых, чем объявлено политикой", w.Sweep, w.Drain)
	}

	// Ровно в потолок — законно: потолок есть граница, а не запрет на неё.
	t.Setenv(reconcileSweepKnob, msEnv(authz.RevocationPolicy.MaterializationCeiling))
	if err := readReconcileWindows().validate(authz.RevocationPolicy.MaterializationCeiling); err != nil {
		t.Fatalf("обход ровно в потолок отвергнут: %v", err)
	}
}

// Сумма цепочки — не украшение отчёта: именно она есть верхняя граница «столько
// действует отозванная выдача». Проба закрепляет, что три слагаемых берутся из
// одного объявления, а не из трёх разных умолчаний.
func TestChainCeilingIsTheSumOfThreeSteps(t *testing.T) {
	p := authz.RevocationPolicy
	if got, want := p.ChainCeiling(), p.DeliveryCeiling+p.MaterializationCeiling+p.Ceiling; got != want {
		t.Fatalf("ChainCeiling = %v, а сумма ступеней %v", got, want)
	}
	if p.Default > p.Ceiling {
		t.Fatalf("умолчание третьей ступени %v выше её потолка %v", p.Default, p.Ceiling)
	}
	if p.DeliveryCeiling <= 0 || p.MaterializationCeiling <= 0 {
		t.Fatalf("потолок ступени не объявлен: доставка %v, пересчёт %v",
			p.DeliveryCeiling, p.MaterializationCeiling)
	}
}

// Провязка судится ОБХОДОМ, а не чтением: страж, написанный верно и никем не
// позванный, выглядит в диффе точно так же, как позванный.
//
// Утверждается ДВА свойства, и второе несущее: (а) корень зовёт чтение пары и
// её проверку; (б) ручки второй ступени читаются РОВНО В ОДНОМ месте — иначе
// воркер получил бы величину, которой страж не видел, и «судится» перестало бы
// означать «судится то, с чем работают».
//
// # Распознаватель ключуется на РУЧКЕ, а не на общем чтеце (kacho#1945)
//
// Здесь считались ВСЕ вызовы `envDurationMS` — то есть общего чтеца ЛЮБОЙ
// миллисекундной ручки процесса. Пока такая ручка в пакете была одна, разница
// между «читают ручки второй ступени» и «зовут envDurationMS» не наблюдалась;
// вторая ручка сделала её видимой — и гейт покраснел на файле, который к окну
// пересчёта не относится ничем.
//
// Это не ослабление, а сужение до СВОЕГО предмета: считается вызов, чей первый
// аргумент — одна из двух ручек второй ступени. Второй их читатель по-прежнему
// находка; читатель ЧУЖОЙ ручки находкой быть перестал, потому что ею и не был.
// reconcileWindowKnobIdents — имена констант ручек ВТОРОЙ СТУПЕНИ. Судятся
// идентификаторы, а не значения: значение — строка, и оно встречается в прозе
// (комментарии, страницы посадки), а гейт по строке краснел бы на собственном
// объяснении.
var reconcileWindowKnobIdents = map[string]bool{
	"reconcileSweepKnob": true,
	"reconcileDrainKnob": true,
}

func TestReconcileWindowGuardIsWiredAndTheKnobsHaveOneReader(t *testing.T) {
	fset := token.NewFileSet()
	pkgDir := "."
	entries, err := os.ReadDir(pkgDir)
	if err != nil {
		t.Fatalf("каталог пакета не читается: %v", err)
	}

	filesParsed := 0
	readCallFiles, validateCallFiles := map[string]int{}, map[string]int{}
	envReaderFiles, ceilingFromPolicy := map[string]int{}, map[string]int{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(pkgDir, name), nil, 0)
		if perr != nil {
			t.Fatalf("%s не разбирается: %v", name, perr)
		}
		filesParsed++
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fn := call.Fun.(type) {
			case *ast.Ident:
				switch fn.Name {
				case "readReconcileWindows":
					readCallFiles[name]++
				case "envDurationMS":
					// Ключ — РУЧКА, а не чтец: `envDurationMS` читает любую
					// миллисекундную ручку процесса, и счёт по его имени
					// считал бы чужие.
					if len(call.Args) > 0 {
						if id, isIdent := call.Args[0].(*ast.Ident); isIdent && reconcileWindowKnobIdents[id.Name] {
							envReaderFiles[name]++
						}
					}
				}
			case *ast.SelectorExpr:
				if fn.Sel.Name == "validate" {
					validateCallFiles[name]++
					// Потолок обязан приезжать ИЗ ПОЛИТИКИ. Литерал на этом
					// месте дал бы второе объявление одного предмета — и оно
					// разошлось бы с суммой цепочки молча.
					for _, arg := range call.Args {
						ast.Inspect(arg, func(inner ast.Node) bool {
							sel, ok := inner.(*ast.SelectorExpr)
							if ok && sel.Sel.Name == "MaterializationCeiling" {
								ceilingFromPolicy[name]++
							}
							return true
						})
					}
				}
			}
			return true
		})
	}

	// Объём осмотренного печатается всегда: «ноль находок» обязано быть отличимо
	// от «ноль прочитанного».
	t.Logf("перепись: файлов Go прочитано %d · чтение пары зовут %v · проверку зовут %v · "+
		"потолок из политики %v · ручки читают %v",
		filesParsed, readCallFiles, validateCallFiles, ceilingFromPolicy, envReaderFiles)

	if filesParsed == 0 {
		t.Fatal("обход пуст — вердикт беспредметен: каталог пакета переехал")
	}
	const root = "serve.go"
	if readCallFiles[root] == 0 {
		t.Errorf("корень (%s) не зовёт чтение пары величин: страж не исполняется ни при каком входе", root)
	}
	if validateCallFiles[root] == 0 {
		t.Errorf("корень (%s) не зовёт проверку пары: страж написан и не исполняется", root)
	}
	if ceilingFromPolicy[root] == 0 {
		t.Errorf("корень (%s) подаёт стражу потолок НЕ из pkg/authz.RevocationPolicy: "+
			"второе объявление одного предмета разойдётся с суммой цепочки молча", root)
	}
	if len(envReaderFiles) != 1 || envReaderFiles["reconcile_window.go"] == 0 {
		t.Errorf("ручки второй ступени читают %v: второй читатель отдаёт воркеру величину, "+
			"которой страж не видел", envReaderFiles)
	}
}
