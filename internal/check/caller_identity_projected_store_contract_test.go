// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"go/ast"
	"go/types"
	"slices"
	"testing"
)

// Один метод записи и одно чтение RPC. Меняется только источник адреса назначения
// или сохранность самого носителя адреса до входа в метод.
func TestCallerIdentityProjectedStoreDestinationContract(t *testing.T) {
	const rpc = "fixture/service/FixtureService/RPC"
	const setup = `
type output[T any] struct{ dst *T }
func makeOutput[T any](dst *T) *output[T] { return &output[T]{dst:dst} }
func (o *output[T]) Store() { *o.dst = source.Value().(T) }
func apply[V interface{Store()}](v V) { v.Store() }
var tracked = &Handler{reader:Benign{}}
`
	declared := []CallerReadDeclaration{{
		RPC: rpc, Producer: "github.com/PRO-Robotech/corelib/operations.PrincipalFromContext",
		Site: "fixture/app.anchor", Kind: CallerObservation, Reason: "Явное контрольное чтение.",
	}}
	for _, tc := range []struct {
		name    string
		startup string
		unknown bool
	}{
		{"standalone", `var local Reader; apply(makeOutput(&local))`, false},
		{"two_instantiations", `var local Reader; var other *Box; apply(makeOutput(&local)); apply(makeOutput(&other))`, false},
		{"field", `apply(makeOutput(&tracked.reader))`, true},
		{"opaque_address", `apply(makeOutput(source.Value().(*Reader)))`, true},
		{"mixed_same_instantiation", `var local Reader; apply(makeOutput(&local)); apply(makeOutput(&tracked.reader))`, true},
		{"whole_receiver_rebound", `var local Reader; o:=makeOutput(&local); alias:=o; *alias=output[Reader]{dst:&tracked.reader}; apply(o)`, true},
		{"opaque_receiver_rebound", `var local Reader; o:=makeOutput(&local); source.Assign(o,output[Reader]{dst:&tracked.reader}); apply(o)`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := callerSoundnessProgram(t, setup, `h.reader.read()`, `tracked`, tc.startup)
			var read string
			for sel, selection := range p.root.info.Selections {
				if selection.Kind() == types.MethodVal && sel.Sel.Name == "read" {
					if read != "" {
						t.Fatal("в примере более одного динамического чтения")
					}
					read = p.fset.PositionFor(sel.Pos(), false).String()
				}
			}
			if read == "" {
				t.Fatal("в примере отсутствует динамическое чтение")
			}
			report := judgeCallerIdentity(p, declared, map[string]bool{"fixture/source": true})
			if report.Invalid != "" {
				t.Fatal(report.Invalid)
			}
			if tc.unknown {
				if !slices.Contains(report.Findings, rpc+": неразрешённый вызов "+read) {
					t.Fatalf("для записи с неподтверждённым назначением пропущено чтение %s: %v", read, report.Findings)
				}
			} else if len(report.Findings) != 0 {
				t.Fatalf("запись в отдельную локальную ячейку: %v", report.Findings)
			}
		})
	}
}

// Единственная разница — сохранение носителя после Store. Экспортированный
// интерфейс позволяет получить его из другого пакета без упоминания приватного
// типа. Сравниваем сам сертификат, чтобы иной lifetime-барьер не маскировал отказ.
func TestCallerIdentityProjectedStoreDispatcherEscape(t *testing.T) {
	for _, tc := range []struct {
		name, after string
		closed      bool
	}{
		{"direct", "", true},
		{"exported_interface", "; Escaped = v", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setup := `
type output[T any] struct{ dst *T }
func makeOutput[T any](dst *T) *output[T] { return &output[T]{dst:dst} }
func (o *output[T]) Store() { *o.dst = source.Value().(T) }
var Escaped any
func apply[V interface{Store()}](v V) { v.Store()` + tc.after + ` }
`
			p := callerSoundnessProgram(t, setup, "", "&Handler{}", "var local Reader; apply(makeOutput(&local))")
			g := newCallerGraph(p)
			var local *types.Var
			for id, obj := range p.root.info.Defs {
				if id.Name == "local" {
					local, _ = obj.(*types.Var)
				}
			}
			if local == nil {
				t.Fatal("не найдена ячейка назначения в main")
			}
			var owners []valueSrc
			for _, write := range g.lifetimeWrites {
				src := write.owner
				if write.whole && src.pkg == p.root && src.fk.fn != nil && src.fk.fn.Name() == "Store" {
					owners = append(owners, src)
				}
			}
			if len(owners) != 1 {
				t.Fatalf("найдено назначений записи в Store: %d, ожидалось одно", len(owners))
			}
			dst := owners[0]
			sel, ok := ast.Unparen(dst.expr).(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "dst" {
				t.Fatal("назначение записи не является полем dst")
			}
			cells := g.closedProjectedStore(dst, sel)
			if tc.closed {
				if len(cells) != 1 || !cells[local] {
					t.Fatalf("прямая передача не доказала единственную локальную ячейку: %v", cells)
				}
			} else if len(cells) != 0 {
				t.Fatalf("сохранение носителя в экспортированном интерфейсе получило сертификат: %v", cells)
			}
		})
	}
}
