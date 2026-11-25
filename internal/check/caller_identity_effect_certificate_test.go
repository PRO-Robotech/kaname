// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"go/ast"
	"maps"
	"strings"
	"testing"
)

// Новый граф оставляет object/resolve memo холодными, сохраняя типизированные
// источники штатной фикстуры. Эти тесты не подменяют завершённый обход RPC.
func callerEffectCertificateSnapshotFixture(t *testing.T) (*callerGraph, valueSrc, valueSrc, map[string]valueSrc) {
	t.Helper()
	prepared, field, base := callerLifetimeCompletionFixture(t, `box:=&Box{reader:Benign{}};_=Concrete{};_=box.reader`)
	g := newCallerGraph(prepared.p)
	g.safeExternal = prepared.safeExternal
	node := callerNode{fn: field.fk.fn, lit: field.fk.lit}
	g.markCallerCalled(node)
	literals := map[string]valueSrc{}
	ast.Inspect(g.bodies[node].node, func(n ast.Node) bool {
		if lit, ok := n.(*ast.CompositeLit); ok {
			if typ := namedOf(field.pkg.info.TypeOf(lit)); typ != nil {
				ref := field
				ref.expr = lit
				literals[typ.Obj().Name()] = ref
			}
		}
		return true
	})
	for _, name := range []string{"Box", "Benign", "Concrete"} {
		if literals[name].expr == nil {
			t.Fatalf("missing typed %s allocation", name)
		}
	}
	return g, field, base, literals
}

// Ожидание задаётся исходными storage/allocation, а не повторным resolver.
func callerEffectCertificateObjects(t *testing.T, field, base valueSrc, literals map[string]valueSrc, value string) map[callerObjectKey]bool {
	t.Helper()
	selector := field.expr.(*ast.SelectorExpr)
	path := fieldPath(field.pkg.info.Selections[selector])
	if len(path) != 1 {
		t.Fatal("fixture must have one direct field")
	}
	member := path[0].Origin()
	storage := callerOwnershipZero(base)
	storage.field = member
	return map[callerObjectKey]bool{
		storage: true,
		{pkg: field.pkg, expr: literals["Box"].expr, field: member}: true,
		{pkg: field.pkg, expr: literals[value].expr}:                true,
	}
}

func callerEffectCertificateReceiver(t *testing.T, g *callerGraph, field valueSrc, name string, wantUnknown bool) {
	t.Helper()
	values, unknown := g.resolve(field, true, map[callerResolveKey]bool{})
	if unknown != wantUnknown || len(values) != 1 || values[0].nilValue || values[0].foreign {
		t.Fatalf("receiver answer: values=%v unknown=%v, want one %s unknown=%v", values, unknown, name, wantUnknown)
	}
	typ := namedOf(values[0].typ)
	if typ == nil || typ.Obj().Name() != name {
		t.Fatalf("receiver resolved to %v, want %s", values[0].typ, name)
	}
}

func TestCallerIdentityEffectCertificateColdWarmSnapshotAnswers(t *testing.T) {
	g, field, base, literals := callerEffectCertificateSnapshotFixture(t)
	g.lifetimeScanning = true
	defer func() { g.lifetimeScanning = false }()
	selector := field.expr.(*ast.SelectorExpr)
	index, entered := g.enterCallerFieldQuery(base, fieldPath(field.pkg.info.Selections[selector]))
	if !entered {
		t.Fatal("fresh snapshot owner was already active")
	}
	defer g.leaveCallerFieldQuery(index)
	g.fieldQueries[index].refs = []valueSrc{literals["Benign"]}
	epoch := g.bindingEpoch
	baseID := g.internObjectSource(base)
	if _, warm := g.initialObjectMemo[baseID]; warm {
		t.Fatal("cold precondition already contains the base")
	}
	want := callerEffectCertificateObjects(t, field, base, literals, "Benign")
	cold, unknown := g.callerObjects(field, map[callerObjectSourceID]bool{})
	if unknown || !maps.Equal(cold, want) {
		t.Fatalf("cold snapshot lost exact aliases: objects=%v unknown=%v", cold, unknown)
	}
	before := maps.Clone(cold)
	if _, warm := g.initialObjectMemo[baseID]; !warm {
		t.Fatal("first traversal did not warm its completed base")
	}
	warm, unknown := g.callerObjects(field, map[callerObjectSourceID]bool{})
	if unknown || !maps.Equal(warm, want) || !maps.Equal(cold, before) || g.bindingEpoch != epoch {
		t.Fatal("memo warming changed the snapshot aliases, UNKNOWN, epoch, or old result")
	}
	callerEffectCertificateReceiver(t, g, field, "Benign", false)
	callerEffectCertificateReceiver(t, g, field, "Benign", false)
	// Проверяется запрет публикации неполного ответа, не арифметика marks.
	if _, published := g.initialObjectMemo[g.internObjectSource(field)]; published {
		t.Fatal("active snapshot escaped as completed initial object provenance")
	}
	if _, published := g.initialResolveMemo[callerResolveKeyFor(field, true)]; published {
		t.Fatal("active snapshot escaped as completed initial receiver provenance")
	}
}

func TestCallerIdentityEffectCertificateBarrierOutcome(t *testing.T) {
	for _, tc := range []struct {
		name, effect string
		unknown      bool
	}{
		{"completed", "", false},
		{"opaque_escape", "source.Mutate(box);", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `box:=&Box{reader:Benign{}};` + tc.effect + `box.reader.read()`
			g, field, base := callerLifetimeCompletionFixture(t, body)
			g.lifetimeScanning = true
			initial, unknown := g.callerObjects(field, map[callerObjectSourceID]bool{})
			if unknown || len(initial) == 0 {
				t.Fatal("initial provenance must be concrete in both lifetime twins")
			}
			before := maps.Clone(initial)
			callerEffectCertificateReceiver(t, g, field, "Benign", false)
			g.lifetimeScanning = false
			if unknown := g.callerLifetimeUnknown(base); unknown != tc.unknown {
				t.Fatalf("lifetime effect: unknown=%v want=%v", unknown, tc.unknown)
			}
			for i := 0; i < 2; i++ {
				objects, unknown := g.callerObjects(field, map[callerObjectSourceID]bool{})
				if unknown != tc.unknown || !maps.Equal(objects, before) || !maps.Equal(initial, before) {
					t.Fatal("full lifetime answer lost initial aliases, escape UNKNOWN, or borrowed immutability")
				}
				callerEffectCertificateReceiver(t, g, field, "Benign", tc.unknown)
			}
			if tc.unknown {
				if _, published := g.objectMemo[g.internObjectSource(field)]; published {
					t.Fatal("early-return lifetime proof published a full object answer")
				}
				if _, published := g.resolveMemo[callerResolveKeyFor(field, true)]; published {
					t.Fatal("early-return lifetime proof published a full receiver answer")
				}
			}
			// Судья проходит регистрацию и реальные вызовы на отдельном графе.
			// Объявлен anchor; Benign не читает личность, opaque escape не доказан.
			declared := []CallerReadDeclaration{{RPC: "fixture/service/FixtureService/RPC", Producer: "github.com/PRO-Robotech/corelib/operations.PrincipalFromContext", Site: "fixture/app.anchor", Kind: CallerObservation, Reason: "Nonempty fixture anchor."}}
			report := judgeCallerIdentity(g.p, declared, map[string]bool{"fixture/source": true})
			if report.Invalid != "" || report.RPCs != 1 || len(report.Reads) == 0 {
				t.Fatalf("judge did not inspect the fixture: %+v", report)
			}
			if !tc.unknown && len(report.Findings) != 0 {
				t.Fatalf("lawful completed lifetime was rejected: %v", report.Findings)
			}
			if tc.unknown {
				unresolved := false
				for _, finding := range report.Findings {
					unresolved = unresolved || strings.Contains(finding, "неразрешённый вызов")
				}
				if !unresolved {
					t.Fatalf("opaque mutation became a proven safe call: %v", report.Findings)
				}
			}
		})
	}
}

func TestCallerIdentityEffectCertificateSnapshotChangeWithoutEpoch(t *testing.T) {
	g, field, base, literals := callerEffectCertificateSnapshotFixture(t)
	g.lifetimeScanning = true
	defer func() { g.lifetimeScanning = false }()
	selector := field.expr.(*ast.SelectorExpr)
	index, entered := g.enterCallerFieldQuery(base, fieldPath(field.pkg.info.Selections[selector]))
	if !entered {
		t.Fatal("fresh snapshot owner was already active")
	}
	defer g.leaveCallerFieldQuery(index)
	g.fieldQueries[index].refs = []valueSrc{literals["Benign"]}
	epoch := g.bindingEpoch
	old, unknown := g.callerObjects(field, map[callerObjectSourceID]bool{})
	if unknown || !maps.Equal(old, callerEffectCertificateObjects(t, field, base, literals, "Benign")) {
		t.Fatal("initial active snapshot did not identify Benign aliases")
	}
	before := maps.Clone(old)
	callerEffectCertificateReceiver(t, g, field, "Benign", false)
	// Меняется только опубликованный владельцем snapshot; source/fields/epoch те же.
	g.fieldQueries[index].refs = []valueSrc{literals["Concrete"]}
	changed, unknown := g.callerObjects(field, map[callerObjectSourceID]bool{})
	if unknown || !maps.Equal(changed, callerEffectCertificateObjects(t, field, base, literals, "Concrete")) {
		t.Fatal("same-epoch snapshot update lost the Concrete allocation or retained Benign")
	}
	callerEffectCertificateReceiver(t, g, field, "Concrete", false)
	if g.bindingEpoch != epoch || !maps.Equal(old, before) {
		t.Fatal("snapshot case changed epoch or mutated an escaped old alias answer")
	}
	// При тех же refs неизвестность snapshot обязана дойти до обоих consumers.
	g.fieldQueries[index].unknown = true
	unknownObjects, unknown := g.callerObjects(field, map[callerObjectSourceID]bool{})
	if !unknown || !maps.Equal(unknownObjects, changed) {
		t.Fatal("same-epoch UNKNOWN update disappeared or changed exact known aliases")
	}
	callerEffectCertificateReceiver(t, g, field, "Concrete", true)
	if g.bindingEpoch != epoch {
		t.Fatal("snapshot UNKNOWN case unexpectedly changed epoch")
	}
}
