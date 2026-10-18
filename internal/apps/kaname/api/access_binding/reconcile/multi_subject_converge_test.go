// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

// multi_subject_converge_test.go — выдача нескольким субъектам, развёрнутая ДО
// kaname#880 одному первому субъекту, доводится до полного состава ПЕРВЫМ ЖЕ
// проходом, который её касается: полным (его зовут обход по таймеру и
// проход при старте) и проходом по объекту (событие зеркала).
//
// Прежнее состояние строится не руками, а тем же материализатором: проход по
// выдаче ОДНОМУ первому субъекту даёт ровно тот состав и те кортежи, что давал
// прежний код (он читал проекцию первого субъекта; сужение класса до чтения —
// то же), за одним отличием — ключ члена `public_reader` прежде не нёс классов,
// и он приводится к прежней форме.
//
// Исход сравнивается не с выписанным списком, а со СВЕЖЕЙ материализацией той же
// выдачи: после прохода записанное (журнал кортежей и реестр выпущенного) обязано
// совпасть с тем, что дала бы выдача, созданная после выкатки.

import (
	"context"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

const msBinding domain.AccessBindingID = "acb0000000000000nd08"

// msTupleSet — множество кортежей.
type msTupleSet map[domain.MembershipTuple]struct{}

func msSetOf(batches ...[]domain.MembershipTuple) msTupleSet {
	out := msTupleSet{}
	for _, b := range batches {
		for _, t := range b {
			out[t] = struct{}{}
		}
	}
	return out
}

func msFlatten(batches [][]domain.MembershipTuple) []domain.MembershipTuple {
	var out []domain.MembershipTuple
	for _, b := range batches {
		out = append(out, b...)
	}
	return out
}

// msFacts — кортежи хранилища после прохода: записанное до него (`pre`) плюс
// записи прохода минус его снятия.
func msFacts(pre []domain.MembershipTuple, f *fakeStore) msTupleSet {
	out := msSetOf(pre, allWrites(f))
	for t := range msSetOf(msFlatten(f.tdeletes)) {
		delete(out, t)
	}
	return out
}

// msLedger — реестр выпущенного после прохода.
func msLedger(f *fakeStore) msTupleSet {
	out := msSetOf(f.ledger, msFlatten(f.recorded))
	for t := range msSetOf(msFlatten(f.forgotten)) {
		delete(out, t)
	}
	return out
}

func msSorted(s msTupleSet) []string {
	out := make([]string, 0, len(s))
	for t := range s {
		out = append(out, t.User+" "+t.Relation+" "+t.Object)
	}
	slices.Sort(out)
	return out
}

// msPreFix — состав и реестр, которые оставил прежний код: разворачивание одному
// первому субъекту, ключ `public_reader` без классов.
func msPreFix(t *testing.T, rules domain.Rules, first string) ([]domain.TargetMember, []domain.MembershipTuple) {
	t.Helper()
	f := msStore(rules, first)
	ndReconcile(t, f)
	members := make([]domain.TargetMember, 0, len(f.upserts))
	for _, m := range f.upserts {
		if strings.HasPrefix(m.RuleFP, publicReaderRuleFPPrefix) {
			m.RuleFP, _, _ = strings.Cut(m.RuleFP, publicReaderClassesSep)
		}
		members = append(members, m)
	}
	return members, msFlatten(f.recorded)
}

// msFresh — свежая материализация выдачи полным составом.
func msFresh(t *testing.T, rules domain.Rules, refs ...string) *fakeStore {
	t.Helper()
	f := msStore(rules, refs...)
	ndReconcile(t, f)
	return f
}

var msConvergeCases = [][]string{
	{msAuth, msAnon}, // исходный случай задачи: класс не первым
	{msUser, msAnon},
	{msAnon, msUser},
	{msUser, "user:usrnd09"},
}

// TestReconcileMultiSubject_PreFixBindingConvergesOnTheFullPass — полный проход
// (тот, что зовут обход по таймеру и проход при старте) доводит выдачу,
// развёрнутую прежним кодом, до свежей материализации — и кортежами, и реестром.
func TestReconcileMultiSubject_PreFixBindingConvergesOnTheFullPass(t *testing.T) {
	rules := ndReaderRules(nil, nil, "items")
	for _, refs := range msConvergeCases {
		t.Run(strings.Join(refs, ","), func(t *testing.T) {
			members, ledger := msPreFix(t, rules, refs[0])
			fresh := msFresh(t, rules, refs...)

			f := msStore(rules, refs...)
			f.current, f.ledger = members, ledger
			ndReconcile(t, f)

			if got, want := msSorted(msFacts(ledger, f)), msSorted(msSetOf(allWrites(fresh))); !slices.Equal(got, want) {
				t.Errorf("кортежи после прохода:\n  %v\nсвежая материализация:\n  %v", got, want)
			}
			if got, want := msSorted(msLedger(f)), msSorted(msLedger(fresh)); !slices.Equal(got, want) {
				t.Errorf("реестр выпущенного после прохода:\n  %v\nсвежая материализация:\n  %v", got, want)
			}
		})
	}
}

// TestReconcileMultiSubject_ConvergedBindingIsNotRewritten — близнец: выдача, уже
// развёрнутая полным составом, следующим проходом не переписывается — ни одной
// записи кортежа и ни одной строки реестра. Одиночная выдача — тоже.
func TestReconcileMultiSubject_ConvergedBindingIsNotRewritten(t *testing.T) {
	rules := ndReaderRules(nil, nil, "items")
	for _, refs := range append(slices.Clone(msConvergeCases), []string{msUser}, []string{msAnon}) {
		t.Run(strings.Join(refs, ","), func(t *testing.T) {
			fresh := msFresh(t, rules, refs...)

			f := msStore(rules, refs...)
			f.current, f.ledger = fresh.upserts, msFlatten(fresh.recorded)
			ndReconcile(t, f)

			if len(f.writes) != 0 || len(f.recorded) != 0 || len(f.tdeletes) != 0 || len(f.forgotten) != 0 {
				t.Errorf("проход по сошедшейся выдаче записал: кортежей %d, реестра %d, снятий %d, забытого %d",
					len(f.writes), len(f.recorded), len(f.tdeletes), len(f.forgotten))
			}
			// Цена: реестр выдачи одному субъекту не читается, нескольким — не
			// более одного раза за проход.
			if want := min(len(refs)-1, 1); f.ledgerReads != want {
				t.Errorf("чтений реестра выдачи за проход %d, ждали %d", f.ledgerReads, want)
			}
		})
	}
}

// TestReconcileMultiSubject_PreFixBindingConvergesOnTheObjectPass — проход по
// объекту (событие зеркала о предмете i1) доводит кортежи выдачи на этом объекте
// до свежей материализации, не трогая остальных объектов.
func TestReconcileMultiSubject_PreFixBindingConvergesOnTheObjectPass(t *testing.T) {
	rules := ndReaderRules(nil, nil, "items")
	refs := []string{msUser, "user:usrnd09"}
	members, ledger := msPreFix(t, rules, refs[0])
	fresh := msFresh(t, rules, refs...)

	f := msStore(rules, refs...)
	f.current, f.ledger = members, ledger
	f.bindingsForObject = []domain.AccessBindingID{msBinding}
	rec := New(fakeRunner{s: f}, nil, catalog.Fixed{F: ndFacts(t)})
	if err := rec.ReconcileObject(context.Background(), "probemod.items", "i1"); err != nil {
		t.Fatalf("проход по объекту: %v", err)
	}

	const object = "probemod_item:i1"
	onObject := func(s msTupleSet) msTupleSet {
		out := maps.Clone(s)
		maps.DeleteFunc(out, func(t domain.MembershipTuple, _ struct{}) bool { return t.Object != object })
		return out
	}
	if got, want := msSorted(onObject(msFacts(ledger, f))), msSorted(onObject(msSetOf(allWrites(fresh)))); !slices.Equal(got, want) {
		t.Errorf("кортежи на %s после прохода:\n  %v\nсвежая материализация:\n  %v", object, got, want)
	}
	for _, tu := range allWrites(f) {
		if tu.Object != object {
			t.Errorf("проход по %s записал кортеж на другом объекте: %v", object, tu)
		}
	}
}
