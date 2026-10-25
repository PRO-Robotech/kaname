// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

// module_role_implied_delete_test.go — материализация роли МОДУЛЯ не приписывает
// удаление к правке (kaname#1006), и выдача, материализованная прежним
// вычислением, сходится к новому набору сводящим проходом (проход при старте).
//
// Прежнее состояние строится не руками, а тем же материализатором: проход по той
// же выдаче с ролью без владельца даёт ровно тот состав и те кортежи, что давало
// прежнее вычисление роли модуля (правило «правка влечёт удаление» владельца не
// спрашивало). Ключ члена от владельца роли не зависит — отпечаток правила тот
// же, — поэтому проход видит члена НЕИЗМЕННЫМ, и именно эта ветвь обязана
// снять лишний кортеж.

import (
	"context"
	"slices"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
)

const miBinding domain.AccessBindingID = "acb-mi-1"

// miStore — выдача роли с правилом `get, list, update` на сетях проекта; policy —
// политика роли выдачи.
func miStore(policy domain.RulePolicy) *fakeStore {
	rule := domain.Rule{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get", "list", "update"}}
	return &fakeStore{
		scope:       domain.ScopeAnchor{Type: "project", ID: "prj-1"},
		subjectType: "user", subjectID: "usr-1", active: true,
		policy: &policy,
		selectors: []domain.RuleSelector{{
			Arm: domain.ArmAnchor, RuleFP: rule.Fingerprint(),
			ObjectTypes: []string{"vpc.network"},
			Verbs:       rule.Verbs,
		}},
		mirror: map[string][]domain.MirrorObject{
			"vpc.network": {{ObjectType: "vpc.network", ObjectID: "net-1", ParentProjectID: "prj-1"}},
		},
	}
}

// miReconcile — полный проход обхода по таймеру.
func miReconcile(t *testing.T, f *fakeStore) {
	t.Helper()
	rec := New(fakeRunner{s: f}, nil, catalogfixture.Source())
	if err := rec.ReconcileBinding(context.Background(), miBinding); err != nil {
		t.Fatalf("полный проход: %v", err)
	}
}

// miConverge — сводящий проход (проход при старте).
func miConverge(t *testing.T, f *fakeStore) {
	t.Helper()
	rec := New(fakeRunner{s: f}, nil, catalogfixture.Source())
	if err := rec.ConvergeBinding(context.Background(), miBinding); err != nil {
		t.Fatalf("сводящий проход: %v", err)
	}
}

func miFlatten(batches [][]domain.MembershipTuple) []domain.MembershipTuple {
	var out []domain.MembershipTuple
	for _, b := range batches {
		out = append(out, b...)
	}
	return out
}

func miLedgerHas(f *fakeStore, relation, object string) bool {
	for _, r := range f.ledgerNow() {
		if r.Tuple.Relation == relation && r.Tuple.Object == object {
			return true
		}
	}
	return false
}

// TestReconcile_ModuleRoleUpdateMaterializesNoDelete — свежая выдача роли модуля
// с правкой не пишет `v_delete`; близнец меняет ровно владельца роли — роль
// платформы с той же правкой `v_delete` пишет.
func TestReconcile_ModuleRoleUpdateMaterializesNoDelete(t *testing.T) {
	const object = "vpc_network:net-1"

	module := miStore(domain.PolicyOfRole(true, "vpc"))
	miReconcile(t, module)
	w := allWrites(module)
	if !hasTuple(w, "v_update", object) {
		t.Fatalf("роль модуля не получила объявленной правки: %v — проба не дошла до предмета", w)
	}
	if hasTuple(w, "v_delete", object) {
		t.Errorf("роль модуля с правкой получила v_delete на %s — манифест удаления не объявлял", object)
	}

	platform := miStore(domain.PolicyOfRole(true, ""))
	miReconcile(t, platform)
	if !hasTuple(allWrites(platform), "v_delete", object) {
		t.Errorf("близнец: роль платформы с правкой не получила v_delete на %s — правило снято шире предмета", object)
	}
}

// TestReconcile_StaleImpliedDeleteIsRevokedOnTheConvergingPass — выдача роли
// модуля, материализованная прежним вычислением (с `v_delete`), после сводящего
// прохода (проход при старте) не несёт `v_delete` ни в движке, ни в реестре
// выпущенного; прочие кортежи члена не трогаются и не переписываются.
func TestReconcile_StaleImpliedDeleteIsRevokedOnTheConvergingPass(t *testing.T) {
	const object = "vpc_network:net-1"

	// Прежнее состояние — то, что писало прежнее вычисление.
	pre := miStore(domain.PolicyOfRole(true, ""))
	miReconcile(t, pre)
	if !hasTuple(allWrites(pre), "v_delete", object) {
		t.Fatalf("прежнее состояние без v_delete — предпосылка пробы не выполнена")
	}

	f := miStore(domain.PolicyOfRole(true, "vpc"))
	f.current = slices.Clone(pre.upserts)
	f.ledger = slices.Clone(pre.ledgerNow())
	miConverge(t, f)

	if !hasTuple(miFlatten(f.tdeletes), "v_delete", object) {
		t.Errorf("сводящий проход не снял v_delete с %s: снятий %v", object, miFlatten(f.tdeletes))
	}
	if miLedgerHas(f, "v_delete", object) {
		t.Errorf("реестр выпущенного по-прежнему несёт v_delete на %s", object)
	}
	for _, rel := range []string{"v_get", "v_update"} {
		if hasTuple(miFlatten(f.tdeletes), rel, object) {
			t.Errorf("проход снял объявленный %s на %s", rel, object)
		}
		if !miLedgerHas(f, rel, object) {
			t.Errorf("реестр потерял объявленный %s на %s", rel, object)
		}
	}
	if len(f.writes) != 0 {
		t.Errorf("проход переписал неизменного члена: записей %v", f.writes)
	}
}

// TestReconcile_PeriodicPassDoesNotReadTheLedgerOfASingleSubjectBinding — граница
// цены: обход по таймеру (ReconcileBinding) реестр выдачи одному субъекту не
// читает и неизменного члена не сводит — сведение платится раз на старт, а не
// каждые полминуты. Близнец — тот же вход сводящим проходом: реестр прочитан
// ровно один раз.
func TestReconcile_PeriodicPassDoesNotReadTheLedgerOfASingleSubjectBinding(t *testing.T) {
	pre := miStore(domain.PolicyOfRole(true, ""))
	miReconcile(t, pre)

	periodic := miStore(domain.PolicyOfRole(true, "vpc"))
	periodic.current = slices.Clone(pre.upserts)
	periodic.ledger = slices.Clone(pre.ledgerNow())
	miReconcile(t, periodic)
	if periodic.ledgerReads != 0 || len(periodic.forgotten) != 0 {
		t.Errorf("обход по таймеру прочитал реестр %d раз и забыл %d строк — цена сведения "+
			"платилась бы на каждом обходе", periodic.ledgerReads, len(periodic.forgotten))
	}

	converging := miStore(domain.PolicyOfRole(true, "vpc"))
	converging.current = slices.Clone(pre.upserts)
	converging.ledger = slices.Clone(pre.ledgerNow())
	miConverge(t, converging)
	if converging.ledgerReads != 1 {
		t.Errorf("сводящий проход прочитал реестр %d раз, ждали 1", converging.ledgerReads)
	}
}

// TestReconcile_ConvergedModuleRoleBindingIsNotRewritten — близнец: выдача роли
// модуля, уже материализованная новым вычислением, сводящим проходом не
// трогается — ни записи, ни снятия, ни забытого.
func TestReconcile_ConvergedModuleRoleBindingIsNotRewritten(t *testing.T) {
	fresh := miStore(domain.PolicyOfRole(true, "vpc"))
	miReconcile(t, fresh)

	f := miStore(domain.PolicyOfRole(true, "vpc"))
	f.current = slices.Clone(fresh.upserts)
	f.ledger = slices.Clone(fresh.ledgerNow())
	miConverge(t, f)

	if len(f.writes) != 0 || len(f.recorded) != 0 || len(f.tdeletes) != 0 || len(f.forgotten) != 0 {
		t.Errorf("проход по сошедшейся выдаче записал: кортежей %d, реестра %d, снятий %d, забытого %d",
			len(f.writes), len(f.recorded), len(f.tdeletes), len(f.forgotten))
	}
}
