// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package seed

// verify_gate_relation_test.go — приёмка Design-B (плоская модель прав, полная по
// глаголам) VBC-19/VBC-20, F-11/F-12: страж сверки «отношение удовлетворяет
// действию».
//
// Страж сверки до Design-B доказывал лишь «материализация состоялась» (ведомость
// непуста) — слепая зона, через которую прошёл класс дефекта Design-A: кортеж
// материализован, но отношение, к которому он сводится, НЕ удовлетворяло
// отношению исполнения, по которому судит каталог. Расширенный страж для каждой
// проверки требуемого отношения живой привязки выполняет НАСТОЯЩИЙ
// Check(subject, required_relation, object) и пропускает переключение ТОЛЬКО
// когда разрешены все 100 %.
//
// Эта unit-проба ведёт стража через поддельные RelationChecker и хранилище.
// Доказательство на настоящем хранилище — собственный интеграционный набор
// реляционной формы (repo/kaname/pg/relverdict, против Postgres): этап S6 снял
// внешний движок, так что «настоящее хранилище» — собственная база этой службы, а
// имя движка здесь отправило бы следующего читателя искать доказательство,
// которого под этим именем больше нет.
//
// Прежний хвост «красное, пока нет VerifyGate.VerifyRelationSatisfiesAction»
// снят: метод есть (seed/verify_gate.go), а пометка, объявляющая красным
// зелёное, не утверждает ничего.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// relCheckStore — дублёр VerifyStore, отдающий ТОЛЬКО перечень проверок отношения;
// прочие методы VerifyStore паникуют (на этом пути не исполняются).
type relCheckStore struct {
	stubVerifyStore
	checks []BindingRelationCheck
	err    error
}

func (s relCheckStore) ListActiveBindingRelationChecks(context.Context) ([]BindingRelationCheck, error) {
	return s.checks, s.err
}

// fakeRelChecker — считает вызовы Check и возвращает заданный вердикт по
// объекту.
type fakeRelChecker struct {
	allow map[string]bool // объект → разрешён
	calls int
}

// SubjectAdmitted — все субъекты этих проб допущены: их предмет — отношение, а
// не допуск (допуск — verify_gate_admission_test.go).
func (c *fakeRelChecker) SubjectAdmitted(context.Context, string) (bool, error) { return true, nil }

func (c *fakeRelChecker) Check(_ context.Context, _ /*subject*/, _ /*relation*/, object string) (bool, error) {
	c.calls++
	return c.allow[object], nil
}

func TestVerifyGate_VBC19_RelationSatisfiesAction_AllAllow(t *testing.T) {
	store := relCheckStore{checks: []BindingRelationCheck{
		{BindingID: "acb_1", Subject: "user:usr_a", Relation: "v_get", Object: "iam_user:usr_x"},
		{BindingID: "acb_2", Subject: "user:usr_b", Relation: "v_list", Object: "vpc_network:vpcn_y"},
	}}
	chk := &fakeRelChecker{allow: map[string]bool{
		"iam_user:usr_x":     true,
		"vpc_network:vpcn_y": true,
	}}

	gate := NewVerifyGate(store, nil).WithRelationChecker(chk)
	report, err := gate.VerifyRelationSatisfiesAction(context.Background())
	require.NoError(t, err)
	assert.True(t, report.NoAccessLoss,
		"VBC-19: 100% of active bindings satisfy required_relation → cutover permitted")
	assert.Equal(t, 2, report.BindingsChecked)
	assert.Empty(t, report.Failures)
	assert.Equal(t, 2, chk.calls, "VBC-19: gate must run a real FGA Check per active binding (not ledger-only)")
}

func TestVerifyGate_VBC20_CutoverBlockedUntilVGetBackfilled(t *testing.T) {
	// Одна живая привязка держит лишь исторический кортеж яруса, поэтому
	// Check(v_get) ОТКАЗЫВАЕТ — страж обязан ПАДАТЬ (переключение закрыто), пока
	// сверщик не дозаполнит v_get.
	store := relCheckStore{checks: []BindingRelationCheck{
		{BindingID: "acb_ok", Subject: "user:usr_a", Relation: "v_get", Object: "iam_user:usr_x"},
		{BindingID: "acb_bad", Subject: "user:usr_b", Relation: "v_get", Object: "iam_role:rol_y"},
	}}
	chk := &fakeRelChecker{allow: map[string]bool{
		"iam_user:usr_x": true,
		// iam_role:rol_y нет → ОТКАЗ (историческая ведомость только ярусов, v_get нет).
	}}

	gate := NewVerifyGate(store, nil).WithRelationChecker(chk)
	report, err := gate.VerifyRelationSatisfiesAction(context.Background())
	require.NoError(t, err)
	assert.False(t, report.NoAccessLoss,
		"VBC-20: an active leaf-member with no v_get (Check DENY) → gate FAIL, cutover blocked (F-11)")
	require.Len(t, report.Failures, 1)
	assert.Equal(t, domain.AccessBindingID("acb_bad"), report.Failures[0].BindingID)
}

func TestVerifyGate_VBC19_NilChecker_SkipNonFatal(t *testing.T) {
	// Неподключённый RelationChecker (nil) делает стража «отношение удовлетворяет»
	// нефатальным пропуском (ran=false) — старт не обязан падать, когда
	// проверяющий отношения недоступен.
	store := relCheckStore{}
	gate := NewVerifyGate(store, nil) // без WithRelationChecker
	report, err := gate.VerifyRelationSatisfiesAction(context.Background())
	require.NoError(t, err)
	assert.True(t, report.NoAccessLoss, "nil checker → non-fatal skip (no assertion made)")
	assert.Equal(t, 0, report.BindingsChecked)
}
