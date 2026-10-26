// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// service_account_creator_explain_integration_test.go — DoD S1 п.8 приёмки
// `service-account-creation-is-its-own-right.md` (PRO-Robotech/kaname#1003):
// запрос материализации ведения (учётки создателя на аккаунте) и запрос снятия
// при конце выдачи идут по индексу, без перебора учёток аккаунта (§3,
// «производительность»).
//
// План снимается с `enable_seqscan = off` (`explainPlan`, тот же приём, что у
// DoD-9 делегирования): на базе мира строк мало, и перебор планировщику дешевле —
// исход «перебор» на десятке строк о пригодности индекса не говорит. Вопрос пробы —
// ПРИГОДЕН ли индекс запросу. Текст запроса материализации — исполняемый
// (`kanamepg.MatchCreatedByQuery`), а не выписанная копия.

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

func TestServiceAccountCreator_DoD8_MaterializationAndTeardownGoByIndex(t *testing.T) {
	w := newSACWorld(t)
	w.requireCreatorRole("DoD-8")
	bc := w.grantC("DoD-8 Дано: G", w.svaIss)
	for _, name := range []string{"cr-x1", "cr-x2", "cr-x3"} {
		w.createSADone(asSA(w.ctx, w.svaIss), string(w.accA), name, "DoD-8 Дано: учётка создателя "+name)
	}

	q, args, ok := kanamepg.MatchCreatedByQuery("iam.serviceAccount",
		domain.ScopeAnchor{Type: "account", ID: string(w.accA)}, []string{w.svaIss})
	require.True(t, ok, "DoD-8: у учётки факт создателя не хранится — отбирать нечем")
	plan := explainPlan(t, w.ctx, w.pool, q, args...)
	t.Logf("DoD-8 план отбора учёток создателя на аккаунте:\n%s", plan)
	require.Contains(t, plan, "service_accounts_creator_idx", "DoD-8: отбор учёток создателя не идёт индексом (аккаунт, создатель)")
	require.NotContains(t, plan, "Seq Scan on service_accounts", "DoD-8: отбор учёток создателя перебирает учётки")

	// Положительный контроль: без условия на создателя частичный индекс
	// неприменим — проба различает «индекс пригоден» и «индекс назван всегда».
	control := explainPlan(t, w.ctx, w.pool,
		`SELECT id FROM kaname.service_accounts o WHERE o.account_id = $1`, string(w.accA))
	t.Logf("DoD-8 контроль (без условия на создателя):\n%s", control)
	require.NotContains(t, control, "service_accounts_creator_idx",
		"DoD-8 контроль: частичный индекс назван и там, где его условие не выполнено — проба вакуумна")

	// Снятие при конце выдачи читает реестр выпущенного ЭТОЙ выдачей — по
	// префиксу первичного ключа, учётки аккаунта не трогаются вовсе.
	teardown := explainPlan(t, w.ctx, w.pool,
		`SELECT fga_user, relation, object, member_object_type, member_object_id
		   FROM kaname.access_binding_emitted_tuples WHERE binding_id = $1`, bc)
	t.Logf("DoD-8 план чтения реестра снимаемой выдачи:\n%s", teardown)
	require.Contains(t, teardown, "access_binding_emitted_tuples_pk", "DoD-8: снятие читает реестр не по ключу выдачи")
	require.NotContains(t, teardown, "service_accounts", "DoD-8: снятие трогает учётки")
}
