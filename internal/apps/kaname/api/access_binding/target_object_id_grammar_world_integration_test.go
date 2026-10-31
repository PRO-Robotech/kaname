// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// target_object_id_grammar_world_integration_test.go — идентификатор объекта в
// цели выдачи подчиняется грамматике объекта на входе `AccessBindingService.Create`
// (PRO-Robotech/kaname#1004, приёмка
// docs/engineering/acceptance/access-target-object-id-follows-the-object-grammar.md,
// сценарии ATI-01, ATI-03, ATI-04).
//
// Проба на обе стороны: каждый запрещённый знак — синхронный отказ с дословным
// текстом и без выдачи, его близнец со знаком `-` и каждая граница `/` —
// выдача, завершённая без ошибки. Снятие проверки формы краснит отрицания,
// запрет `/` краснит близнецов.
//
// Мир — П6 (`newPCRWorld`), те же части, что корень службы.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

func TestAccessTarget_ObjectIDFollowsTheObjectGrammarAtCreate(t *testing.T) {
	w := newPCRWorld(t)
	twin := slashBase + "/o-ne"
	ver := time.Now()
	registerSlashRepo(w, slashBase+"/one", ver)
	registerSlashRepo(w, twin, ver)
	role := w.seedRole("object_id_grammar",
		domain.Rules{{Module: "registry", Resources: []string{"repositories"}, Verbs: []string{"get"}}})
	ctx := asUser(w.ctx, w.usrA)
	grants := func() int { return w.activeGrantsOf(w.usrB, role) }

	// ATI-03, близнец: знак `-` вместо запрещённого — выдача без ошибки.
	w.createDone(ctx, w.grantRequest(userSubject(w.usrB), role, repoTarget(twin)), "ATI-03 близнец "+twin)
	require.Equal(t, 1, grants(), "ATI-03 близнец: выдач usr-B")

	// ATI-03 — каждый запрещённый знак в середине идентификатора.
	for _, c := range []struct{ name, x string }{
		{"пробел", " "},
		{"табуляция", "\t"},
		{"перевод строки", "\n"},
		{"решётка", "#"},
		{"двоеточие", ":"},
	} {
		t.Run("ATI-03 "+c.name, func(t *testing.T) {
			id := slashBase + "/o" + c.x + "ne"
			op, err := w.ab.Create(ctx, w.grantRequest(userSubject(w.usrB), role, repoTarget(id)))
			requireSyncRefusal(t, err, codes.InvalidArgument, objectIDRefusal(0), "ATI-03 "+c.name)
			assert.Nil(t, op, "ATI-03 %s: у синхронного отказа Operation не создаётся", c.name)
		})
	}
	require.Equal(t, 1, grants(), "ATI-03: отказы не завели ни одной выдачи")

	// ATI-04 — отказ называет позицию негодного элемента.
	op, err := w.ab.Create(ctx, w.grantRequest(userSubject(w.usrB), role,
		repoTarget(slashBase+"/one", slashBase+"/one two")))
	requireSyncRefusal(t, err, codes.InvalidArgument, objectIDRefusal(1), "ATI-04")
	assert.Nil(t, op, "ATI-04: у синхронного отказа Operation не создаётся")
	require.Equal(t, 1, grants(), "ATI-04: отказ не завёл выдачи")

	// ATI-01 — законный идентификатор с `/` и каждая его граница принимаются
	// целью выдачи дословно: каждая — своя цель, своя выдача.
	in := slashInputs()
	for _, c := range in {
		w.createDone(ctx, w.grantRequest(userSubject(w.usrB), role, repoTarget(c.id)), "ATI-01 "+c.name+" "+c.id)
	}
	assert.Equal(t, 1+len(in), grants(), "ATI-01: выдач usr-B — близнец и по одной на каждый вход")
}
