// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// CE09 сохраняет оба доказательства: настоящая асинхронная выдача ждёт
// незафиксированный отзыв и после commit отказывает Т-D1; отдельно настоящий
// HoldActive обязан ждать read-only NO KEY UPDATE держателя того же D1.
// Legacy Writer встаёт на compat fence до бизнес-SQL. Точный key/PID доказывает
// API гонку, а row probe отличает нужный FOR SHARE от слабого FOR KEY SHARE.

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

func TestGrantDelegation_CE09_GrantWriteWaitsForAnUncommittedRevoke(t *testing.T) {
	w := newGDWorld(t)
	w.requireSubject("CE-09 замок")
	d1 := w.d1()
	gdRequireHoldActiveShareLock(w, d1)

	rev, err := w.repo.Writer(w.ctx)
	require.NoError(t, err)
	committed := false
	defer func() {
		if !committed {
			_ = rev.Rollback(w.ctx)
		}
	}()
	gw := rev.AccessBindingsW().GrantDelegationsW()
	_, err = gw.LockForRevoke(w.ctx, domain.GrantDelegationID(d1))
	require.NoError(t, err, "Дано: отзыв взял строку D1")
	_, err = gw.MarkRevoked(w.ctx, domain.GrantDelegationID(d1),
		domain.GrantDelegationActor{Type: "user", ID: string(w.usrA)}, time.Now().UTC())
	require.NoError(t, err, "Дано: отзыв перевёл D1 в REVOKED (не зафиксировано)")

	holderPID := gdCompatOwner(w)
	op, err := w.abx.Create(asSA(w.ctx, w.svaIss), w.v())
	require.NoError(t, err, "синхронное решение видит D1 действующим: отзыв не зафиксирован")

	gdAwaitCompatWaiter(w, holderPID, "")
	require.NoError(t, rev.Commit(w.ctx), "фиксация отзыва D1")
	committed = true

	done := awaitOp(t, w.ctx, w.ops, op.GetId())
	require.NotNil(t, done.Error, "выдача по отзываемому D1 записана")
	assert.Equal(t, codes.FailedPrecondition, codes.Code(done.Error.Code), "код (текст %q)", done.Error.Message)
	assert.Equal(t, fmt.Sprintf("grant delegation %s was revoked before the access binding was written", d1),
		done.Error.Message, "текст Т-D1")
	assert.Zero(t, w.countActiveDelegated(d1), "действующих выдач по D1")
}
