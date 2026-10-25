// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// grant_delegation_fk_integration_test.go — внешний ключ
// `grant_delegations_active_delegate_fk` отвечает текстом Р6 с обеих сторон
// (PRO-Robotech/kaname#986, строка GD-45 DoD приёмки; находка ревью
// FK-23503-UNMAPPED).
//
// Программная проверка (`create.go` — учётка есть; `saWriter.Delete` — нет
// действующего делегирования) судит свой снимок, а ключ — свежий. Обе пробы
// ставят ключ в положение, где программная проверка уже прошла, и утверждают
// текст ответа:
//
//   - сторона ВСТАВКИ: строка делегирования на учётку, которой нет, — ответ
//     ключа, а не программной проверки (её этот вызов обходит);
//   - сторона СНЯТИЯ: делегирование вставлено и не зафиксировано, удаление
//     учётки стартует и встаёт на замке; после фиксации вставки ответ обязан
//     назвать делегирование (Р6), а не «на ресурс ещё ссылаются».
//
// Ожидание замка — держателем, а не паузой: проба ждёт, пока удаление
// встанет на замке (`pg_stat_activity`), и только тогда фиксирует вставку.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// rawDelegation — строка делегирования пары (acc-A, delegate) от usr-A, оси D1.
func (w *gdWorld) rawDelegation(delegate string) domain.GrantDelegation {
	return domain.GrantDelegation{
		ID:           domain.GrantDelegationID(ids.NewID(domain.PrefixGrantDelegation)),
		AccountID:    w.accA,
		DelegateID:   domain.ServiceAccountID(delegate),
		RoleIDs:      []domain.RoleID{w.rolPuller},
		TargetTypes:  []string{"registry.registries"},
		SubjectTypes: []domain.SubjectType{domain.SubjectTypeServiceAccount},
		Module:       "registry",
		Status:       domain.GrantDelegationActive,
		DelegatedBy:  domain.GrantDelegationActor{Type: "user", ID: string(w.usrA)},
	}
}

// GD-45, сторона вставки: делегирование на учётку, которой нет, — текст Р6
// «ServiceAccount <id> not found», а не общий текст неразобранного ключа.
func TestGrantDelegation_GD45_KeyRefusesADelegationToAMissingAccountWithItsText(t *testing.T) {
	w := newGDWorld(t)
	missing := ids.NewID(domain.PrefixServiceAccount)

	wr, err := w.repo.Writer(w.ctx)
	require.NoError(t, err)
	defer func() { _ = wr.Rollback(w.ctx) }()
	_, ierr := wr.AccessBindingsW().GrantDelegationsW().Insert(w.ctx, w.rawDelegation(missing))
	require.Error(t, ierr, "строка делегирования на несуществующую учётку вставлена")

	st, _ := status.FromError(shared.MapRepoErr(ierr))
	assert.Equal(t, codes.FailedPrecondition, st.Code(), "код (текст %q)", st.Message())
	assert.Equal(t, fmt.Sprintf("ServiceAccount %s not found", missing), st.Message(), "текст Р6")
}

// GD-45, сторона снятия: удаление учётки, пришедшее, пока делегирование на неё
// вставлено и не зафиксировано, после фиксации отвечает текстом Р6 с id
// делегирования; учётка на месте.
func TestGrantDelegation_GD45_DeleteRacingAnInsertNamesTheDelegation(t *testing.T) {
	w := newGDWorld(t)
	w.requireSubject("GD-45 гонка")

	ins, err := w.repo.Writer(w.ctx)
	require.NoError(t, err)
	committed := false
	defer func() {
		if !committed {
			_ = ins.Rollback(w.ctx)
		}
	}()
	d, err := ins.AccessBindingsW().GrantDelegationsW().Insert(w.ctx, w.rawDelegation(w.svaIss))
	require.NoError(t, err, "Дано: делегирование на sva-iss вставлено (не зафиксировано)")

	op, err := w.sas.Delete(asUser(w.ctx, w.usrS), &iamv1.DeleteServiceAccountRequest{ServiceAccountId: w.svaIss})
	require.NoError(t, err, "удаление учётки асинхронно: отказ — в операции")

	w.awaitLockWaiter("service_accounts", 30*time.Second, "удаление учётки встало на замке вставки делегирования")
	require.NoError(t, ins.Commit(w.ctx), "фиксация вставки делегирования")
	committed = true

	done := awaitOp(t, w.ctx, w.ops, op.GetId())
	require.NotNil(t, done.Error, "учётка-делегат удалена при действующем делегировании")
	assert.Equal(t, codes.FailedPrecondition, codes.Code(done.Error.Code), "код (текст %q)", done.Error.Message)
	assert.Equal(t, fmt.Sprintf("service account %s holds an active grant delegation %s; revoke it first", w.svaIss, d.ID),
		done.Error.Message, "текст Р6")
	var n int
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.service_accounts WHERE id = $1`, w.svaIss).Scan(&n))
	assert.Equal(t, 1, n, "учётка на месте")
}

// awaitLockWaiter — ждёт, пока в базе мира появится сеанс, стоящий на замке, чей
// запрос называет `table`. Срок истёк — проба падает: расстановка не создана,
// и судить исход нельзя.
func (w *gdWorld) awaitLockWaiter(table string, within time.Duration, why string) {
	w.t.Helper()
	ctx, cancel := context.WithTimeout(w.ctx, within)
	defer cancel()
	for {
		var n int
		require.NoError(w.t, w.pool.QueryRow(ctx, `
			SELECT count(*) FROM pg_stat_activity
			 WHERE datname = current_database() AND wait_event_type = 'Lock' AND query ILIKE '%' || $1 || '%'`,
			table).Scan(&n))
		if n > 0 {
			return
		}
		select {
		case <-ctx.Done():
			w.t.Fatalf("%s: за %s ни один сеанс не встал на замке (%s)", why, within, table)
		case <-time.After(20 * time.Millisecond):
		}
	}
}
