// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package grant_delegation

// revoke_retry_test.go — отзыв делегирования, ставший жертвой взаимной
// блокировки, исполняется заново, а не завершает операцию отказом (задача
// PRO-Robotech/kaname#986, находка ревью SD-986-I1).
//
// Отзыв делегирования не берёт advisory-замков выдач (CE-10) и делит строки с
// фоновой материализацией; цикл ожиданий база разрывает откатом одной стороны
// целиком (40P01/40001, признак `iamerr.ErrAborted`). Тело отзыва — одна
// транзакция записи, после коммита оно ничего не делает, поэтому повтор
// безопасен по построению (тот же класс, что снятие выдачи, `delete.go`,
// kaname#679).
//
// Проба без базы: первая транзакция откатывается на первом же замке с
// `ErrAborted`, вторая проходит. Близнец — отказ не этого класса (уже отозвано):
// повтора нет, ответ прежний.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	repoab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	repogd "github.com/PRO-Robotech/kaname/internal/repo/kaname/grant_delegation"
)

// retryRepo — хранилище пробы: каждая транзакция записи — новая попытка;
// `lockErr` — исход замка строки делегирования на попытке с этим номером.
type retryRepo struct {
	kanamerepo.Repository
	lockErr   map[int]error
	attempts  int
	committed int
}

func (r *retryRepo) Writer(context.Context) (kanamerepo.Writer, error) {
	r.attempts++
	return &retryWriter{r: r, attempt: r.attempts}, nil
}

type retryWriter struct {
	kanamerepo.Writer
	r       *retryRepo
	attempt int
}

func (w *retryWriter) AccessBindingsW() repoab.WriterIface { return retryABW{w: w} }
func (w *retryWriter) EmitAuditEvent(context.Context, outboxtypes.AuditEvent) error {
	return nil
}
func (w *retryWriter) Commit(context.Context) error   { w.r.committed++; return nil }
func (w *retryWriter) Rollback(context.Context) error { return nil }

type retryABW struct {
	repoab.WriterIface
	w *retryWriter
}

func (a retryABW) GrantDelegationsW() repogd.WriterIface { return retryGDW{w: a.w} }

type retryGDW struct {
	repogd.WriterIface
	w *retryWriter
}

func (g retryGDW) LockForRevoke(_ context.Context, id domain.GrantDelegationID) (domain.GrantDelegation, error) {
	if err := g.w.r.lockErr[g.w.attempt]; err != nil {
		return domain.GrantDelegation{}, err
	}
	return retryDelegation(id, domain.GrantDelegationActive), nil
}

func (g retryGDW) MarkRevoked(_ context.Context, id domain.GrantDelegationID, by domain.GrantDelegationActor, at time.Time) (domain.GrantDelegation, error) {
	d := retryDelegation(id, domain.GrantDelegationRevoked)
	d.RevokedAt, d.RevokedBy = &at, &by
	return d, nil
}

func (g retryGDW) ActiveBindingIDs(context.Context, domain.GrantDelegationID) ([]domain.AccessBindingID, error) {
	return nil, nil
}

// Идентификаторы пробы — формой продукта (префикс и 17 знаков), как их судит
// shared.ValidateResourceID.
var (
	retryID       = domain.GrantDelegationID(ids.NewID(domain.PrefixGrantDelegation))
	retryAccount  = domain.AccountID(ids.NewID(domain.PrefixAccount))
	retryDelegate = domain.ServiceAccountID(ids.NewID(domain.PrefixServiceAccount))
	retryRole     = domain.RoleID(ids.NewID(domain.PrefixRole))
	retryUser     = ids.NewID(domain.PrefixUser)
)

func retryDelegation(id domain.GrantDelegationID, st domain.GrantDelegationStatus) domain.GrantDelegation {
	return domain.GrantDelegation{
		ID: id, AccountID: retryAccount, DelegateID: retryDelegate,
		RoleIDs: []domain.RoleID{retryRole}, TargetTypes: []string{"registry.registries"},
		SubjectTypes: []domain.SubjectType{domain.SubjectTypeServiceAccount},
		Module:       "registry", Status: st,
		DelegatedBy: domain.GrantDelegationActor{Type: "user", ID: retryUser},
		CreatedAt:   time.Unix(1_700_000_000, 0).UTC(),
	}
}

func TestRevokeGrantDelegation_SD986I1_DeadlockVictimIsRetried(t *testing.T) {
	aborted := iamerr.Wrapf(iamerr.ErrAborted, "deadlock detected")
	for _, tc := range []struct {
		name         string
		lockErr      map[int]error
		wantErr      codes.Code
		wantAttempts int
	}{
		{name: "жертва взаимной блокировки — повтор, отзыв проходит",
			lockErr: map[int]error{1: aborted}, wantErr: codes.OK, wantAttempts: 2},
		{name: "близнец: уже отозвано — без повтора",
			lockErr: map[int]error{1: iamerr.Wrapf(iamerr.ErrFailedPrecondition, "grant delegation %s is already revoked", retryID)},
			wantErr: codes.FailedPrecondition, wantAttempts: 1},
		{name: "жертва на каждой попытке — прежний отказ после исчерпания",
			lockErr: map[int]error{1: aborted, 2: aborted, 3: aborted, 4: aborted},
			wantErr: codes.Aborted, wantAttempts: 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &retryRepo{lockErr: tc.lockErr}
			u := NewRevokeGrantDelegationUseCase(repo, nil)

			res, err := u.doRevoke(context.Background(), retryID,
				domain.GrantDelegationActor{Type: "user", ID: retryUser}, retryUser)

			require.Equal(t, tc.wantAttempts, repo.attempts, "число транзакций отзыва")
			require.Equal(t, tc.wantErr, status.Code(err), "код (ошибка %v)", err)
			if tc.wantErr == codes.OK {
				require.NotNil(t, res, "результат операции")
				require.Equal(t, 1, repo.committed, "зафиксирована ровно одна транзакция")
				return
			}
			require.Zero(t, repo.committed, "отказ ничего не зафиксировал")
		})
	}
}
