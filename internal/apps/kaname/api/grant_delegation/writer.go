// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package grant_delegation

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

type delegationWriterFactory = kaname.GrantDelegationWriterFactory

const (
	delegationCreate = kaname.GrantDelegationCreate
	delegationUpdate = kaname.GrantDelegationUpdate
)

// WithAuthorityWriter получает готовый startup adapter с immutable bundle.
// Только отсутствие вызова настройки сохраняет legacy. Явный nil закрывает writer.
func (u *CreateGrantDelegationUseCase) WithAuthorityWriter(f delegationWriterFactory) *CreateGrantDelegationUseCase {
	u.authorityWriter = f
	u.authorityConfigured = true
	return u
}
func (u *UpdateGrantDelegationUseCase) WithAuthorityWriter(f delegationWriterFactory) *UpdateGrantDelegationUseCase {
	u.authorityWriter = f
	u.authorityConfigured = true
	return u
}

type delegationWriteRepo struct {
	Repo
	factory    delegationWriterFactory
	configured bool
	mutation   kaname.GrantDelegationMutation
	proposed   domain.GrantDelegation
}

func (r delegationWriteRepo) Writer(ctx context.Context) (Writer, error) {
	if !r.configured {
		return r.Repo.Writer(ctx)
	}
	if r.factory == nil {
		return nil, authzguard.AuthzBackendUnavailable()
	}
	value := reflect.ValueOf(r.factory)
	if value.Kind() == reflect.Ptr && value.IsNil() {
		return nil, authzguard.AuthzBackendUnavailable()
	}

	return r.factory.GrantDelegationWriter(ctx, r.mutation, r.proposed)
}
func delegationDecisionAt(w Writer, legacy time.Time) time.Time {
	if a, ok := w.(interface{ AuthorityFence() kaname.AuthorityFence }); ok {
		return a.AuthorityFence().DecisionAt()
	}
	return legacy
}

func refreshDelegationDecision(ctx context.Context, w Writer) error {
	if a, ok := w.(interface{ RefreshGrantDelegationDecision(context.Context) error }); ok {
		return a.RefreshGrantDelegationDecision(ctx)
	}
	return nil
}

// Только настроенный participant повторяет весь worker: новая RR discovery,
// новая RC TX, те же checks, mutation/audit/operation-history одной попыткой.
// До Commit нет внешних эффектов; legacy путь сохраняет прежний один запуск.
func doDelegationWriteTx(ctx context.Context, repo delegationWriteRepo, action func(context.Context, Writer) (domain.GrantDelegation, error)) (domain.GrantDelegation, error) {
	if !repo.configured {
		return shared.DoWithWriteTx(ctx, repo, action)
	}
	var zero domain.GrantDelegation
	for attempt := 1; attempt <= revokeAttempts; attempt++ {
		out, err := delegationWriteOnce(ctx, repo, action)
		if err == nil {
			return out, nil
		}
		// Старые pair-lock methods возвращают PgError напрямую; их deadlock
		// требует такого же полного rollback/restart, как mapped repo ErrAborted.
		var sqlState interface{ SQLState() string }
		if errors.As(err, &sqlState) && (sqlState.SQLState() == "40001" || sqlState.SQLState() == "40P01") {
			err = errors.Join(iamerr.ErrAborted, err)
		}
		if !errors.Is(err, iamerr.ErrAborted) || attempt == revokeAttempts {
			return zero, shared.MapRepoErrAt(ctx, err)
		}
		timer := time.NewTimer(time.Duration(attempt) * revokeRetryBackoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return zero, shared.MapRepoErrAt(ctx, ctx.Err())
		case <-timer.C:
		}
	}
	return zero, shared.MapRepoErrAt(ctx, iamerr.ErrAborted)
}
func delegationWriteOnce(ctx context.Context, repo delegationWriteRepo, action func(context.Context, Writer) (domain.GrantDelegation, error)) (domain.GrantDelegation, error) {
	var zero domain.GrantDelegation
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	w, err := repo.Writer(ctx)
	if err != nil {
		return zero, err
	}
	if w == nil {
		return zero, authzguard.AuthzBackendUnavailable()
	}
	committed := false
	defer func() {
		if !committed {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			_ = w.Rollback(cleanup)
		}
	}()
	out, err := action(ctx, w)
	if err != nil {
		return zero, err
	}
	if err = ctx.Err(); err != nil {
		return zero, err
	}
	if err = w.Commit(ctx); err != nil {
		return zero, err
	}
	committed = true
	return out, nil
}
