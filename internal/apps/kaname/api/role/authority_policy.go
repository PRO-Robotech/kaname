// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package role

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

type rolePolicySelection struct {
	configured bool
	factory    kaname.RoleAuthorityWriterFactory
}

func (u *CreateRoleUseCase) WithRoleAuthorityWriter(f kaname.RoleAuthorityWriterFactory) *CreateRoleUseCase {
	u.policy = rolePolicySelection{true, f}
	return u
}
func (u *UpdateRoleUseCase) WithRoleAuthorityWriter(f kaname.RoleAuthorityWriterFactory) *UpdateRoleUseCase {
	u.policy = rolePolicySelection{true, f}
	return u
}
func (h *Handler) WithRoleAuthorityWriter(f kaname.RoleAuthorityWriterFactory) *Handler {
	h.create.WithRoleAuthorityWriter(f)
	h.update.WithRoleAuthorityWriter(f)
	return h
}

var errRoleMutationCleanup = errors.New("role mutation cleanup failed")

// Три полных попытки: фабрика, OLD-authority gate, тело и Commit. Ошибка
// после возврата writer тоже откатывает audit/projection и начинает новый RR.
func roleMutationRetryable(err error) bool {
	if errors.Is(err, errRoleMutationCleanup) {
		return false
	}
	var pe *pgconn.PgError
	return errors.Is(err, kaname.ErrAuthorityClassificationChanged) || errors.Is(err, iamerr.ErrAborted) ||
		(errors.As(err, &pe) && (pe.Code == "40001" || pe.Code == "40P01" || pe.Code == "P1034"))
}

func roleMutationAttempts(ctx context.Context, attempt func() (domain.Role, error)) (domain.Role, error) {
	var err error
	for n := 0; n < 3; n++ {
		if err = ctx.Err(); err != nil {
			return domain.Role{}, err
		}
		var out domain.Role
		out, err = attempt()
		if err == nil {
			return out, nil
		}
		if ctx.Err() != nil {
			return domain.Role{}, ctx.Err()
		}
		if !roleMutationRetryable(err) {
			return domain.Role{}, err
		}
	}
	return domain.Role{}, iamerr.Wrapf(iamerr.ErrAborted, "Authority changed, retry")
}

func (s rolePolicySelection) run(ctx context.Context, repo Repo, r domain.Role, create, rules bool, body func(context.Context, Writer) (domain.Role, error), reconcilers ...TupleReconciler) (out domain.Role, result error) {
	if !s.configured {
		return shared.DoWithWriteTx(ctx, repo, body)
	}
	defer func() {
		if result != nil {
			if errors.Is(result, kaname.ErrSourceReadLimit) {
				result = iamerr.Wrapf(iamerr.ErrUnavailable, "Authority evaluation incomplete")
			}
			result = shared.MapRepoErrAt(ctx, result)
		}
	}()
	factory, ok := s.factory.(kaname.RoleMutationWriterFactory)
	if !ok || factory == nil {
		return out, iamerr.Wrapf(iamerr.ErrUnavailable, "Role mutation preparation unavailable")
	}
	request := kaname.RoleMutationRequest{Role: r, Create: create, Rules: rules}
	if !create && rules && len(reconcilers) != 0 && reconcilers[0] != nil {
		request.Tuples, ok = reconcilers[0].(kaname.RoleTupleBuilder)
		if !ok {
			return out, iamerr.Wrapf(iamerr.ErrUnavailable, "Role tuple preparation unavailable")
		}
	}
	actor := grantpolicy.Actor(ctx)
	return roleMutationAttempts(ctx, func() (out domain.Role, result error) {
		w, err := factory.RoleMutationWriter(ctx, request, actor)
		if err != nil {
			return out, err
		}
		if w == nil {
			return out, iamerr.Wrapf(iamerr.ErrUnavailable, "Role authority writer unavailable")
		}
		defer func() {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			if rollback := w.Rollback(cleanup); rollback != nil {
				result = errors.Join(errRoleMutationCleanup, result, rollback)
			}
		}()
		// Фабрика уже удерживает весь mutation footprint и взяла final DB clock.
		// Сама роль и её проекции пока OLD: собственная запись не доказывает право.
		if create || rules {
			err = grantpolicy.RequireRole(ctx, w, actor, r, create)
		} else {
			err = grantpolicy.RequireRoleMethod(ctx, w, actor, r, false)
		}
		if err != nil {
			return out, err
		}
		out, err = body(ctx, w)
		if err != nil {
			return domain.Role{}, err
		}
		if !create && rules {
			promoter, ok := w.(kaname.RoleCapabilityPromoter)
			if !ok {
				return domain.Role{}, iamerr.Wrapf(iamerr.ErrUnavailable, "Role capability promotion unavailable")
			}
			if err = promoter.PromoteRoleCapabilities(ctx, r.ID); err != nil {
				return domain.Role{}, err
			}
		}
		if err = ctx.Err(); err != nil {
			return domain.Role{}, err
		}
		if err = w.Commit(ctx); err != nil {
			return domain.Role{}, err
		}
		return out, nil
	})
}

// В active writer projection использует immutable catalog того же bundle;
// горячий внешний cache не участвует в решении и последующей записи.
func writerRoleFacts(w Writer, fallback catalog.Source) (*catalog.Facts, error) {
	if semantic, ok := w.(kaname.SemanticAuthorityWriter); ok {
		if err := semantic.SemanticBundle().Validate(); err != nil {
			return nil, err
		}
		var h catalog.Halves
		if err := json.Unmarshal(semantic.SemanticBundle().CanonicalCatalog(), &h); err != nil {
			return nil, err
		}
		return catalog.NewFacts(h)
	}
	return fallback.Facts(), nil
}
