// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package role

import (
	"context"
	"errors"
	"sort"

	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/authzfilter"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	rolerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/role"
)

// Plans приходит из admitted composition корня; глобальный Shared не читается.
func (u *CreateRoleUseCase) WithGrantReferencePlans(p *authzmodel.Plans) *CreateRoleUseCase {
	u.referencePlans = p
	return u
}
func (u *UpdateRoleUseCase) WithGrantReferencePlans(p *authzmodel.Plans) *UpdateRoleUseCase {
	u.referencePlans = p
	return u
}

func checkGrantReferences(ctx context.Context, w Writer, owner domain.Role, caps []domain.GrantCapabilityRule, create bool, plans *authzmodel.Plans) error {
	if len(caps) == 0 {
		return nil
	}
	var checker kanamerepo.RelationChecker
	var err error
	subject := principalSubject(operations.PrincipalFromContext(ctx))
	if semantic, ok := w.(kanamerepo.SemanticAuthorityWriter); ok {
		// Обычная authority подтверждается независимо от proposed content.
		// Проверка ссылок продолжает использовать настоящий pinned native checker.
		if err = grantpolicy.RequireRoleMethod(ctx, semantic, grantpolicy.Actor(ctx), owner, create); err != nil {
			return err
		}
		checker = semantic.SemanticRelationChecker()
		if checker == nil {
			return iamerr.Wrapf(iamerr.ErrUnavailable, "Grant reference model unavailable")
		}
	} else {
		if plans == nil {
			return iamerr.Wrapf(iamerr.ErrUnavailable, "Grant reference model unavailable")
		}
		checker, err = w.TransactionRelationChecker(plans)
		if err != nil {
			return err
		}
		relation, object := "v_update", "iam_role:"+string(owner.ID)
		if create {
			relation = "editor"
			object = "account:" + string(owner.AccountID)
			if owner.ProjectID != "" {
				object = "project:" + string(owner.ProjectID)
			}
		}
		if subject == "" {
			return iamerr.Wrapf(iamerr.ErrPermissionDenied, "Role authoring denied")
		}
		allowed, e := checker.Check(ctx, subject, relation, object)
		if e != nil {
			return e
		}
		if !allowed {
			return iamerr.Wrapf(iamerr.ErrPermissionDenied, "Role authoring denied")
		}
	}
	refs, ok := w.RolesW().(rolerepo.GrantReferenceReader)
	if !ok {
		return iamerr.Wrapf(iamerr.ErrUnavailable, "Grant reference reader unavailable")
	}
	if err := refs.LockGrantAuthoringAxes(ctx, caps); err != nil {
		return err
	}
	account, err := refs.LockGrantOwnerAccount(ctx, owner)
	if err != nil {
		return err
	}
	ids := map[domain.RoleID]bool{}
	for _, cap := range caps {
		if cap.Kind == domain.GrantCapabilityBindRole {
			ids[cap.BoundRoleID] = true
		}
	}
	ordered := make([]domain.RoleID, 0, len(ids))
	for id := range ids {
		ordered = append(ordered, id)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	for _, id := range ordered {
		ref, err := refs.LockGrantReference(ctx, id)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, iamerr.ErrNotFound) {
				return iamerr.Wrapf(iamerr.ErrNotFound, "Role reference not found")
			}
			return iamerr.Wrapf(iamerr.ErrUnavailable, "Role reference reader unavailable")
		}
		// Один ID: канонический Get predicate не распараллеливает SQL одной TX.
		if !ref.Role.IsSystem {
			visible, e := authzfilter.VisibleSet(ctx, grantReferenceObjectChecker{checker}, subject, "iam_role", []string{string(id)})
			if e != nil {
				return e
			}
			if !visible[string(id)] {
				return iamerr.Wrapf(iamerr.ErrNotFound, "Role reference not found")
			}
		}
		if !ref.Live {
			return iamerr.Wrapf(iamerr.ErrNotFound, "Role reference not found")
		}
		if !rolerepo.CommonGrantAnchor(owner, account, ref.Role, ref.AccountID) {
			return iamerr.Wrapf(iamerr.ErrFailedPrecondition, "Role reference has no common grant scope")
		}
	}
	return nil
}

// kaname#1034: canonical Get использует ObjectChecker, а same-TX native порт
// предоставляет Check с уже сохранёнными Plans и person admission. Передаём
// вопрос тому же checker; непустые условия этот узкий порт не умеет доказать.
type grantReferenceObjectChecker struct{ checker kanamerepo.RelationChecker }

func (c grantReferenceObjectChecker) CheckWithContext(ctx context.Context, subject, relation, object string, conditions map[string]any) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if c.checker == nil || len(conditions) != 0 {
		return false, iamerr.Wrapf(iamerr.ErrUnavailable, "Grant reference conditional checker unavailable")
	}
	return c.checker.Check(ctx, subject, relation, object)
}

var _ authzfilter.ObjectChecker = grantReferenceObjectChecker{}
