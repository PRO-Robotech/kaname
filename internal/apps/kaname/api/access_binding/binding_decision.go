// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

import (
	"context"
	"errors"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	ab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	"google.golang.org/protobuf/types/known/anypb"
)

// kaname#1034: явное active-mode wiring; nil сохраняет прежнюю дверь. Ошибка
// установленного runner никогда не переходит в legacy fallback.
func (u *CreateAccessBindingUseCase) WithBindingDecisions(p kaname.BindingDecisionRunner) *CreateAccessBindingUseCase {
	u.decisions = p
	return u
}
func (u *UpdateAccessBindingUseCase) WithBindingDecisions(p kaname.BindingDecisionRunner) *UpdateAccessBindingUseCase {
	u.decisions = p
	return u
}

// WithBindingDecisions подключает оба уже созданных use-case; режим выбирает
// композиционный корень отдельно от ordinary participant и только явно.
func (h *Handler) WithBindingDecisions(p kaname.BindingDecisionRunner) *Handler {
	h.create.WithBindingDecisions(p)
	h.update.WithBindingDecisions(p)
	return h
}
func bindingDecisionActor(ctx context.Context) (domain.Subject, error) {
	s, ok := authzguard.PrincipalSubject(ctx)
	if !ok {
		return domain.Subject{}, authzguard.PermissionDenied()
	}
	typ, id, ok := strings.Cut(s, ":")
	if !ok {
		return domain.Subject{}, authzguard.PermissionDenied()
	}
	return domain.Subject{Type: domain.SubjectType(typ), ID: domain.SubjectID(id)}, nil
}
func proposedBinding(b domain.AccessBinding, r domain.Role) granteffect.Binding {
	return granteffect.Binding{SourceID: string(b.ID), Role: r, Scope: domain.ScopeAnchor{Type: string(b.ResourceType), ID: b.ResourceID}, Target: b.Target, Subjects: b.Subjects, CapabilityVersion: 1}
}
func bindingDecisionError(err error) error {
	// Отказ не раскрывает путь решения: публичный контракт одинаков для
	// отсутствующего источника и недостаточной authority (приёмка #1034).
	if errors.Is(err, iamerr.ErrNotFound) || errors.Is(err, iamerr.ErrPermissionDenied) || isPermissionDenied(err) {
		return authzguard.PermissionDenied()
	}
	return shared.MapRepoErr(err)
}
func (u *CreateAccessBindingUseCase) checkBindingDecision(ctx context.Context, b domain.AccessBinding) (domain.GrantDelegationID, error) {
	actor, err := bindingDecisionActor(ctx)
	if err != nil {
		return "", err
	}
	err = u.decisions.RunBindingDecision(ctx, actor, b, true, buildSubjectsDecisionTuples, func(ctx context.Context, w kaname.SemanticAuthorityWriter, current domain.AccessBinding, r domain.Role) error {
		return grantpolicy.RequireBinding(ctx, w, actor, proposedBinding(current, r))
	})
	if err == nil {
		return "", nil
	}
	// Только отказ в праве; ошибка backend/admission/budget не превращается в D5.
	if !errors.Is(err, iamerr.ErrPermissionDenied) && !isPermissionDenied(err) {
		return "", bindingDecisionError(err)
	}
	runner, ok := u.decisions.(kaname.DelegatedBindingDecisionRunner)
	if !ok || u.delegated == nil {
		return "", bindingDecisionError(err)
	}
	var captured domain.GrantDelegationID
	err = runner.RunDelegatedBindingDecision(ctx, actor, b, buildSubjectsDecisionTuples, func(ctx context.Context, w kaname.SemanticAuthorityWriter, current domain.AccessBinding, r domain.Role) error {
		if err := requireDelegatedBindingDecision(ctx, w, actor, current, r); err != nil {
			return err
		}
		captured = current.DelegationID
		return nil
	})
	if err != nil {
		return "", bindingDecisionError(err)
	}
	return captured, nil
}
func buildSubjectsDecisionTuples(b domain.AccessBinding, r domain.Role) []ab.RelationTuple {
	return buildSubjectsBindingTuples(b, b.Subjects, r)
}
func (u *CreateAccessBindingUseCase) doCreateDecision(ctx context.Context, b domain.AccessBinding, auditActor string) (*anypb.Any, error) {
	actor, err := bindingDecisionActor(ctx)
	if err != nil {
		return nil, err
	}
	var created domain.AccessBinding
	var role domain.Role
	apply := func(ctx context.Context, w kaname.SemanticAuthorityWriter, current domain.AccessBinding, r domain.Role) error {
		if b.DelegationID != "" {
			if current.DelegationID != b.DelegationID || u.delegated == nil {
				return authzguard.PermissionDenied()
			}
			if err := requireDelegatedBindingDecision(ctx, w, actor, current, r); err != nil {
				return err
			}
		} else {
			if current.DelegationID != "" {
				return authzguard.PermissionDenied()
			}
			if err := grantpolicy.RequireBinding(ctx, w, actor, proposedBinding(current, r)); err != nil {
				return err
			}
		}
		// kaname#1034: LRO/fence wait не разрешает вставить уже истёкшую выдачу.
		if current.ExpiresAt != nil && !current.ExpiresAt.After(w.AuthorityFence().DecisionAt()) {
			return shared.InvalidArg("expires_at", "binding expired before the decision")
		}
		if err := u.validateStructuralGatesIn(ctx, w, r, current); err != nil {
			return err
		}
		var err error
		created, role, err = u.writeCreatedBinding(ctx, w, current, auditActor, true)
		return err
	}
	if b.DelegationID != "" {
		runner, ok := u.decisions.(kaname.DelegatedBindingDecisionRunner)
		if !ok {
			return nil, authzguard.PermissionDenied()
		}
		err = runner.RunDelegatedBindingDecision(ctx, actor, b, buildSubjectsDecisionTuples, apply)
	} else {
		err = u.decisions.RunBindingDecision(ctx, actor, b, true, buildSubjectsDecisionTuples, apply)
	}
	if err != nil {
		return nil, bindingDecisionError(err)
	}
	u.afterCreatedBinding(ctx, created, role)
	return marshalAB(created)
}
func (u *UpdateAccessBindingUseCase) checkUpdateDecision(ctx context.Context, b domain.AccessBinding) error {
	actor, err := bindingDecisionActor(ctx)
	if err != nil {
		return err
	}
	err = u.decisions.RunBindingDecision(ctx, actor, b, false, nil, func(ctx context.Context, w kaname.SemanticAuthorityWriter, current domain.AccessBinding, _ domain.Role) error {
		return grantpolicy.RequireScopeAdministration(ctx, w, actor, domain.ScopeAnchor{Type: string(current.ResourceType), ID: current.ResourceID})
	})
	return bindingDecisionError(err)
}
func (u *UpdateAccessBindingUseCase) updateDecision(ctx context.Context, id domain.AccessBindingID, applyDP, deletionProtection, labelsChanged bool, labels domain.Labels) (domain.AccessBinding, error) {
	actor, err := bindingDecisionActor(ctx)
	if err != nil {
		return domain.AccessBinding{}, err
	}
	var updated domain.AccessBinding
	err = u.decisions.RunBindingDecision(ctx, actor, domain.AccessBinding{ID: id}, false, nil, func(ctx context.Context, w kaname.SemanticAuthorityWriter, current domain.AccessBinding, _ domain.Role) error {
		if err := grantpolicy.RequireScopeAdministration(ctx, w, actor, domain.ScopeAnchor{Type: string(current.ResourceType), ID: current.ResourceID}); err != nil {
			return err
		}
		var err error
		updated, err = u.writeBindingMetadata(ctx, w, id, applyDP, deletionProtection, labelsChanged, labels)
		return err
	})
	return updated, bindingDecisionError(err)
}
