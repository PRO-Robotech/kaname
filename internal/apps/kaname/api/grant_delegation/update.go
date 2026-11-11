// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package grant_delegation

// Update расширяет три оси действующего делегирования (#1032). Проверки
// повторяются на текущей строке под общим с Revoke замком пары/строки; права,
// роли и мутация читаются в той же транзакции без вложенного займа из пула.

import (
	"context"
	"fmt"
	"log/slog"
	"slices"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
)

// UpdateInput несёт полные желаемые наборы выбранных осей. Маска не является
// списком добавлений; отсутствие выбранной оси означает запрещённый пустой набор.
type UpdateInput struct {
	GrantDelegationID string
	RoleIDs           []string
	TargetTypes       []string
	SubjectTypes      []string
	UpdateMask        []string
}

type UpdateGrantDelegationUseCase struct {
	repo      Repo
	opsRepo   operations.Repo
	cat       catalog.Source
	relations clients.RelationStore
	logger    *slog.Logger
}

func NewUpdateGrantDelegationUseCase(repo Repo, ops operations.Repo, cat catalog.Source) *UpdateGrantDelegationUseCase {
	return &UpdateGrantDelegationUseCase{repo: repo, opsRepo: ops, cat: cat}
}

func (u *UpdateGrantDelegationUseCase) WithRelationStore(relations clients.RelationStore, logger *slog.Logger) *UpdateGrantDelegationUseCase {
	u.relations, u.logger = relations, logger
	return u
}

var updateAxisAliases = map[string]string{
	"role_ids": "role_ids", "roleIds": "role_ids",
	"target_types": "target_types", "targetTypes": "target_types",
	"subject_types": "subject_types", "subjectTypes": "subject_types",
}

var updateMutableFields = map[string]struct{}{
	"role_ids": {}, "roleIds": {}, "target_types": {}, "targetTypes": {},
	"subject_types": {}, "subjectTypes": {},
}

var updateImmutableFields = func() map[string]string {
	out := map[string]string{}
	for _, field := range [][2]string{
		{"id", "id"}, {"account_id", "accountId"}, {"delegate", "delegate"},
		{"module", "module"}, {"status", "status"}, {"delegated_by", "delegatedBy"},
		{"created_at", "createdAt"}, {"revoked_at", "revokedAt"}, {"revoked_by", "revokedBy"},
	} {
		message := field[1] + " is immutable after GrantDelegation.Create"
		out[field[0]], out[field[1]] = message, message
	}
	return out
}()

// updatePatch владеет своими копиями входа: асинхронный исполнитель не зависит
// от последующих изменений protobuf-запроса вызывающим.
type updatePatch struct {
	id                                domain.GrantDelegationID
	roles                             []domain.RoleID
	targets                           []string
	subjects                          []domain.SubjectType
	setRoles, setTargets, setSubjects bool
}

func validateUpdateInput(in UpdateInput) (updatePatch, error) {
	p := updatePatch{id: domain.GrantDelegationID(in.GrantDelegationID)}
	if err := validateDelegationID(p.id); err != nil {
		return p, err
	}
	if err := shared.ValidateUpdateMask(in.UpdateMask, updateMutableFields, updateImmutableFields); err != nil {
		return p, err
	}
	if len(in.UpdateMask) == 0 {
		p.setRoles, p.setTargets, p.setSubjects = true, true, true
	}
	for _, path := range in.UpdateMask {
		switch updateAxisAliases[path] {
		case "role_ids":
			p.setRoles = true
		case "target_types":
			p.setTargets = true
		case "subject_types":
			p.setSubjects = true
		}
	}
	if p.setRoles {
		if err := validateSet("role_ids", "role", "roles", in.RoleIDs, domain.MaxGrantDelegationRoles); err != nil {
			return p, err
		}
		for _, role := range in.RoleIDs {
			p.roles = append(p.roles, domain.RoleID(role))
		}
	}
	if p.setTargets {
		if err := validateSet("target_types", "type", "types", in.TargetTypes, domain.MaxGrantDelegationTargetTypes); err != nil {
			return p, err
		}
		p.targets = slices.Clone(in.TargetTypes)
	}
	if p.setSubjects {
		var err error
		p.subjects, err = subjectTypesOf(in.SubjectTypes)
		if err != nil {
			return p, err
		}
	}
	return p, nil
}

func (p updatePatch) apply(current domain.GrantDelegation) domain.GrantDelegation {
	next := current
	if p.setRoles {
		next.RoleIDs = p.roles
	}
	if p.setTargets {
		next.TargetTypes = p.targets
	}
	if p.setSubjects {
		next.SubjectTypes = p.subjects
	}
	return domain.SortedGrantDelegationAxes(next)
}

func (u *UpdateGrantDelegationUseCase) Execute(ctx context.Context, in UpdateInput) (*operations.Operation, error) {
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, err
	}
	patch, err := validateUpdateInput(in)
	if err != nil {
		return nil, err
	}
	current, err := loadDelegation(ctx, u.repo, patch.id)
	if err != nil {
		return nil, err
	}
	preflightAuthority := func(ctx context.Context) error {
		return requireAccountGrantAuthority(ctx, u.repo, u.relations, current.AccountID)
	}
	if err := requireUpdateAuthority(ctx, current, preflightAuthority); err != nil {
		return nil, err
	}
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	err = u.validateFinal(ctx, rd, current, patch.apply(current))
	_ = rd.Rollback(ctx)
	if err != nil {
		return nil, err
	}
	plans, err := authzmodel.Shared()
	if err != nil || plans == nil {
		return nil, authzguard.AuthzBackendUnavailable()
	}
	op, err := operations.NewFromContext(ctx, domain.PrefixOperationIAM,
		fmt.Sprintf("Update grant delegation %s", patch.id),
		&iamv1.UpdateGrantDelegationMetadata{GrantDelegationId: string(patch.id), AccountId: string(current.AccountID)})
	if err != nil {
		return nil, err
	}
	if err := u.opsRepo.Create(ctx, op); err != nil {
		return nil, err
	}
	operations.Run(ctx, u.opsRepo, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		out, err := u.doUpdate(ctx, patch, plans)
		if err != nil && u.logger != nil {
			u.logger.ErrorContext(ctx, "grant delegation update operation failed", "op", op.ID, "grant_delegation", string(patch.id), "err", err)
		}
		return out, err
	})
	return &op, nil
}

// Сначала полномочия вызывающего, затем ACTIVE и полномочия сохранённого автора.
// Контекст автора используется только для вопроса и не уходит в аудит/операцию.
func requireUpdateAuthority(ctx context.Context, d domain.GrantDelegation, authority func(context.Context) error) error {
	if err := authority(ctx); err != nil {
		return err
	}
	if !d.Active() {
		return status.Errorf(codes.FailedPrecondition, "grant delegation %s is already revoked", d.ID)
	}
	creator := operations.WithPrincipal(ctx, operations.Principal{Type: d.DelegatedBy.Type, ID: d.DelegatedBy.ID})
	err := authority(creator)
	if status.Code(err) == codes.PermissionDenied || status.Code(err) == codes.NotFound {
		return status.Errorf(codes.FailedPrecondition, "grant delegation %s: delegator no longer has grant authority", d.ID)
	}
	return err
}

// validateFinal проверяет весь итог, включая невыбранные сохранённые типы,
// раньше монотонности. Снятый из живого каталога тип не оживает через другую ось.
func (u *UpdateGrantDelegationUseCase) validateFinal(ctx context.Context, rd Reader, current, next domain.GrantDelegation) error {
	var facts domain.TargetTypeCatalog
	if u.cat != nil {
		facts = u.cat.Facts()
	}
	for _, target := range next.TargetTypes {
		if !domain.ValidTargetType(facts, target) {
			return shared.InvalidArg("target_types", fmt.Sprintf("Illegal argument target_types[] %q (not a live entry of the platform resource catalog; grantable types are published by %s)", target, domain.CatalogEndpoint))
		}
	}
	module, err := delegationModule(ctx, rd, next)
	if err != nil {
		return err
	}
	if module != current.Module {
		return status.Errorf(codes.FailedPrecondition, "grant delegation %s: module is immutable after GrantDelegation.Create", current.ID)
	}
	for _, role := range current.RoleIDs {
		if !slices.Contains(next.RoleIDs, role) {
			return narrowing(current.ID, "role_ids")
		}
	}
	for _, target := range current.TargetTypes {
		if !slices.Contains(next.TargetTypes, target) {
			return narrowing(current.ID, "target_types")
		}
	}
	for _, subject := range current.SubjectTypes {
		if !slices.Contains(next.SubjectTypes, subject) {
			return narrowing(current.ID, "subject_types")
		}
	}
	return nil
}

func narrowing(id domain.GrantDelegationID, axis string) error {
	return status.Errorf(codes.FailedPrecondition, "grant delegation %s: %s may only expand", id, axis)
}

func (u *UpdateGrantDelegationUseCase) doUpdate(ctx context.Context, patch updatePatch, plans *authzmodel.Plans) (*anypb.Any, error) {
	out, err := shared.DoWithWriteTx(ctx, u.repo, func(ctx context.Context, w Writer) (domain.GrantDelegation, error) {
		gw := w.AccessBindingsW().GrantDelegationsW()
		current, err := gw.LockForRevoke(ctx, patch.id)
		if err != nil {
			return domain.GrantDelegation{}, err
		}
		checker, err := w.TransactionRelationChecker(plans)
		if err != nil {
			return domain.GrantDelegation{}, err
		}
		authority := func(ctx context.Context) error {
			return requireAccountGrantAuthorityWithOwner(ctx, checker, current.AccountID, func(ctx context.Context) (domain.UserID, error) {
				return accountOwnerFromReader(ctx, w, current.AccountID)
			})
		}
		if err := requireUpdateAuthority(ctx, current, authority); err != nil {
			return domain.GrantDelegation{}, err
		}
		next := patch.apply(current)
		if err := u.validateFinal(ctx, w, current, next); err != nil {
			return domain.GrantDelegation{}, err
		}
		before := domain.SortedGrantDelegationAxes(current)
		if slices.Equal(before.RoleIDs, next.RoleIDs) && slices.Equal(before.TargetTypes, next.TargetTypes) && slices.Equal(before.SubjectTypes, next.SubjectTypes) {
			return before, nil
		}
		updated, err := gw.UpdateAxes(ctx, next)
		if err != nil {
			return domain.GrantDelegation{}, err
		}
		if err := w.EmitAuditEvent(ctx, outboxtypes.AuditEvent{
			EventType: "iam.grant_delegation.updated", TenantAccountID: string(current.AccountID),
			Payload: map[string]any{
				"actor": authzguard.PrincipalUserID(ctx), "delegation_id": string(current.ID), "account_id": string(current.AccountID),
				"before": delegationAxesAudit(before), "after": delegationAxesAudit(next),
			},
		}); err != nil {
			return domain.GrantDelegation{}, err
		}
		return updated, nil
	})
	if err != nil {
		return nil, err
	}
	return marshalGD(out)
}

func delegationAxesAudit(d domain.GrantDelegation) map[string]any {
	return map[string]any{"role_ids": d.RoleIDs, "target_types": d.TargetTypes, "subject_types": d.SubjectTypes}
}
