// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	abrepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/authorityprotocol"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/jackc/pgx/v5"
)

// InitialAccessLabelApply называет редакцию определения и её точную область.
// Получатель определяется по действующему владельцу аккаунта внутри транзакции.
type InitialAccessLabelApply struct {
	Account          string
	Project          string
	DefinitionID     domain.AccessLabelDefinitionID
	ExpectedRevision int64
}

type InitialAccessLabelApplyResult struct {
	RoleID    domain.RoleID          `json:"roleId"`
	BindingID domain.AccessBindingID `json:"bindingId"`
}

// IssueInitialAccessLabelApply вызывает закрытую операцию владельца миграций.
func (r *Repository) IssueInitialAccessLabelApply(ctx context.Context, in InitialAccessLabelApply, expected *granteffect.Bundle) (InitialAccessLabelApplyResult, error) {
	if in.Account == "" || in.Account != strings.TrimSpace(in.Account) || in.Project != strings.TrimSpace(in.Project) {
		return InitialAccessLabelApplyResult{}, errors.New("нужен точный аккаунт и, для определения в проекте, идентификатор его проекта")
	}
	if err := in.DefinitionID.Validate(); err != nil {
		return InitialAccessLabelApplyResult{}, err
	}
	if in.ExpectedRevision <= 0 {
		return InitialAccessLabelApplyResult{}, errors.New("нужна положительная ожидаемая редакция определения")
	}
	if r == nil || r.master == nil || expected == nil {
		return InitialAccessLabelApplyResult{}, kaname.ErrSemanticIdentityUnavailable
	}
	if err := expected.Validate(); err != nil {
		return InitialAccessLabelApplyResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, authorityLifecycleDeadline)
	defer cancel()
	if _, err := r.master.Exec(ctx, `SELECT kaname.authority_protocol_require_owner()`); err != nil {
		return InitialAccessLabelApplyResult{}, err
	}
	identity := expected.Identity()
	contract, err := authorityprotocol.NewFullContract(ctx, r.master, identity.ModelID, identity.CatalogID, identity.ProjectorVersion)
	if err != nil {
		return InitialAccessLabelApplyResult{}, err
	}

	// Кандидаты неизменны между попытками. При повторном вызове запись
	// истории даёт исходные ID даже после отзыва или удаления привязки.
	candidate := InitialAccessLabelApplyResult{
		RoleID:    domain.RoleID(ids.NewID(domain.PrefixRole)),
		BindingID: domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding)),
	}
	var result InitialAccessLabelApplyResult
	err = runFullInstallationTx(contract.Context(ctx), r.master, kaname.AuthorityRole, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		result, err = issueInitialAccessLabelApplyTx(ctx, tx, in, candidate)
		return err
	})
	if err != nil {
		return InitialAccessLabelApplyResult{}, err
	}
	return result, nil
}

func issueInitialAccessLabelApplyTx(ctx context.Context, tx pgx.Tx, in InitialAccessLabelApply, candidate InitialAccessLabelApplyResult) (InitialAccessLabelApplyResult, error) {
	var recipient domain.SubjectID
	var operator string
	if err := tx.QueryRow(ctx, `SELECT kaname._authority_initial_access_label_apply_target_v1($1, $2, $3::uuid, $4), current_user::text`,
		in.Account, in.Project, in.DefinitionID, in.ExpectedRevision).Scan(&recipient, &operator); err != nil {
		return InitialAccessLabelApplyResult{}, err
	}

	var existing InitialAccessLabelApplyResult
	var account, project string
	var priorRecipient domain.SubjectID
	err := tx.QueryRow(ctx, `SELECT role_id, binding_id, account_id, project_id, recipient_user_id
FROM kaname.authority_initial_access_label_apply_issuance WHERE definition_id=$1::uuid`, in.DefinitionID).
		Scan(&existing.RoleID, &existing.BindingID, &account, &project, &priorRecipient)
	if err == nil {
		if account != in.Account || project != in.Project || priorRecipient != recipient {
			return InitialAccessLabelApplyResult{}, errors.New("первая выдача уже назначена другой области или прежнему владельцу")
		}
		return existing, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return InitialAccessLabelApplyResult{}, err
	}

	subject := domain.Subject{Type: domain.SubjectTypeUser, ID: recipient}
	sourceRole := domain.Role{
		ID:          candidate.RoleID,
		AccountID:   domain.AccountID(in.Account),
		Name:        domain.RoleName("apply_" + strings.ToLower(string(candidate.RoleID))),
		Description: "Изначальное право менять одну защищённую метку",
		Rules: domain.Rules{{
			Module: "iam", Resources: []string{"accessLabel"}, Verbs: []string{"apply"},
			ResourceNames: []string{string(in.DefinitionID)},
		}},
	}
	binding := domain.AccessBinding{
		ID: candidate.BindingID, RoleID: sourceRole.ID,
		SubjectID: subject.ID, SubjectType: subject.Type, Subjects: []domain.Subject{subject},
		ResourceType: "account", ResourceID: in.Account, Scope: domain.ScopeAccount,
		Status: domain.AccessBindingStatusActive, Target: domain.AccessTarget{AllInScope: true},
	}
	if in.Project != "" {
		sourceRole.AccountID = ""
		sourceRole.ProjectID = domain.ProjectID(in.Project)
		binding.ResourceType, binding.ResourceID, binding.Scope = "project", in.Project, domain.ScopeProject
	}

	writer := &writeTx{readTx: readTx{tx: tx}}
	if err = writeInitialAccessLabelSourceRole(ctx, writer, in, sourceRole, operator); err != nil {
		return InitialAccessLabelApplyResult{}, fmt.Errorf("роль первой выдачи: %w", err)
	}
	if err = writeInitialAccessLabelSourceBinding(ctx, writer, in.Account, binding, operator); err != nil {
		return InitialAccessLabelApplyResult{}, fmt.Errorf("привязка первой выдачи: %w", err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO kaname.authority_initial_access_label_apply_issuance
(definition_id, definition_revision, account_id, project_id, recipient_user_id, role_id, binding_id, issued_at)
VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, clock_timestamp())`,
		in.DefinitionID, in.ExpectedRevision, in.Account, in.Project, recipient, candidate.RoleID, candidate.BindingID)
	return candidate, err
}

func writeInitialAccessLabelSourceRole(ctx context.Context, w *writeTx, in InitialAccessLabelApply, role domain.Role, operator string) error {
	roles := w.RolesW()
	if _, err := roles.Insert(ctx, role); err != nil {
		return err
	}
	if err := roles.ReplaceRuleRefs(ctx, role.ID, domain.RuleRefsOf(role.Rules)); err != nil {
		return err
	}
	if _, err := w.tx.Exec(ctx, `SELECT kaname._authority_initial_access_label_apply_project_v1($1, $2, $3::uuid, $4, $5)`,
		in.Account, in.Project, in.DefinitionID, in.ExpectedRevision, role.ID); err != nil {
		return err
	}
	if err := w.EmitAuditEvent(ctx, service.AuditEvent{
		EventType: "iam.role.created", TenantAccountID: in.Account,
		Payload: map[string]any{
			"actor": operator, "resource_type": "role", "resource_id": string(role.ID),
			"account_id": in.Account, "name": string(role.Name), "source": "initial_access_label_apply",
		},
	}); err != nil {
		return err
	}
	if role.AccountID != "" {
		if err := w.EmitFGARelationWrite(ctx, []service.RelationTuple{{
			User: "account:" + in.Account, Relation: "account", Object: "iam_role:" + string(role.ID),
		}}); err != nil {
			return err
		}
	}
	return w.EmitReconcileEvent(ctx, "mirror.upsert", "iam.role", string(role.ID))
}

func writeInitialAccessLabelSourceBinding(ctx context.Context, w *writeTx, account string, binding domain.AccessBinding, operator string) error {
	parent, ok := binding.StructuralParent()
	if !ok {
		return kaname.ErrInvalidAuthorityFencePlan
	}
	bindings := &capabilityBindingWriter{WriterIface: w.AccessBindingsW(), tx: w.tx}
	stored, err := bindings.Insert(ctx, binding)
	if err != nil {
		return err
	}
	if err = bindings.InsertSubjects(ctx, stored.ID, binding.Subjects); err != nil {
		return err
	}
	// Роль authoring-only. Иерархия привязки нужна для обычного отзыва.
	tuples := []abrepo.RelationTuple{{User: parent.User, Relation: parent.Relation, Object: parent.Object}}
	if err = bindings.EmitRelationWrite(ctx, tuples); err != nil {
		return err
	}
	if err = bindings.InsertEmittedTuples(ctx, stored.ID, tuples); err != nil {
		return err
	}
	if err = bindings.EmitSubjectChangeEvent(ctx, abrepo.SubjectChangeEvent{
		SubjectType: string(binding.SubjectType), SubjectID: string(binding.SubjectID),
		EventType: "binding_grant", Op: "binding_upsert",
	}); err != nil {
		return err
	}
	if err = bindings.EmitAuditEvent(ctx, abrepo.AuditEvent{
		EventType: abrepo.AuditEventTypeGranted, Actor: operator,
		SubjectType: string(binding.SubjectType), SubjectID: string(binding.SubjectID),
		ResourceType: string(stored.ResourceType), ResourceID: stored.ResourceID,
		RoleID: string(stored.RoleID), BindingID: string(stored.ID), TenantAccountID: account,
		ExtraPayload: map[string]any{"source": "initial_access_label_apply"},
	}); err != nil {
		return err
	}
	return w.EmitReconcileEvent(ctx, "mirror.upsert", "iam.accessBinding", string(stored.ID))
}
