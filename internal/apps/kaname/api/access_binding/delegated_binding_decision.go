// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package access_binding

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// kaname#1034 D5 сохраняет исключение kaname#986, а не делает RequireBinding
// всеразрешающим. Writer уже держит GD и полный global source guard; все reads
// и source-backed creator decision выполняются после последнего legacy wait.
func requireDelegatedBindingDecision(ctx context.Context, w kaname.SemanticAuthorityWriter, actor domain.Subject, b domain.AccessBinding, role domain.Role) error {
	if actor.Type != domain.SubjectTypeServiceAccount || actor.Validate() != nil || b.DelegationID == "" || len(b.Subjects) == 0 {
		return authzguard.PermissionDenied()
	}
	source, ok := w.(kaname.SemanticSourceReader)
	if !ok {
		return kaname.ErrSourceUnconfirmed
	}
	// Typed existence/person admission повторяется на TX; прежний синхронный
	// отказ RequireBinding не заменяет свежую годность самого делегата.
	if _, err := source.AdmitSourceActor(ctx, actor); err != nil {
		return err
	}
	d, err := w.AccessBindings().GrantDelegations().Get(ctx, b.DelegationID)
	if err != nil {
		return denyOnNotFound(err)
	}
	if !d.Active() || !d.IsDelegate(string(actor.Type), string(actor.ID)) || !d.AllowsRole(b.RoleID) || role.ID != b.RoleID || domain.RoleDeclaringModule(role) != d.Module || b.GrantedRelation != "" {
		return authzguard.PermissionDenied()
	}
	account, err := delegationAccountOfScope(ctx, w, b)
	if err != nil {
		return err
	}
	if account != d.AccountID {
		return authzguard.PermissionDenied()
	}
	for _, target := range b.Target.Resources {
		if domain.ModuleOfCatalogType(target.Type) != d.Module {
			return authzguard.PermissionDenied()
		}
	}
	if err := delegatedTargetWithin(ctx, w, d, b.Target); err != nil {
		return err
	}
	for _, subject := range b.Subjects {
		if err := delegatedSubjectWithin(ctx, w, d, subject); err != nil {
			return err
		}
	}
	creatorType, ok := domain.SubjectTypeOfPrincipal(d.DelegatedBy.Type)
	if !ok || (creatorType != domain.SubjectTypeUser && creatorType != domain.SubjectTypeServiceAccount) || d.DelegatedBy.ID == "" {
		return authzguard.PermissionDenied()
	}
	creator := domain.Subject{Type: creatorType, ID: domain.SubjectID(d.DelegatedBy.ID)}
	// Свежий owner/cluster-admin/source-backed admin, не один relation_fact и
	// не собственные use-права делегата. Аудит и GrantedBy остаются caller.
	return grantpolicy.RequireScopeAdministration(ctx, w, creator, domain.ScopeAnchor{Type: "account", ID: string(d.AccountID)})
}
