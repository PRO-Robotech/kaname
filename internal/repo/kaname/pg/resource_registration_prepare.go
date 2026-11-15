// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/PRO-Robotech/corelib/authz/proxytuple"
	corevalidate "github.com/PRO-Robotech/corelib/validate"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/registrationpolicy"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// Это только registration часть полного staged manifest. Descendants, carriers,
// receipts и folded output добавляются до выбора coordinator accounts; этот
// промежуточный результат сам по себе не открывает TX и не разрешает запись.
type resourceRegistrationPreparation struct {
	input                kaname.ResourceDecisionIntent
	module               resourceModuleIdentity
	catalog              resourceCatalogRow
	row                  service.ResourceMirrorRow
	hierarchies          []domain.ParentHierarchy
	oldScopes, newScopes []domain.ContainerScope
	footprint            *resourceFootprint
	parents              *resourceParentCapture
	bindingRefuses       bool
}

func prepareResourceRegistration(ctx context.Context, parents *resourceParentCapture, module resourceModuleIdentity, in kaname.ResourceDecisionIntent) (*resourceRegistrationPreparation, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if parents == nil || !module.valid() {
		return nil, kaname.ErrSourceUnconfirmed
	}
	// Ограничение применяется до Snapshot/unnest и обхода. Частичный parent
	// claim не используется: сверх общего read budget возвращается Unknown.
	if parents.source == nil || parents.source.budget == nil {
		return nil, kaname.ErrSourceUnconfirmed
	}
	if len(in.Mirror.ParentChain) > parents.source.budget.RemainingRows() {
		return nil, kaname.ErrSourceReadLimit
	}
	if err := chargeNativePolicyBudget(parents.source.budget, len(in.Mirror.ParentChain), 0); err != nil {
		return nil, err
	}
	switch in.Action {
	case kaname.ResourceDecisionRegister, kaname.ResourceDecisionUnregister, kaname.ResourceDecisionPublish, kaname.ResourceDecisionUnpublish:
	default:
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	if err := registrationpolicy.ValidateShape(module.catalogModule, in.Tuple.User, in.Tuple.Relation, in.Tuple.Object); err != nil {
		return nil, err
	}
	typ, id, ok := strings.Cut(in.Tuple.Object, ":")
	if !ok || in.Mirror.ObjectType != typ || in.Mirror.ObjectID != id {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	publishing := in.Action == kaname.ResourceDecisionPublish || in.Action == kaname.ResourceDecisionUnpublish
	pureGrant := proxytuple.IsPublicReadGrant(in.Tuple.User, in.Tuple.Relation)
	if publishing != pureGrant {
		return nil, authzguard.PermissionDenied()
	}
	if err := corevalidate.Labels("labels", in.Mirror.Labels); err != nil {
		return nil, err
	}
	captured, err := parents.catalog(ctx, typ)
	if err != nil {
		return nil, err
	}
	selected, known := captured.selected()
	if in.Action == kaname.ResourceDecisionRegister && (!known || !selected.live) {
		name := typ
		if known {
			name = selected.identity.Dotted
		}
		return nil, &kaname.ResourceDecisionFieldError{Field: "object", Description: fmt.Sprintf("resource type %q is not a live entry of the platform resource catalog", name)}
	}
	if !known || selected.identity.Module != module.catalogModule {
		return nil, authzguard.PermissionDenied()
	}
	if err := registrationpolicy.ValidateShape(module.catalogModule, in.Tuple.User, in.Tuple.Relation, selected.identity.ObjectType+":"+id); err != nil {
		return nil, err
	}
	prepared := &resourceRegistrationPreparation{input: in.Snapshot(), module: module, catalog: selected, row: in.Snapshot().Mirror, footprint: newResourceFootprint(), parents: parents}
	prepared.row.ObjectType = selected.identity.Dotted
	if err := prepared.footprint.addObject(domain.ResourceRef{Type: selected.identity.Dotted, ID: id}); err != nil {
		return nil, err
	}
	if in.Action == kaname.ResourceDecisionRegister {
		policy := selected.policy
		if err := resourcePermanentProjectForm(policy, in.Mirror); err != nil {
			return nil, err
		}
		subjectType, _, _ := strings.Cut(in.Tuple.User, ":")
		if !proxytuple.Hierarchical(proxytuple.Relation(in.Tuple.Relation)) {
			pointer, ok := policy.Pointer(in.Tuple.Relation)
			if !ok || pointer.Type != subjectType || !registrationpolicy.NamedPointerSubjectType(subjectType) {
				return nil, authzguard.PermissionDenied()
			}
		}
		if !policy.Admits(in.Tuple.Relation, subjectType) {
			return nil, authzguard.PermissionDenied()
		}
		// Тот же predicate, что у canonical command view. Его входные persistent
		// строки уже входят в capture; 2 catalog + 1 binding ограничены PK/UNIQUE.
		if _, err = parents.permanentProject(ctx, policy.ObjectType, id); err != nil {
			return nil, err
		}
		if err = chargeNativePolicyBudget(parents.source.budget, 3, 1); err != nil {
			return nil, err
		}
		chain := in.Mirror.ParentChain
		if chain == nil {
			chain = []string{}
		}
		if err = parents.tx.QueryRow(ctx, `SELECT kaname.object_project_binding_refuses($1,$2,$3,$4)`, policy.ObjectType, id, in.Mirror.ParentProjectID, chain).Scan(&prepared.bindingRefuses); err != nil {
			return nil, err
		}
		prepared.hierarchies, prepared.newScopes, err = parents.derive(ctx, in.Tuple.User, in.Tuple.Relation, in.Tuple.Object, policy, domain.ParentClaim{ProjectID: in.Mirror.ParentProjectID, AccountID: in.Mirror.ParentAccountID, Chain: in.Mirror.ParentChain})
		if err != nil {
			if errors.Is(err, iamerr.ErrParentScopeMismatch) && prepared.bindingRefuses {
				return nil, iamerr.ObjectBoundToOtherProject(in.Tuple.Object, policy.ObjectType, id)
			}
			return nil, err
		}
		if len(prepared.hierarchies) == 0 || len(prepared.newScopes) == 0 {
			return nil, kaname.ErrSourceUnconfirmed
		}
		if err = prepared.footprint.addRegistrationScopes(prepared.newScopes); err != nil {
			return nil, err
		}
		if prepared.row.ParentAccountID == "" && prepared.row.ParentProjectID != "" {
			prepared.row.ParentAccountID = prepared.hierarchies[0].AccountID
		}
	}
	prepared.oldScopes, err = parents.savedScopes(ctx, selected.identity.ObjectType, id)
	if err != nil {
		return nil, err
	}
	if len(prepared.oldScopes) == 0 {
		// Новый ключ не имеет OLD owner. Уже существующее зеркало без выводимой
		// области не превращается в регистрацию только по NEW утверждениям.
		_, exists, err := parents.mirror(ctx, selected.identity.ObjectType, id)
		if err != nil {
			return nil, err
		}
		if exists {
			return nil, kaname.ErrSourceUnconfirmed
		}
		if in.Action != kaname.ResourceDecisionRegister {
			return nil, authzguard.PermissionDenied()
		}
	} else if err = prepared.footprint.addRegistrationScopes(prepared.oldScopes); err != nil {
		return nil, err
	}
	if _, err = parents.source.read(ctx, parents.tx, resourceSourceKey{kind: resourceSourcePointerFacts, typ: selected.identity.ObjectType, id: id}); err != nil {
		return nil, err
	}
	return prepared, nil
}
func resourcePermanentProjectForm(policy domain.WritePolicy, row service.ResourceMirrorRow) error {
	if !policy.PermanentProject {
		return nil
	}
	if row.ParentProjectID == "" {
		return &kaname.ResourceDecisionFieldError{Field: "parent_project_id", Description: fmt.Sprintf("parent_project_id: required for object type %s with a permanent project", policy.ObjectType)}
	}
	for _, link := range row.ParentChain {
		if typ, id, ok := strings.Cut(link, ":"); ok && typ == "project" && id != "" {
			return nil
		}
	}
	return &kaname.ResourceDecisionFieldError{Field: "parent_chain", Description: fmt.Sprintf("parent_chain: must name the project for object type %s with a permanent project", policy.ObjectType)}
}

// Даже account gate отказ сохраняет прежний приоритет project binding. Этот
// выбор не читает новый snapshot после final clock и не меняет gate result.
func (p *resourceRegistrationPreparation) accountRefusal(err error) error {
	if err == nil || p == nil {
		return err
	}
	if p.input.Action == kaname.ResourceDecisionRegister && p.bindingRefuses {
		return iamerr.ObjectBoundToOtherProject(p.input.Tuple.Object, p.catalog.identity.ObjectType, p.row.ObjectID)
	}
	return err
}
