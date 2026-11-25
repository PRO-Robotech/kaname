// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

type initialRegistrationBinding struct {
	binding           granteffect.Binding
	authoredRules     domain.Rules
	expiresAt         *time.Time
	pending           bool
	projectionPending bool
}

type initialRegistrationAncestorSources struct {
	coordinate domain.ScopeAnchor
	facts      []resourceSourceRow
	holders    []resourceSourceRow
}

// initialRegistrationCapture is only an RR census. Its empty OLD and NEW
// images, binding sources and direct facts must be rechecked under their RC
// guards. The writer still has to prove source provenance, projection,
// expiry, apply authority and Grant before making any change.
type initialRegistrationCapture struct {
	source        *resourceSourceCapture
	image         granteffect.InitialRegistrationImage
	actor         domain.Subject
	sourceVersion time.Time
	bindings      []initialRegistrationBinding
	ancestors     []initialRegistrationAncestorSources
}

// captureInitialRegistrationLabels is for the first versioned project
// registration on a canonical project pointer. It uses the same source
// cache as stageRegistration, before that cache has been sealed. A future
// signed preflight must cover its new census predicates before this can be
// connected to a mutation.
func (p *resourceRegistrationPreparation) captureInitialRegistrationLabels(ctx context.Context, initial domain.Labels) (*initialRegistrationCapture, error) {
	if p == nil || p.parents == nil || p.parents.source == nil || p.parents.source.sealed ||
		p.input.Action != kaname.ResourceDecisionRegister || !p.module.valid() || !p.catalog.live ||
		p.module.catalogModule != p.catalog.identity.Module || p.catalog.identity.Module == "iam" ||
		p.row.ObjectType != p.catalog.identity.Dotted || domain.FeedSourceForType(p.row.ObjectType) != domain.FeedMirror ||
		!nativeQuestionToken(p.row.ObjectID) ||
		p.row.SourceVersion.IsZero() || !p.row.SourceVersion.Equal(p.input.Mirror.SourceVersion) ||
		!maps.Equal(p.row.Labels, p.input.Mirror.Labels) || len(initial) == 0 || initial.Validate() != nil ||
		p.bindingRefuses || len(p.oldScopes) != 0 || len(p.newScopes) != 1 || len(p.hierarchies) != 1 {
		return nil, kaname.ErrSourceUnconfirmed
	}
	scope := p.newScopes[0]
	canonical := domain.ProjectHierarchy(scope.ProjectID, scope.AccountID)
	if !scope.Registered || domain.ScopeProject.ValidateAgainst("project", scope.ProjectID) != nil ||
		domain.ScopeAccount.ValidateAgainst("account", scope.AccountID) != nil ||
		!nativeQuestionToken(scope.ProjectID) || !nativeQuestionToken(scope.AccountID) ||
		!slices.Equal(canonical.Links, p.hierarchies[0].Links) || !slices.Equal(canonical.Links, p.row.ParentChain) ||
		p.hierarchies[0].ProjectID != scope.ProjectID || p.hierarchies[0].AccountID != scope.AccountID ||
		p.row.ParentProjectID != scope.ProjectID || p.row.ParentAccountID != scope.AccountID ||
		p.input.Tuple.User != canonical.Links[0] || p.input.Tuple.Relation != "project" ||
		p.input.Tuple.Object != p.catalog.identity.ObjectType+":"+p.row.ObjectID {
		return nil, kaname.ErrSourceUnconfirmed
	}
	protected := make(map[string]string, len(initial))
	for key, value := range initial {
		if !utf8.ValidString(string(value)) || strings.ContainsRune(string(value), 0) {
			return nil, kaname.ErrSourceUnconfirmed
		}
		protected[string(key)] = string(value)
	}
	if err := p.captureAbsentInitialRegistration(ctx); err != nil {
		return nil, err
	}
	ref := domain.ResourceRef{Type: p.row.ObjectType, ID: p.row.ObjectID}
	out := &initialRegistrationCapture{
		source: p.parents.source, sourceVersion: p.row.SourceVersion,
		actor: domain.Subject{Type: domain.SubjectTypeServiceAccount, ID: domain.SubjectID(p.module.actor)},
		image: granteffect.InitialRegistrationImage{Root: ref, New: domain.MirrorObject{
			ObjectType: ref.Type, ObjectID: ref.ID, ParentProjectID: scope.ProjectID, ParentAccountIDs: []string{scope.AccountID},
			Labels: maps.Clone(p.row.Labels), AccessLabels: protected,
		}},
	}
	project := domain.ScopeAnchor{Type: "project", ID: scope.ProjectID}
	account := domain.ScopeAnchor{Type: "account", ID: scope.AccountID}
	cluster := domain.ScopeAnchor{Type: "cluster", ID: domain.ClusterSingletonID}
	if err := out.captureAncestors(ctx, p.parents, p.catalog.identity.ObjectType, project, account, cluster); err != nil {
		return nil, err
	}
	var err error
	out.bindings, err = captureInitialRegistrationBindings(ctx, p.parents, ref, []domain.ScopeAnchor{project, account, cluster})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Absence of the mirror alone does not establish first registration. Holding
// an empty materialized result, including the negative replay predicates,
// prevents an existing authority source from being treated as absent OLD.
func (p *resourceRegistrationPreparation) captureAbsentInitialRegistration(ctx context.Context) error {
	for _, kind := range []resourceSourceKind{
		resourceSourceMirror, resourceSourceParentEdges, resourceSourceRegistrationScopes,
		resourceSourceProjectBinding, resourceSourcePointerFacts, resourceSourceDescendantEdges,
		resourceSourceRegistrationPointers, resourceSourceObjectReceipts, resourceSourceObjectPublication,
		resourceSourceObjectRetirement, resourceSourceObjectMembers, resourceSourceObjectLedger, resourceSourceFactLedgerHolders,
		resourceSourceMetadataPolicyReceipt,
	} {
		typ := p.catalog.identity.ObjectType
		switch kind {
		case resourceSourceMirror, resourceSourceObjectMembers, resourceSourceObjectLedger, resourceSourceMetadataPolicyReceipt:
			typ = p.catalog.identity.Dotted
		}
		rows, err := p.parents.source.read(ctx, p.parents.tx, resourceSourceKey{kind: kind, typ: typ, id: p.row.ObjectID})
		if err != nil {
			return err
		}
		if len(rows) != 0 {
			return kaname.ErrSourceUnconfirmed
		}
	}
	return nil
}

func (c *initialRegistrationCapture) captureAncestors(ctx context.Context, parents *resourceParentCapture, rootType string, project, account, cluster domain.ScopeAnchor) error {
	projectObject, present, err := parents.captureObjectProjection(ctx, domain.ScopeTypeProjectDotted, project.ID)
	if err != nil {
		return err
	}
	if !present || projectObject.ParentProjectID != project.ID || !slices.Equal(projectObject.ParentAccountIDs, []string{account.ID}) {
		return kaname.ErrSourceUnconfirmed
	}
	accountObject, present, err := parents.captureObjectProjection(ctx, domain.ScopeTypeAccountDotted, account.ID)
	if err != nil {
		return err
	}
	if !present || !slices.Equal(accountObject.ParentAccountIDs, []string{account.ID}) {
		return kaname.ErrSourceUnconfirmed
	}
	projectSources, err := captureInitialRegistrationAncestorSources(ctx, parents, project)
	if err != nil {
		return err
	}
	accountSources, err := captureInitialRegistrationAncestorSources(ctx, parents, account)
	if err != nil {
		return err
	}
	owningAccount, err := projectSources.hasPointer("account", account)
	if err != nil {
		return err
	}
	if !owningAccount {
		return kaname.ErrSourceUnconfirmed
	}
	toProject := authzmodel.EffectHop{From: rootType, Pointer: "project", To: "project"}
	toAccount := authzmodel.EffectHop{From: "project", Pointer: "account", To: "account"}
	c.image.Ancestors = []granteffect.RegistrationAncestor{
		{Path: []authzmodel.EffectHop{toProject}, Object: projectObject},
		{Path: []authzmodel.EffectHop{toProject, toAccount}, Object: accountObject},
	}
	c.ancestors = []initialRegistrationAncestorSources{projectSources, accountSources}
	projectCluster, err := projectSources.hasPointer("cluster", cluster)
	if err != nil {
		return err
	}
	accountCluster, err := accountSources.hasPointer("cluster", cluster)
	if err != nil {
		return err
	}
	if projectCluster || accountCluster {
		clusterSources, err := captureInitialRegistrationAncestorSources(ctx, parents, cluster)
		if err != nil {
			return err
		}
		c.ancestors = append(c.ancestors, clusterSources)
		clusterObject := domain.MirrorObject{ObjectType: domain.ScopeTypeClusterDotted, ObjectID: cluster.ID}
		if projectCluster {
			c.image.Ancestors = append(c.image.Ancestors, granteffect.RegistrationAncestor{
				Path: []authzmodel.EffectHop{toProject, {From: "project", Pointer: "cluster", To: "cluster"}}, Object: clusterObject,
			})
		}
		if accountCluster {
			c.image.Ancestors = append(c.image.Ancestors, granteffect.RegistrationAncestor{
				Path: []authzmodel.EffectHop{toProject, toAccount, {From: "account", Pointer: "cluster", To: "cluster"}}, Object: clusterObject,
			})
		}
	}
	return nil
}

func captureInitialRegistrationAncestorSources(ctx context.Context, parents *resourceParentCapture, coordinate domain.ScopeAnchor) (initialRegistrationAncestorSources, error) {
	out := initialRegistrationAncestorSources{coordinate: coordinate}
	var err error
	out.facts, err = parents.source.read(ctx, parents.tx, resourceSourceKey{kind: resourceSourcePointerFacts, typ: coordinate.Type, id: coordinate.ID})
	if err != nil {
		return out, err
	}
	out.holders, err = parents.source.read(ctx, parents.tx, resourceSourceKey{kind: resourceSourceFactLedgerHolders, typ: coordinate.Type, id: coordinate.ID})
	if err != nil {
		return out, err
	}
	if coordinate.Type == "cluster" {
		// Raw folded relation facts by themselves are not provenance of
		// cluster grants. Keep their additional holder rows in the census.
		_, err = parents.source.read(ctx, parents.tx, resourceSourceKey{kind: resourceSourceClusterFactHolders, typ: coordinate.Type, id: coordinate.ID})
	}
	return out, err
}

func (s initialRegistrationAncestorSources) hasPointer(relation string, target domain.ScopeAnchor) (bool, error) {
	type fact struct {
		ObjectType string `json:"object_type"`
		ObjectID   string `json:"object_id"`
		Relation   string `json:"relation"`
		Subject    string `json:"subject"`
		Condition  string `json:"condition_name"`
	}
	found := false
	for _, row := range s.facts {
		var f fact
		if json.Unmarshal(row.value, &f) != nil || f.ObjectType != s.coordinate.Type || f.ObjectID != s.coordinate.ID {
			return false, kaname.ErrSourceUnconfirmed
		}
		if f.Relation != relation {
			continue
		}
		if found || f.Condition != "" || f.Subject != target.Type+":"+target.ID {
			return false, kaname.ErrSourceUnconfirmed
		}
		found = true
	}
	return found, nil
}

func captureInitialRegistrationBindings(ctx context.Context, parents *resourceParentCapture, ref domain.ResourceRef, scopes []domain.ScopeAnchor) ([]initialRegistrationBinding, error) {
	ids := make(map[string]bool)
	keys := make([]resourceSourceKey, 0, len(scopes)+2)
	for _, scope := range scopes {
		keys = append(keys, resourceSourceKey{kind: resourceSourceRegistrationScopeBindings, typ: scope.Type, id: scope.ID})
	}
	keys = append(keys,
		resourceSourceKey{kind: resourceSourceRegistrationOtherClusterBindings, typ: "cluster", id: domain.ClusterSingletonID},
		resourceSourceKey{kind: resourceSourceBindingsNamingObject, typ: ref.Type, id: ref.ID},
	)
	for _, key := range keys {
		rows, err := parents.source.read(ctx, parents.tx, key)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			b, err := resourceCapturedBinding(row.value)
			if err != nil {
				return nil, err
			}
			if b.Status.Validate() != nil || !nativeQuestionToken(string(b.ID)) {
				return nil, kaname.ErrSourceUnconfirmed
			}
			if b.Status == domain.AccessBindingStatusRevoked {
				continue
			}
			anchor := scopeAnchorFor(b)
			if b.RevokedAt != nil || b.Scope.ValidateAgainst(anchor.Type, anchor.ID) != nil ||
				key.kind == resourceSourceRegistrationOtherClusterBindings ||
				(key.kind == resourceSourceRegistrationScopeBindings && (anchor.Type != key.typ || anchor.ID != key.id)) {
				return nil, kaname.ErrSourceUnconfirmed
			}
			if !slices.Contains(scopes, anchor) {
				if key.kind == resourceSourceBindingsNamingObject {
					// A names target in another valid scope cannot contain NEW.
					continue
				}
				return nil, kaname.ErrSourceUnconfirmed
			}
			// Collect all authored bindings in scope, including ones without
			// matching materialized selectors. Active explicit role-less
			// producers need a separate provenance path.
			if b.RoleID == "" || b.GrantedRelation != "" {
				return nil, kaname.ErrSourceUnconfirmed
			}
			ids[string(b.ID)] = true
		}
	}
	out := resourceOutputCapture{bindings: make(map[string]domain.AccessBinding), roles: make(map[string]domain.Role)}
	if err := out.captureBindings(ctx, parents, ids); err != nil {
		return nil, err
	}
	bindings := make([]initialRegistrationBinding, 0, len(ids))
	for _, id := range resourceSortedSet(ids) {
		b := out.bindings[id]
		role, found := out.roles[string(b.RoleID)]
		if !found || b.ID == "" || len(b.Subjects) == 0 {
			return nil, kaname.ErrSourceUnconfirmed
		}
		if role.Lifecycle.State == domain.RoleLifecycleWithdrawn {
			continue
		}
		roleRows, err := parents.source.read(ctx, parents.tx, resourceSourceKey{kind: resourceSourceRole, typ: "role", id: string(role.ID)})
		if err != nil {
			return nil, err
		}
		if len(roleRows) != 1 {
			return nil, kaname.ErrSourceUnconfirmed
		}
		authored, err := resourceCapturedRole(roleRows[0].value)
		if err != nil {
			return nil, err
		}
		// Retain both the authored rules and the materializing layout so a
		// projection discrepancy cannot masquerade as no effect on NEW.
		if _, err := parents.source.read(ctx, parents.tx, resourceSourceKey{kind: resourceSourceRoleVerbs, typ: "role", id: string(role.ID)}); err != nil {
			return nil, err
		}
		pending, err := parents.source.read(ctx, parents.tx, resourceSourceKey{kind: resourceSourceRolePendingVerbs, typ: "role", id: string(role.ID)})
		if err != nil {
			return nil, err
		}
		records, err := parents.source.read(ctx, parents.tx, resourceSourceKey{kind: resourceSourceBinding, typ: "binding", id: id})
		if err != nil {
			return nil, err
		}
		var carrier struct {
			Version *int `json:"grant_capability_version"`
		}
		if len(records) != 1 || json.Unmarshal(records[0].value, &carrier) != nil || carrier.Version == nil ||
			(*carrier.Version != 0 && *carrier.Version != 1) ||
			b.RevokedAt != nil || (b.Status != domain.AccessBindingStatusActive && b.Status != domain.AccessBindingStatusPending) ||
			!slices.Contains(scopes, scopeAnchorFor(b)) {
			return nil, kaname.ErrSourceUnconfirmed
		}
		bindings = append(bindings, initialRegistrationBinding{
			binding: granteffect.Binding{SourceID: id, Role: role, Scope: scopeAnchorFor(b), Target: b.Target,
				Subjects: b.Subjects, CapabilityVersion: *carrier.Version},
			authoredRules: authored.Rules, expiresAt: b.ExpiresAt,
			pending: b.Status == domain.AccessBindingStatusPending, projectionPending: len(pending) != 0,
		})
	}
	return bindings, nil
}
