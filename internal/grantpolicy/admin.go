// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package grantpolicy

import (
	"context"
	"slices"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantcoverage"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

type scopeObject struct {
	anchor  domain.ScopeAnchor
	account domain.AccountID
	labels  domain.Labels
}

func scopeObjects(ctx context.Context, w kaname.SemanticAuthorityWriter, scope domain.ScopeAnchor) (map[string]scopeObject, error) {
	out := map[string]scopeObject{"cluster": {anchor: domain.ScopeAnchor{Type: "cluster", ID: domain.ClusterSingletonID}}}
	var account domain.AccountID
	switch scope.Type {
	case "cluster":
		if scope.ID != domain.ClusterSingletonID {
			return nil, denied()
		}
	case "account":
		account = domain.AccountID(scope.ID)
	case "project":
		p, e := w.Projects().Get(ctx, domain.ProjectID(scope.ID))
		if e != nil {
			return nil, e
		}
		account = p.AccountID
		out["project"] = scopeObject{anchor: scope, account: account, labels: p.Labels}
	default:
		return nil, denied()
	}
	if account != "" {
		a, e := w.Accounts().Get(ctx, account)
		if e != nil {
			return nil, e
		}
		out["account"] = scopeObject{anchor: domain.ScopeAnchor{Type: "account", ID: string(a.ID)}, account: a.ID, labels: a.Labels}
	}
	return out, nil
}

// административный источник читается до mutation. Native bool сам по себе
// недостаточен: ему нужен живой canonical source либо complete compiler witness.
func administrative(ctx context.Context, w kaname.SemanticAuthorityWriter, p WitnessedLowerBound, scope domain.ScopeAnchor) (bool, error) {
	if !p.valid(w) {
		return false, unavailable()
	}
	objects, err := scopeObjects(ctx, w, scope)
	if err != nil {
		return false, err
	}
	for _, s := range p.census.Structural.Direct {
		if s.SourceKind == kaname.CanonicalClusterAdmin {
			ok, e := check(ctx, w, p.census.Actor, "system_admin", "cluster:"+domain.ClusterSingletonID)
			if e != nil || ok {
				return ok, e
			}
		}
		if s.SourceKind == kaname.CanonicalAccountOwner && scope.Type != "cluster" && objects["account"].anchor.ID == s.ObjectID {
			// accounts.owner_user_id — самостоятельный действующий bootstrap producer.
			// Admission уже выполнен на этой TX; отсутствие derived native tuple не
			// отменяет owner contract и не создаёт новый независимый вечный факт.
			return true, nil
		}
	}
	witnessed := false
	for _, effect := range append(p.effects.Effects(), p.admin...) {
		if effect.Kind != granteffect.ScopeAdmin || effect.Type != scope.Type || effect.Condition.Name != "" || effect.Condition.Parameters != "" {
			continue
		}
		if scopeEffectMatches(effect, scope, objects) {
			witnessed = true
			break
		}
	}
	if !witnessed {
		return false, nil
	}
	return check(ctx, w, p.census.Actor, "admin", scope.Type+":"+scope.ID)
}

// Только объявленные структурные шаги scope→account→cluster; произвольное
// отношение, creator или неизвестный путь не подменяется совпадением ID.
func scopeEffectMatches(e granteffect.Effect, scope domain.ScopeAnchor, objects map[string]scopeObject) bool {
	for _, c := range e.Constraints {
		typ := scope.Type
		for _, hop := range c.Path {
			if hop.From != typ || !((typ == "project" && hop.To == "account" && hop.Pointer == "account") || ((typ == "project" || typ == "account") && hop.To == "cluster" && hop.Pointer == "cluster")) {
				return false
			}
			typ = hop.To
		}
		o, ok := objects[typ]
		if !ok || c.Type != typ {
			return false
		}
		if c.Within != nil {
			parent, ok := objects[c.Within.Type]
			if !ok || parent.anchor != *c.Within {
				return false
			}
		}
		switch c.Region.Objects.Kind {
		case grantcoverage.AllObjects:
		case grantcoverage.ObjectIDs:
			if !slices.Contains(c.Region.Objects.IDs, o.anchor.ID) {
				return false
			}
		default:
			return false
		}
		if c.Region.Creator.Kind != grantcoverage.AnyCreator {
			return false
		}
		for k, v := range c.Region.Labels {
			if got, ok := o.labels[domain.LabelKey(k)]; !ok || got != domain.LabelVal(v) {
				return false
			}
		}
	}
	return len(e.Constraints) > 0
}
