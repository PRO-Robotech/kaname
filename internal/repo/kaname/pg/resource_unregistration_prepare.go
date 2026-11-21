// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"slices"
	"time"

	"github.com/PRO-Robotech/corelib/authz/proxytuple"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/service"
)

type resourcePointerCapture struct {
	tuple               service.RelationTuple
	version             time.Time
	active, versionless bool
}
type resourceUnregisteredObject struct {
	catalog          resourceCatalogRow
	modelType, id    string
	present, dropAll bool
	version          time.Time
	pointers         []resourcePointerCapture
}
type resourceUnregistrationPreparation struct {
	registration *resourceRegistrationPreparation
	root         resourceUnregisteredObject
	descendants  []resourceUnregisteredObject
	withdrawal   *resourceWithdrawalBody
}

// Решение о cascade следует исходу родительского DELETE, вычисленному из RR
// состояния и повторно удостоверяемому до clock. Устаревшее надгробие не
// превращается в снятие потомков. Даже отсутствующий потомок сохраняет свой
// захваченный edge/pointer эффект, но его выдачи компилятор не отзывает.
func prepareResourceUnregistration(ctx context.Context, p *resourceRegistrationPreparation, actor string, facts *catalog.Facts) (*resourceUnregistrationPreparation, error) {
	if p == nil || p.input.Action != kaname.ResourceDecisionUnregister || p.parents == nil {
		return nil, kaname.ErrSourceUnconfirmed
	}
	if p.catalog.live {
		anchors, err := p.parents.pointers(ctx, p.catalog.identity.ObjectType, p.row.ObjectID, p.catalog.policy, false)
		if err != nil {
			return nil, err
		}
		for _, anchor := range anchors {
			h, ok, err := p.parents.auditHierarchy(ctx, anchor)
			if err != nil {
				return nil, err
			}
			if ok {
				p.hierarchies = []domain.ParentHierarchy{h}
				break
			}
		}
	}
	root, err := captureResourceUnregisteredObject(ctx, p.parents, p.catalog, p.input.Mirror.ObjectID)
	if err != nil {
		return nil, err
	}
	if !proxytuple.Hierarchical(proxytuple.Relation(p.input.Tuple.Relation)) {
		owned := false
		for _, pointer := range root.pointers {
			owned = owned || pointer.tuple == p.input.Tuple
		}
		if !owned {
			return nil, authzguard.PermissionDenied()
		}
	}
	active := false
	for _, pointer := range root.pointers {
		active = active || pointer.active
		if pointer.active && pointer.versionless && !p.row.SourceVersion.IsZero() && !pointer.version.Before(p.row.SourceVersion) {
			return nil, authzguard.PermissionDenied()
		}
	}
	root.dropAll = p.row.SourceVersion.IsZero() && active
	deleted := root.present && (root.dropAll || resourceVersionAtMost(root.version, p.row.SourceVersion))
	result := &resourceUnregistrationPreparation{registration: p, root: root}
	// Перечень захватывается и для no-op: входное состояние остаётся тем же
	// полным источником классификации, который будет проверен в RC.
	descendants, err := captureResourceDescendants(ctx, p.parents, p.catalog, root.id)
	if err != nil {
		return nil, err
	}
	keys := []domain.ResourceRef{}
	if deleted {
		keys = append(keys, domain.ResourceRef{Type: p.catalog.identity.Dotted, ID: root.id})
	}
	for _, descendant := range descendants {
		child, err := captureResourceUnregisteredObject(ctx, p.parents, descendant.catalog, descendant.id)
		if err != nil {
			return nil, err
		}
		if child.present != descendant.mirrorPresent {
			return nil, kaname.ErrSourceUnconfirmed
		}
		if !deleted {
			continue
		}
		child.dropAll = true
		result.descendants = append(result.descendants, child)
		if child.present {
			keys = append(keys, domain.ResourceRef{Type: child.catalog.identity.Dotted, ID: child.id})
		}
		if child.present {
			// Это собственные снимаемые регистрации модуля, не foreign carriers.
			if err := p.footprint.addRegistrationScopes(descendant.scopes); err != nil {
				return nil, err
			}
		} else {
			for _, scope := range descendant.scopes {
				if err := p.footprint.addMutationAccount(domain.AccountID(scope.AccountID)); err != nil {
					return nil, err
				}
			}
		}
		if err := p.footprint.addObject(domain.ResourceRef{Type: child.catalog.identity.Dotted, ID: child.id}); err != nil {
			return nil, err
		}
	}
	if len(keys) > 0 {
		result.withdrawal, err = prepareResourceWithdrawalBody(ctx, p, keys, actor, facts)
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

// Ноль — только хранимый -infinity либо явный legacy input, не wall clock.
func resourceVersionAtMost(stored, tombstone time.Time) bool {
	return stored.IsZero() || (!tombstone.IsZero() && !stored.After(tombstone))
}
func resourceStoredVersion(raw json.RawMessage) (time.Time, error) {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return time.Time{}, kaname.ErrSourceUnconfirmed
	}
	if value == "-infinity" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || t.IsZero() {
		return time.Time{}, kaname.ErrSourceUnconfirmed
	}
	return t, nil
}

func captureResourceUnregisteredObject(ctx context.Context, parents *resourceParentCapture, cat resourceCatalogRow, id string) (resourceUnregisteredObject, error) {
	out := resourceUnregisteredObject{catalog: cat, modelType: cat.identity.ObjectType, id: id}
	rows, err := parents.source.read(ctx, parents.tx, resourceSourceKey{kind: resourceSourceMirror, typ: cat.identity.Dotted, id: id})
	if err != nil {
		return out, err
	}
	if len(rows) > 1 {
		return out, kaname.ErrSourceUnconfirmed
	}
	if len(rows) == 1 {
		var row struct {
			Type    string          `json:"object_type"`
			ID      string          `json:"object_id"`
			Version json.RawMessage `json:"source_version"`
		}
		if err = json.Unmarshal(rows[0].value, &row); err != nil {
			return out, err
		}
		if row.Type != cat.identity.Dotted || row.ID != id {
			return out, kaname.ErrSourceUnconfirmed
		}
		out.version, err = resourceStoredVersion(row.Version)
		if err != nil {
			return out, err
		}
		out.present = true
	}
	if _, err = parents.source.read(ctx, parents.tx, resourceSourceKey{kind: resourceSourceParentEdges, typ: out.modelType, id: id}); err != nil {
		return out, err
	}
	if _, err = parents.source.read(ctx, parents.tx, resourceSourceKey{kind: resourceSourcePointerFacts, typ: out.modelType, id: id}); err != nil {
		return out, err
	}
	pointers, err := parents.source.read(ctx, parents.tx, resourceSourceKey{kind: resourceSourceRegistrationPointers, typ: out.modelType, id: id})
	if err != nil {
		return out, err
	}
	for _, captured := range pointers {
		var pointer struct {
			Module      string          `json:"module"`
			Type        string          `json:"object_type"`
			ID          string          `json:"object_id"`
			Relation    string          `json:"relation"`
			Subject     string          `json:"subject"`
			Active      bool            `json:"active"`
			Versionless bool            `json:"versionless"`
			Version     json.RawMessage `json:"source_version"`
		}
		if err = json.Unmarshal(captured.value, &pointer); err != nil {
			return out, err
		}
		if pointer.Type != out.modelType || pointer.ID != id {
			return out, kaname.ErrSourceUnconfirmed
		}
		if pointer.Module != cat.identity.Module {
			continue
		}
		if pointer.Subject == "" || pointer.Relation == "" {
			return out, kaname.ErrSourceUnconfirmed
		}
		version, err := resourceStoredVersion(pointer.Version)
		if err != nil {
			return out, err
		}
		out.pointers = append(out.pointers, resourcePointerCapture{tuple: service.RelationTuple{User: pointer.Subject, Relation: pointer.Relation, Object: out.modelType + ":" + id}, version: version, active: pointer.Active, versionless: pointer.Versionless})
	}
	slices.SortFunc(out.pointers, func(a, b resourcePointerCapture) int {
		if a.tuple.Relation < b.tuple.Relation {
			return -1
		}
		if a.tuple.Relation > b.tuple.Relation {
			return 1
		}
		if a.tuple.User < b.tuple.User {
			return -1
		}
		if a.tuple.User > b.tuple.User {
			return 1
		}
		return 0
	})
	return out, nil
}
