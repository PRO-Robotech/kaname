// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

import (
	"context"
	"errors"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/stretchr/testify/require"
)

type parentGraphCatalog struct {
	policies map[string]domain.WritePolicy
	retired  map[string]bool
	txs      []service.Tx
}

func (c *parentGraphCatalog) WritePolicyTx(_ context.Context, tx service.Tx, typ string) (string, domain.WritePolicy, bool, error) {
	c.txs = append(c.txs, tx)
	p, ok := c.policies[typ]
	return typ, p, ok && !c.retired[typ], nil
}
func (*parentGraphCatalog) CatalogTypeTx(context.Context, service.Tx, string) (domain.CatalogTypeIdentity, bool, error) {
	panic("unexpected catalog identity read")
}

type parentGraphScopes struct {
	sceneScopes
	facts        map[string][]string
	txs          []service.Tx
	pointerReads int
	fail         error
}

func (s *parentGraphScopes) ProjectAccountTx(ctx context.Context, tx service.Tx, id string) (string, bool, error) {
	s.txs = append(s.txs, tx)
	return s.sceneScopes.ProjectAccountTx(ctx, tx, id)
}
func (s *parentGraphScopes) ContainerScopeTx(ctx context.Context, tx service.Tx, typ, id string) (domain.ContainerScope, error) {
	s.txs = append(s.txs, tx)
	return s.sceneScopes.ContainerScopeTx(ctx, tx, typ, id)
}
func (s *parentGraphScopes) PointerSubjectsTx(ctx context.Context, tx service.Tx, typ, id string, names []string) ([]string, error) {
	s.txs = append(s.txs, tx)
	s.pointerReads++
	if s.fail != nil {
		return nil, s.fail
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(names) != 1 {
		panic("expected an exact relation")
	}
	return append([]string(nil), s.facts[typ+":"+id+"/"+names[0]]...), nil
}

// Bounded port сохраняет наблюдение точного relation/type, TX и ошибок.
func (s *parentGraphScopes) BoundedPointerSubjectsTx(ctx context.Context, tx service.Tx, typ, id string, names []string) ([]string, error) {
	return s.PointerSubjectsTx(ctx, tx, typ, id, names)
}

func parentGraphUC() (*RegisterResourceUseCase, *parentGraphScopes, *parentGraphCatalog) {
	scope := domain.ContainerScope{Registered: true, ProjectID: "p", AccountID: "a"}
	s := &parentGraphScopes{sceneScopes: sceneScopes{projects: map[string]string{"p": "a"}, containers: map[string]domain.ContainerScope{"probemod_item:i": scope, "probemod_box:b": scope}}, facts: map[string][]string{"probemod_item:i/box": {"probemod_box:b"}, "probemod_box:b/project": {"project:p"}}}
	c := &parentGraphCatalog{policies: map[string]domain.WritePolicy{
		"probemod_item": {ObjectType: "probemod_item", Pointers: []domain.ParentPointer{{Name: "box", Type: "probemod_box"}}},
		"probemod_box":  {ObjectType: "probemod_box", Pointers: []domain.ParentPointer{{Name: "project", Type: "project"}}},
	}}
	return &RegisterResourceUseCase{scopes: s, catalogTypes: c}, s, c
}
func tagParentPolicy() domain.WritePolicy {
	return domain.WritePolicy{ObjectType: "probemod_tag", Pointers: []domain.ParentPointer{{Name: "item", Type: "probemod_item"}}}
}

func TestDeriveParentCanonicalFullChainUsesOneTx(t *testing.T) {
	uc, s, c := parentGraphUC()
	tx := &smTx{}
	want := []string{"probemod_item:i", "probemod_box:b", "project:p", "account:a"}
	hs, err := uc.deriveParent(context.Background(), tx, tupleIntent{subject: "probemod_item:i", relation: "item", object: "probemod_tag:t"}, tagParentPolicy(), domain.ParentClaim{ProjectID: "p", AccountID: "a", Chain: want})
	require.NoError(t, err)
	require.Equal(t, []domain.ParentHierarchy{{Links: want, ProjectID: "p", AccountID: "a"}}, hs)
	require.Equal(t, 2, s.pointerReads)
	require.Len(t, c.txs, 2)
	for _, got := range append(s.txs, c.txs...) {
		require.Same(t, tx, got)
	}
	_, err = uc.deriveParent(context.Background(), tx, tupleIntent{subject: "probemod_item:i", relation: "item", object: "probemod_tag:t"}, tagParentPolicy(), domain.ParentClaim{Chain: []string{"probemod_item:i", "probemod_box:forged", "project:p", "account:a"}})
	require.ErrorIs(t, err, iamerr.ErrParentScopeMismatch)
}

func TestDeriveParentIncompleteOrWrongTypedFactsNeverAdmit(t *testing.T) {
	backend := errors.New("reader failed")
	for _, tc := range []struct {
		name   string
		change func(*parentGraphScopes)
		want   error
	}{
		{"missing_fact", func(s *parentGraphScopes) { delete(s.facts, "probemod_item:i/box") }, iamerr.ErrParentScopeMismatch},
		{"wrong_pointer_type", func(s *parentGraphScopes) { s.facts["probemod_item:i/box"] = []string{"project:p"} }, iamerr.ErrParentScopeMismatch},
		{"missing_parent", func(s *parentGraphScopes) { delete(s.containers, "probemod_box:b") }, iamerr.ErrParentScopeMismatch},
		{"fifth_fact", func(s *parentGraphScopes) {
			s.facts["probemod_item:i/box"] = []string{"probemod_box:b", "probemod_box:c", "probemod_box:d", "probemod_box:e", "probemod_box:f"}
		}, iamerr.ErrParentScopeMismatch},
		{"backend_error", func(s *parentGraphScopes) { s.fail = backend }, backend},
		{"cancelled", func(s *parentGraphScopes) { s.fail = context.Canceled }, context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			uc, s, _ := parentGraphUC()
			tc.change(s)
			hs, err := uc.deriveParent(context.Background(), &smTx{}, tupleIntent{subject: "probemod_item:i", relation: "item", object: "probemod_tag:t"}, tagParentPolicy(), domain.ParentClaim{})
			require.ErrorIs(t, err, tc.want)
			require.Nil(t, hs)
		})
	}
}

func TestDeriveParentDP14DoesNotReadBeyondSavedScope(t *testing.T) {
	uc, s, c := parentGraphUC()
	s.containers["probemod_item:i"] = domain.ContainerScope{Registered: true}
	s.fail = errors.New("pointer graph must not be read")
	intent := tupleIntent{subject: "probemod_item:i", relation: "item", object: "probemod_tag:t"}
	hs, err := uc.deriveParent(context.Background(), &smTx{}, intent, tagParentPolicy(), domain.ParentClaim{Chain: []string{"probemod_item:i"}})
	require.NoError(t, err)
	require.Equal(t, []domain.ParentHierarchy{{Links: []string{"probemod_item:i"}}}, hs)
	require.Zero(t, s.pointerReads)
	require.Empty(t, c.txs)
	hs, err = uc.deriveParent(context.Background(), &smTx{}, intent, tagParentPolicy(), domain.ParentClaim{Chain: []string{"probemod_item:i", "project:p"}})
	require.ErrorIs(t, err, iamerr.ErrParentScopeMismatch)
	require.Nil(t, hs)
}

func TestDeriveParentReadBudgetStopsBeforeAnotherPage(t *testing.T) {
	uc, s, c := parentGraphUC()
	_, err := uc.parentPointerSubjects(context.Background(), &smTx{}, "probemod_item", "i", c.policies["probemod_item"], &parentHierarchyReadBudget{reads: domain.MaxParentHierarchyReads})
	require.ErrorIs(t, err, domain.ErrParentHierarchyInvalid)
	require.Zero(t, s.pointerReads)
}

// Оба исторических вызывающих — Unregister и RecordRefusal — используют этот
// audit helper с admittedWrite=false. Его сокращённый H не участвует в Register.
func TestDeriveParentCleanupAuditDoesNotRequireParentPolicy(t *testing.T) {
	for _, name := range []string{"retired_parent_policy", "absent_parent_policy"} {
		t.Run(name, func(t *testing.T) {
			uc, s, c := parentGraphUC()
			c.policies["probemod_tag"] = tagParentPolicy()
			if name == "retired_parent_policy" {
				c.retired = map[string]bool{"probemod_item": true}
			} else {
				delete(c.policies, "probemod_item")
			}
			s.facts["probemod_tag:t/item"] = []string{"probemod_item:i"}
			intent := tupleIntent{subject: "probemod_item:i", relation: "item", object: "probemod_tag:t"}
			tx := &smTx{}
			h, err := uc.registrationHierarchy(context.Background(), tx, intent, false)
			require.NoError(t, err)
			require.Equal(t, domain.ParentHierarchy{Links: []string{"probemod_item:i", "project:p", "account:a"}, ProjectID: "p", AccountID: "a"}, h)
			require.Len(t, c.txs, 1, "cleanup читает лишь политику самого снимаемого объекта")
			hs, err := uc.deriveParent(context.Background(), tx, intent, tagParentPolicy(), domain.ParentClaim{})
			require.ErrorIs(t, err, iamerr.ErrParentScopeMismatch, "новая регистрация с тем же неполным parent source закрыта")
			require.Nil(t, hs)
		})
	}
}

// Обёртка намеренно экспортирует только прежний scope contract: нельзя молча
// перейти к неограниченному reader при отсутствии нового admission port.
type legacyParentScopesOnly struct{ registrationScopeReader }

func TestDeriveParentMissingBoundedReaderFailsClosed(t *testing.T) {
	uc, scopes, catalog := parentGraphUC()
	uc.scopes = legacyParentScopesOnly{registrationScopeReader: scopes}
	hs, err := uc.deriveParent(context.Background(), &smTx{}, tupleIntent{subject: "probemod_item:i", relation: "item", object: "probemod_tag:t"}, tagParentPolicy(), domain.ParentClaim{})
	require.ErrorIs(t, err, iamerr.ErrParentScopeMismatch)
	require.Nil(t, hs)
	require.Zero(t, scopes.pointerReads, "старый unbounded reader не является fallback")
	require.Empty(t, catalog.txs)
}
