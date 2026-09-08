// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain_test

// structural_tuple_test.go — the shared projection, asserted where it lives.
//
// These triples have two consumers that must never disagree: the outbox emitter
// (access_binding/tuples.go::hierarchyParentTuple, account/create.go,
// project/create.go) writes them to the authorization store, and
// internal/authzcascade supplies the SAME triples as request-scoped facts so the
// super-access cascade resolves without waiting for that write. Because there is one
// function, "do the two agree" is not a question a test has to ask; what a test has
// to pin is the SHAPE, since the store accepts exactly one form per relation and a
// wrong one is rejected at the wire rather than caught here.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

func TestAccessBinding_StructuralParent(t *testing.T) {
	cases := []struct {
		name    string
		binding domain.AccessBinding
		want    domain.StructuralTuple
		wantOK  bool
	}{
		{
			name:    "account scope",
			binding: domain.AccessBinding{ID: "abn-1", ResourceType: "account", ResourceID: "acc-1"},
			want: domain.StructuralTuple{
				User: "account:acc-1", Relation: "account", Object: "iam_access_binding:abn-1"},
			wantOK: true,
		},
		{
			name:    "project scope",
			binding: domain.AccessBinding{ID: "abn-2", ResourceType: "project", ResourceID: "prj-1"},
			want: domain.StructuralTuple{
				User: "project:prj-1", Relation: "project", Object: "iam_access_binding:abn-2"},
			wantOK: true,
		},
		{
			name: "cluster scope resolves against the singleton",
			binding: domain.AccessBinding{
				ID: "abn-3", ResourceType: "cluster", ResourceID: domain.ClusterSingletonID},
			want: domain.StructuralTuple{
				User:     "cluster:" + domain.ClusterSingletonID,
				Relation: "cluster", Object: "iam_access_binding:abn-3"},
			wantOK: true,
		},
		{
			name:    "scope type is case-insensitive",
			binding: domain.AccessBinding{ID: "abn-4", ResourceType: "ACCOUNT", ResourceID: "acc-1"},
			want: domain.StructuralTuple{
				User: "account:acc-1", Relation: "account", Object: "iam_access_binding:abn-4"},
			wantOK: true,
		},
		{
			name: "a non-hierarchy scope is not a parent",
			binding: domain.AccessBinding{
				ID: "abn-5", ResourceType: "compute_instance", ResourceID: "ins-1"},
			wantOK: false,
		},
		{
			// Unreachable through the API; the guard is what keeps a malformed row
			// from becoming a tuple the store rejects and the outbox retries forever.
			name:    "an empty scope id yields nothing rather than an empty object id",
			binding: domain.AccessBinding{ID: "abn-6", ResourceType: "cluster", ResourceID: ""},
			wantOK:  false,
		},
		{
			name:    "no binding id",
			binding: domain.AccessBinding{ResourceType: "account", ResourceID: "acc-1"},
			wantOK:  false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := tc.binding.StructuralParent()
			require.Equal(t, tc.wantOK, ok)
			if tc.wantOK {
				assert.Equal(t, tc.want, got)
			}
		})
	}
}

func TestAccount_StructuralFacts(t *testing.T) {
	got := domain.Account{ID: "acc-1", OwnerUserID: "usr-1"}.StructuralFacts()
	assert.Equal(t, []domain.StructuralTuple{
		{User: "cluster:" + domain.ClusterSingletonID, Relation: "cluster", Object: "account:acc-1"},
		{User: "user:usr-1", Relation: "owner", Object: "account:acc-1"},
	}, got, "an account carries its cluster pointer and its owner — the owner because the "+
		"model reads it as a source of verbs on the account object itself")

	// An owner-less row must not produce an owner tuple with an empty subject.
	got = domain.Account{ID: "acc-1"}.StructuralFacts()
	assert.Equal(t, []domain.StructuralTuple{
		{User: "cluster:" + domain.ClusterSingletonID, Relation: "cluster", Object: "account:acc-1"},
	}, got)

	assert.Nil(t, domain.Account{OwnerUserID: "usr-1"}.StructuralFacts(), "no account id, no facts")
}

func TestProject_StructuralFacts(t *testing.T) {
	got := domain.Project{ID: "prj-1", AccountID: "acc-1"}.StructuralFacts()
	assert.Equal(t, []domain.StructuralTuple{
		{User: "cluster:" + domain.ClusterSingletonID, Relation: "cluster", Object: "project:prj-1"},
		{User: "account:acc-1", Relation: "account", Object: "project:prj-1"},
	}, got, "project.super_admin reads BOTH the account and the cluster pointer")

	got = domain.Project{ID: "prj-1"}.StructuralFacts()
	assert.Equal(t, []domain.StructuralTuple{
		{User: "cluster:" + domain.ClusterSingletonID, Relation: "cluster", Object: "project:prj-1"},
	}, got, "an account-less project must not claim an account")

	assert.Nil(t, domain.Project{AccountID: "acc-1"}.StructuralFacts(), "no project id, no facts")
}

func TestScopedStructuralFacts(t *testing.T) {
	got, ok := domain.AccountScopedStructuralFact("acc-1", "iam_group", "grp-1")
	require.True(t, ok)
	assert.Equal(t, domain.StructuralTuple{
		User: "account:acc-1", Relation: "account", Object: "iam_group:grp-1"}, got)

	// A system role has no owning account. It must not become reachable from ANY
	// account's administrator, so the absence of the column is the absence of the fact.
	_, ok = domain.AccountScopedStructuralFact("", "iam_role", "rol-system")
	assert.False(t, ok, "an object with no owning account must yield no account pointer")

	// Зеркальная половина той же проверки: неполная координата не становится
	// кортежем и на аккаунтной проекции — иначе «пустое поле» превратилось бы в
	// указатель на объект `account:`, достижимый администратором любого аккаунта.
	for _, tc := range [][3]string{{"acc-1", "", "grp-1"}, {"acc-1", "iam_group", ""}} {
		if _, ok := domain.AccountScopedStructuralFact(tc[0], tc[1], tc[2]); ok {
			t.Fatalf("an incomplete coordinate must not become a tuple: %v", tc)
		}
	}
}
