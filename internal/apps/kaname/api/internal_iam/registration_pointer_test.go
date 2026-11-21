// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

import (
	"context"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/authz/proxytuple"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/testsupport/registrationwriterfixture"
)

func TestNamedPointer_ShapeDefersOnlyCatalogDecision(t *testing.T) {
	require.NoError(t, validateRegistrationShape("probemod", "probemod_box:b1", "box", "probemod_item:i1"))
	require.NoError(t, validateRegistrationShape("probemod", "project:p1", "workspace", "probemod_item:i1"))
	for _, tc := range []struct{ name, module, subject, relation, object string }{
		{"no-actor", "", "probemod_box:b1", "box", "probemod_item:i1"},
		{"wildcard", "probemod", "probemod_box:*", "box", "probemod_item:i1"},
		{"class", "probemod", "system_class:anonymous", "box", "probemod_item:i1"},
		{"bad-relation", "probemod", "probemod_box:b1", "b*", "probemod_item:i1"},
		{"bad-subject", "probemod", "probemod_box:b1#member", "box", "probemod_item:i1"},
		{"closed-publication", "probemod", "system_class:anonymous", "v_get", "probemod_item:i1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Error(t, validateRegistrationShape(tc.module, tc.subject, tc.relation, tc.object))
		})
	}
	for _, typ := range proxytuple.ForbiddenObjectTypes() {
		t.Run("object-"+typ, func(t *testing.T) {
			require.Error(t, validateRegistrationShape("probemod", "probemod_box:b1", "box", typ+":id"))
		})
		if typ != "project" {
			require.False(t, namedPointerSubjectType(typ), typ)
			require.Error(t, validateRegistrationShape("probemod", typ+":id", "box", "probemod_item:i1"))
		}
	}
	require.True(t, namedPointerSubjectType("project"))
	require.True(t, namedPointerSubjectType("probemod_box"))
}

type pointerScopeProbe struct {
	sceneScopes
	owner string
	tuple service.RelationTuple
	saves int
	tx    service.Tx
}

func (s *pointerScopeProbe) SaveRegistrationPointerTx(_ context.Context, tx service.Tx, owner string, tuple service.RelationTuple, _ time.Time) (bool, error) {
	s.owner, s.tuple, s.tx = owner, tuple, tx
	s.saves++
	return true, nil
}

func (*pointerScopeProbe) RegistrationPointersTx(context.Context, service.Tx, string, string) ([]service.RelationTuple, error) {
	panic("unexpected pointer read in registration probe")
}

func (*pointerScopeProbe) RetireRegistrationPointersTx(context.Context, service.Tx, string, string, time.Time) error {
	panic("unexpected pointer retirement in registration probe")
}

func (*pointerScopeProbe) PrepareRegistrationWithdrawalTx(context.Context, service.Tx, string, string, time.Time) (bool, bool, error) {
	panic("unexpected withdrawal in registration probe")
}

func (*pointerScopeProbe) RetireDescendantRegistrationPointersTx(context.Context, service.Tx, string, string, time.Time) ([]service.VersionedRelationTuple, error) {
	panic("unexpected descendant retirement in registration probe")
}

// Родитель имеет собственную текущую политику и owning строку проекта.
type namedParentCatalog struct{ *ownerCatalog }

func (c namedParentCatalog) WritePolicyTx(ctx context.Context, tx service.Tx, typ string) (string, domain.WritePolicy, bool, error) {
	if typ == "probemod_box" {
		c.policyReads++
		return "probemod.boxes", domain.WritePolicy{ObjectType: typ, Module: "probemod", Pointers: []domain.ParentPointer{{Name: "project", Type: "project"}}}, true, nil
	}
	return c.ownerCatalog.WritePolicyTx(ctx, tx, typ)
}

func TestNamedPointerLawfulDynamicAndProjectParentsReachWrite(t *testing.T) {
	for _, tc := range []struct{ name, subject, relation, parentType string }{
		{"container", "probemod_box:b1", "box", "probemod_box"},
		{"project", "project:" + unitProject, "workspace", "project"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			catalog := &ownerCatalog{typ: "probemod_item", owner: "probemod", live: true, known: true,
				pointers: []domain.ParentPointer{{Name: tc.relation, Type: tc.parentType}}}
			scopes := &pointerScopeProbe{sceneScopes: unitScopes()}
			scopes.containers["probemod_box:b1"] = domain.ContainerScope{Registered: true, ProjectID: unitProject, AccountID: unitAccount}
			scopes.pointers["probemod_box:b1"] = []string{"project:" + unitProject}
			txb := &smTxBeginner{}
			mirror := newMirrorSpy()
			emitter := &countingEmitter{}
			uc := NewRegisterResourceUseCase(emitter, mirror, txb, namedParentCatalog{catalog}, &recordingPublisher{}, &recordingWithdrawal{}, noAudit{}, scopes).
				WithRegistrationAuthority(registrationwriterfixture.Authority{Module: "probemod"})
			req := &regReq{subject: tc.subject, relation: tc.relation, object: "probemod_item:i1"}
			require.NoError(t, uc.Register(context.Background(), req))
			require.True(t, txb.tx.committed)
			wantReads := 1
			if tc.parentType == "probemod_box" {
				wantReads++
			}
			require.Equal(t, wantReads, catalog.policyReads)
			require.Equal(t, 1, mirror.upserts)
			require.Equal(t, 1, emitter.writes)
			require.Equal(t, 1, scopes.saves)
			require.Equal(t, "probemod", scopes.owner)
			require.Equal(t, service.RelationTuple{User: tc.subject, Relation: tc.relation, Object: req.object}, scopes.tuple)
			require.Same(t, txb.tx, scopes.tx)
		})
	}
}

func TestNamedPointerUnknownResourceKeepsObjectFieldDiagnostic(t *testing.T) {
	catalog := &ownerCatalog{}
	txb := &smTxBeginner{}
	mirror := newMirrorSpy()
	emitter := &countingEmitter{}
	uc := NewRegisterResourceUseCase(emitter, mirror, txb, catalog, &recordingPublisher{}, &recordingWithdrawal{}, noAudit{}, unitScopes()).
		WithRegistrationAuthority(registrationwriterfixture.Authority{Module: "probemod"})
	err := uc.Register(context.Background(), &regReq{subject: "probemod_box:b1", relation: "box", object: "probemod_unknown:i1"})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.NotNil(t, txb.tx)
	require.False(t, txb.tx.committed)
	var fields []string
	for _, detail := range status.Convert(err).Details() {
		if bad, ok := detail.(*errdetails.BadRequest); ok {
			for _, field := range bad.GetFieldViolations() {
				fields = append(fields, field.GetField())
			}
		}
	}
	require.Equal(t, []string{"object"}, fields)
	require.Zero(t, mirror.upserts)
	require.Zero(t, emitter.writes)
}

func TestNamedPointer_DoesNotExpandSharedProxyPolicy(t *testing.T) {
	require.Error(t, validateProxyTuple("probemod", "probemod_box:b1", "box", "probemod_item:i1"))
	require.False(t, proxytuple.IsProxyWritable("probemod_box:b1", "box"))
}
