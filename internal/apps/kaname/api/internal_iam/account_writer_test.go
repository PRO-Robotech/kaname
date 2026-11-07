// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package internal_iam

import (
	"context"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"testing"
	"time"
)

type awAuthority struct {
	module  string
	allowed map[string]bool
	calls   []string
	err     error
}

func (a *awAuthority) Authorize(context.Context) (string, error) {
	if a.module == "" {
		return "", proxyWriteRefusal()
	}
	return a.module, nil
}
func (a *awAuthority) AuthorizeCatalogModule(ctx context.Context) (string, error) {
	return a.Authorize(ctx)
}
func (a *awAuthority) AuthorizeAccount(_ context.Context, id string) error {
	a.calls = append(a.calls, id)
	if a.err != nil {
		return a.err
	}
	if !a.allowed[id] {
		return proxyWriteRefusal()
	}
	return nil
}
func TestAccountWriter_AllDistinctAdmittedAccountsRequired(t *testing.T) {
	a := &awAuthority{module: "registry", allowed: map[string]bool{"A": true}}
	uc := (&RegisterResourceUseCase{}).WithRegistrationAuthority(a)
	hs := []domain.ContainerScope{{Registered: true, ProjectID: "PA", AccountID: "A"}, {Registered: true, ProjectID: "PA2", AccountID: "A"}, {Registered: true, ProjectID: "PB", AccountID: "B"}}
	err := uc.authorizeScopes(context.Background(), hs)
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	require.Equal(t, []string{"A", "B"}, a.calls)
	a.calls = nil
	a.allowed["B"] = true
	require.NoError(t, uc.authorizeScopes(context.Background(), hs))
	require.Equal(t, []string{"A", "B"}, a.calls)
	a.calls = nil
	require.Equal(t, codes.PermissionDenied, status.Code(uc.authorizeScopes(context.Background(), []domain.ContainerScope{{}})))
	require.Empty(t, a.calls)
}
func TestAccountWriter_PrivateWriterBranchesCannotBypassAuthority(t *testing.T) {
	uc := &RegisterResourceUseCase{} // Без портов полномочий, транзакции и записи.
	ctx := context.Background()
	tu := tupleIntent{subject: "project:P", relation: "project", object: "registry_registry:object"}
	_, _, _, err := uc.emit(ctx, tu, service.ResourceMirrorRow{}, true)
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	_, _, _, err = uc.emit(ctx, tu, service.ResourceMirrorRow{}, false)
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	tu = tupleIntent{subject: "system_class:anonymous", relation: "v_get", object: "registry_repository:object/app"}
	for _, published := range []bool{true, false} {
		err = uc.publish(ctx, tu, published, time.Time{})
		require.Equal(t, codes.PermissionDenied, status.Code(err))
		require.Equal(t, "permission denied", status.Convert(err).Message())
	}
}

// Канонический аккаунт реестра — лишь полномочия. Он не должен расширять H,
// используемую при проверке заявленных данных, а успешный путь известного проекта не добавляет чтений.
type awSavedScopeProbe struct {
	sceneScopes
	reads  []string
	scopes []domain.ContainerScope
}

func (p *awSavedScopeProbe) SavedRegistrationScopesTx(_ context.Context, _ service.Tx, typ, id string) ([]domain.ContainerScope, error) {
	p.reads = append(p.reads, typ+":"+id)
	return p.scopes, nil
}
func TestAccountWriter_ProjectedHierarchyAndSavedAuthorityStaySeparate(t *testing.T) {
	ctx := context.Background()
	reader := &awSavedScopeProbe{scopes: []domain.ContainerScope{
		{Registered: true, ProjectID: "PA", AccountID: "A"}, {Registered: true, ProjectID: "PB", AccountID: "B"},
	}}
	auth := &awAuthority{module: "registry", allowed: map[string]bool{"A": true}}
	uc := (&RegisterResourceUseCase{scopes: reader}).WithRegistrationAuthority(auth)
	h := domain.ParentHierarchy{Links: []string{"registry_registry:K"}}
	scopes, err := uc.registrationAuthorities(ctx, nil, []domain.ParentHierarchy{h, h})
	require.NoError(t, err)
	require.Equal(t, []string{"registry_registry:K"}, reader.reads)
	require.Empty(t, h.ProjectID)
	require.Empty(t, h.AccountID)
	require.Equal(t, []string{"registry_registry:K"}, h.Links)
	require.Equal(t, codes.PermissionDenied, status.Code(uc.authorizeScopes(ctx, scopes)))
	require.Equal(t, []string{"A", "B"}, auth.calls)
	reader.reads = nil
	known := domain.ProjectHierarchy("PA", "A")
	scopes, err = uc.registrationAuthorities(ctx, nil, []domain.ParentHierarchy{known})
	require.NoError(t, err)
	require.Empty(t, reader.reads, "known hierarchy reuses its canonical read")
	require.Equal(t, []domain.ContainerScope{{Registered: true, ProjectID: "PA", AccountID: "A"}}, scopes)
}
