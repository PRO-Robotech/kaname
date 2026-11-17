// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/observability/metrics"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
)

// Здесь нет ручных With...Writer: все семь actual handlers получают ports
// только из production buildServices → wireFullStartupServices.
func TestFullStartupAllSevenCRUDHandlersUsePreparedProductionPorts(t *testing.T) {
	cfg := fullStartupCompositionConfig(t)
	ctx, owner, _, logger := bootRolesOnLiveBase(t)
	actor, _ := fullStartupSeedPerson(t, ctx, owner, "seven-crud-owner")
	runtime := fullStartupRuntimePool(t, ctx, owner)
	model, bundle := fullStartupTestBundle(t, ctx, owner)
	privileged := kanamepg.New(owner, nil)
	require.NoError(t, privileged.StageFullAuthorityBundle(ctx, bundle))
	require.NoError(t, privileged.ActivateFullAuthorityBundle(ctx, bundle))
	cfg.AuthorityProtocol = config.AuthorityProtocolConfig{Participation: "participant", FullSemantics: true}
	ctx, profile, err := prepareFullStartup(ctx, cfg, runtime, logger)
	require.NoError(t, err)
	require.NotNil(t, profile)
	halves, err := kanamepg.NewCatalogRepo(runtime).ReadCatalogHalves(ctx)
	require.NoError(t, err)
	facts, err := catalog.NewFacts(halves)
	require.NoError(t, err)
	ops := operations.NewRepo(runtime, "kaname")
	operations.Start()
	svcs := buildServices(runtime, nil, ops, profile.primary, profile.primary, catalog.Fixed{F: facts}, kanamepg.NewCatalogRepo(runtime), metrics.NewRegistry(), cfg, testModuleRoster(), nil, logger, model.plans)
	_, err = wireFullStartupServices(ctx, profile, profile.primary, svcs, runtime)
	require.NoError(t, err)
	as := func() context.Context {
		return operations.WithPrincipal(ctx, operations.Principal{Type: "user", ID: actor})
	}
	created, err := svcs.accountHandler.Create(as(), &iamv1.CreateAccountRequest{Name: "startup-seven-account"})
	require.NoError(t, err)
	fullStartupAwait(t, ctx, ops, created.GetId())
	var account iamv1.CreateAccountMetadata
	require.NoError(t, created.GetMetadata().UnmarshalTo(&account))
	require.NotEmpty(t, account.GetAccountId())
	require.NotEmpty(t, account.GetDefaultProjectId())
	projectOp, err := svcs.projectHandler.Create(as(), &iamv1.CreateProjectRequest{AccountId: account.GetAccountId(), Name: "startup-seven-project"})
	require.NoError(t, err)
	fullStartupAwait(t, ctx, ops, projectOp.GetId())
	var project iamv1.CreateProjectMetadata
	require.NoError(t, projectOp.GetMetadata().UnmarshalTo(&project))
	require.NotEmpty(t, project.GetProjectId())
	saOp, err := svcs.serviceAccountHandler.Create(as(), &iamv1.CreateServiceAccountRequest{AccountId: account.GetAccountId(), Name: "startup-seven-sa"})
	require.NoError(t, err)
	fullStartupAwait(t, ctx, ops, saOp.GetId())
	var sa iamv1.CreateServiceAccountMetadata
	require.NoError(t, saOp.GetMetadata().UnmarshalTo(&sa))
	require.NotEmpty(t, sa.GetServiceAccountId())
	roleOp, err := svcs.roleHandler.Create(as(), &iamv1.CreateRoleRequest{Name: "startup_seven_role", DefinitionTier: &iamv1.DefinitionTier{TierType: "iam.account", TierId: account.GetAccountId()}, Rules: []*iamv1.Rule{{Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"}}}})
	require.NoError(t, err)
	fullStartupAwait(t, ctx, ops, roleOp.GetId())
	var role iamv1.CreateRoleMetadata
	require.NoError(t, roleOp.GetMetadata().UnmarshalTo(&role))
	require.NotEmpty(t, role.GetRoleId())
	var saved int
	require.NoError(t, runtime.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM kaname.accounts WHERE id=$1 AND owner_user_id=$5)+
 (SELECT count(*) FROM kaname.projects WHERE id=$2 AND account_id=$1)+
 (SELECT count(*) FROM kaname.service_accounts WHERE id=$3 AND account_id=$1)+
 (SELECT count(*) FROM kaname.roles WHERE id=$4 AND account_id=$1)`, account.GetAccountId(), project.GetProjectId(), sa.GetServiceAccountId(), role.GetRoleId(), actor).Scan(&saved))
	require.Equal(t, 4, saved)
	roleDeleted, err := svcs.roleHandler.Delete(as(), &iamv1.DeleteRoleRequest{RoleId: role.GetRoleId()})
	require.NoError(t, err)
	fullStartupAwait(t, ctx, ops, roleDeleted.GetId())
	saDeleted, err := svcs.serviceAccountHandler.Delete(as(), &iamv1.DeleteServiceAccountRequest{ServiceAccountId: sa.GetServiceAccountId()})
	require.NoError(t, err)
	fullStartupAwait(t, ctx, ops, saDeleted.GetId())
	for _, id := range []string{project.GetProjectId(), account.GetDefaultProjectId()} {
		deleted, e := svcs.projectHandler.Delete(as(), &iamv1.DeleteProjectRequest{ProjectId: id})
		require.NoError(t, e)
		fullStartupAwait(t, ctx, ops, deleted.GetId())
	}
	deleted, err := svcs.accountHandler.Delete(as(), &iamv1.DeleteAccountRequest{AccountId: account.GetAccountId()})
	require.NoError(t, err)
	fullStartupAwait(t, ctx, ops, deleted.GetId())
	require.NoError(t, runtime.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM kaname.accounts WHERE id=$1)+
 (SELECT count(*) FROM kaname.projects WHERE id IN ($2,$5))+
 (SELECT count(*) FROM kaname.service_accounts WHERE id=$3)+
 (SELECT count(*) FROM kaname.roles WHERE id=$4)+
 (SELECT count(*) FROM kaname.access_bindings WHERE resource_id=$1 OR role_id=$4)`, account.GetAccountId(), project.GetProjectId(), sa.GetServiceAccountId(), role.GetRoleId(), account.GetDefaultProjectId()).Scan(&saved))
	require.Zero(t, saved)
	// Удаления не уничтожают человека; source actor остаётся реальным.
	var person bool
	require.NoError(t, runtime.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM kaname.users WHERE id=$1)`, actor).Scan(&person))
	require.True(t, person)
}
