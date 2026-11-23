// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/grpcsrv"
	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/observability/metrics"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/registrationscene"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Публичный Register проходит через настоящую production composition. В FULL
// фикстура не вызывает WithResourceDecisionRunner и не подменяет gate/registrar.
// STAGED сохраняет отдельную поддерживаемую ветку serve, а не превращается в FULL.
func TestResourceStartupCanonicalRegistrationFullAndStaged(t *testing.T) {
	for _, full := range []bool{true, false} {
		name := "STAGED"
		if full {
			name = "FULL"
		}
		t.Run(name, func(t *testing.T) {
			cfg := fullStartupCompositionConfig(t)
			ctx, owner, _, logger := bootRolesOnLiveBase(t)
			scene := registrationscene.Seed(t, ctx, owner)
			roster := testModuleRoster()
			privileged := kanamepg.New(owner, nil)
			writer, err := privileged.Writer(ctx)
			require.NoError(t, err)
			defer func() { _ = writer.Rollback(ctx) }()
			_, err = writer.ServiceAccountsW().Insert(ctx, domain.ServiceAccount{
				ID:        domain.ServiceAccountID(authzguard.ServiceAccountIDForService("vpc")),
				AccountID: domain.AccountID(scene.Account), Name: "kacho-vpc",
			})
			require.NoError(t, err)
			require.NoError(t, writer.Commit(ctx))
			// Штатный план установки создаёт account-scoped writer. Прямых allow
			// facts и заменителя проверки полномочий в этой пробе нет.
			require.NoError(t, seed.ApplyRegistrationAccountWriters(ctx,
				kanamepg.NewRegistrationAccountWriterStore(owner), roster,
				seed.RegistrationWriterPlan{Assignments: []domain.RegistrationAccountWriter{{
					AssignmentID: "startup-resource-vpc", AccountID: scene.Account, Module: "vpc",
				}}}))
			runtime := fullStartupRuntimePool(t, ctx, owner)
			runtime, queryTrace := resourceStartupObservedPool(t, ctx, runtime)
			model, bundle := fullStartupTestBundle(t, ctx, owner)
			cfg.AuthorityProtocol = config.AuthorityProtocolConfig{Participation: "participant", FullSemantics: full}
			if full {
				require.NoError(t, privileged.StageFullAuthorityBundle(ctx, bundle))
				require.NoError(t, privileged.ActivateFullAuthorityBundle(ctx, bundle))
			} else {
				require.NoError(t, privileged.PrepareAuthorityBundle(ctx, bundle))
				require.NoError(t, privileged.ActivateAuthorityBundle(ctx, bundle))
			}
			ctx, profile, err := prepareFullStartup(ctx, cfg, runtime, logger)
			require.NoError(t, err)
			repo := kanamepg.New(runtime, nil)
			if full {
				require.NotNil(t, profile)
				repo = profile.primary
			} else {
				require.Nil(t, profile)
			}
			halves, err := kanamepg.NewCatalogRepo(runtime).ReadCatalogHalves(ctx)
			require.NoError(t, err)
			facts, err := catalog.NewFacts(halves)
			require.NoError(t, err)
			ops := operations.NewRepo(runtime, "kaname")
			operations.Start()
			svcs := buildServices(runtime, nil, ops, repo, repo, catalog.Fixed{F: facts},
				kanamepg.NewCatalogRepo(runtime), metrics.NewRegistry(), cfg, roster, nil, logger, model.plans)
			if full {
				_, err = wireFullStartupServices(ctx, profile, repo, svcs, runtime)
				require.NoError(t, err)
			} else {
				// Те же существующие вызовы, что participant && fullStartup == nil в serve.
				handed, err := loadGroupParticipationBundle(ctx, cfg.AuthorityProtocol, repo, model)
				require.NoError(t, err)
				resources, err := kanamepg.NewResourceObjectParticipant(ctx, repo, handed)
				require.NoError(t, err)
				beginner, err := resources.RegistrationTxBeginner(runtime)
				require.NoError(t, err)
				objects, err := resources.NewObjectReconciler(logger)
				require.NoError(t, err)
				svcs.resourceRegistrar.WithResourceTxBeginner(beginner)
				require.NoError(t, svcs.bindingReconciler.WithObjectReconciler(objects))
			}
			moduleCtx := grpcsrv.WithCertIdentityIn(ctx, grpcsrv.NewTrustDomain("kacho.cloud"),
				"spiffe://kacho.cloud/ns/kacho/sa/kacho-vpc", true)
			module, err := authzguard.NewRelationWriteGate(nil).WithModuleRoster(roster).Authorize(moduleCtx)
			require.NoError(t, err)
			require.Equal(t, "vpc", module)
			id := ids.NewID("net")
			req := &iamv1.RegisterResourceRequest{SubjectId: "project:" + scene.Project,
				Relation: "project", Object: "vpc_network:" + id,
				ParentProjectId: scene.Project, ParentAccountId: scene.Account,
				ParentChain: scene.ProjectChain(), SourceVersion: timestamppb.New(time.Now().UTC())}
			// Метка наблюдения не меняет сертификат, gate, deadline или публичный вызов.
			moduleCtx = context.WithValue(moduleCtx, resourceStartupTraceScope{}, queryTrace)
			response, err := svcs.internalIAMHandler.RegisterResource(moduleCtx, req)
			queryTrace.report(t)
			require.NoError(t, err, "канонический RegisterResource через production %s", name)
			require.NotNil(t, response)
			var mirror, retained, fact bool
			require.NoError(t, runtime.QueryRow(ctx, `SELECT
 EXISTS(SELECT 1 FROM kaname.resource_mirror WHERE object_type='vpc.network' AND object_id=$1),
 EXISTS(SELECT 1 FROM kaname.resource_registration_scope WHERE object_type='vpc_network' AND object_id=$1 AND project_id=$2 AND account_id=$3),
 EXISTS(SELECT 1 FROM kaname.relation_fact WHERE object_type='vpc_network' AND object_id=$1 AND relation='project' AND subject=$4)`,
				id, scene.Project, scene.Account, "project:"+scene.Project).Scan(&mirror, &retained, &fact))
			require.True(t, mirror, "успех имеет durable зеркало")
			require.True(t, retained, "сохранена каноническая область")
			require.True(t, fact, "зафиксирован канонический родитель")

			// Тип без childRegistration сохраняет прежний цикл записи и снятия.
			removed, err := svcs.internalIAMHandler.UnregisterResource(moduleCtx, &iamv1.UnregisterResourceRequest{
				SubjectId: req.SubjectId, Relation: req.Relation, Object: req.Object,
				SourceVersion: timestamppb.New(req.SourceVersion.AsTime().Add(time.Microsecond)),
			})
			require.NoError(t, err, "канонический UnregisterResource через production %s", name)
			require.NotNil(t, removed)
			require.NoError(t, runtime.QueryRow(ctx, `SELECT
 EXISTS(SELECT 1 FROM kaname.resource_mirror WHERE object_type='vpc.network' AND object_id=$1),
 EXISTS(SELECT 1 FROM kaname.resource_registration_scope WHERE object_type='vpc_network' AND object_id=$1 AND project_id=$2 AND account_id=$3),
 EXISTS(SELECT 1 FROM kaname.relation_fact WHERE object_type='vpc_network' AND object_id=$1 AND relation='project' AND subject=$4)`,
				id, scene.Project, scene.Account, "project:"+scene.Project).Scan(&mirror, &retained, &fact))
			require.False(t, mirror)
			require.True(t, retained, "снятие сохраняет каноническую область для поздних событий")
			require.False(t, fact)
		})
	}
}
