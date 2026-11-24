// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	authorizeapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/authorize"
	moduleapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/module"
	permissioncatalogapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/permission_catalog"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/authzcascade"
	"github.com/PRO-Robotech/kaname/internal/authzsnapshot"
	"github.com/PRO-Robotech/kaname/internal/callerorigin"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/personmarks"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/service"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

const replicaPublicationDocument = `apiVersion: iam/v1
module: erp
revision: 1
resources:
  - name: contract
    objectType: erp_contract_item
    parents: [project]
    producer: authored
    verbs:
      - get
      - {name: sign, class: update}
`

type publicationReplica struct {
	profile     *publishedStartupProfile
	server      *grpc.Server
	conn        *grpc.ClientConn
	publication iamv1.CatalogPublicationServiceClient
	catalog     iamv1.PermissionCatalogServiceClient
}

// У каждого экземпляра своя роль LOGIN, поколение писателя, фоновое обновление
// снимка и сервер gRPC. Фикстура подаёт уже подтверждённую личность. TLS, Bearer
// и два независимых системных процесса проверяются отдельно.
func startPublicationReplica(t *testing.T, ctx context.Context, owner *pgxpool.Pool, logger *slog.Logger, operator, reader string) *publicationReplica {
	t.Helper()
	runtime := fullStartupRuntimePool(t, ctx, owner)
	cfg := config.Config{AuthorityProtocol: config.AuthorityProtocolConfig{Participation: "participant", FullSemantics: true}}
	_, startup, err := prepareFullStartup(ctx, cfg, runtime, logger)
	require.NoError(t, err)
	require.NotNil(t, startup.publication)
	profile := startup.publication
	checker := authzcascade.WrapAdmitted(relverdict.NewAsker(runtime), personmarks.New(runtime))
	uc, err := moduleapp.NewPublicationUseCase(profile.store, profile.writers, checker, operations.NewRepo(runtime, "kaname"), 2*1024*1024, logger)
	require.NoError(t, err)
	pin, err := authorizeapp.PublicationUnary(profile.store)
	require.NoError(t, err)
	verifiedCredentialFixture := func(ctx context.Context, req any, info *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		identity := md.Get("test-verified-identity")
		if len(identity) == 1 && (identity[0] == operator || identity[0] == reader) {
			ctx = operations.WithPrincipal(ctx, operations.Principal{Type: "user", ID: identity[0]})
			ctx = callerorigin.With(ctx, callerorigin.PresentedCredential)
			ctx = callerorigin.WithAssurance(ctx, "2")
		}
		return next(ctx, req)
	}
	server := grpc.NewServer(grpc.ChainUnaryInterceptor(verifiedCredentialFixture, pin))
	registerPublicServices(server, &services{
		catalogPublicationHandler: moduleapp.NewPublicationHandler(uc),
		permissionCatalogHandler:  permissioncatalogapp.NewHandler(permissioncatalogapp.NewListPermissionCatalogUseCase(nil)),
	}, nil)
	listener := bufconn.Listen(1024 * 1024)
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()
	conn, err := grpc.NewClient("passthrough:///publication-replica", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return listener.DialContext(ctx) }))
	require.NoError(t, err)
	workerCtx, cancel := context.WithCancel(ctx)
	workerDone := make(chan error, 1)
	go func() { workerDone <- runPublishedAuthorization(workerCtx, profile.store, profile.poll, logger) }()
	t.Cleanup(func() {
		cancel()
		require.NoError(t, conn.Close())
		server.Stop()
		require.NoError(t, listener.Close())
		select {
		case err := <-workerDone:
			require.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Error("published snapshot worker did not stop")
		}
		select {
		case err := <-served:
			require.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Error("publication gRPC server did not stop")
		}
	})
	return &publicationReplica{profile: profile, server: server, conn: conn, publication: iamv1.NewCatalogPublicationServiceClient(conn), catalog: iamv1.NewPermissionCatalogServiceClient(conn)}
}

func publicationReplicaContext(ctx context.Context, user string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "test-verified-identity", user)
}

// Здесь вызываются штатные операции владельца базы. Цикл команды migrator
// проверяется отдельно.
func activateReplicaPublication(t *testing.T, ctx context.Context, owner *kanamepg.Repository, revision int64) {
	t.Helper()
	next, err := owner.LoadPublicationAuthorityBundle(ctx)
	require.NoError(t, err)
	require.Equal(t, revision, next.Revision)
	advanced, err := owner.AdvanceNextCatalogPublication(ctx, next)
	require.NoError(t, err)
	require.True(t, advanced)
}

func awaitPublicationReplicas(t *testing.T, ctx context.Context, replicas []*publicationReplica, revision int64, digest string, verbs []string) {
	t.Helper()
	// Штатный фоновый опрос применяет модель и каталог в двух уже работающих
	// экземплярах. Стенд не обновляет снимок вручную и не пересоздаёт серверы.
	require.Eventually(t, func() bool {
		for _, replica := range replicas {
			pinned, err := replica.profile.store.Pin(ctx)
			if err != nil {
				return false
			}
			snapshot, ok := authzsnapshot.FromContext(pinned)
			if !ok || snapshot.Revision != revision || snapshot.Digest != digest {
				return false
			}
			response, err := replica.catalog.ListPermissionCatalog(ctx, &iamv1.ListPermissionCatalogRequest{})
			if err != nil {
				return false
			}
			var actual []string
			for _, module := range response.GetModules() {
				if module.GetModule() == "erp" {
					for _, resource := range module.GetResources() {
						if resource.GetResource() == "contract" {
							actual = resource.GetVerbs()
						}
					}
				}
			}
			if len(actual) != len(verbs) {
				return false
			}
			for _, verb := range verbs {
				found := false
				for _, value := range actual {
					found = found || value == verb
				}
				if !found {
					return false
				}
			}
		}
		return true
	}, catalogSnapshotRefreshPeriod(), 20*time.Millisecond, "both continuing replicas must expose the published revision and exact action set within the configured window")
}

func TestCatalogPublicationTwoContinuingReplicasTransport(t *testing.T) {
	if testing.Short() {
		t.Skip("requires PostgreSQL")
	}
	t.Setenv(catalogSnapshotRefreshKnob, "15000")
	base, ownerPool, _, logger := bootRolesOnLiveBase(t)
	ctx, cancel := context.WithTimeout(base, 180*time.Second)
	defer cancel()
	operator, _ := fullStartupSeedPerson(t, ctx, ownerPool, "catalog operator")
	reader, _ := fullStartupSeedPerson(t, ctx, ownerPool, "ordinary reader")
	tx, err := ownerPool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(context.Background()) }()
	_, created, err := kanamepg.NewClusterAdminGrantWriter(ownerPool).Grant(ctx, tx, domain.GrantSubjectTypeUser, domain.SubjectID(operator), operator)
	require.NoError(t, err)
	require.True(t, created)
	require.NoError(t, kanamepg.NewFGAOutboxEmitter().EmitWriteTx(ctx, tx, []service.RelationTuple{{User: "user:" + operator, Relation: "system_admin", Object: "cluster:" + domain.ClusterSingletonID}}))
	require.NoError(t, tx.Commit(ctx))
	_, bundle := fullStartupTestBundle(t, ctx, ownerPool)
	owner := kanamepg.New(ownerPool, nil)
	baseline, err := owner.BootstrapCatalogPublication(ctx, bundle, nil)
	require.NoError(t, err)
	replicas := []*publicationReplica{
		startPublicationReplica(t, ctx, ownerPool, logger, operator, reader),
		startPublicationReplica(t, ctx, ownerPool, logger, operator, reader),
	}
	require.NotSame(t, replicas[0].profile.store, replicas[1].profile.store)
	require.NotSame(t, replicas[0].server, replicas[1].server)
	adminCtx := publicationReplicaContext(ctx, operator)
	readerCtx := publicationReplicaContext(ctx, reader)
	for _, replica := range replicas {
		response, err := replica.catalog.ListPermissionCatalog(readerCtx, &iamv1.ListPermissionCatalogRequest{})
		require.NoError(t, err)
		for _, module := range response.GetModules() {
			require.NotEqual(t, "erp", module.GetModule())
		}
	}

	publish := func(replica *publicationReplica, document string) *iamv1.ApplyCatalogPublicationResponse {
		t.Helper()
		plan, err := replica.publication.PlanPublication(adminCtx, &iamv1.PlanCatalogPublicationRequest{Module: "erp", Document: []byte(document)})
		require.NoError(t, err)
		op, err := replica.publication.ApplyPublication(adminCtx, &iamv1.ApplyCatalogPublicationRequest{Module: "erp", Document: []byte(document), StateToken: plan.GetStateToken()})
		require.NoError(t, err)
		require.True(t, op.GetDone())
		response := &iamv1.ApplyCatalogPublicationResponse{}
		require.NoError(t, op.GetResponse().UnmarshalTo(response))
		return response
	}
	firstStarted := time.Now()
	first := publish(replicas[0], replicaPublicationDocument)
	require.Equal(t, baseline.Revision+1, first.GetModelRevision())
	activateReplicaPublication(t, ctx, owner, first.GetModelRevision())
	awaitPublicationReplicas(t, readerCtx, replicas, first.GetModelRevision(), first.GetModelDigest(), []string{"get", "sign"})
	require.Less(t, time.Since(firstStarted), catalogSnapshotRefreshPeriod(), "publication, owner activation and both replica refreshes fit the configured window")

	// The second existing replica publishes the next action with its refreshed
	// writer generation; a startup-only contract cannot pass this step.
	secondDocument := strings.Replace(replicaPublicationDocument, "revision: 1", "revision: 2", 1) + "      - {name: approve, class: update}\n"
	secondStarted := time.Now()
	second := publish(replicas[1], secondDocument)
	require.Equal(t, first.GetModelRevision()+1, second.GetModelRevision())
	activateReplicaPublication(t, ctx, owner, second.GetModelRevision())
	awaitPublicationReplicas(t, readerCtx, replicas, second.GetModelRevision(), second.GetModelDigest(), []string{"get", "sign", "approve"})
	require.Less(t, time.Since(secondStarted), catalogSnapshotRefreshPeriod(), "extension, owner activation and both replica refreshes fit the configured window")

	repeated := publish(replicas[0], secondDocument)
	require.Equal(t, second.GetModelRevision(), repeated.GetModelRevision())
	require.Equal(t, second.GetModelDigest(), repeated.GetModelDigest())
	assertUnchanged := func(t *testing.T) {
		t.Helper()
		var head, models, parts int64
		var digest string
		require.NoError(t, ownerPool.QueryRow(ctx, `SELECT max(revision),count(*) FROM kaname.publication_model_revision`).Scan(&head, &models))
		require.NoError(t, ownerPool.QueryRow(ctx, `SELECT count(*) FROM kaname.module_part_revision WHERE module='erp'`).Scan(&parts))
		require.NoError(t, ownerPool.QueryRow(ctx, `SELECT digest FROM kaname.publication_model_revision WHERE revision=$1`, head).Scan(&digest))
		require.Equal(t, second.GetModelRevision(), head)
		require.Equal(t, second.GetModelDigest(), digest)
		require.Equal(t, int64(3), models)
		require.Equal(t, int64(2), parts)
	}
	assertUnchanged(t)
	for _, rejected := range []struct {
		name, document string
		caller         context.Context
		code           codes.Code
	}{
		{"anonymous", secondDocument, ctx, codes.PermissionDenied},
		{"non-operator", secondDocument, readerCtx, codes.PermissionDenied},
		{"invalid-document", "apiVersion: [", adminCtx, codes.InvalidArgument},
		{"revision-collision", strings.Replace(secondDocument, "approve", "cancel", 1), adminCtx, codes.FailedPrecondition},
	} {
		t.Run(rejected.name, func(t *testing.T) {
			_, err := replicas[0].publication.PlanPublication(rejected.caller, &iamv1.PlanCatalogPublicationRequest{Module: "erp", Document: []byte(rejected.document)})
			require.Equal(t, rejected.code, status.Code(err), "%v", err)
			_, err = replicas[0].publication.ApplyPublication(rejected.caller, &iamv1.ApplyCatalogPublicationRequest{Module: "erp", Document: []byte(rejected.document), StateToken: "must-not-commit"})
			require.Equal(t, rejected.code, status.Code(err), "%v", err)
			assertUnchanged(t)
		})
	}
	awaitPublicationReplicas(t, readerCtx, replicas, second.GetModelRevision(), second.GetModelDigest(), []string{"get", "sign", "approve"})
}
