// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"context"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/testsupport/registrationscene"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestProducerReceiptSameTransactionRollbackTypedOwnerAndModule(t *testing.T) {
	ctx, pool, _ := authorityTestDB(t)
	scene := registrationscene.Seed(t, ctx, pool)
	store := kanamepg.NewRegistrationScopeReader()
	r := domain.ProducerReceipt{Kind: domain.RegistrationOwnerReceipt, Module: "registry", CatalogType: "registry.registries", ObjectType: "registry_registry", ObjectID: "receipt", Relation: "owner", Subject: domain.Subject{Type: domain.SubjectTypeUser, ID: "same"}, Scopes: []domain.ContainerScope{{Registered: true, ProjectID: scene.Project, AccountID: scene.Account}}, SourceVersion: time.Now()}
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	require.NoError(t, store.SaveProducerReceiptTx(ctx, tx, r))
	r.Subject.Type = domain.SubjectTypeServiceAccount
	require.NoError(t, store.SaveProducerReceiptTx(ctx, tx, r))
	var n int
	require.NoError(t, tx.QueryRow(ctx, `SELECT count(*) FROM kaname.producer_source_receipt WHERE object_id='receipt' AND active AND model_identity IS NULL`).Scan(&n))
	require.Equal(t, 2, n)
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.producer_source_receipt WHERE object_id='receipt'`).Scan(&n))
	require.Zero(t, n)
	// Старая метка не снимает source; точная снимает лишь typed user.
	require.NoError(t, kanamepg.NewFGAOutboxEmitter().EmitOrderedDeleteTx(ctx, tx, []service.RelationTuple{{User: "user:same", Relation: "owner", Object: "registry_registry:receipt"}}, r.SourceVersion.Add(-time.Second)))
	require.NoError(t, tx.QueryRow(ctx, `SELECT count(*) FROM kaname.producer_source_receipt WHERE object_id='receipt' AND active`).Scan(&n))
	require.Equal(t, 2, n)
	require.NoError(t, kanamepg.NewFGAOutboxEmitter().EmitOrderedDeleteTx(ctx, tx, []service.RelationTuple{{User: "user:same", Relation: "owner", Object: "registry_registry:receipt"}}, r.SourceVersion))
	require.NoError(t, tx.QueryRow(ctx, `SELECT count(*) FROM kaname.producer_source_receipt WHERE object_id='receipt' AND active AND subject_type='service_account'`).Scan(&n))
	require.Equal(t, 1, n)
	r.Module = "foreign"
	r.CatalogType = "foreign.registry"
	require.ErrorIs(t, store.SaveProducerReceiptTx(ctx, tx, r), domain.ErrProducerReceipt)
	require.NoError(t, tx.Rollback(ctx))
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.producer_source_receipt WHERE object_id='receipt'`).Scan(&n))
	require.Zero(t, n)
}
func TestProducerReceiptPublicationReplayVersionlessAndTombstone(t *testing.T) {
	uc, pool := publicReadRig(t)
	ctx := context.Background()
	id := "reg-receipt/team/app"
	registerPublicReadTarget(t, uc, pool, id)
	v1, v2 := versions()
	publish(t, uc, id, v1)
	var active, unknown bool
	var version time.Time
	read := func() {
		require.NoError(t, pool.QueryRow(ctx, `SELECT active,model_identity IS NULL AND catalog_identity IS NULL AND projector_version IS NULL,source_version FROM kaname.producer_source_receipt WHERE kind='publication' AND object_type=$1 AND object_id=$2`, publicReadType, id).Scan(&active, &unknown, &version))
	}
	read()
	require.True(t, active)
	require.True(t, unknown)
	require.True(t, version.Equal(v1))
	publish(t, uc, id, v1)
	publish(t, uc, id, v1.Add(-time.Second))
	read()
	require.True(t, active)
	require.True(t, version.Equal(v1))
	withdraw(t, uc, id, time.Time{})
	read()
	require.False(t, active)
	require.True(t, version.Equal(v1))
	publish(t, uc, id, v1)
	read()
	require.False(t, active)
	publish(t, uc, id, v2)
	read()
	require.True(t, active)
	require.True(t, version.Equal(v2))
	withdraw(t, uc, id, v2.Add(time.Second))
	read()
	require.False(t, active)
}
func TestProducerReceiptDescendantPublicationWithdrawal(t *testing.T) {
	uc, pool := publicReadRig(t)
	ctx := context.Background()
	scene := registrationscene.Seed(t, ctx, pool)
	v1, v2 := versions()
	parent := "receipt-parent"
	child := parent + "/team/app"
	require.NoError(t, uc.Register(ctx, &iamv1.RegisterResourceRequest{SubjectId: "project:" + scene.Project, Relation: "project", Object: "registry_registry:" + parent, ParentProjectId: scene.Project, ParentAccountId: scene.Account, ParentChain: scene.ProjectChain(), SourceVersion: timestamppb.New(v1.Add(-time.Second))}))
	require.NoError(t, uc.Register(ctx, &iamv1.RegisterResourceRequest{SubjectId: "registry_registry:" + parent, Relation: "parent", Object: publicReadObject(child), ParentChain: []string{"registry_registry:" + parent}, SourceVersion: timestamppb.New(v1)}))
	publish(t, uc, child, v2.Add(time.Hour))
	require.NoError(t, uc.Unregister(ctx, &iamv1.UnregisterResourceRequest{SubjectId: "project:" + scene.Project, Relation: "project", Object: "registry_registry:" + parent, SourceVersion: timestamppb.New(v2)}))
	var active bool
	require.NoError(t, pool.QueryRow(ctx, `SELECT active FROM kaname.producer_source_receipt WHERE kind='publication' AND object_id=$1`, child).Scan(&active))
	require.False(t, active)
}
