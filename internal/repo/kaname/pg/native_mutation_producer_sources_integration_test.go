// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/registrationscene"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
)

// Законные nonbinding источники созданы actual Register/Publish. Отдельный
// writer на каждый Check исключает перенос подтверждения через withdrawal.
func TestNativeMutationRegistrationAndPublicationSources(t *testing.T) {
	uc, pool := publicReadRig(t)
	ctx, cancelSetup := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelSetup()
	body, err := os.ReadFile("../../../../tests/authz-fixtures/registry-own-stand-fixture.yaml")
	require.NoError(t, err)
	declaration, err := manifest.Load(body)
	require.NoError(t, err)
	_, err = applierOver(t, pool).Apply(ctx, declaration)
	require.NoError(t, err)
	// Actor владеет только своей отдельной сценой. Проверяемые ресурсы
	// находятся в чужой области: account-owner не маскирует producer receipt.
	actorScene := registrationscene.Seed(t, ctx, pool)
	scene := registrationscene.Seed(t, ctx, pool)
	require.NotEqual(t, actorScene.Account, scene.Account)
	var uid string
	require.NoError(t, pool.QueryRow(ctx, `SELECT owner_user_id FROM kaname.accounts WHERE id=$1`, actorScene.Account).Scan(&uid))
	var ownsTarget, clusterGrant, bindingGrant, groupCarrier bool
	require.NoError(t, pool.QueryRow(ctx, `SELECT
 EXISTS(SELECT 1 FROM kaname.accounts WHERE id=$1 AND owner_user_id=$2),
 EXISTS(SELECT 1 FROM kaname.cluster_admin_grants WHERE subject_type='user' AND subject_id=$2),
 EXISTS(SELECT 1 FROM kaname.access_binding_subjects WHERE subject_type='user' AND subject_id=$2),
 EXISTS(SELECT 1 FROM kaname.group_members WHERE member_type='user' AND member_id=$2)`, scene.Account, uid).Scan(&ownsTarget, &clusterGrant, &bindingGrant, &groupCarrier))
	require.False(t, ownsTarget, "actor не владеет аккаунтом проверяемых объектов")
	require.False(t, clusterGrant, "нет самостоятельного cluster-admin основания")
	require.False(t, bindingGrant, "нет альтернативной выдачи пользователю")
	require.False(t, groupCarrier, "нет альтернативного группового носителя")
	_, err = pool.Exec(ctx, `UPDATE kaname.users SET email_verified_at=clock_timestamp() WHERE id=$1`, uid)
	require.NoError(t, err)
	object := "registry_registry:mutation-source-owner"
	require.NoError(t, uc.Register(ctx, &iamv1.RegisterResourceRequest{SubjectId: "project:" + scene.Project, Relation: "project", Object: object, ParentProjectId: scene.Project, ParentAccountId: scene.Account, ParentChain: scene.ProjectChain()}))
	require.NoError(t, uc.Register(ctx, &iamv1.RegisterResourceRequest{SubjectId: "user:" + uid, Relation: "owner", Object: object, ParentProjectId: scene.Project, ParentAccountId: scene.Account, ParentChain: scene.ProjectChain()}))
	publicID := "mutation-source-public/team/app"
	// Эти actual Register используют тот же ограниченный setup context;
	// общие старые helpers создавали внутри собственный Background.
	require.NoError(t, uc.Register(ctx, &iamv1.RegisterResourceRequest{SubjectId: "project:" + scene.Project, Relation: "project", Object: "registry_registry:mutation-source-public", ParentProjectId: scene.Project, ParentAccountId: scene.Account, ParentChain: scene.ProjectChain()}))
	require.NoError(t, uc.Register(ctx, &iamv1.RegisterResourceRequest{SubjectId: "registry_registry:mutation-source-public", Relation: "parent", Object: publicReadObject(publicID)}))
	require.NoError(t, uc.Register(ctx, &iamv1.RegisterResourceRequest{SubjectId: publicReadSubject, Relation: publicReadRelation, Object: publicReadObject(publicID)}))
	repo := kanamepg.New(pool, nil)
	bundle := semanticBundleDB(t, ctx, pool)
	semanticFixtureIdentity(t, ctx, pool, bundle)
	actor := domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(uid)}
	check := func(relation, target string) (bool, error) {
		requestCtx, cancelRequest := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancelRequest()
		w, e := repo.PlannedSemanticPopulationWriter(requestCtx, kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}, bundle, []kaname.SemanticReadIntent{{Actor: actor, Native: []kaname.SemanticNativeQuestion{{Relation: relation, Object: target}}}})
		if w != nil {
			defer func() {
				cleanup, cancelCleanup := context.WithTimeout(context.WithoutCancel(requestCtx), 5*time.Second)
				defer cancelCleanup()
				require.NoError(t, w.Rollback(cleanup))
			}()
		}
		require.NoError(t, e)
		require.NotNil(t, w)
		return w.SemanticRelationChecker().Check(requestCtx, "user:"+uid, relation, target)
	}
	for _, tc := range []struct{ relation, object string }{{"v_update", object}, {"v_create", object}, {publicReadRelation, publicReadObject(publicID)}} {
		got, e := check(tc.relation, tc.object)
		require.NoError(t, e)
		require.True(t, got, "живой canonical producer %s %s", tc.relation, tc.object)
	}
	// Отрицательная fixture имитирует лаг доставки уже снятого producer.
	// Ни один новый tuple или receipt здесь не создаётся; время не подменяется.
	withdrawCtx, cancelWithdrawal := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancelWithdrawal()
	tag, err := pool.Exec(withdrawCtx, `UPDATE kaname.producer_source_receipt SET active=false,invalidation='withdrawn' WHERE object_id=ANY($1::text[])`, []string{"mutation-source-owner", publicID})
	require.NoError(t, err)
	require.EqualValues(t, 2, tag.RowsAffected())
	for _, tc := range []struct{ relation, object string }{{"v_update", object}, {"v_create", object}, {publicReadRelation, publicReadObject(publicID)}} {
		got, e := check(tc.relation, tc.object)
		require.NoError(t, e, "известный снятый producer не маскируется UNKNOWN")
		require.False(t, got, "stale fact не заменяет source: %s %s", tc.relation, tc.object)
	}
}
