// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/dto/toproto"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/testsupport/installruntime"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

// Обе службы используют штатный бинарник, один enrolled LOGIN и одну публикацию.
// Оператор с record_writer получает первичную выдачу apply только для одного ключа.
func TestUserAccessLabelsTwoNativeReplicas(t *testing.T) {
	if os.Getenv("KANAME_ACCESS_LABEL_REPLICA_ACCEPTANCE") != "1" {
		t.Skip("NOT_EXECUTED: requires the leased native access-label acceptance job and KANAME_RID_* frozen artifacts")
	}
	f := newInstallationNativeWorldConfigured(t, 7200, "", false, false, nativeWorldOptions{boundedPostgres: true})
	ctx, pool := f.given.ctx, f.given.pool
	uid, account := string(f.given.user), f.tenantID
	stop, cancel := context.WithTimeout(ctx, 20*time.Second)
	err := f.session.Stop(stop)
	cancel()
	require.NoError(t, err)
	owner := kanamepg.New(pool, nil)

	// Базовый serve уже выдал оператору system_admin. Для исходных строк
	// SQL-фикстуры ставим штатные структурные отношения их реального членства.
	var member bool
	require.NoError(t, pool.QueryRow(ctx, `SELECT EXISTS(SELECT FROM kaname.memberships m
		JOIN kaname.accounts a ON a.id=m.account_id WHERE m.user_id=$1 AND m.account_id=$2
		  AND m.state='ACTIVE' AND a.owner_user_id=m.user_id)`, uid, account).Scan(&member))
	require.True(t, member)
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	require.NoError(t, kanamepg.NewFGAOutboxEmitter().EmitWriteTx(ctx, tx, []service.RelationTuple{
		{User: "cluster:" + domain.ClusterSingletonID, Relation: "cluster", Object: "account:" + account},
		{User: "account:" + account, Relation: "account", Object: "iam_user:" + uid},
	}))
	require.NoError(t, tx.Commit(ctx))
	declare := func(key string) kanamepg.AccessLabelDeclarationResult {
		t.Helper()
		result, err := owner.AddAccessLabelValues(ctx, kanamepg.AccessLabelDeclaration{
			Account: account, Module: "iam", Resource: "user", Key: key, Values: []string{"internal", "public"},
		})
		require.NoError(t, err)
		return result
	}
	allowed := declare("classification")
	declare("department")
	_, bundle := fullStartupTestBundle(t, ctx, pool)
	require.NoError(t, owner.StageFullAuthorityBundle(ctx, bundle))
	require.NoError(t, owner.ActivateFullAuthorityBundle(ctx, bundle))
	_, err = owner.IssueInitialAccessLabelApply(ctx, kanamepg.InitialAccessLabelApply{
		Account: account, DefinitionID: domain.AccessLabelDefinitionID(allowed.ID), ExpectedRevision: allowed.Revision,
	}, bundle)
	require.NoError(t, err)

	ownerFile := filepath.Join(f.session.Root, "user-publication-owner.yaml")
	require.NoError(t, os.WriteFile(ownerFile, []byte("{}\n"), 0600))
	migrator := os.Getenv("KANAME_RID_MIGRATOR")
	_ = publicationNativeDigest(t, migrator)
	bootstrap := startPublicationOwnerCommand(t, ctx, f.session.Root, "user-publication", publicationNativeEnvironment(f.session.Environment,
		map[string]string{"KANAME_CONFIG_PATH": ownerFile}), migrator, "authority-bundle", "bootstrap-publication", "--image-only")
	bootstrap.await(t, 90*time.Second)

	primary := provisionNativeRuntime(t, f, filepath.Join(f.session.Root, "user-runtime-grants.log"))
	executor := primary.Copy()
	executor.User, executor.Password = fullStartupRestrictedLogin(t, ctx, pool)
	f.secrets = append(f.secrets, executor.Password)
	_, err = pool.Exec(ctx, `SELECT kaname.authority_role_actor_login_configure_v1($1::regrole,$2::regrole)`, primary.User, executor.User)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `SELECT kaname.authority_metadata_user_install_v1($1::regrole,$2::regrole,true)`, primary.User, executor.User)
	require.NoError(t, err)
	a := startNativeAccessLabelReplica(t, f, "user-a", installruntime.DefaultNativePorts(), primary, executor)
	b := startNativeAccessLabelReplica(t, f, "user-b", installruntime.SecondNativePorts(), primary, executor)
	require.NotEqual(t, a.pid, b.pid)
	// TLS-готовность не означает завершение стартовых UPDATE проекций ролей.
	// PATCH здесь проверяет apply при установившейся политике. Обе реплики
	// продолжают обслуживать трафик; их готовность под нагрузкой не подменяем.
	ridAwaitRoleProjectionsAt(t, ctx, a.process, "user-labels-replica-a")
	ridAwaitRoleProjectionsAt(t, ctx, b.process, "user-labels-replica-b")
	// Обновляем Bearer на первом FULL listener после подготовки обеих реплик.
	f.renewOperator(t, ctx)
	bearer := f.operator.Bearer()
	path := "/iam/v1/users/" + url.PathEscape(uid)
	update := func(writer, observer *nativeAccessLabelReplica, key, value string, mixed bool) (installruntime.Operation, error) {
		t.Helper()
		form := map[string]any{"userId": uid, "accessLabels": map[string]string{key: value}, "updateMask": "accessLabels"}
		if mixed {
			form["labels"] = map[string]string{"team": "green"}
			form["updateMask"] = "labels,accessLabels"
		}
		var raw json.RawMessage
		code, err := writer.wire.JSON(ctx, http.MethodPatch, path, bearer, form, &raw)
		require.NoError(t, err)
		if code != http.StatusOK {
			var failure struct {
				Code int `json:"code"`
			}
			require.NoError(t, json.Unmarshal(raw, &failure))
			t.Fatalf("PATCH через %s: HTTP %d, код gRPC %d", writer.name, code, failure.Code)
		}
		var pending installruntime.Operation
		require.NoError(t, json.Unmarshal(raw, &pending))
		require.NotEmpty(t, pending.ID)
		// Всегда читаем операцию через другую реплику, даже если PATCH уже вернул done.
		return observer.wire.AwaitOperation(ctx, bearer, installruntime.Operation{ID: pending.ID})
	}
	snapshot := func() string {
		t.Helper()
		var row string
		require.NoError(t, pool.QueryRow(ctx, `SELECT jsonb_build_array(u.xmin::text,u.ctid::text,to_jsonb(u),
			(SELECT count(*) FROM kaname.resource_journal WHERE resource_kind='iam_user' AND resource_id=u.id))::text
			FROM ONLY kaname.users u WHERE u.id=$1`, uid).Scan(&row))
		return row
	}
	before := snapshot()
	denied, err := update(a, b, "department", "internal", false)
	require.Error(t, err)
	require.True(t, denied.Done)
	require.NotNil(t, denied.Error)
	require.Equal(t, int(codes.PermissionDenied), denied.Error.Code)
	require.Empty(t, denied.Response)
	require.Equal(t, before, snapshot())

	var oldLabels map[string]string
	require.NoError(t, pool.QueryRow(ctx, `SELECT labels FROM kaname.users WHERE id=$1`, uid).Scan(&oldLabels))
	check := func(writer, observer *nativeAccessLabelReplica, value string, mixed bool, labels map[string]string) {
		t.Helper()
		done, err := update(writer, observer, "classification", value, mixed)
		require.NoError(t, err)
		require.True(t, done.Done)
		var resultAny, metadataAny anypb.Any
		require.NoError(t, protojson.Unmarshal(done.Response, &resultAny))
		require.NoError(t, protojson.Unmarshal(done.Metadata, &metadataAny))
		var result iamv1.User
		var md iamv1.UpdateUserMetadata
		require.NoError(t, resultAny.UnmarshalTo(&result))
		require.NoError(t, metadataAny.UnmarshalTo(&md))
		require.True(t, proto.Equal(&md, &iamv1.UpdateUserMetadata{UserId: uid, AccountId: account, ProtectedLabels: true}))
		require.Equal(t, uid, result.GetId())
		require.Equal(t, map[string]string{"classification": value}, result.GetAccessLabels())
		require.True(t, maps.Equal(labels, result.GetLabels()))

		var read json.RawMessage
		code, err := observer.wire.JSON(ctx, http.MethodGet, path, bearer, nil, &read)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
		var visible iamv1.User
		require.NoError(t, protojson.Unmarshal(read, &visible))
		require.True(t, proto.Equal(&result, &visible))

		reader, err := owner.Reader(ctx)
		require.NoError(t, err)
		stored, err := reader.Users().Get(ctx, domain.UserID(uid))
		rollbackErr := reader.Rollback(ctx)
		require.NoError(t, rollbackErr)
		require.NoError(t, err)
		expected, err := toproto.MarshalUserOperationResponse(stored)
		require.NoError(t, err)
		var storedUser iamv1.User
		require.NoError(t, expected.UnmarshalTo(&storedUser))
		require.True(t, proto.Equal(&storedUser, &result))
		var atomic bool
		require.NoError(t, pool.QueryRow(ctx, `SELECT o.user_access_labels AND o.done AND o.error_code IS NULL
			AND o.resource_id=u.id AND o.principal_type='user' AND o.principal_id=$1 AND o.account_id=$3
			AND o.response_type=$4 AND o.response_data=$5 AND o.xmin=u.xmin AND EXISTS(
			  SELECT FROM ONLY kaname.resource_journal j WHERE j.xmin=u.xmin AND j.resource_id=u.id
			    AND j.resource_kind='iam_user' AND j.event_type='UPDATED')
			FROM ONLY kaname.users u JOIN ONLY kaname.operations o ON o.id=$2 WHERE u.id=$1`,
			uid, done.ID, account, expected.TypeUrl, expected.Value).Scan(&atomic))
		require.True(t, atomic, "User, канонический ответ и журнал должны иметь один xid")
	}
	check(a, b, "internal", false, oldLabels)
	check(b, a, "public", true, map[string]string{"team": "green"})
	a.assertContinuing(t)
	b.assertContinuing(t)
}
