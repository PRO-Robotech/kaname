// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	userapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/user"
	"github.com/PRO-Robotech/kaname/internal/callerorigin"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/dto/toproto"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/multitracer"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

const userMetadataPrepareFacade = "kaname.authority_metadata_user_prepare_v1(text,text,text,jsonb,jsonb,jsonb,text,text,jsonb,integer,integer,integer)"

func TestUserMetadataSignedProtectedOperationCommit(t *testing.T) {
	r, owner := writerProtocolRigBeforePreparation(t)
	actor := bindingPublicOwner(t, r)
	seedMembership(t, r.ctx, r.admin, domain.UserID(actor), domain.AccountID(r.a), "ACTIVE")
	uid := seedMemberUser(t, r.ctx, r.admin, r.a, "user-protected-target")
	seedMembership(t, r.ctx, r.admin, domain.UserID(uid), domain.AccountID(r.a), "ACTIVE")
	recipient := seedMemberUser(t, r.ctx, r.admin, r.a, "user-protected-reader")
	subject := "user:" + recipient
	_, err := r.admin.Exec(r.ctx, `UPDATE kaname.users SET labels='{"team":"blue"}' WHERE id=$1`, uid)
	require.NoError(t, err)
	_, err = r.admin.Exec(r.ctx, `UPDATE kaname.users SET email_verified_at=clock_timestamp() WHERE id=ANY($1::text[])`, []string{recipient, actor})
	require.NoError(t, err)
	definition, err := owner.AddAccessLabelValues(r.ctx, kanamepg.AccessLabelDeclaration{
		Account: r.a, Module: "iam", Resource: "user", Key: "classification", Values: []string{"internal", "public"},
	})
	require.NoError(t, err)
	require.NoError(t, owner.PrepareAuthorityBundle(r.ctx, r.bundle))
	var binding domain.AccessBindingID
	w := metadataFixtureModeWithRig(t, false, "full", r, func(r protocolRig) {
		tx, err := r.admin.Begin(r.ctx)
		require.NoError(t, err)
		defer policyFixtureRollback(tx)
		_, _, err = kanamepg.NewClusterAdminGrantWriter(r.admin).Grant(r.ctx, tx, domain.GrantSubjectTypeUser, domain.SubjectID(actor), actor)
		require.NoError(t, err)
		facts := append(fgaTuplesGrantSystemAdmin(actor),
			service.RelationTuple{User: "cluster:" + domain.ClusterSingletonID, Relation: "cluster", Object: "account:" + r.a},
			service.RelationTuple{User: "account:" + r.a, Relation: "account", Object: "iam_user:" + uid})
		require.NoError(t, kanamepg.NewFGAOutboxEmitter().EmitWriteTx(r.ctx, tx, facts))
		require.NoError(t, tx.Commit(r.ctx))
		binding = groupLifecycleBinding(t, r, r.a, recipient, "user_protected_reader", domain.Rule{
			Module: "iam", Resources: []string{"user"}, Verbs: []string{"get"}, MatchLabels: map[string]string{"team": "blue"},
		})
		source := rolePolicyCatalog(t, r)
		engine := reconcile.New(kanamepg.NewReconcileAdapter(r.admin, source), slog.Default(), source)
		require.NoError(t, engine.ReconcileBinding(r.ctx, binding))
	})
	// Временный enrolled LOGIN выполняет и pending, и всю подписанную запись.
	seat, name, _ := roleActorFiniteLogin(t, r)
	trace := &userMetadataFacadeTrace{t: t}
	config := seat.Config()
	if previous := config.ConnConfig.Tracer; previous != nil {
		config.ConnConfig.Tracer = multitracer.New(previous, trace)
	} else {
		config.ConnConfig.Tracer = trace
	}
	traced, err := pgxpool.NewWithConfig(r.ctx, config)
	require.NoError(t, err)
	t.Cleanup(traced.Close)
	enrolled := r
	enrolled.runtime, enrolled.repo = traced, kanamepg.New(traced, nil)
	seatRepo, _ := fullContractRepository(t, enrolled)
	roles, err := kanamepg.NewRolePolicyWriters(r.ctx, w.full, seatRepo, r.bundle)
	require.NoError(t, err)
	var directWrite, directOperationsRead, scalarFinalize bool
	require.NoError(t, traced.QueryRow(r.ctx, `SELECT
		has_column_privilege(current_user,'kaname.users','access_labels','UPDATE')
		OR has_column_privilege(current_user,'kaname.users','labels','UPDATE')
		OR has_any_column_privilege(current_user,'kaname.operations','INSERT,UPDATE'),
		has_table_privilege(current_user,'kaname.operations','SELECT'),
		has_function_privilege(current_user,'kaname.authority_scalar_sequence_finalize_v3()','EXECUTE')`).Scan(&directWrite, &directOperationsRead, &scalarFinalize))
	require.False(t, directWrite)
	require.False(t, directOperationsRead)
	require.False(t, scalarFinalize)
	const configure = `SELECT kaname.authority_metadata_user_install_v1($1::regrole,$2::regrole,$3::boolean)`
	writer, err := roles.InstalledUserAccessLabels(r.ctx)
	require.NoError(t, err)
	require.Nil(t, writer)
	_, err = traced.Exec(r.ctx, configure, r.role, name, true)
	requireAccessDefinitionSQLState(t, err, "42501")
	_, err = r.admin.Exec(r.ctx, configure, name, r.role, true)
	requireAccessDefinitionSQLState(t, err, "42501")
	// Частичная выдача не открывает Go-порт и не ремонтируется без явного отзыва.
	_, err = r.admin.Exec(r.ctx, "GRANT EXECUTE ON FUNCTION "+userMetadataPrepareFacade+" TO "+pgx.Identifier{name}.Sanitize())
	require.NoError(t, err)
	writer, err = roles.InstalledUserAccessLabels(r.ctx)
	require.Nil(t, writer)
	require.ErrorIs(t, err, kaname.ErrSemanticIdentityUnavailable)
	_, err = r.admin.Exec(r.ctx, configure, r.role, name, true)
	requireAccessDefinitionSQLState(t, err, "55000")
	_, err = r.admin.Exec(r.ctx, configure, r.role, name, false)
	require.NoError(t, err)
	_, err = r.admin.Exec(r.ctx, configure, r.role, name, true)
	require.NoError(t, err)
	_, err = r.admin.Exec(r.ctx, configure, r.role, name, true)
	require.NoError(t, err)
	writer, err = roles.InstalledUserAccessLabels(r.ctx)
	require.NoError(t, err)
	require.NotNil(t, writer)
	t.Run("private predicate body must match", func(t *testing.T) {
		const predicate = "kaname._authority_metadata_user_protected_approve_v1(text,uuid,timestamptz,integer,integer,integer)"
		var original, changed string
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT pg_get_functiondef(p.oid),
			replace(pg_get_functiondef(p.oid),p.prosrc,p.prosrc||chr(10)) FROM pg_catalog.pg_proc p WHERE p.oid=$1::regprocedure`,
			predicate).Scan(&original, &changed))
		require.NotEqual(t, original, changed)
		_, err := r.admin.Exec(r.ctx, changed)
		require.NoError(t, err)
		t.Cleanup(func() {
			_, err := r.admin.Exec(r.ctx, original)
			require.NoError(t, err)
		})
		ports, err := roles.InstalledUserAccessLabels(r.ctx)
		require.Nil(t, ports)
		require.ErrorIs(t, err, kaname.ErrSemanticIdentityUnavailable)
	})
	_, err = traced.Exec(r.ctx, `SELECT kaname.authority_metadata_user_finalize_v1($1)`, uid)
	requireAccessDefinitionSQLState(t, err, "42501")
	t.Run("shared signed decision cannot prepare", func(t *testing.T) {
		// Выдаём только EXECUTE, чтобы различить отказ самой owner-функции и обычный ACL.
		quoted := pgx.Identifier{r.role}.Sanitize()
		_, err := r.admin.Exec(r.ctx, "GRANT EXECUTE ON FUNCTION "+userMetadataPrepareFacade+" TO "+quoted)
		require.NoError(t, err)
		t.Cleanup(func() {
			_, err := r.admin.Exec(r.ctx, "REVOKE EXECUTE ON FUNCTION "+userMetadataPrepareFacade+" FROM "+quoted)
			require.NoError(t, err)
		})
		var population json.RawMessage
		require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT jsonb_build_object('generation',generation,
			'count',row_count,'revision',revision_sum) FROM kaname.authority_policy_population_read(4096)`).Scan(&population))
		tx, err := r.runtime.BeginTx(r.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
		require.NoError(t, err)
		lifecycleRollback(t, tx)
		id := r.bundle.Identity()
		_, err = tx.Exec(r.ctx, `SELECT kaname.authority_protocol_enter_full_v3('global',ARRAY[]::text[],
			'[]'::jsonb,'resource',$1,$2,$3,'decision',$4::jsonb)`, id.ModelID, id.CatalogID, id.ProjectorVersion, population)
		require.NoError(t, err)
		_, err = tx.Exec(r.ctx, `SELECT * FROM kaname.authority_metadata_user_prepare_v1(
			$1,'1','(0,1)','{}','[]','{}','user',$2,'{}',0,0,0)`, uid, actor)
		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr)
		require.Equal(t, "42501", pgErr.Code)
		require.Equal(t, "user metadata requires the enrolled executor and ordinary runtime", pgErr.Message)
	})
	update := userapp.NewUpdateUserUseCase(w.full, w.ops)
	handler := userapp.NewHandler(nil, nil, update, nil, nil, nil, nil, nil).WithUserAccessLabelsWriter(userMetadataLoggingWriter{
		UserAccessLabelsWriter: writer,
		logger:                 slog.New(slog.NewTextHandler(t.Output(), nil)),
	})
	ctx := callerorigin.WithAssurance(callerorigin.With(declarerCtx(r.ctx, actor), callerorigin.PresentedCredential), "1")
	allowed, err := w.door.Check(ctx, "user:"+actor, "record_writer", "iam_user:"+uid)
	require.NoError(t, err)
	require.True(t, allowed, "тот же актор проходит record_writer до выдачи apply")
	var original json.RawMessage
	var expectedLoginKind string
	require.NoError(t, r.runtime.QueryRow(ctx, `SELECT to_jsonb(u),u.expected_login_kind::text FROM ONLY kaname.users u WHERE id=$1`, uid).Scan(&original, &expectedLoginKind))
	require.Equal(t, "password", expectedLoginKind, "вычисляемая колонка пользователя участвует в проверке полного образа после UPDATE")
	run := func(value string, labels map[string]string) *operations.Operation {
		t.Helper()
		mask := []string{"access_labels"}
		if labels != nil {
			mask = append(mask, "labels")
		}
		op, err := handler.Update(ctx, &iamv1.UpdateUserRequest{
			UserId: uid, AccessLabels: map[string]string{"classification": value}, Labels: labels, UpdateMask: &fieldmaskpb.FieldMask{Paths: mask},
		})
		require.NoError(t, err)
		require.NotEmpty(t, op.GetId())
		return awaitOperation(t, ctx, w.ops, op.GetId())
	}
	snapshot := func() string {
		t.Helper()
		var value string
		require.NoError(t, r.admin.QueryRow(ctx, `SELECT jsonb_build_array(u.xmin::text,u.ctid::text,to_jsonb(u),
		 (SELECT count(*) FROM ONLY kaname.resource_journal WHERE resource_kind='iam_user' AND resource_id=u.id),
		 (SELECT count(*) FROM ONLY kaname.audit_outbox WHERE event_type='iam.user.updated' AND event_payload->>'resource_id'=u.id),
		 (SELECT count(*) FROM ONLY kaname.resource_reconcile_outbox WHERE object_type='iam.user' AND object_id=u.id),
		 (SELECT to_jsonb(d) FROM ONLY kaname.authority_access_label_dirty_root d WHERE root_type='iam.user' AND root_id=u.id),
		 (SELECT jsonb_agg(to_jsonb(f) ORDER BY object_type,object_id,relation,subject) FROM ONLY kaname.authority_access_label_dirty_fact f WHERE root_type='iam.user' AND root_id=u.id),
		 (SELECT revision FROM ONLY kaname.authority_policy_epoch WHERE key='user:'||u.id),
		 (SELECT revision FROM ONLY kaname.authority_binding_epoch WHERE scope=''))::text
		 FROM ONLY kaname.users u WHERE u.id=$1`, uid).Scan(&value))
		return value
	}
	before := snapshot()
	denied := run("internal", nil)
	require.True(t, trace.prepared.Load(), "FULL writer исполнил prepare на назначенном LOGIN")
	require.NotNil(t, denied.Error)
	require.Equal(t, int32(codes.PermissionDenied), denied.Error.Code, denied.Error.Message)
	require.Nil(t, denied.Response)
	require.Equal(t, before, snapshot())
	issued, err := owner.IssueInitialAccessLabelApply(ctx, kanamepg.InitialAccessLabelApply{
		Account: r.a, DefinitionID: domain.AccessLabelDefinitionID(definition.ID), ExpectedRevision: definition.Revision,
	}, r.bundle)
	require.NoError(t, err)
	var exactApply bool
	require.NoError(t, r.admin.QueryRow(ctx, `SELECT EXISTS(SELECT FROM ONLY kaname.access_bindings b
		JOIN ONLY kaname.authority_role_access_label_rule ar ON ar.role_id=b.role_id
		JOIN ONLY kaname.access_binding_subjects s ON s.binding_id=b.id AND s.subject_type='user' AND s.subject_id=$3
		WHERE b.id=$1 AND b.role_id=$2 AND ar.definition_id=$4::uuid AND b.grant_capability_version=1)`,
		issued.BindingID, issued.RoleID, actor, definition.ID).Scan(&exactApply))
	require.True(t, exactApply)
	checkCommit := func(done *operations.Operation, labels, classification string, changed []string) {
		t.Helper()
		require.Nil(t, done.Error)
		require.True(t, done.Done)
		metadata, err := operations.MetadataFor[*iamv1.UpdateUserMetadata](done)
		require.NoError(t, err)
		require.Equal(t, uid, metadata.GetUserId())
		require.Equal(t, r.a, metadata.GetAccountId())
		require.True(t, metadata.GetProtectedLabels())
		rd, err := w.full.Reader(ctx)
		require.NoError(t, err)
		actual, err := rd.Users().Get(ctx, domain.UserID(uid))
		require.NoError(t, err)
		require.NoError(t, rd.Rollback(ctx))
		want, err := toproto.MarshalUserOperationResponse(actual)
		require.NoError(t, err)
		require.True(t, proto.Equal(want, done.Response), "точный тип и байты канонического Any")
		var exact bool
		require.NoError(t, r.runtime.QueryRow(ctx, `SELECT
		  o.user_access_labels AND o.done AND o.resource_id=u.id AND o.created_by=$3
		  AND o.principal_type='user' AND o.principal_id=$3 AND o.account_id=$4
		  AND o.response_type=$8 AND o.response_data=$9
		  AND u.xmin=o.xmin AND to_jsonb(u)=$5::jsonb||jsonb_build_object(
		      'labels',jsonb_build_object('team',$6::text),'access_labels',jsonb_build_object('classification',$7::text))
		  AND (SELECT count(*) FROM ONLY kaname.resource_journal j WHERE j.xmin=u.xmin
		      AND j.resource_id=u.id AND j.resource_kind='iam_user' AND j.event_type='UPDATED'
		      AND j.scope=jsonb_build_array(jsonb_build_object('type','account','id',$4::text)) AND j.payload=jsonb_build_object('id',u.id))=1
		  AND (SELECT count(*) FROM ONLY kaname.audit_outbox a WHERE a.xmin=u.xmin AND a.event_type='iam.user.updated'
		      AND a.tenant_account_id=$4 AND a.event_payload=jsonb_build_object('actor',$3::text,'resource_type','user',
		            'resource_id',u.id,'account_id',$4::text,'changed_fields',to_jsonb($10::text[])))=1
		  AND (SELECT count(*) FROM ONLY kaname.resource_reconcile_outbox q WHERE q.xmin=u.xmin
		      AND q.object_id=u.id AND q.object_type='iam.user' AND q.event_type='mirror.upsert')=1
		  FROM ONLY kaname.users u CROSS JOIN ONLY kaname.operations o WHERE u.id=$1 AND o.id=$2`,
			uid, done.ID, actor, r.a, original, labels, classification, want.TypeUrl, want.Value, changed).Scan(&exact))
		require.True(t, exact, "User, terminal operation, журнал, аудит и reconcile зафиксированы одной транзакцией")
	}
	// User.Get спрашивает v_get. Журнал хранит этот глагол, а native Check
	// выводит его из роли и совпадения selector с текущими метками пользователя.
	var emittedGet bool
	require.NoError(t, r.admin.QueryRow(ctx, `SELECT EXISTS(SELECT FROM ONLY kaname.access_binding_emitted_tuples l
		WHERE l.binding_id=$2 AND l.source='member' AND l.member_object_type='iam.user'
		  AND l.member_object_id=$1 AND l.object='iam_user:'||$1 AND l.fga_user=$3 AND l.relation='v_get')`,
		uid, binding, subject).Scan(&emittedGet))
	require.True(t, emittedGet)
	readerCtx := declarerCtx(r.ctx, recipient)
	checkRead := func(want bool) {
		t.Helper()
		allowed, err := w.door.Check(readerCtx, subject, "v_get", "iam_user:"+uid)
		require.NoError(t, err)
		require.Equal(t, want, allowed, "нативное решение User.Get для получателя этой привязки")
	}
	checkRead(true)
	// Fold сохраняет физические отношения уровня доступа (viewer). Именно
	// их координаты обязаны полностью совпасть с поколением отзыва.
	var originalRelations []string
	require.NoError(t, r.admin.QueryRow(ctx, `SELECT array_agg(DISTINCT l.relation ORDER BY l.relation)
		FROM ONLY kaname.access_binding_emitted_tuples l
		JOIN ONLY kaname.relation_fact f ON f.object_type='iam_user' AND f.object_id=$1 AND f.subject=l.fga_user AND f.relation=l.relation
		WHERE l.binding_id=$2 AND l.source='member' AND l.member_object_type='iam.user'
		  AND l.member_object_id=$1 AND l.object='iam_user:'||$1 AND l.fga_user=$3`, uid, binding, subject).Scan(&originalRelations))
	require.Contains(t, originalRelations, "viewer")
	fresh := func(want bool) {
		t.Helper()
		var allMatch bool
		require.NoError(t, r.admin.QueryRow(ctx, `SELECT bool_and(kaname.authority_access_label_fact_fresh_v1('iam_user',$1,rel,$2)=$4)
		    FROM unnest($3::text[]) rel`, uid, subject, originalRelations, want).Scan(&allMatch))
		require.True(t, allMatch)
	}
	checkCommit(run("internal", nil), "blue", "internal", []string{"access_labels"})
	checkRead(true)
	fresh(true)
	var clean bool
	require.NoError(t, r.admin.QueryRow(ctx, `SELECT NOT EXISTS(SELECT FROM ONLY kaname.authority_access_label_dirty_root
		WHERE root_type='iam.user' AND root_id=$1)`, uid).Scan(&clean))
	require.True(t, clean, "совпадение обычного selector сохраняет все координаты")
	mixed := run("public", map[string]string{"team": "green"})
	checkCommit(mixed, "green", "public", []string{"labels", "access_labels"})
	checkRead(false)
	fresh(false)
	var pending []string
	var exactRoot, exactFacts bool
	require.NoError(t, r.admin.QueryRow(ctx, `SELECT d.xmin::text=o.xmin::text AND d.new_labels='{"classification":"public"}',
		array_agg(f.relation ORDER BY f.relation),
		bool_and(f.xmin=o.xmin AND f.object_type='iam_user' AND f.object_id=$1 AND f.subject=$3)
		FROM ONLY kaname.authority_access_label_dirty_root d JOIN ONLY kaname.authority_access_label_dirty_fact f
		  USING(root_type,root_id,generation) CROSS JOIN ONLY kaname.operations o
		WHERE d.root_type='iam.user' AND d.root_id=$1 AND o.id=$2
		GROUP BY d.xmin::text,o.xmin::text,d.new_labels`, uid, mixed.ID, subject).Scan(&exactRoot, &pending, &exactFacts))
	require.True(t, exactRoot)
	require.True(t, exactFacts)
	require.Equal(t, originalRelations, pending, "каждая потерянная координата закрыта до обработки outbox")

	// Повторное назначение пары очищает User ACL. Новому LOGIN они достаются
	// только при отдельном включении владельцем.
	_, err = r.admin.Exec(r.ctx, `SELECT kaname.authority_role_actor_login_configure_v1($1::regrole,$2::regrole)`, r.role, name)
	require.NoError(t, err)
	writer, err = roles.InstalledUserAccessLabels(r.ctx)
	require.NoError(t, err)
	require.Nil(t, writer)
	_, err = r.admin.Exec(r.ctx, configure, r.role, name, true)
	require.NoError(t, err)
	replacement, newName, _ := roleActorFiniteLogin(t, r)
	var oldCanPrepare, newCanPrepare bool
	require.NoError(t, replacement.QueryRow(r.ctx, `SELECT has_function_privilege($1::regrole,$2::regprocedure,'EXECUTE'),
		has_function_privilege(session_user,$2::regprocedure,'EXECUTE')`, name, userMetadataPrepareFacade).Scan(&oldCanPrepare, &newCanPrepare))
	require.False(t, oldCanPrepare)
	require.False(t, newCanPrepare)
	_, err = r.admin.Exec(r.ctx, configure, r.role, name, true)
	requireAccessDefinitionSQLState(t, err, "42501")
	_, err = r.admin.Exec(r.ctx, configure, r.role, newName, true)
	require.NoError(t, err)
	_, err = r.admin.Exec(r.ctx, configure, r.role, newName, false)
	require.NoError(t, err)
	require.NoError(t, replacement.QueryRow(r.ctx, `SELECT has_function_privilege(session_user,$1::regprocedure,'EXECUTE')`, userMetadataPrepareFacade).Scan(&newCanPrepare))
	require.False(t, newCanPrepare)
}

// Сохраняем исходную ошибку worker до преобразования в публичный статус.
type userMetadataLoggingWriter struct {
	kaname.UserAccessLabelsWriter
	logger *slog.Logger
}

func (w userMetadataLoggingWriter) UpdateUserAccessLabels(ctx context.Context, id domain.UserID, labels, access domain.Labels, actor domain.Subject, pending operations.Operation) (operations.Operation, bool, error) {
	op, changed, err := w.UserAccessLabelsWriter.UpdateUserAccessLabels(ctx, id, labels, access, actor, pending)
	if err != nil {
		logger := w.logger
		var dbErr *pgconn.PgError
		if errors.As(err, &dbErr) {
			logger = logger.With("sqlstate", dbErr.Code, "where", dbErr.Where, "detail", dbErr.Detail)
		}
		logger.ErrorContext(ctx, "User.Update writer", "operation", pending.ID, "error", err)
	}
	return op, changed, err
}

// Пишем исходную PgError до её преобразования в PermissionDenied в writer.
// Аргументы команд и текст посторонних запросов в диагностику не попадают.
type userMetadataFacadeTrace struct {
	t        *testing.T
	prepared atomic.Bool
}

type userMetadataFacadeTraceKey struct{}

func (tr *userMetadataFacadeTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, query pgx.TraceQueryStartData) context.Context {
	for _, prefix := range []string{"kaname.authority_metadata_user_", "kaname.authority_user_access_labels_operation_"} {
		if _, tail, ok := strings.Cut(query.SQL, prefix); ok {
			method, _, call := strings.Cut(tail, "(")
			if call && strings.HasSuffix(method, "_v1") {
				if method == "prepare_v1" {
					tr.prepared.Store(true)
				}
				return context.WithValue(ctx, userMetadataFacadeTraceKey{}, prefix+method)
			}
		}
	}
	return ctx
}

func (tr *userMetadataFacadeTrace) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, result pgx.TraceQueryEndData) {
	method, ok := ctx.Value(userMetadataFacadeTraceKey{}).(string)
	var dbErr *pgconn.PgError
	if ok && errors.As(result.Err, &dbErr) {
		tr.t.Logf("User.Update SQL %s: SQLSTATE %s: %s; detail=%s; where=%s", method, dbErr.Code, dbErr.Message, dbErr.Detail, dbErr.Where)
	}
}
