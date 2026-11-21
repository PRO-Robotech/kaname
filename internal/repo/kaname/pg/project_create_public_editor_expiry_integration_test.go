// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	bindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	projectapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/project"
	roleapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/role"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Право рождается публичными Role.Create и AccessBinding.Create уже после
// настоящей full2 activation. Ветка account.create общей фикстуры здесь нужна
// только для bootstrap: она НЕ выдаёт member системный editor и НЕ вызывает UC.
// Более пяти минут проходят вне UC и вне транзакции; часы или expires_at не меняются.
func TestProjectCreatePublicEditorGrantExpiresAfterActualPreclockWait(t *testing.T) {
	w := sevenCRUDPublicFixture(t, "account.create", "")
	base := context.WithoutCancel(w.ctx)
	setup, stopSetup := context.WithTimeout(base, 30*time.Second)
	defer stopSetup()
	w.ctx = setup
	require.NoError(t, w.full.ValidateAuthorityRuntime(setup))
	require.NoError(t, w.full.ValidateFullAuthorityBundle(setup, w.r.bundle))
	require.NotEqual(t, w.owner, w.actor)
	require.Zero(t, sevenCRUDCount(t, w, `SELECT count(*) FROM kaname.accounts WHERE owner_user_id=$1`, w.actor))
	require.Zero(t, sevenCRUDCount(t, w, `SELECT count(*) FROM kaname.cluster_admin_grants WHERE subject_type='user' AND subject_id=$1`, w.actor))
	require.Zero(t, sevenCRUDCount(t, w, `SELECT count(*) FROM kaname.access_binding_subjects WHERE subject_type='user' AND subject_id=$1`, w.actor))
	for _, relation := range []string{"owner", "admin", "editor"} {
		allowed, err := w.door.Check(setup, "user:"+w.actor, relation, "account:"+w.r.a)
		require.NoError(t, err)
		require.False(t, allowed, "Дано: до публичной выдачи нет %s или альтернативного допуска", relation)
	}

	source := rolePolicyCatalog(t, w.r)
	writers, err := kanamepg.NewGrantPolicyWriters(setup, w.full, w.r.bundle)
	require.NoError(t, err)
	membership, err := kanamepg.NewGroupMembershipParticipant(setup, w.full, w.r.bundle)
	require.NoError(t, err)
	stages, err := membership.NewBindingStageParticipant(setup, slog.Default())
	require.NoError(t, err)
	resources, err := kanamepg.NewResourceObjectParticipant(setup, w.full, w.r.bundle)
	require.NoError(t, err)
	objects, err := resources.NewObjectReconciler(slog.Default())
	require.NoError(t, err)
	engine := reconcile.New(kanamepg.NewReconcileAdapter(w.r.runtime, source), slog.Default(), source)
	require.NoError(t, engine.WithStagedBindingReconciler(stages))
	require.NoError(t, engine.WithObjectReconciler(objects))

	role := domain.Role{AccountID: domain.AccountID(w.r.a), Name: "public_expiring_editor",
		Rules: domain.Rules{{Module: "iam", Resources: []string{"account"}, Verbs: []string{"get", "list", "update"}}}}
	roleUC := roleapp.NewCreateRoleUseCase(w.full, w.ops, source).WithRoleAuthorityWriter(writers)
	t.Log("PUBLIC_EDITOR_PRECONDITION stage=actual_role_create")
	op, err := roleUC.Execute(declarerCtx(setup, w.owner), role)
	sevenCRUDResult(t, w, op, err, codes.OK)
	require.NoError(t, w.r.runtime.QueryRow(setup, `SELECT id FROM kaname.roles WHERE account_id=$1 AND name=$2 AND NOT is_system`, w.r.a, string(role.Name)).Scan(&role.ID))
	require.NotEmpty(t, role.ID)
	stopSetup()

	grantCtx, stopGrant := context.WithTimeout(base, 30*time.Second)
	defer stopGrant()
	w.ctx = grantCtx
	var serverAt time.Time
	require.NoError(t, w.r.runtime.QueryRow(grantCtx, `SELECT clock_timestamp()`).Scan(&serverAt))
	skew := time.Since(serverAt)
	require.True(t, skew > -5*time.Second && skew < 5*time.Second, "Дано: server/client skew укладывается в запас публичного TTL")
	expires := serverAt.Add(bindingapp.MinExpiresIn + 20*time.Second)
	binding := domain.AccessBinding{RoleID: role.ID, ResourceType: "account", ResourceID: w.r.a,
		Scope: domain.ScopeAccount, Subjects: []domain.Subject{{Type: domain.SubjectTypeUser, ID: domain.SubjectID(w.actor)}},
		Target: domain.AccessTarget{AllInScope: true}, ExpiresAt: &expires}
	bindingUC := bindingapp.NewCreateAccessBindingUseCase(w.full, w.ops, source).
		WithBindingDecisions(writers).WithReconciler(engine).WithRelationStore(w.door, slog.Default())
	t.Log("PUBLIC_EDITOR_PRECONDITION stage=actual_binding_create")
	op, err = bindingUC.Execute(declarerCtx(grantCtx, w.owner), binding)
	sevenCRUDResult(t, w, op, err, codes.OK)
	var storedExpiry time.Time
	require.NoError(t, w.r.runtime.QueryRow(grantCtx, `SELECT b.id,b.expires_at FROM kaname.access_bindings b
 JOIN kaname.access_binding_subjects s ON s.binding_id=b.id
 WHERE b.role_id=$1 AND b.resource_type='account' AND b.resource_id=$2
 AND s.subject_type='user' AND s.subject_id=$3 AND b.status='ACTIVE' AND b.revoked_at IS NULL
 AND NOT b.is_system AND COALESCE(b.granted_relation,'')='' AND b.grant_capability_version=1
 AND b.granted_by_user_id=$4`, string(role.ID), w.r.a, w.actor, w.owner).Scan(&binding.ID, &storedExpiry))
	require.WithinDuration(t, expires, storedExpiry, time.Microsecond)
	expires = storedExpiry
	// Доставка выполняется настоящим staged worker, не owner INSERT факта.
	// Повторный проход допустим и позволяет независимо проверить результат async UC.
	t.Log("PUBLIC_EDITOR_PRECONDITION stage=actual_staged_materialization")
	require.NoError(t, engine.ReconcileBinding(grantCtx, binding.ID))
	require.Equal(t, 1, sevenCRUDCount(t, w, `SELECT count(*) FROM kaname.access_binding_subjects WHERE subject_type='user' AND subject_id=$1`, w.actor))
	require.Equal(t, 1, sevenCRUDCount(t, w, `SELECT count(*) FROM kaname.access_binding_emitted_tuples
 WHERE binding_id=$1 AND member_object_type='iam.account' AND member_object_id=$2
 AND fga_user=$3 AND relation='editor' AND object=$4`, string(binding.ID), w.r.a, "user:"+w.actor, "account:"+w.r.a))
	require.Equal(t, 1, sevenCRUDCount(t, w, `SELECT count(*) FROM kaname.relation_fact
 WHERE subject=$1 AND relation='editor' AND object_type='account' AND object_id=$2
 AND condition_name='' AND condition_params='{}'::jsonb`, "user:"+w.actor, w.r.a))
	for _, relation := range []string{"owner", "admin"} {
		allowed, checkErr := w.door.Check(grantCtx, "user:"+w.actor, relation, "account:"+w.r.a)
		require.NoError(t, checkErr)
		require.False(t, allowed, "выдача editor не маскируется %s", relation)
	}
	allowed, err := w.door.Check(grantCtx, "user:"+w.actor, "editor", "account:"+w.r.a)
	require.NoError(t, err)
	require.True(t, allowed, "Дано: публичная истекающая выдача уже даёт editor")
	stopGrant()

	liveCtx, stopLive := context.WithTimeout(base, 30*time.Second)
	defer stopLive()
	w.ctx = liveCtx
	live := domain.Project{AccountID: domain.AccountID(w.r.a), Name: "editor-expiry-live", Labels: domain.Labels{}}
	projectUC := projectapp.NewCreateProjectUseCase(w.full, w.ops).WithProjectCreateWriter(w.factory)
	op, err = projectUC.Execute(declarerCtx(liveCtx, w.actor), live)
	positive := sevenCRUDResult(t, w, op, err, codes.OK)
	require.NotNil(t, positive.Metadata)
	var liveMeta iamv1.CreateProjectMetadata
	require.NoError(t, positive.Metadata.UnmarshalTo(&liveMeta))
	require.NotEmpty(t, liveMeta.GetProjectId())
	require.Equal(t, 1, sevenCRUDCount(t, w, `SELECT count(*) FROM kaname.projects WHERE id=$1 AND account_id=$2 AND name=$3`, liveMeta.GetProjectId(), w.r.a, string(live.Name)))
	sevenCRUDFact(t, w, "account:"+w.r.a, "account", "project:"+liveMeta.GetProjectId(), true)
	sevenCRUDFact(t, w, "cluster:"+domain.ClusterSingletonID, "cluster", "project:"+liveMeta.GetProjectId(), true)
	sevenCRUDCommitted(t, w, "iam.project.created", "project", "iam.project", liveMeta.GetProjectId())
	t.Logf("PUBLIC_EDITOR_PRECONDITIONS_CONFIRMED role=%s binding=%s positive_project=%s expiry=%s", role.ID, binding.ID, liveMeta.GetProjectId(), expires.Format(time.RFC3339Nano))
	stopLive()

	// Только чтение server clock; ни UC, ни fence, ни открытая TX не живут пять минут.
	idleCtx, stopIdle := context.WithTimeout(base, bindingapp.MinExpiresIn+30*time.Second)
	_, err = projectEditorExpiryWaitClock(idleCtx, w.r.runtime, expires.Add(-12*time.Second), 250*time.Millisecond)
	stopIdle()
	require.NoError(t, err)

	// Новый прежний 30s budget начинается ПОСЛЕ долгого ожидания. Фабрика не
	// хранит setup context: каждый вызов получает этот свежий профильный context.
	negativeCtx, stopNegative := context.WithTimeout(base, 30*time.Second)
	defer stopNegative()
	w.ctx = negativeCtx
	dedicatedCtx, factory, pid := sevenCRUDDedicatedFactory(t, w)
	before := sevenCRUDSnapshot(t, w)
	holder, err := w.r.runtime.Begin(negativeCtx)
	require.NoError(t, err)
	var pending *operations.Operation
	terminalObserved := false
	released := false
	release := func() error {
		if released {
			return nil
		}
		cleanup, stop := context.WithTimeout(context.WithoutCancel(negativeCtx), 5*time.Second)
		defer stop()
		rollbackErr := holder.Rollback(cleanup)
		if errors.Is(rollbackErr, pgx.ErrTxClosed) {
			rollbackErr = nil
		}
		if rollbackErr == nil {
			released = true
		}
		return rollbackErr
	}
	// Установлено до первого утверждения под blocker. Даже Fatal освобождает
	// родителя и ждёт собственный detached LRO в прежнем 20s окне.
	defer func() {
		assert.NoError(t, release(), "освобождение parent blocker")
		if pending != nil && !terminalObserved {
			cleanup, stop := context.WithTimeout(context.WithoutCancel(negativeCtx), 20*time.Second)
			defer stop()
			_, cleanupErr := projectEditorExpiryAwaitOperation(cleanup, w.ops, pending.ID)
			assert.NoError(t, cleanupErr, "собственный worker после cleanup должен завершиться")
		}
	}()
	holderPID := int(holder.Conn().PgConn().PID())
	var parent string
	require.NoError(t, holder.QueryRow(negativeCtx, `SELECT id FROM kaname.accounts WHERE id=$1 FOR UPDATE`, w.r.a).Scan(&parent))
	require.Equal(t, w.r.a, parent)
	require.NoError(t, w.r.runtime.QueryRow(negativeCtx, `SELECT clock_timestamp()`).Scan(&serverAt))
	require.True(t, serverAt.Before(expires), "выдача жива до запуска второго UC")
	allowed, err = w.door.Check(negativeCtx, "user:"+w.actor, "editor", "account:"+w.r.a)
	require.NoError(t, err)
	require.True(t, allowed)
	expiring := domain.Project{AccountID: domain.AccountID(w.r.a), Name: "editor-expiry-denied", Labels: domain.Labels{}}
	pending, err = projectapp.NewCreateProjectUseCase(w.full, w.ops).WithProjectCreateWriter(factory).
		Execute(declarerCtx(dedicatedCtx, w.actor), expiring)
	require.NoError(t, err)
	require.NotNil(t, pending)
	require.NotNil(t, pending.Metadata)
	var deniedMeta iamv1.CreateProjectMetadata
	require.NoError(t, pending.Metadata.UnmarshalTo(&deniedMeta))
	require.NotEmpty(t, deniedMeta.GetProjectId())

	waitCtx, stopWait := context.WithTimeout(negativeCtx, 5*time.Second)
	blocked := false
	tick := time.NewTicker(10 * time.Millisecond)
	for !blocked && waitCtx.Err() == nil {
		err = w.r.admin.QueryRow(waitCtx, `SELECT $2=ANY(pg_blocking_pids($1))
 AND EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND query LIKE '%authority_resource_prewait_v2%')`, pid, holderPID).Scan(&blocked)
		if err != nil || blocked {
			break
		}
		select {
		case <-waitCtx.Done():
		case <-tick.C:
		}
	}
	tick.Stop()
	stopWait()
	require.NoError(t, err)
	require.True(t, blocked, "exact writer PID ждёт exact holder внутри настоящего prewait")
	require.NoError(t, w.r.runtime.QueryRow(negativeCtx, `SELECT clock_timestamp()`).Scan(&serverAt))
	require.True(t, serverAt.Before(expires), "выдача жива после доказанного preclock wait")
	allowed, err = w.door.Check(negativeCtx, "user:"+w.actor, "editor", "account:"+w.r.a)
	require.NoError(t, err)
	require.True(t, allowed)

	serverAt, err = projectEditorExpiryWaitClock(negativeCtx, w.r.runtime, expires, 20*time.Millisecond)
	require.NoError(t, err)
	require.False(t, serverAt.Before(expires))
	require.NoError(t, w.r.admin.QueryRow(negativeCtx, `SELECT $2=ANY(pg_blocking_pids($1))`, pid, holderPID).Scan(&blocked))
	require.True(t, blocked, "expiry пересечена до освобождения того же blocker")
	require.Equal(t, 1, sevenCRUDCount(t, w, `SELECT count(*) FROM kaname.access_bindings WHERE id=$1 AND status='ACTIVE'
 AND revoked_at IS NULL AND expires_at=$2 AND expires_at<=clock_timestamp()`, string(binding.ID), expires))
	// Нам нужен отказ по сроку сохранённого источника, а не успешная очистка факта.
	require.Equal(t, 1, sevenCRUDCount(t, w, `SELECT count(*) FROM kaname.relation_fact WHERE subject=$1 AND relation='editor' AND object_type='account' AND object_id=$2`, "user:"+w.actor, w.r.a))
	allowed, nativeErr := w.door.Check(negativeCtx, "user:"+w.actor, "editor", "account:"+w.r.a)
	t.Logf("PROJECT_CREATE_PUBLIC_EDITOR_EXPIRY binding=%s expires=%s observed=%s native_allowed=%t native_error=%v writer_pid=%d holder_pid=%d", binding.ID, expires.Format(time.RFC3339Nano), serverAt.Format(time.RFC3339Nano), allowed, nativeErr, pid, holderPID)
	assert.NoError(t, nativeErr)
	// Публичный Check наблюдает сохранённую проекцию и может вернуть allow.
	// Он не подменяет проверку мутации после final clock: ниже обязательны
	// PermissionDenied actual Project.Create и отсутствие business effects.
	assert.NoError(t, release())
	completionCtx, stopCompletion := context.WithTimeout(negativeCtx, 20*time.Second)
	done, completionErr := projectEditorExpiryAwaitOperation(completionCtx, w.ops, pending.ID)
	stopCompletion()
	terminalObserved = completionErr == nil && done != nil
	assert.NoError(t, completionErr)
	if assert.NotNil(t, done) {
		actual := codes.OK
		if done.Error != nil {
			actual = status.FromProto(done.Error).Code()
		}
		t.Logf("PROJECT_CREATE_PUBLIC_EDITOR_EXPIRY operation=%s terminal=%t code=%s response_present=%t", pending.ID, done.Done, actual, done.Response != nil)
		assert.True(t, done.Done)
		assert.Equal(t, codes.PermissionDenied, actual)
		assert.Nil(t, done.Response)
	}
	// Отдельный прежний observer budget сохраняет снимок даже при ошибке Check/LRO.
	observeCtx, stopObserve := context.WithTimeout(base, 30*time.Second)
	defer stopObserve()
	w.ctx = observeCtx
	assert.Equal(t, before, sevenCRUDSnapshot(t, w), "отказ не меняет project/journal/FGA/audit и остальные business rows; LRO исключён")
	assert.Zero(t, sevenCRUDCount(t, w, `SELECT count(*) FROM kaname.projects WHERE id=$1`, deniedMeta.GetProjectId()))
}

// Опрос не создаёт authority и не задаёт время решения. Каждый SELECT имеет
// отдельный 1s budget; длительное окно разрешено только ожиданию вне UC.
func projectEditorExpiryWaitClock(ctx context.Context, pool *pgxpool.Pool, target time.Time, interval time.Duration) (time.Time, error) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		queryCtx, stop := context.WithTimeout(ctx, time.Second)
		var at time.Time
		err := pool.QueryRow(queryCtx, `SELECT clock_timestamp()`).Scan(&at)
		stop()
		if err != nil || !at.Before(target) {
			return at, err
		}
		select {
		case <-ctx.Done():
			return at, ctx.Err()
		case <-tick.C:
		}
	}
}

// Только собственный LRO и caller-owned budget; ошибка не вызывает Fatal,
// чтобы после отрицательного исхода сохранился независимый снимок эффектов.
func projectEditorExpiryAwaitOperation(ctx context.Context, repo operations.Repo, id string) (*operations.Operation, error) {
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		op, err := repo.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		if op == nil {
			return nil, errors.New("собственная операция отсутствует")
		}
		if op.Done {
			return op, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-tick.C:
		}
	}
}
