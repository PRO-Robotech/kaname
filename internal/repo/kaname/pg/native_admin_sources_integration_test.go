// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	roleapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/role"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/bindingset"
	"github.com/stretchr/testify/require"
)

// Проверка всегда идёт настоящим runtime LOGIN через participant и его Check.
// Прежний read door используется только как явно stale-positive counterpart.
func checkLiveAdministrative(t *testing.T, w delegationUCWorld, subject, relation, object string) (bool, error) {
	t.Helper()
	d := administrativeCheckerIntent(w)
	typ, id, _ := strings.Cut(subject, ":")
	writer, err := w.participant.GrantDelegationWriter(operations.WithPrincipal(w.r.ctx, operations.Principal{Type: typ, ID: id}), kaname.GrantDelegationCreate, d)
	require.NoError(t, err)
	defer func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(w.r.ctx), 5*time.Second)
		defer cancel()
		require.NoError(t, writer.Rollback(ctx))
	}()
	checker, err := writer.TransactionRelationChecker(nil)
	require.NoError(t, err)
	return checker.Check(w.r.ctx, subject, relation, object)
}

// Checker использует уже существующие реальные SA/role fixture. Создавать
// новые raw строки при каждом Check нельзя после strict activation.
func administrativeCheckerIntent(w delegationUCWorld) domain.GrantDelegation {
	roles := make([]domain.RoleID, len(w.input.RoleIDs))
	for i, id := range w.input.RoleIDs {
		roles[i] = domain.RoleID(id)
	}
	return domain.GrantDelegation{ID: domain.GrantDelegationID(ids.NewID("gdl")), AccountID: domain.AccountID(w.r.a), DelegateID: domain.ServiceAccountID(w.input.DelegateID), RoleIDs: roles, TargetTypes: []string{"registry.registries"}, SubjectTypes: []domain.SubjectType{domain.SubjectTypeServiceAccount}, Module: "registry", DelegatedBy: domain.GrantDelegationActor{Type: "user", ID: w.owner}}
}

// Проверяемая координата — сам account. Законная пообъектная цель сохраняет
// настоящий rules producer, но не пересчитывает весь растущий IAM inventory
// ради каждого из 257 holders. Fact/ledger здесь не копируются и не выдумываются.
func administrativeHolderBinding(w delegationUCWorld, id domain.AccessBindingID, subject domain.Subject) domain.AccessBinding {
	return domain.AccessBinding{ID: id, SubjectType: subject.Type, SubjectID: subject.ID, RoleID: domain.RoleID(domain.ClusterAdminRoleID), ResourceType: "account", ResourceID: w.r.a, Scope: domain.ScopeAccount, Status: domain.AccessBindingStatusActive, Target: domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "iam.account", ID: w.r.a}}}}
}

func materializeAdministrativeHolder(t *testing.T, w delegationUCWorld, id domain.AccessBindingID, subject domain.Subject) {
	t.Helper()
	engine := reconcile.New(kanamepg.NewReconcileAdapter(w.r.admin, w.source), slog.Default(), w.source)
	materializeAdministrativeHolderUsing(t, w, engine, id, subject)
}

func materializeAdministrativeHolderUsing(t *testing.T, w delegationUCWorld, engine *reconcile.Reconciler, id domain.AccessBindingID, subject domain.Subject) {
	t.Helper()
	writer, err := lifecycleOwner(w.r).Writer(w.r.ctx)
	require.NoError(t, err)
	defer func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(w.r.ctx), 5*time.Second)
		defer cancel()
		_ = writer.Rollback(ctx)
	}()
	_, err = bindingset.Insert(w.r.ctx, writer.AccessBindingsW(), administrativeHolderBinding(w, id, subject))
	require.NoError(t, err)
	require.NoError(t, writer.Commit(w.r.ctx))
	require.NoError(t, engine.ReconcileBinding(w.r.ctx, id))
	var count int
	require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1 AND member_object_type='iam.account' AND member_object_id=$3 AND fga_user=$2 AND relation='admin' AND object=$4`, id, domain.FGASubjectRef(string(subject.Type), string(subject.ID)), w.r.a, "account:"+w.r.a).Scan(&count))
	require.Positive(t, count, "предпосылка: настоящий producer выпустил admin")
}

// Только fixture DML без публичного typed setter (expiry/condition). Entry
// настоящий: ordinary LOGIN, immutable bundle, protocol xact locks и witness.
// Ни owner bypass, ни отключение triggers здесь не используются.
func administrativeFixtureExec(t *testing.T, w delegationUCWorld, query string, args ...any) int64 {
	t.Helper()
	tx, err := w.r.runtime.Begin(w.r.ctx)
	require.NoError(t, err)
	defer func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(w.r.ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(ctx)
	}()
	in := kaname.AuthorityWriteIntent{Kind: kaname.AuthorityBinding, Bundle: w.r.bundle, Plan: kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}}
	w.r.enter(t, tx, in, "participant")
	tag, err := tx.Exec(w.r.ctx, query, args...)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(w.r.ctx))
	return tag.RowsAffected()
}

func TestLiveAdministrativeAlternativeHolderAfterLedgerPage(t *testing.T) {
	w := delegationUCFixture(t)
	actor := domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(w.member)}
	engine := reconcile.New(kanamepg.NewReconcileAdapter(w.r.admin, w.source), slog.Default(), w.source)
	var last domain.AccessBindingID
	for i := 1; i <= 257; i++ {
		last = domain.AccessBindingID(fmt.Sprintf("acb%017d", i))
		materializeAdministrativeHolderUsing(t, w, engine, last, actor)
		if i < 257 {
			// Лаг удаления проекции: canonical revoke уже применён, tuple/ledger ещё
			// сохранены. Не инъекция разрешения: каждый tuple выведен reconciler выше.
			tag, err := w.r.admin.Exec(w.r.ctx, `UPDATE kaname.access_bindings SET status='REVOKED',revoked_at=clock_timestamp() WHERE id=$1`, last)
			require.NoError(t, err)
			require.EqualValues(t, 1, tag.RowsAffected())
		}
	}
	var holders, revoked int
	require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(DISTINCT e.binding_id),count(DISTINCT e.binding_id) FILTER(WHERE b.status='REVOKED') FROM kaname.access_binding_emitted_tuples e JOIN kaname.access_bindings b ON b.id=e.binding_id WHERE e.member_object_type='iam.account' AND e.member_object_id=$1 AND e.fga_user=$2 AND e.relation='admin' AND e.object=$3`, w.r.a, "user:"+w.member, "account:"+w.r.a).Scan(&holders, &revoked))
	require.Equal(t, 257, holders, "полная страница stale ledger и отдельный поздний holder")
	require.Equal(t, 256, revoked)
	native, err := w.door.Check(w.r.ctx, "user:"+w.member, "admin", "account:"+w.r.a)
	require.NoError(t, err)
	require.True(t, native)
	got, err := checkLiveAdministrative(t, w, "user:"+w.member, "admin", "account:"+w.r.a)
	require.NoError(t, err)
	require.True(t, got, "257-й живой holder не теряется после первой страницы")
	tag, err := w.r.admin.Exec(w.r.ctx, `UPDATE kaname.access_bindings SET expires_at=clock_timestamp() WHERE id=$1`, last)
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected())
	native, err = w.door.Check(w.r.ctx, "user:"+w.member, "admin", "account:"+w.r.a)
	require.NoError(t, err)
	require.True(t, native, "public read намеренно не меняется этой дельтой")
	got, err = checkLiveAdministrative(t, w, "user:"+w.member, "admin", "account:"+w.r.a)
	require.NoError(t, err)
	require.False(t, got, "сняты все живые источники, stale fact не даёт mutation authority")
	authorityWaitReleased(t, w.r.runtime)
}

func TestLiveAdministrativeGroupCarrierAndTypedSubject(t *testing.T) {
	w := delegationUCFixture(t)
	group := ids.NewID("grp")
	_, err := w.r.admin.Exec(w.r.ctx, `INSERT INTO kaname.groups(id,account_id,name) VALUES($1,$2,'live-admin-group')`, group, w.r.a)
	require.NoError(t, err)
	_, err = w.r.admin.Exec(w.r.ctx, `INSERT INTO kaname.group_members(group_id,member_type,member_id) VALUES($1,'user',$2)`, group, w.member)
	require.NoError(t, err)
	id := domain.AccessBindingID(ids.NewID("acb"))
	materializeAdministrativeHolder(t, w, id, domain.Subject{Type: domain.SubjectTypeGroup, ID: domain.SubjectID(group)})
	got, err := checkLiveAdministrative(t, w, "user:"+w.member, "admin", "account:"+w.r.a)
	require.NoError(t, err)
	require.True(t, got)
	// Совпадение идентификаторов не превращает учётку в человека группы.
	_, err = w.r.admin.Exec(w.r.ctx, `INSERT INTO kaname.service_accounts(id,account_id,name) VALUES($1,$2,'live-admin-collision')`, w.member, w.r.a)
	require.NoError(t, err)
	got, err = checkLiveAdministrative(t, w, "service_account:"+w.member, "admin", "account:"+w.r.a)
	require.NoError(t, err)
	require.False(t, got)
	_, err = w.r.admin.Exec(w.r.ctx, `UPDATE kaname.access_bindings SET expires_at=clock_timestamp() WHERE id=$1`, id)
	require.NoError(t, err)
	got, err = checkLiveAdministrative(t, w, "user:"+w.member, "admin", "account:"+w.r.a)
	require.NoError(t, err)
	require.False(t, got)
}

func TestLiveAdministrativeUnknownLedgerAndCanonicalClusterExpiry(t *testing.T) {
	w := delegationUCFixture(t)
	id := domain.AccessBindingID(ids.NewID("acb"))
	materializeAdministrativeHolder(t, w, id, domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(w.member)})
	// Удаление индекса происхождения не даёт права угадать carrier по одному fact.
	_, err := w.r.admin.Exec(w.r.ctx, `DELETE FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1`, id)
	require.NoError(t, err)
	got, err := checkLiveAdministrative(t, w, "user:"+w.member, "admin", "account:"+w.r.a)
	require.False(t, got)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
	w.grantClusterAdmin(t)
	got, err = checkLiveAdministrative(t, w, "user:"+w.member, "system_admin", "cluster:cluster_root")
	require.NoError(t, err)
	require.True(t, got)
	_, err = w.r.admin.Exec(w.r.ctx, `UPDATE kaname.cluster_admin_grants SET granted_until=clock_timestamp() WHERE subject_type='user' AND subject_id=$1`, w.member)
	require.NoError(t, err)
	got, err = checkLiveAdministrative(t, w, "user:"+w.member, "system_admin", "cluster:cluster_root")
	require.NoError(t, err)
	require.False(t, got)
}

func TestLiveAdministrativeLateNativeFactPageAndClosedWriter(t *testing.T) {
	w := delegationUCFixture(t)
	groups := make([]string, 257)
	bindings := make([]domain.AccessBindingID, 257)
	for i := range groups {
		groups[i] = fmt.Sprintf("grp%017d", i+1)
		bindings[i] = domain.AccessBindingID(fmt.Sprintf("acb%017d", i+1))
	}
	// Одна настоящая популяция, один object producer fanout. 257 отдельных
	// full-binding scans раньше повторно материализовали каждый новый IAM row.
	tag, err := w.r.admin.Exec(w.r.ctx, `INSERT INTO kaname.groups(id,account_id,name) SELECT id,$2,id FROM unnest($1::text[]) AS g(id)`, groups, w.r.a)
	require.NoError(t, err)
	require.EqualValues(t, 257, tag.RowsAffected())
	tag, err = w.r.admin.Exec(w.r.ctx, `INSERT INTO kaname.group_members(group_id,member_type,member_id) SELECT id,'user',$2 FROM unnest($1::text[]) AS g(id)`, groups, w.member)
	require.NoError(t, err)
	require.EqualValues(t, 257, tag.RowsAffected())
	seed, err := lifecycleOwner(w.r).Writer(w.r.ctx)
	require.NoError(t, err)
	defer func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(w.r.ctx), 5*time.Second)
		defer cancel()
		_ = seed.Rollback(ctx)
	}()
	for i, group := range groups {
		_, err = bindingset.Insert(w.r.ctx, seed.AccessBindingsW(), administrativeHolderBinding(w, bindings[i], domain.Subject{Type: domain.SubjectTypeGroup, ID: domain.SubjectID(group)}))
		require.NoError(t, err)
	}
	require.NoError(t, seed.Commit(w.r.ctx))
	engine := reconcile.New(kanamepg.NewReconcileAdapter(w.r.admin, w.source), slog.Default(), w.source)
	require.NoError(t, engine.ReconcileObject(w.r.ctx, "iam.account", w.r.a))
	expireBindingFixture(t, w.r, bindings[:256]...)
	var holders, facts, expired int
	var lastSubject string
	require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(DISTINCT e.binding_id),count(DISTINCT f.subject),count(DISTINCT e.binding_id) FILTER(WHERE b.expires_at<=clock_timestamp()),max(f.subject COLLATE "C") FROM kaname.access_binding_emitted_tuples e JOIN kaname.access_bindings b ON b.id=e.binding_id JOIN kaname.relation_fact f ON f.object_type='account' AND f.object_id=$1 AND f.relation='admin' AND f.subject=e.fga_user WHERE e.binding_id=ANY($2::text[]) AND e.member_object_type='iam.account' AND e.member_object_id=$1 AND e.relation='admin' AND e.object=$3`, w.r.a, bindings, "account:"+w.r.a).Scan(&holders, &facts, &expired, &lastSubject))
	require.Equal(t, 257, holders)
	require.Equal(t, 257, facts, "пагинация настоящих native facts, не только ledger")
	require.Equal(t, 256, expired)
	require.Equal(t, "group:"+groups[256]+"#member", lastSubject, "живой native fact расположен после первой страницы")
	got, err := checkLiveAdministrative(t, w, "user:"+w.member, "admin", "account:"+w.r.a)
	require.NoError(t, err)
	require.True(t, got, "живой fact за 256 истёкшими источниками")
	d := administrativeCheckerIntent(w)
	writer, err := w.participant.GrantDelegationWriter(declarerCtx(w.r.ctx, w.member), kaname.GrantDelegationCreate, d)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(w.r.ctx), 5*time.Second)
		defer cancel()
		_ = writer.Rollback(ctx)
	})
	checker, err := writer.TransactionRelationChecker(nil)
	require.NoError(t, err)
	cancelled, cancel := context.WithCancel(w.r.ctx)
	cancel()
	got, err = checker.Check(cancelled, "user:"+w.member, "admin", "account:"+w.r.a)
	require.False(t, got)
	require.ErrorIs(t, err, context.Canceled)
	require.NoError(t, writer.Rollback(w.r.ctx))
	got, err = checker.Check(w.r.ctx, "user:"+w.member, "admin", "account:"+w.r.a)
	require.False(t, got)
	require.Error(t, err, "ошибка закрытой TX не обходится альтернативным holder")
	authorityWaitReleased(t, w.r.runtime)
}

func TestLiveAdministrativeCurrentRoleMismatchCannotUseStaleFact(t *testing.T) {
	w := delegationUCFixture(t)
	id := domain.AccessBindingID(ids.NewID("acb"))
	materializeAdministrativeHolder(t, w, id, domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(w.member)})
	got, err := checkLiveAdministrative(t, w, "user:"+w.member, "admin", "account:"+w.r.a)
	require.NoError(t, err)
	require.True(t, got)
	// Authored роль уже изменена, старая projection/ledger ещё не перестроена.
	// Подтверждением не служат ни живой binding, ни прежний факт по отдельности.
	tag, err := w.r.admin.Exec(w.r.ctx, `UPDATE kaname.roles SET rules='[]',permissions='[]' WHERE id=$1`, domain.ClusterAdminRoleID)
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected())
	native, err := w.door.Check(w.r.ctx, "user:"+w.member, "admin", "account:"+w.r.a)
	require.NoError(t, err)
	require.True(t, native)
	got, err = checkLiveAdministrative(t, w, "user:"+w.member, "admin", "account:"+w.r.a)
	require.False(t, got)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
}

// kaname#1034: настоящий Role.Update повторяет native canonical visibility
// ссылки на custom role. Actor имеет D2 bind + точечный role.v_update, но не
// account-admin; admin tier выводится настоящим object materializer.
func TestLiveAdministrativeRoleUpdateReferenceObjectTier(t *testing.T) {
	for _, mode := range []string{"live", "expired", "condition"} {
		t.Run(mode, func(t *testing.T) {
			w := delegationUCFixture(t)
			writers, diagnostic := newRoleMutationDiagnosticFactory(t, w)
			require.NoError(t, lifecycleOwner(w.r).ActivateAuthorityBundle(w.r.ctx, w.r.bundle))
			ops := operations.NewRepo(w.r.runtime, "kaname")
			create := roleapp.NewCreateRoleUseCase(w.r.repo, ops, w.source).WithRoleAuthorityWriter(writers)
			makeRole := func(name string, rules domain.Rules) domain.RoleID {
				op, e := create.Execute(declarerCtx(w.r.ctx, w.owner), domain.Role{AccountID: domain.AccountID(w.r.a), Name: domain.RoleName(name), Rules: rules})
				require.NoError(t, e)
				done := awaitOperation(t, w.r.ctx, ops, op.ID)
				require.Nil(t, done.Error, "actual Role.Create(%s), operation=%s, raw diagnostic=%s", name, op.ID, diagnostic.snapshot())
				var id domain.RoleID
				require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT id FROM kaname.roles WHERE account_id=$1 AND name=$2`, w.r.a, name).Scan(&id))
				return id
			}
			ordinary := domain.Rules{{Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"}}}
			target := makeRole("live_reference_target", ordinary)
			edited := makeRole("live_reference_edited", ordinary)
			// ResourceNames у bind содержит именно ID: projector сохраняет его
			// в BoundRoleID. Bootstrap owner ещё не имеет native видимости ссылки.
			capability := domain.Rule{Module: "iam", Resources: []string{"role"}, Verbs: []string{"bind"}, ResourceNames: []string{string(target)}}
			var targetLive bool
			require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT live FROM kaname.roles WHERE id=$1 AND account_id=$2 AND name='live_reference_target'`, target, w.r.a).Scan(&targetLive))
			require.True(t, targetLive)
			for _, relation := range []string{"viewer", "v_list"} {
				visible, e := checkLiveAdministrative(t, w, "user:"+w.owner, relation, "iam_role:"+string(target))
				require.NoError(t, e)
				require.False(t, visible, "bootstrap ownership не подменяет native reference visibility")
			}
			// Ровно list на target, настоящая роль и materializer. Эта setup-выдача
			// не добавляет owner admin и не касается полномочий проверяемого member.
			referenceReader := makeRole("live_reference_reader", domain.Rules{{Module: "iam", Resources: []string{"role"}, Verbs: []string{"list"}}})
			readBinding := domain.AccessBindingID(ids.NewID("acb"))
			readSeed, err := w.r.repo.ParticipantAuthorityWriter(w.r.ctx, kaname.AuthorityWriteIntent{Kind: kaname.AuthorityBinding, Bundle: w.r.bundle, Plan: kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}})
			if readSeed != nil {
				t.Cleanup(func() {
					ctx, cancel := context.WithTimeout(context.WithoutCancel(w.r.ctx), 5*time.Second)
					defer cancel()
					_ = readSeed.Rollback(ctx)
				})
			}
			require.NoError(t, err)
			_, err = bindingset.Insert(w.r.ctx, readSeed.AccessBindingsW(), domain.AccessBinding{ID: readBinding, SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(w.owner), RoleID: referenceReader, ResourceType: "account", ResourceID: w.r.a, Scope: domain.ScopeAccount, Status: domain.AccessBindingStatusActive, Target: domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "iam.role", ID: string(target)}}}})
			require.NoError(t, err)
			require.NoError(t, readSeed.Commit(w.r.ctx))
			staged := withdrawalParticipant(t, w.r, nil)
			require.NoError(t, staged.ReconcileStagedBinding(declarerCtx(w.r.ctx, w.owner), readBinding, false, nil))
			var readObjects, readLists, readAdmins int
			require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(DISTINCT object),count(*) FILTER(WHERE object=$2 AND relation='v_list' AND fga_user=$3),count(*) FILTER(WHERE relation='admin') FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1 AND member_object_type='iam.role'`, readBinding, "iam_role:"+string(target), "user:"+w.owner).Scan(&readObjects, &readLists, &readAdmins))
			require.Equal(t, 1, readObjects)
			require.Equal(t, 1, readLists)
			require.Zero(t, readAdmins)
			ownerVisible, e := checkLiveAdministrative(t, w, "user:"+w.owner, "v_list", "iam_role:"+string(target))
			require.NoError(t, e)
			require.True(t, ownerVisible)
			ownerAdmin, e := checkLiveAdministrative(t, w, "user:"+w.owner, "admin", "iam_role:"+string(target))
			require.NoError(t, e)
			require.False(t, ownerAdmin)
			// Wildcard даёт настоящий admin tier, но не сочетается с names в
			// самом правиле. Узость задаёт конечный target object-carrier.
			holder := makeRole("live_reference_holder", domain.Rules{
				{Module: "iam", Resources: []string{"role"}, Verbs: []string{"*"}},
			})
			// D2 требует whole-scope carrier; отдельная capability-only роль не
			// добавляет account-admin или широких CRUD-прав на остальные roles.
			bindHolder := makeRole("live_reference_bind", domain.Rules{capability})
			var boundRole domain.RoleID
			require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT bound_role_id FROM kaname.role_bind_role_rule WHERE role_id=$1`, bindHolder).Scan(&boundRole))
			require.Equal(t, target, boundRole, "authored ID прошёл actual Create normalization и projection")
			binding := domain.AccessBindingID(ids.NewID("acb"))
			seed, err := w.r.repo.ParticipantAuthorityWriter(w.r.ctx, kaname.AuthorityWriteIntent{Kind: kaname.AuthorityBinding, Bundle: w.r.bundle, Plan: kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}})
			require.NoError(t, err)
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.WithoutCancel(w.r.ctx), 5*time.Second)
				defer cancel()
				_ = seed.Rollback(ctx)
			})
			_, err = bindingset.Insert(w.r.ctx, seed.AccessBindingsW(), domain.AccessBinding{ID: binding, SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(w.member), RoleID: holder, ResourceType: "account", ResourceID: w.r.a, Scope: domain.ScopeAccount, Status: domain.AccessBindingStatusActive, Target: domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "iam.role", ID: string(target)}, {Type: "iam.role", ID: string(edited)}}}})
			require.NoError(t, err)
			_, err = bindingset.Insert(w.r.ctx, seed.AccessBindingsW(), domain.AccessBinding{ID: domain.AccessBindingID(ids.NewID("acb")), SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(w.member), RoleID: bindHolder, ResourceType: "account", ResourceID: w.r.a, Scope: domain.ScopeAccount, Status: domain.AccessBindingStatusActive, Target: domain.AccessTarget{AllInScope: true}})
			require.NoError(t, err)
			require.NoError(t, seed.Commit(w.r.ctx))
			// Настоящий typed promotion, тот же метод, что завершает Role.Update;
			// DB/default=0 не выдаётся за действующий D2 carrier.
			owner := domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(w.owner)}
			promoter, err := writers.RoleAuthorityWriter(declarerCtx(w.r.ctx, w.owner), domain.Role{ID: bindHolder, AccountID: domain.AccountID(w.r.a)}, false, owner)
			require.NoError(t, err)
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.WithoutCancel(w.r.ctx), 5*time.Second)
				defer cancel()
				_ = promoter.Rollback(ctx)
			})
			require.NoError(t, promoter.(kaname.RoleCapabilityPromoter).PromoteRoleCapabilities(w.r.ctx, bindHolder))
			require.NoError(t, promoter.Commit(w.r.ctx))
			require.NoError(t, staged.ReconcileStagedBinding(declarerCtx(w.r.ctx, w.owner), binding, false, nil))
			var tier, viewer int
			require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FILTER(WHERE relation='admin'),count(*) FILTER(WHERE relation='viewer') FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1 AND object=$2`, binding, "iam_role:"+string(target)).Scan(&tier, &viewer))
			require.Positive(t, tier)
			require.Zero(t, viewer, "viewer должен пройти через реальный admin cascade")
			var objectAdmins, liveBindCarriers int
			require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(DISTINCT object) FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1 AND relation='admin' AND object LIKE 'iam_role:%'`, binding).Scan(&objectAdmins))
			require.Equal(t, 2, objectAdmins, "object-admin ограничен target и edited")
			require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.access_bindings WHERE role_id=$1 AND grant_capability_version=1 AND status='ACTIVE' AND revoked_at IS NULL`, bindHolder).Scan(&liveBindCarriers))
			require.Equal(t, 1, liveBindCarriers, "отдельный D2 carrier действительно promoted")
			admin, e := w.door.Check(w.r.ctx, "user:"+w.member, "admin", "account:"+w.r.a)
			require.NoError(t, e)
			require.False(t, admin)
			visible, e := checkLiveAdministrative(t, w, "user:"+w.member, "viewer", "iam_role:"+string(target))
			require.NoError(t, e)
			require.True(t, visible)
			switch mode {
			case "expired":
				changed := administrativeFixtureExec(t, w, `UPDATE kaname.access_bindings SET expires_at=clock_timestamp() WHERE id=$1`, binding)
				require.EqualValues(t, 1, changed)
			case "condition":
				// Реальный tuple уже есть. Довода MFA в запросе нет: условие не
				// снимается source wrapper и не становится безусловным admin.
				changed := administrativeFixtureExec(t, w, `UPDATE kaname.relation_fact SET condition_name='mfa_fresh',condition_params='{}' WHERE object_type='iam_role' AND object_id=$1 AND relation='admin' AND subject=$2`, target, "user:"+w.member)
				require.EqualValues(t, 1, changed)
			}
			// Только object carrier изменён режимом. D2 остаётся отдельным живым
			// whole-scope источником и не может заменить утраченный reference/method.
			require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.access_bindings WHERE role_id=$1 AND grant_capability_version=1 AND status='ACTIVE' AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>clock_timestamp()) AND NOT (target ? 'resources')`, bindHolder).Scan(&liveBindCarriers))
			require.Equal(t, 1, liveBindCarriers)
			if mode == "condition" {
				allowed, e := checkLiveAdministrative(t, w, "user:"+w.member, "admin", "iam_role:"+string(target))
				require.NoError(t, e)
				require.False(t, allowed, "MFA-условие admin не обходится источником")
				// Canonical visibility вправе использовать отдельный живой v_list;
				// false условие одного leaf не отравляет альтернативный довод.
			}
			update := roleapp.NewUpdateRoleUseCase(w.r.repo, ops, w.source).WithRoleAuthorityWriter(writers)
			op, e := update.Execute(declarerCtx(w.r.ctx, w.member), roleapp.UpdateRoleInput{ID: edited, Rules: domain.Rules{capability}, UpdateMask: []string{"rules"}})
			require.NoError(t, e)
			done := awaitOperation(t, w.r.ctx, ops, op.ID)
			var projected int
			require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.role_bind_role_rule WHERE role_id=$1`, edited).Scan(&projected))
			if mode != "expired" {
				require.Nil(t, done.Error)
				require.Equal(t, 1, projected)
			} else {
				require.NotNil(t, done.Error)
				require.Zero(t, projected)
			}
			authorityWaitReleased(t, w.r.runtime)
		})
	}
}
