// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// deletion_refusal_names_the_remainder_integration_test.go — отказ снятия
// человека и аккаунта называет первого держащего, шаг и счёт на живой базе
// (kaname#725, приёмка `deletion-refusals-name-the-remainder-and-the-step.md`,
// DRS-04, DRS-07, DRS-08, DRS-11, DRS-13).
//
// Утверждается текст ЦЕЛИКОМ и `ErrorInfo` парой с кодом: текст — контракт, а
// клиент решает по `reason` и `metadata`. «Первый» — наименьший `id`; `id`
// выдаются из случайного источника, поэтому ожидаемый первый вычисляется из
// посеянных, а не задаётся порядком создания.

import (
	"context"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/refusaldomain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// repoRefusal — отказ оператора снятия, как его видит клиент: тот же
// `MapRepoErr`, что у воркера операции.
func repoRefusal(t *testing.T, _ *removalEnv, del func(ctx context.Context) error) (*status.Status, map[string]string) {
	t.Helper()
	return mappedRefusal(t, del(context.Background()))
}

// mappedRefusal — разбор уже полученного отказа; отдельно от вызова, чтобы
// снятие из горутины пробы не звало require вне своей горутины.
func mappedRefusal(t *testing.T, err error) (*status.Status, map[string]string) {
	t.Helper()
	require.Error(t, err, "снятие обязано быть отвергнуто")
	// У этой repository-пробы нет composition root службы. До настоящего
	// MapRepoErr объявляем тот же продуктовый домен, что при старте службы.
	require.NoError(t, refusaldomain.Declare(refusaldomain.ProductSuffix))
	st, ok := status.FromError(shared.MapRepoErr(err))
	require.True(t, ok)
	require.Equal(t, codes.FailedPrecondition, st.Code())
	for _, d := range st.Details() {
		if ei, ok := d.(*errdetails.ErrorInfo); ok {
			require.Equal(t, "REFERENCE_IN_USE", ei.GetReason())
			require.Equal(t, refusaldomain.For(refusaldomain.ServiceIAM), ei.GetDomain())
			return st, ei.GetMetadata()
		}
	}
	t.Fatalf("у отказа нет ErrorInfo: %v", st)
	return nil, nil
}

func (e *removalEnv) userDeleteRefusal(t *testing.T, uid domain.UserID) (*status.Status, map[string]string) {
	t.Helper()
	return repoRefusal(t, e, func(ctx context.Context) error {
		w, err := e.repo.Writer(ctx)
		require.NoError(t, err)
		defer func() { _ = w.Rollback(ctx) }()
		return w.UsersW().Delete(ctx, uid)
	})
}

func (e *removalEnv) accountDeleteRefusal(t *testing.T, acc domain.AccountID) (*status.Status, map[string]string) {
	t.Helper()
	return repoRefusal(t, e, func(ctx context.Context) error {
		w, err := e.repo.Writer(ctx)
		require.NoError(t, err)
		defer func() { _ = w.Rollback(ctx) }()
		return w.AccountsW().Delete(ctx, acc)
	})
}

// grantOn — выдача на произвольную область (аккаунт либо проект).
func (e *removalEnv) grantOn(t *testing.T, scopeType, scopeID string, uid domain.UserID) domain.AccessBindingID {
	t.Helper()
	ctx := context.Background()
	w, err := e.repo.Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(ctx) }()
	ab, err := w.AccessBindingsW().Insert(ctx, domain.AccessBinding{
		ID:              domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding)),
		SubjectType:     userSubject(uid).Type,
		SubjectID:       userSubject(uid).ID,
		RoleID:          domain.RoleID(domain.ClusterAdminRoleID),
		ResourceType:    domain.ResourceType(scopeType),
		ResourceID:      scopeID,
		GrantedByUserID: removalCloudAdmin,
		Target:          domain.AccessTarget{AllInScope: true},
	})
	require.NoError(t, err, "Дано: выдача на %s %s", scopeType, scopeID)
	require.NoError(t, w.AccessBindingsW().InsertSubjects(ctx, ab.ID, []domain.Subject{userSubject(uid)}))
	require.NoError(t, w.Commit(ctx))
	return ab.ID
}

func smallest(xs ...string) string {
	s := append([]string(nil), xs...)
	sort.Strings(s)
	return s[0]
}

// TestDRS04_TwoOwnAccountsNameTheSmallest — DRS-04: два своих аккаунта —
// назван наименьший, счёт два.
func TestDRS04_TwoOwnAccountsNameTheSmallest(t *testing.T) {
	e := newRemovalEnv(t)
	ctx := context.Background()
	uid, acc := bootstrapAdmin(t, ctx, e.repo, "drs04")
	acc2 := seedAccount(t, ctx, e.repo, "drs04-second", uid)
	first := smallest(string(acc), string(acc2.ID))

	st, meta := e.userDeleteRefusal(t, uid)
	require.Equal(t, "User "+string(uid)+" owns accounts and cannot be deleted: delete Account "+first+
		" first (accounts owned: 2)", st.Message())
	require.Equal(t, map[string]string{"resource_type": "account", "resource_id": first, "remaining": "2"}, meta)
}

// TestDRS07_TwoBindingsInTwoScopesNameTheSmallest — DRS-07 (и DRS-05 охраной):
// две выдачи в двух областях — названа наименьшая с её областью; признак есть
// на рубеже охраны.
func TestDRS07_TwoBindingsInTwoScopesNameTheSmallest(t *testing.T) {
	e := newRemovalEnv(t)
	uid := e.homeless(t, "drs07")
	_, accF, prjQ := e.selfRegistered(t, "drs07f")
	onAccount := e.grantOn(t, "account", string(accF), uid)
	onProject := e.grantOn(t, "project", string(prjQ), uid)

	firstID, scopeType, scopeID := string(onAccount), "account", string(accF)
	if string(onProject) < string(onAccount) {
		firstID, scopeType, scopeID = string(onProject), "project", string(prjQ)
	}
	want := fmt.Sprintf("User %s has active access bindings and cannot be deleted: AccessBinding %s on %s %s is revoked by an administrator of that %s (active bindings: 2)",
		uid, firstID, scopeType, scopeID, scopeType)

	require.Equal(t, opOutcome{code: 9, msg: want}, e.deleteUser(t, uid, uid))
	st, meta := e.userDeleteRefusal(t, uid)
	require.Equal(t, want, st.Message())
	require.Equal(t, map[string]string{"resource_type": "access_binding", "resource_id": firstID, "remaining": "2"}, meta)
}

// TestDRS08_GroupMembershipNamesTheGroup — DRS-08: выдач нет, есть членство в
// группе — названа группа; близнец — после исключения снятие проходит.
func TestDRS08_GroupMembershipNamesTheGroup(t *testing.T) {
	e := newRemovalEnv(t)
	ctx := context.Background()
	uid := e.homeless(t, "drs08")
	_, accF, _ := e.selfRegistered(t, "drs08f")
	grp := ids.NewID(domain.PrefixGroup)
	_, err := e.pool.Exec(ctx, `INSERT INTO kaname.groups (id, account_id, name) VALUES ($1, $2, $3)`,
		grp, string(accF), "grp-drs08")
	require.NoError(t, err, "Дано: группа")
	_, err = e.pool.Exec(ctx, `INSERT INTO kaname.group_members (group_id, member_type, member_id) VALUES ($1, 'user', $2)`,
		grp, string(uid))
	require.NoError(t, err, "Дано: членство")

	st, meta := e.userDeleteRefusal(t, uid)
	require.Equal(t, "User "+string(uid)+" is a member of one or more groups and cannot be deleted: Group "+grp+
		" removes the member by its administrator (groups: 1)", st.Message())
	require.Equal(t, map[string]string{"resource_type": "group", "resource_id": grp, "remaining": "1"}, meta)

	_, err = e.pool.Exec(ctx, `DELETE FROM kaname.group_members WHERE group_id = $1`, grp)
	require.NoError(t, err)
	require.Equal(t, opOutcome{}, e.deleteUser(t, uid, uid), "близнец: членства нет — снятие проходит")
}

// TestDRS11_EachAccountHolderKindHasItsOwnRefusal — DRS-11 и DRS-10: по
// одному отказу на вид держащего; при проекте и сервисном аккаунте вместе
// назван проект (порядок видов).
func TestDRS11_EachAccountHolderKindHasItsOwnRefusal(t *testing.T) {
	e := newRemovalEnv(t)
	ctx := context.Background()
	type seeded struct {
		insert   string
		prefix   string
		phrase   string
		noun     string
		label    string
		metaType string
		name     string // имя — по ограничению формы имени своей таблицы
	}
	for _, k := range []seeded{
		{`INSERT INTO kaname.service_accounts (id, account_id, name) VALUES ($1, $2, $3)`,
			domain.PrefixServiceAccount, "contains service accounts", "ServiceAccount", "service accounts", "service_account", "drs11-sa"},
		{`INSERT INTO kaname.groups (id, account_id, name) VALUES ($1, $2, $3)`,
			domain.PrefixGroup, "contains groups", "Group", "groups", "group", "drs11-group"},
		{`INSERT INTO kaname.roles (id, account_id, name, description, permissions) VALUES ($1, $2, $3, 'drs11', '["iam.users.*.read"]'::jsonb)`,
			domain.PrefixRole, "contains custom roles", "Role", "custom roles", "role", "drs11_role"},
	} {
		t.Run(k.metaType, func(t *testing.T) {
			uid, acc := e.emptied(t, "drs11"+k.metaType)
			id := ids.NewID(k.prefix)
			_, err := e.pool.Exec(ctx, k.insert, id, string(acc), k.name)
			require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): Дано: %s", k.metaType)

			want := fmt.Sprintf("Account %s %s and cannot be deleted: delete %s %s first (%s: 1)",
				acc, k.phrase, k.noun, id, k.label)
			require.Equal(t, opOutcome{code: 9, msg: want}, e.deleteAccount(t, uid, acc))
			st, meta := e.accountDeleteRefusal(t, acc)
			require.Equal(t, want, st.Message())
			require.Equal(t, map[string]string{"resource_type": k.metaType, "resource_id": id, "remaining": "1"}, meta)
		})
	}

	t.Run("проект и сервисный аккаунт — назван проект", func(t *testing.T) {
		uid, acc, prj := e.selfRegistered(t, "drs11both")
		_, err := e.pool.Exec(ctx, `INSERT INTO kaname.service_accounts (id, account_id, name) VALUES ($1, $2, $3)`,
			ids.NewID(domain.PrefixServiceAccount), string(acc), "drs11-both")
		require.NoError(t, err)
		require.Equal(t, opOutcome{code: 9, msg: "Account " + string(acc) + " contains projects and cannot be deleted: delete Project " +
			string(prj) + " first (projects: 1)"}, e.deleteAccount(t, uid, acc))
	})
}

// DRS-13: усиленный compatibility admission перенёс ожидание ДО снимка
// DELETE. Прежнее расписание «обычный AB Writer фиксируется после снимка охраны»
// теперь недостижимо: оба Writer владеют одним exclusive fence. Здесь остаются
// настоящая конкуренция и полный named refusal. Отдельная schema-проба ниже
// проверяет Р2 на native trigger, но не выдаётся за старый after-snapshot Given.
func TestDRS13_HolderCommittedBeforeWriterAdmissionIsNamedTheSameWay(t *testing.T) {
	e := newRemovalEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	uid := e.homeless(t, "drs13")
	_, accF, _ := e.selfRegistered(t, "drs13f")

	holderTrace := &finalDecisionTrace{}
	holderPool := finalDecisionTracePool(t, ctx, e.pool, holderTrace)
	t0, err := kanamepg.New(holderPool, nil).Writer(ctx)
	require.NoError(t, err)
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		_ = t0.Rollback(cleanup)
	}()
	ab, err := t0.AccessBindingsW().Insert(ctx, domain.AccessBinding{
		ID:              domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding)),
		SubjectType:     userSubject(uid).Type,
		SubjectID:       userSubject(uid).ID,
		RoleID:          domain.RoleID(domain.ClusterAdminRoleID),
		ResourceType:    domain.ResourceType("account"),
		ResourceID:      string(accF),
		GrantedByUserID: removalCloudAdmin,
		Target:          domain.AccessTarget{AllInScope: true},
	})
	require.NoError(t, err, "Дано: выдача B3 в незафиксированной T0")
	require.NoError(t, t0.AccessBindingsW().InsertSubjects(ctx, ab.ID, []domain.Subject{userSubject(uid)}))

	holderPID := int(holderTrace.pid.Load())
	require.NotZero(t, holderPID)
	deleteTrace := &finalDecisionTrace{}
	deletePool := finalDecisionTracePool(t, ctx, e.pool, deleteTrace)
	type outcome struct {
		admission, deletion, rollback error
	}
	done := make(chan outcome, 1)
	joined := false
	defer func() {
		cancel()
		if !joined {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("Writer/Delete не завершился после cancel")
			}
		}
	}()
	go func() {
		w, err := kanamepg.New(deletePool, nil).Writer(ctx)
		if err != nil {
			done <- outcome{admission: err}
			return
		}
		err = w.UsersW().Delete(ctx, uid)
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		rollback := w.Rollback(cleanup)
		stop()
		done <- outcome{deletion: err, rollback: rollback}
	}()

	// Наблюдаем точный ранний Writer fence, его two-int key и PID T0.
	// Ошибка admission, другой lock или уже начавшийся DELETE не подходят.
	require.Eventually(t, func() bool {
		pid := int(deleteTrace.pid.Load())
		if pid == 0 {
			return false
		}
		var waiting bool
		err := e.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity a
 WHERE a.pid=$1 AND a.datname=current_database() AND a.wait_event_type='Lock'
 AND $2::integer=ANY(pg_blocking_pids(a.pid))
 AND position('SELECT pg_advisory_xact_lock(1262569292,0)' in a.query)>0
 AND EXISTS(SELECT 1 FROM pg_locks l WHERE l.pid=a.pid AND NOT l.granted
   AND l.locktype='advisory' AND l.database=(SELECT oid FROM pg_database WHERE datname=current_database())
   AND l.classid=1262569292::oid AND l.objid=0::oid AND l.objsubid=2 AND l.mode='ExclusiveLock'))`, pid, holderPID).Scan(&waiting)
		return err == nil && waiting
	}, 30*time.Second, 10*time.Millisecond, "Writer должен ждать точный compat fence T0 до её commit")

	var visible bool
	require.NoError(t, e.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM kaname.access_bindings WHERE id=$1)`, string(ab.ID)).Scan(&visible))
	require.False(t, visible, "B3 ещё не зафиксирована, DELETE пока не начался")
	require.NoError(t, t0.Commit(ctx), "Дано: B3 зафиксирована до допуска ожидающего Writer")

	var result outcome
	select {
	case result = <-done:
		joined = true
	case <-time.After(30 * time.Second):
		t.Fatal("Writer/Delete не завершился после commit держателя")
	}
	require.NoError(t, result.admission)
	require.NoError(t, result.rollback)
	st, meta := mappedRefusal(t, result.deletion)
	require.Equal(t, fmt.Sprintf("User %s has active access bindings and cannot be deleted: AccessBinding %s on account %s is revoked by an administrator of that account (active bindings: 1)",
		uid, ab.ID, accF), st.Message())
	require.Equal(t, map[string]string{"resource_type": "access_binding", "resource_id": string(ab.ID), "remaining": "1"}, meta)
	var users, bindings int
	require.NoError(t, e.pool.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM kaname.users WHERE id=$1),
 (SELECT count(*) FROM kaname.access_bindings WHERE id=$2 AND revoked_at IS NULL)`, string(uid), string(ab.ID)).Scan(&users, &bindings))
	require.Equal(t, 1, users)
	require.Equal(t, 1, bindings)
}

// Native schema-рубеж и производственная гидратация обязаны дать ту же полную
// форму, что обычный guard. Это самостоятельное доказательство Р2, без
// имитации concurrent commit после снимка и без замены named oracle fallback.
func TestDRS13_SchemaBackstopNamesCommittedHolder(t *testing.T) {
	e := newRemovalEnv(t)
	ctx := context.Background()
	uid := e.homeless(t, "drs13-schema")
	_, acc, _ := e.selfRegistered(t, "drs13-schema-holder")
	ab := e.grantOn(t, "account", string(acc), uid)
	guard, guardMeta := e.userDeleteRefusal(t, uid)
	native, err, cleanupErr := kanamepg.UserDeleteSchemaRefusalForTest(ctx, e.repo, uid)
	require.NoError(t, cleanupErr, "schema Writer должен штатно откатиться")
	require.NotNil(t, native, "должен сработать настоящий backend trigger, не программный guard")
	require.Equal(t, "23503", native.Code)
	require.Equal(t, "access_binding_subjects_subject_ref", native.ConstraintName)
	require.Equal(t, fmt.Sprintf("user %s is referenced by an access binding subject and cannot be deleted", uid), native.Message)
	st, meta := mappedRefusal(t, err)
	require.Equal(t, fmt.Sprintf("User %s has active access bindings and cannot be deleted: AccessBinding %s on account %s is revoked by an administrator of that account (active bindings: 1)", uid, ab, acc), st.Message())
	require.Equal(t, map[string]string{"resource_type": "access_binding", "resource_id": string(ab), "remaining": "1"}, meta)
	require.Equal(t, guard.Message(), st.Message())
	require.Equal(t, guardMeta, meta)
	var users, bindings, subjects int
	require.NoError(t, e.pool.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM kaname.users WHERE id=$1),
 (SELECT count(*) FROM kaname.access_bindings WHERE id=$2 AND revoked_at IS NULL),
 (SELECT count(*) FROM kaname.access_binding_subjects WHERE binding_id=$2 AND subject_type='user' AND subject_id=$1)`, string(uid), string(ab)).Scan(&users, &bindings, &subjects))
	require.Equal(t, 1, users)
	require.Equal(t, 1, bindings)
	require.Equal(t, 1, subjects)
}
