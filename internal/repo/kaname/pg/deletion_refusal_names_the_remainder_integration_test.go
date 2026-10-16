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
	st, ok := status.FromError(shared.MapRepoErr(err))
	require.True(t, ok)
	require.Equal(t, codes.FailedPrecondition, st.Code())
	for _, d := range st.Details() {
		if ei, ok := d.(*errdetails.ErrorInfo); ok {
			require.Equal(t, "REFERENCE_IN_USE", ei.GetReason())
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
	}
	for _, k := range []seeded{
		{`INSERT INTO kaname.service_accounts (id, account_id, name) VALUES ($1, $2, $3)`,
			domain.PrefixServiceAccount, "contains service accounts", "ServiceAccount", "service accounts", "service_account"},
		{`INSERT INTO kaname.groups (id, account_id, name) VALUES ($1, $2, $3)`,
			domain.PrefixGroup, "contains groups", "Group", "groups", "group"},
		{`INSERT INTO kaname.roles (id, account_id, name, permissions) VALUES ($1, $2, $3, '[]'::jsonb)`,
			domain.PrefixRole, "contains custom roles", "Role", "custom roles", "role"},
	} {
		t.Run(k.metaType, func(t *testing.T) {
			uid, acc := e.emptied(t, "drs11"+k.metaType)
			id := ids.NewID(k.prefix)
			_, err := e.pool.Exec(ctx, k.insert, id, string(acc), "drs11-"+k.metaType)
			require.NoError(t, err, "Дано: %s", k.metaType)

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

// TestDRS13_HolderCommittedAfterTheGuardSnapshotIsNamedTheSameWay — DRS-13
// (рубеж гонки, Р2): выдача зафиксирована ПОСЛЕ снимка охраны и до триггера
// схемы — снятие отвергает триггер, и отказ той же формы, что у охраны, с
// этой выдачей.
//
// Окно ставится детерминированно, без задержек в схеме: выдача B3 вставлена
// транзакцией T0 и не зафиксирована — вставка держит ключевой замок строки
// человека (`subject_ref_exists`, FOR KEY SHARE). Снятие берёт снимок (B3 ему
// не видна — охрана пропускает), упирается в замок строки и ждёт T0. T0
// фиксируется; триггер схемы читает своим снимком и видит B3.
func TestDRS13_HolderCommittedAfterTheGuardSnapshotIsNamedTheSameWay(t *testing.T) {
	e := newRemovalEnv(t)
	ctx := context.Background()
	uid := e.homeless(t, "drs13")
	_, accF, _ := e.selfRegistered(t, "drs13f")

	t0, err := e.repo.Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = t0.Rollback(ctx) }()
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

	done := make(chan error, 1)
	go func() {
		w, err := e.repo.Writer(ctx)
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = w.Rollback(ctx) }()
		done <- w.UsersW().Delete(ctx, uid)
	}()

	// Снятие стоит в окне — ждёт замка строки человека, который держит T0.
	deadline := time.Now().Add(30 * time.Second)
	for {
		var waiting int
		require.NoError(t, e.pool.QueryRow(ctx,
			`SELECT count(*) FROM pg_locks WHERE NOT granted AND locktype IN ('transactionid', 'tuple')`).Scan(&waiting))
		if waiting > 0 {
			break
		}
		require.True(t, time.Now().Before(deadline), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): снятие не дошло до окна гонки")
		time.Sleep(10 * time.Millisecond)
	}
	require.NoError(t, t0.Commit(ctx), "Дано: B3 зафиксирована в окне")

	st, meta := mappedRefusal(t, <-done)
	require.Equal(t, fmt.Sprintf("User %s has active access bindings and cannot be deleted: AccessBinding %s on account %s is revoked by an administrator of that account (active bindings: 1)",
		uid, ab.ID, accF), st.Message())
	require.Equal(t, map[string]string{"resource_type": "access_binding", "resource_id": string(ab.ID), "remaining": "1"}, meta)
}
