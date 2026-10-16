// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// identity_removal_in_order_integration_test.go — человек снимает себя после
// своего аккаунта (задача kaname#664, приёмка
// `docs/engineering/acceptance/own-account-and-identity-are-removed-in-order.md`,
// сценарии S3: KN664-30…48, и DoD 2 — читатели колонки дома).
//
// # Как строится «Когда»
//
// Настоящие глаголы (`UserService.Delete`, `AccountService.Delete`,
// `UserService.Invite`, `AccountService.Create`) над настоящей базой. Отказ
// токена на предъявлении судится ПРАВИЛОМ ОТЗЫВА пути запроса
// (`tokenrevocation.Revoked`) против настоящего авторитета отсечек
// (`MintedTokenRevocationRepo`) — тем вопросом, который читатель
// предъявленного удостоверения задаёт на промахе своего кеша. Окно кеша
// (`RevocationCacheTTL`) — свойство читателя, общее для всякой отсечки; его
// держит `presentedcred` (`TestKAN_REV_01…04`), здесь оно не пересказывается.
//
// # Гонки
//
// KN664-40 и KN664-41 — по сто повторов; каждый повтор утверждает, что его исход
// входит в перечисленный приёмкой набор, прогон печатает число повторов по
// каждому исходу. Исходы, производимые дверью края (синхронные 401/403), на
// этом уровне не производятся и в наборе не числятся — это сказано, а не
// умолчано.

import (
	"context"
	stderrors "errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"

	accountapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/account"
	userapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/user"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/tokenrevocation"
)

// removalCloudAdmin — вызывающий от имени облака. Глагол прав не решает (их
// решает край), поэтому его личность здесь — только актор аудита и отсечки.
const removalCloudAdmin = domain.UserID("usr-kn664-cloud-admin")

func stripSentinel(err error) string { return iamerr.StripSentinel(err) }

func isFailedPrecondition(err error) bool { return stderrors.Is(err, iamerr.ErrFailedPrecondition) }

// homeless — человек U после KN664-10: аккаунт снят, колонка дома пуста.
func (e *removalEnv) homeless(t *testing.T, tag string) domain.UserID {
	t.Helper()
	uid, acc := e.emptied(t, tag)
	require.Equal(t, opOutcome{}, e.deleteAccount(t, uid, acc), "Дано: аккаунт U снят (KN664-10)")
	return uid
}

// tokenClaims — утверждения токена доступа человека, выпущенного в момент at.
func tokenClaims(sub domain.UserID, at time.Time) jwt.MapClaims {
	return jwt.MapClaims{"sub": string(sub), "iat": float64(at.Unix()), "jti": "jti-" + ids.NewID("tok")}
}

func (e *removalEnv) revokedOnPresentation(t *testing.T, claims jwt.MapClaims) bool {
	t.Helper()
	revoked, err := tokenrevocation.Revoked(context.Background(), kanamepg.NewMintedTokenRevocationRepo(e.pool), claims)
	require.NoError(t, err, "авторитет отзыва обязан ответить")
	return revoked
}

func (e *removalEnv) userRow(t *testing.T, uid domain.UserID) int {
	t.Helper()
	return countRows(t, e.pool, `SELECT count(*) FROM kaname.users WHERE id = $1`, string(uid))
}

// seedSession — живая браузерная сессия человека.
func (e *removalEnv) seedSession(t *testing.T, uid domain.UserID, n int) string {
	t.Helper()
	digest := fmt.Sprintf("%064x", n)
	_, err := e.pool.Exec(context.Background(), `
		INSERT INTO kaname.human_sessions
		       (id, user_id, bearer_digest, authenticated_at, last_presented_at, expires_at,
		        assurance_level, presented_methods)
		VALUES ($1, $2, $3, now(), now(), now() + interval '1 hour', '2', ARRAY['password'])`,
		"hs-"+ceremonyPad(fmt.Sprint(n)), string(uid), digest)
	require.NoError(t, err, "Дано: браузерная сессия")
	return digest
}

// grant — выдача роли администратора проекта субъектам на проект; первый
// субъект — проекция `subject_*`, остальные — дочерняя таблица.
func (e *removalEnv) grant(t *testing.T, prj domain.ProjectID, subjects ...domain.Subject) domain.AccessBindingID {
	t.Helper()
	ctx := context.Background()
	w, err := e.repo.Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(ctx) }()
	ab, err := w.AccessBindingsW().Insert(ctx, domain.AccessBinding{
		ID:              domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding)),
		SubjectType:     subjects[0].Type,
		SubjectID:       subjects[0].ID,
		RoleID:          domain.RoleID(domain.ClusterAdminRoleID),
		ResourceType:    domain.ResourceType("project"),
		ResourceID:      string(prj),
		GrantedByUserID: removalCloudAdmin,
		Target:          domain.AccessTarget{AllInScope: true},
	})
	require.NoError(t, err, "Дано: выдача")
	require.NoError(t, w.AccessBindingsW().InsertSubjects(ctx, ab.ID, subjects))
	require.NoError(t, w.Commit(ctx))
	return ab.ID
}

// revoke — отзыв выдачи тем же оператором, что `AccessBindingService.Revoke`:
// строка остаётся в состоянии REVOKED.
func (e *removalEnv) revoke(t *testing.T, id domain.AccessBindingID) {
	t.Helper()
	ctx := context.Background()
	w, err := e.repo.Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(ctx) }()
	_, err = w.AccessBindingsW().RevokeGuarded(ctx, id, removalCloudAdmin)
	require.NoError(t, err, "Дано: выдача отозвана")
	require.NoError(t, w.Commit(ctx))
	require.Equal(t, 1, countRows(t, e.pool,
		`SELECT count(*) FROM kaname.access_bindings WHERE id = $1 AND status = 'REVOKED'`, string(id)),
		"предпосылка: строка выдачи осталась в состоянии REVOKED")
}

func userSubject(uid domain.UserID) domain.Subject {
	return domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(uid)}
}

// TestKN664_30_PersonRemovesSelfAfterTheAccount — KN664-30 и KN664-32 (близнец
// последнего «Тогда»: токен другого человека не задет).
func TestKN664_30_PersonRemovesSelfAfterTheAccount(t *testing.T) {
	e := newRemovalEnv(t)
	ctx := context.Background()
	uid := e.homeless(t, "30")
	other, _, _ := e.selfRegistered(t, "30n")
	digest := e.seedSession(t, uid, 6640)
	// Адреса подтверждены: токен человека с неподтверждённым адресом
	// отвергается правилом предъявления и без отсечки (kaname#456, Р5а), и
	// положительный контроль был бы невыразим.
	_, err := e.pool.Exec(ctx, `UPDATE kaname.users SET email_verified_at = now() WHERE id = ANY($1)`,
		[]string{string(uid), string(other)})
	require.NoError(t, err)
	issued := time.Now().Add(-time.Minute)
	presentedBefore := tokenClaims(uid, issued)
	neverPresented := tokenClaims(uid, issued)
	ofOther := tokenClaims(other, issued)
	require.False(t, e.revokedOnPresentation(t, presentedBefore), "предпосылка: до снятия токен U принимается")
	require.False(t, e.revokedOnPresentation(t, ofOther), "предпосылка: токен N принимается")

	before := time.Now()
	require.Equal(t, opOutcome{}, e.deleteUser(t, uid, uid), "человек снимает себя после своего аккаунта")
	after := time.Now()

	rd, err := e.repo.Reader(ctx)
	require.NoError(t, err)
	_, err = rd.Users().Get(ctx, uid)
	_ = rd.Rollback(ctx)
	require.Error(t, err)
	require.Equal(t, "User "+string(uid)+" not found", stripSentinel(err))

	_, reason, err := kanamepg.NewHumanSessionRepo(e.pool).Resolve(ctx, domain.BearerDigest(digest), time.Now())
	require.NoError(t, err)
	require.NotEmpty(t, reason, "сессии снятого человека нет — единый отказ «сессии нет»")
	require.Zero(t, countRows(t, e.pool, `SELECT count(*) FROM kaname.user_login_methods WHERE user_id = $1`, string(uid)),
		"способы входа ушли вместе с человеком")

	at, found, err := kanamepg.NewMintedTokenRevocationRepo(e.pool).RevokedBefore(ctx, string(uid))
	require.NoError(t, err)
	require.True(t, found, "снятие личности обязано записать отсечку субъекта (Р5)")
	require.False(t, at.Before(before.Add(-time.Second)) || at.After(after.Add(time.Second)),
		"момент отсечки %s вне окна снятия [%s, %s]", at, before, after)
	var decidedBy string
	require.NoError(t, e.pool.QueryRow(ctx,
		`SELECT revoked_by FROM kaname.minted_token_revocations WHERE subject = $1`, string(uid)).Scan(&decidedBy))
	require.Equal(t, string(uid), decidedBy, "решивший отсечку — актор снятия")

	require.True(t, e.revokedOnPresentation(t, presentedBefore),
		"токен U, выпущенный до снятия, на предъявлении после окна отвергается")
	require.True(t, e.revokedOnPresentation(t, neverPresented),
		"токен U, не предъявлявшийся до снятия, отвергается сразу")
	require.False(t, e.revokedOnPresentation(t, ofOther), "KN664-32: токен N, выпущенный в ту же секунду, принимается")
}

// TestKN664_31_PersonWhoStillOwnsTheAccountIsRefused — KN664-31, близнец KN664-30.
func TestKN664_31_PersonWhoStillOwnsTheAccountIsRefused(t *testing.T) {
	e := newRemovalEnv(t)
	ctx := context.Background()
	uid, acc := e.emptied(t, "31")
	digest := e.seedSession(t, uid, 6631)

	require.Equal(t, opOutcome{code: 9, msg: "User " + string(uid) + " owns accounts and cannot be deleted: delete Account " +
		string(acc) + " first (accounts owned: 1)"},
		e.deleteUser(t, uid, uid))

	require.Equal(t, 1, e.userRow(t, uid))
	require.Equal(t, 1, countRows(t, e.pool, `SELECT count(*) FROM kaname.accounts WHERE id = $1`, string(acc)))
	res, reason, err := kanamepg.NewHumanSessionRepo(e.pool).Resolve(ctx, domain.BearerDigest(digest), time.Now())
	require.NoError(t, err)
	require.Empty(t, reason, "сессия U по-прежнему принимается")
	require.Equal(t, uid, res.User.ID)
	_, found, err := kanamepg.NewMintedTokenRevocationRepo(e.pool).RevokedBefore(ctx, string(uid))
	require.NoError(t, err)
	require.False(t, found, "отказанное снятие не оставило отсечки: токен U принимается")
}

// TestKN664_33_35_RecordsThatOutliveThePerson — KN664-33 (запись отзыва
// выхода), KN664-34 (ключ сервисного аккаунта, выпущенный человеком, при
// отозванной выдаче в чужом аккаунте), KN664-35 (личный токен уходит вместе с
// человеком).
func TestKN664_33_35_RecordsThatOutliveThePerson(t *testing.T) {
	e := newRemovalEnv(t)
	ctx := context.Background()
	uid := e.homeless(t, "33")
	_, accB, prjB := e.selfRegistered(t, "33b")

	jti := "jti-kn664-33-" + string(uid)
	_, err := e.pool.Exec(ctx, `INSERT INTO kaname.session_revocations (token_jti, user_id, ttl_expires_at, reason)
		VALUES ($1, $2, now() + interval '1 hour', 'logout')`, jti, string(uid))
	require.NoError(t, err, "Дано: U выходил из системы")
	personal := ids.NewID("uoc")
	_, err = e.pool.Exec(ctx, `INSERT INTO kaname.user_oauth_clients
		(id, user_id, created_by_user_id, credential_kind, secret_hash, expires_at)
		VALUES ($1, $2, $2, 'SECRET', decode(repeat('ab', 32), 'hex'), now() + interval '1 day')`, personal, string(uid))
	require.NoError(t, err, "Дано: личный токен U")
	sa := ids.NewID(domain.PrefixServiceAccount)
	_, err = e.pool.Exec(ctx, `INSERT INTO kaname.service_accounts (id, account_id, name) VALUES ($1, $2, 'kn664-33')`,
		sa, string(accB))
	require.NoError(t, err)
	saKey := ids.NewID("soc")
	_, err = e.pool.Exec(ctx, `INSERT INTO kaname.service_account_oauth_clients
		(id, sva_id, created_by_user_id, credential_kind, secret_hash, expires_at)
		VALUES ($1, $2, $3, 'SECRET', decode(repeat('cd', 32), 'hex'), now() + interval '1 day')`,
		saKey, sa, string(uid))
	require.NoError(t, err, "Дано: U выпустил ключ сервисного аккаунта в B")
	e.revoke(t, e.grant(t, prjB, userSubject(uid)))

	require.Equal(t, opOutcome{}, e.deleteUser(t, uid, uid))

	require.Equal(t, 1, countRows(t, e.pool, `SELECT count(*) FROM kaname.session_revocations WHERE token_jti = $1`, jti),
		"KN664-33: запись отзыва выхода переживает человека до своего срока")
	var createdBy string
	require.NoError(t, e.pool.QueryRow(ctx,
		`SELECT created_by_user_id FROM kaname.service_account_oauth_clients WHERE id = $1`, saKey).Scan(&createdBy))
	require.Equal(t, string(uid), createdBy, "KN664-34: ключ сервисного аккаунта сохраняет атрибуцию снятого")
	require.Zero(t, countRows(t, e.pool, `SELECT count(*) FROM kaname.user_oauth_clients WHERE id = $1`, personal),
		"KN664-35: личный токен уходит вместе с человеком")
}

// TestKN664_36_46_47_RevokedBindingDoesNotHoldThePerson — KN664-36 (активная
// выдача держит), KN664-46 (отозванная — нет), KN664-47 (человек — второй
// субъект; отозвана — нет, не отозвана — держит).
func TestKN664_36_46_47_RevokedBindingDoesNotHoldThePerson(t *testing.T) {
	for _, tc := range []struct {
		name    string
		second  bool
		revoked bool
	}{
		{name: "KN664-36 активная, первый субъект"},
		{name: "KN664-46 отозванная, первый субъект", revoked: true},
		{name: "KN664-47 близнец: активная, второй субъект", second: true},
		{name: "KN664-47 отозванная, второй субъект", second: true, revoked: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newRemovalEnv(t)
			uid := e.homeless(t, "36")
			_, accB, prjB := e.selfRegistered(t, "36b")
			subjects := []domain.Subject{userSubject(uid)}
			if tc.second {
				first := e.seedMember(t, "36x", accB)
				subjects = []domain.Subject{userSubject(first), userSubject(uid)}
			}
			ab := e.grant(t, prjB, subjects...)
			if tc.revoked {
				e.revoke(t, ab)
			}

			got := e.deleteUser(t, uid, uid)
			if tc.revoked {
				require.Equal(t, opOutcome{}, got, "отозванная выдача — история, а не держатель (Р10)")
				require.Zero(t, e.userRow(t, uid))
				return
			}
			require.Equal(t, opOutcome{code: 9, msg: "User " + string(uid) + " has active access bindings and cannot be deleted: AccessBinding " +
				string(ab) + " on project " + string(prjB) + " is revoked by an administrator of that project (active bindings: 1)"}, got)
			require.Equal(t, 1, e.userRow(t, uid), "строка U на месте")
		})
	}
}

// TestKN664_48_GroupAndServiceAccountWithOnlyRevokedBindings — KN664-48 и его
// близнец.
func TestKN664_48_GroupAndServiceAccountWithOnlyRevokedBindings(t *testing.T) {
	for _, revoked := range []bool{true, false} {
		t.Run(fmt.Sprintf("revoked=%v", revoked), func(t *testing.T) {
			e := newRemovalEnv(t)
			ctx := context.Background()
			_, accB, prjB := e.selfRegistered(t, "48")
			grp := domain.GroupID(ids.NewID(domain.PrefixGroup))
			sa := domain.ServiceAccountID(ids.NewID(domain.PrefixServiceAccount))
			w, err := e.repo.Writer(ctx)
			require.NoError(t, err)
			_, err = w.GroupsW().Insert(ctx, domain.Group{ID: grp, AccountID: accB, Name: "kn664-48", Labels: domain.Labels{}})
			require.NoError(t, err)
			_, err = w.ServiceAccountsW().Insert(ctx, domain.ServiceAccount{ID: sa, AccountID: accB, Name: "kn664-48", Enabled: true, Labels: domain.Labels{}})
			require.NoError(t, err)
			require.NoError(t, w.Commit(ctx))
			gb := e.grant(t, prjB, domain.Subject{Type: domain.SubjectTypeGroup, ID: domain.SubjectID(grp)})
			sb := e.grant(t, prjB, domain.Subject{Type: domain.SubjectTypeServiceAccount, ID: domain.SubjectID(sa)})
			if revoked {
				e.revoke(t, gb)
				e.revoke(t, sb)
			}

			w, err = e.repo.Writer(ctx)
			require.NoError(t, err)
			gerr := w.GroupsW().Delete(ctx, grp)
			if gerr != nil {
				_ = w.Rollback(ctx)
			} else {
				require.NoError(t, w.Commit(ctx))
			}
			w, err = e.repo.Writer(ctx)
			require.NoError(t, err)
			serr := w.ServiceAccountsW().Delete(ctx, sa)
			if serr != nil {
				_ = w.Rollback(ctx)
			} else {
				require.NoError(t, w.Commit(ctx))
			}

			if revoked {
				require.NoError(t, gerr, "группа с одними отозванными выдачами снимается")
				require.NoError(t, serr, "сервисный аккаунт с одними отозванными выдачами снимается")
				return
			}
			require.Error(t, gerr)
			require.Equal(t, "Group "+string(grp)+" has active access bindings and cannot be deleted", stripSentinel(gerr))
			require.Error(t, serr)
			require.Equal(t, "ServiceAccount "+string(sa)+" has active access bindings and cannot be deleted", stripSentinel(serr))
		})
	}
}

// TestKN664_37_PersonRemovalRemovesEveryMembershipPointer — KN664-37.
func TestKN664_37_PersonRemovalRemovesEveryMembershipPointer(t *testing.T) {
	e := newRemovalEnv(t)
	ctx := context.Background()
	_, accA := e.emptied(t, "37a")
	_, accB := e.emptied(t, "37b")
	member := e.seedMember(t, "37", accA, accB)
	require.ElementsMatch(t, []string{pointer(member, accA), pointer(member, accB)}, membershipPointers(t, e.pool, member),
		"предпосылка: указатели членства в A и B есть")

	require.Equal(t, opOutcome{}, e.deleteUser(t, member, member))

	require.Empty(t, membershipPointers(t, e.pool, member),
		"указатели ВСЕХ членств снимаются вместе с личностью, а не только аккаунта колонки дома")
	require.Zero(t, countRows(t, e.pool, `SELECT count(*) FROM kaname.relation_fact
		WHERE object_type = 'iam_user' AND object_id = $1`, string(member)),
		"в модели прав остались факты об объекте снятой личности")
	require.Equal(t, 1, countRows(t, e.pool, `SELECT count(*) FROM kaname.resource_reconcile_outbox
		WHERE object_type = 'iam.user' AND object_id = $1 AND event_type = 'mirror.delete'`, string(member)),
		"событие реконсайла снятия iam.user")
	_ = ctx
}

// TestKN664_37_IntentRefusalLeavesThePerson — второе «Тогда» KN664-37.
func TestKN664_37_IntentRefusalLeavesThePerson(t *testing.T) {
	e := newRemovalEnv(t)
	ctx := context.Background()
	_, accA := e.emptied(t, "37ra")
	_, accB := e.emptied(t, "37rb")
	member := e.seedMember(t, "37r", accA, accB)
	digest := e.seedSession(t, member, 66437)
	intentsBefore := countRows(t, e.pool, `SELECT count(*) FROM kaname.fga_outbox`)
	_, err := e.pool.Exec(ctx, fmt.Sprintf(`
		CREATE FUNCTION kaname.kn664_refuse_pointer() RETURNS trigger LANGUAGE plpgsql AS $f$
		BEGIN
		  IF NEW.event_type = 'fga.tuple.delete' AND NEW.payload::text LIKE '%%%s%%' THEN
		    RAISE EXCEPTION 'kn664 injected intent refusal';
		  END IF;
		  RETURN NEW;
		END $f$;
		CREATE TRIGGER kn664_refuse_pointer BEFORE INSERT ON kaname.fga_outbox
		  FOR EACH ROW EXECUTE FUNCTION kaname.kn664_refuse_pointer();`, "account:"+string(accB)))
	require.NoError(t, err)

	require.Equal(t, opOutcome{code: 13, msg: "internal error"}, e.deleteUser(t, member, member))

	require.Equal(t, 1, e.userRow(t, member), "строка на месте")
	require.ElementsMatch(t, []string{string(accA), string(accB)}, memberships(t, e.pool, member), "членства на месте")
	_, reason, err := kanamepg.NewHumanSessionRepo(e.pool).Resolve(ctx, domain.BearerDigest(digest), time.Now())
	require.NoError(t, err)
	require.Empty(t, reason, "сессия на месте")
	require.Equal(t, intentsBefore, countRows(t, e.pool, `SELECT count(*) FROM kaname.fga_outbox`), "новых строк очереди нет")
	_, found, err := kanamepg.NewMintedTokenRevocationRepo(e.pool).RevokedBefore(ctx, string(member))
	require.NoError(t, err)
	require.False(t, found, "откатанное снятие не оставило отсечки")
}

// TestKN664_HomelessPersonIsReadByEveryReader — DoD 2: каждый читатель колонки
// дома из переписи §0.5 читает пустую колонку как «дома нет» и не падает.
func TestKN664_HomelessPersonIsReadByEveryReader(t *testing.T) {
	e := newRemovalEnv(t)
	ctx := context.Background()
	uid, acc := e.emptied(t, "rd")
	_, other := e.emptied(t, "rdb")
	member := e.seedMember(t, "rd", acc, other)
	digest := e.seedSession(t, member, 66499)
	require.Equal(t, opOutcome{}, e.deleteAccount(t, uid, acc), "Дано: дом участника снят")
	var home *string
	require.NoError(t, e.pool.QueryRow(ctx, `SELECT account_id FROM kaname.users WHERE id = $1`, string(member)).Scan(&home))
	require.Nil(t, home, "предпосылка: колонка дома пуста")

	t.Run("user_repo Users().Get", func(t *testing.T) {
		rd, err := e.repo.Reader(ctx)
		require.NoError(t, err)
		defer func() { _ = rd.Rollback(ctx) }()
		got, err := rd.Users().Get(ctx, member)
		require.NoError(t, err)
		require.Empty(t, got.AccountID)
	})
	t.Run("human_session_repo Resolve", func(t *testing.T) {
		got, reason, err := kanamepg.NewHumanSessionRepo(e.pool).Resolve(ctx, domain.BearerDigest(digest), time.Now())
		require.NoError(t, err, "предъявление сессии участника без дома не обязано падать")
		require.Empty(t, reason)
		require.Equal(t, member, got.User.ID)
		require.Empty(t, got.User.AccountID)
	})
	t.Run("human_session_repo RecoveryTarget", func(t *testing.T) {
		got, found, err := kanamepg.NewHumanSessionRepo(e.pool).RecoveryTarget(ctx, domain.Email("kn664-rd-member@example.com"))
		require.NoError(t, err)
		require.True(t, found)
		require.Empty(t, got.User.AccountID)
	})
	t.Run("access_key_repo UserOf", func(t *testing.T) {
		got, err := kanamepg.NewAccessKeyRepo(e.pool).UserOf(ctx, member)
		require.NoError(t, err)
		require.Empty(t, got.AccountID)
	})
	t.Run("user_oauth_clients_repos AccountForUser", func(t *testing.T) {
		got, may, err := kanamepg.NewUserOAuthClientRepo(e.pool).AccountForUser(ctx, member)
		require.NoError(t, err, "выдача личного токена участнику без дома не обязана падать")
		require.Empty(t, got)
		require.True(t, may)
	})
	t.Run("user_pool_repo GetByID", func(t *testing.T) {
		got, err := kanamepg.NewUserPoolRepo(e.pool).GetByID(ctx, member)
		require.NoError(t, err)
		require.Empty(t, got.AccountID)
	})
}

// TestKN664_40_PersonRemovalRacesAccountCreation — KN664-40: сто повторов.
// Исход (б) — отказ предъявления токена создания — производит дверь
// предъявления, а не глагол; на этом уровне он не производится.
func TestKN664_40_PersonRemovalRacesAccountCreation(t *testing.T) {
	e := newRemovalEnv(t)
	ctx := context.Background()
	const repeats = 100
	counts := map[string]int{}
	for i := 0; i < repeats; i++ {
		owner := mustSeedUser(t, ctx, e.pool, fmt.Sprintf("kn66440o%d", i))
		ownerAcc := seedAccount(t, ctx, e.repo, fmt.Sprintf("kn664-40-%d", i), owner)
		person := e.seedMember(t, fmt.Sprintf("40-%d", i), ownerAcc.ID)

		var (
			wg             sync.WaitGroup
			delOp, accOp   *operations.Operation
			delErr, accErr error
		)
		wg.Add(2)
		go func() {
			defer wg.Done()
			delOp, delErr = userapp.NewDeleteUserUseCase(e.repo, e.ops).Execute(principalCtx(person), person)
		}()
		go func() {
			defer wg.Done()
			accOp, accErr = accountapp.NewCreateAccountUseCase(e.repo, e.ops).Execute(principalCtx(person),
				domain.Account{Name: domain.AccountName(fmt.Sprintf("kn664-40-own-%d", i)), Labels: domain.Labels{}})
		}()
		wg.Wait()
		require.NoError(t, delErr)
		require.NoError(t, accErr)
		del, created := e.outcome(t, delOp), e.outcome(t, accOp)
		owned := countRows(t, e.pool, `SELECT count(*) FROM kaname.accounts WHERE owner_user_id = $1`, string(person))
		alive := e.userRow(t, person)

		switch {
		case created == opOutcome{} && del == opOutcome{code: 9, msg: "User " + string(person) + " owns accounts and cannot be deleted: delete Account " +
			ownedAccountOf(t, e.pool, person) + " first (accounts owned: 1)"}:
			counts["а: аккаунт создан, снятие отвергнуто"]++
		case del == opOutcome{} && created == opOutcome{code: 9, msg: "User " + string(person) + " not found"}:
			counts["в: личность снята, создание — «User not found»"]++
		default:
			t.Fatalf("повтор %d: исход вне набора KN664-40: снятие %s, создание %s", i, del, created)
		}
		require.False(t, alive == 0 && owned > 0, "повтор %d: аккаунт пережил своего владельца", i)
	}
	t.Logf("KN664-40: повторов %d; по исходам: %v", repeats, counts)
}

// raceInviteAuthz — дверь прав приглашения открыта: её исход — предмет других
// проб, здесь спрашивается гонка строк.
type raceInviteAuthz struct{}

func (raceInviteAuthz) Check(context.Context, string, string, string) (bool, error) { return true, nil }

// TestKN664_41_PersonRemovalRacesAnInvitation — KN664-41: сто повторов.
func TestKN664_41_PersonRemovalRacesAnInvitation(t *testing.T) {
	e := newRemovalEnv(t)
	ctx := context.Background()
	const repeats = 100
	counts := map[string]int{}
	for i := 0; i < repeats; i++ {
		owner := mustSeedUser(t, ctx, e.pool, fmt.Sprintf("kn66441o%d", i))
		home := seedAccount(t, ctx, e.repo, fmt.Sprintf("kn664-41-home-%d", i), owner)
		accB := seedAccount(t, ctx, e.repo, fmt.Sprintf("kn664-41-b-%d", i), owner)
		person := e.seedMember(t, fmt.Sprintf("41-%d", i), home.ID)
		email := domain.Email(fmt.Sprintf("kn664-41-%d-member@example.com", i))

		var (
			wg             sync.WaitGroup
			delOp, invOp   *operations.Operation
			delErr, invErr error
		)
		wg.Add(2)
		go func() {
			defer wg.Done()
			delOp, delErr = userapp.NewDeleteUserUseCase(e.repo, e.ops).Execute(principalCtx(person), person)
		}()
		go func() {
			defer wg.Done()
			invOp, invErr = userapp.NewInviteUserUseCase(e.repo, e.ops, raceInviteAuthz{}).
				WithInviteTTL(24*time.Hour).
				WithInviteMailRateLimit(outboxtypes.InviteMailRateLimit{MaxPerWindow: 10, Window: time.Hour}, nil).
				Execute(principalCtx(owner), userapp.InviteUserInput{AccountID: accB.ID, Email: email})
		}()
		wg.Wait()
		require.NoError(t, delErr)
		require.NoError(t, invErr)
		del, inv := e.outcome(t, delOp), e.outcome(t, invOp)
		require.Equal(t, opOutcome{}, del, "повтор %d: снятие в каждом повторе завершается успешно", i)

		var invitedID string
		invited := countRows(t, e.pool, `SELECT count(*) FROM kaname.users WHERE lower(email) = lower($1)`, string(email))
		if invited == 1 {
			require.NoError(t, e.pool.QueryRow(ctx, `SELECT id FROM kaname.users WHERE lower(email) = lower($1)`,
				string(email)).Scan(&invitedID))
		}
		switch {
		case inv == opOutcome{} && invited == 0:
			counts["а: приглашение раньше снятия, членство снято с личностью"]++
		case inv == opOutcome{} && invited == 1 && invitedID != string(person):
			counts["б: снятие раньше чтения почты, новая строка"]++
			require.Equal(t, []string{string(accB.ID)}, memberships(t, e.pool, domain.UserID(invitedID)))
		case inv == opOutcome{code: 9, msg: "User " + string(person) + " not found"}:
			counts["в: почта прочитана до снятия, транзакция — после"]++
		default:
			t.Fatalf("повтор %d: исход приглашения вне набора KN664-41: %s (строк по почте %d, id %q)", i, inv, invited, invitedID)
		}
		require.Zero(t, e.userRow(t, person), "повтор %d: строка человека с идентификатором U вернулась", i)
		require.Empty(t, memberships(t, e.pool, person), "повтор %d: членство указывает на отсутствующую личность", i)
		require.Empty(t, membershipPointers(t, e.pool, person), "повтор %d: указатель членства пережил личность", i)
	}
	t.Logf("KN664-41: повторов %d; по исходам: %v", repeats, counts)
}

// TestKN664_41c_InvitationOfARemovedIdentifierIsRefused — исход (в) KN664-41
// детерминированно: транзакция приглашения называет идентификатор, снятый
// между её чтением и вставкой (Р11).
func TestKN664_41c_InvitationOfARemovedIdentifierIsRefused(t *testing.T) {
	e := newRemovalEnv(t)
	ctx := context.Background()
	owner := mustSeedUser(t, ctx, e.pool, "kn66441co")
	home := seedAccount(t, ctx, e.repo, "kn664-41c-home", owner)
	accB := seedAccount(t, ctx, e.repo, "kn664-41c-b", owner)
	person := e.seedMember(t, "41c", home.ID)
	require.Equal(t, opOutcome{}, e.deleteUser(t, removalCloudAdmin, person), "Дано: человек снят")

	w, err := e.repo.Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(ctx) }()
	_, _, err = w.UsersW().InsertPending(ctx, domain.User{
		ID: person, AccountID: accB.ID, Email: "kn664-41c-member@example.com",
		DisplayName: "KN664", InviteStatus: domain.InviteStatusPending,
	}, time.Time{})
	require.Error(t, err, "вставка строки с идентификатором снятого человека обязана отказать")
	require.True(t, isFailedPrecondition(err), "код — FAILED_PRECONDITION, а не ALREADY_EXISTS: %v", err)
	require.Equal(t, "User "+string(person)+" not found", stripSentinel(err))

	// Близнец: свежий идентификатор той же почты проходит.
	w2, err := e.repo.Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = w2.Rollback(ctx) }()
	_, inserted, err := w2.UsersW().InsertPending(ctx, domain.User{
		ID: domain.UserID(ids.NewID(domain.PrefixUser)), AccountID: accB.ID, Email: "kn664-41c-member@example.com",
		DisplayName: "KN664", InviteStatus: domain.InviteStatusPending,
	}, time.Time{})
	require.NoError(t, err)
	require.True(t, inserted)
}
