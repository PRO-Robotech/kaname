// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// authorization_ceremony_repo_integration_test.go — инварианты хранилища
// церемонии на уровне БАЗЫ (LINE-A-1, группа I: 17, 26, 28; ban #10). Каждое
// отрицание стоит рядом со своим законным близнецом.

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/ceremony"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

const acTarget = "https://console.ceremony.test/cb"

type acWorld struct {
	pool    *pgxpool.Pool
	repo    *pg.AuthorizationCeremonyRepo
	user    domain.UserID
	session domain.HumanSessionID
	client  domain.InteractiveClientID
}

func newACWorld(t *testing.T, tag string) acWorld {
	t.Helper()
	pool := hsPool(t)
	ctx := context.Background()
	user := lmPeople(t, pool, "ac"+tag, 1)[0]
	now := time.Now().UTC().Add(-time.Minute)
	s := domain.HumanSession{
		ID: domain.HumanSessionID("hss-ac" + tag), UserID: user, AuthenticatedAt: now, LastPresentedAt: now,
		ExpiresAt: now.Add(time.Hour), AssuranceLevel: "1", PresentedMethods: []string{"password"},
	}
	hsIssue(t, pg.NewHumanSessionRepo(pool), s)
	id := domain.InteractiveClientID(ids.NewHyphenID(ids.PrefixInteractiveClientHyphen))
	_, err := pg.NewInteractiveClientRepo(pool).Insert(ctx, domain.InteractiveClient{
		ID: id, Name: domain.InteractiveClientName("ac-" + strings.ToLower(tag)), RedirectURIs: []string{acTarget},
		PostLogoutRedirectURIs: []string{}, ClientID: string(id), Audiences: []string{}, GrantTypes: []string{},
		Status: domain.InteractiveClientActive,
	})
	require.NoError(t, err)
	return acWorld{pool: pool, repo: pg.NewAuthorizationCeremonyRepo(pool), user: user, session: s.ID, client: id}
}

func (w acWorld) issue(t *testing.T) (domain.CeremonySecret, string) {
	t.Helper()
	code, err := domain.NewCeremonySecret()
	require.NoError(t, err)
	challenge := domain.PKCEChallengeS256(strings.Repeat("v", 43))
	ok, err := w.repo.IssueCode(context.Background(), ceremony.CodeIssue{
		Digest: code.Digest(), Client: w.client, Session: w.session, Subject: w.user, RedirectURI: acTarget,
		Scope: "openid", CodeChallenge: challenge, TTL: domain.AuthorizationCodeTTL,
	})
	require.NoError(t, err)
	require.True(t, ok, "законная выдача не легла")
	return code, challenge
}

func (w acWorld) redemption(code domain.CeremonySecret, challenge string) ceremony.CodeRedemption {
	return ceremony.CodeRedemption{Digest: code.Digest(), Client: w.client, RedirectURI: acTarget, Challenge: challenge,
		Grant: domain.AuthorizationGrantID(ids.NewID(domain.AuthorizationGrantIDPrefix))}
}

// TestAuthorizationCeremonyRepo_IssueIsConditionalOnClientTargetAndSession —
// условие выдачи судит ТОТ ЖЕ оператор: снятый клиент, чужая цель, чужой
// человек при сессии, снятая сессия — ни одной строки. Близнец — законная
// выдача ложится.
func TestAuthorizationCeremonyRepo_IssueIsConditionalOnClientTargetAndSession(t *testing.T) {
	w := newACWorld(t, "i1")
	ctx := context.Background()
	w.issue(t)

	code, _ := domain.NewCeremonySecret()
	base := ceremony.CodeIssue{Digest: code.Digest(), Client: w.client, Session: w.session, Subject: w.user,
		RedirectURI: acTarget, CodeChallenge: domain.PKCEChallengeS256(strings.Repeat("v", 43)), TTL: time.Minute}
	for what, mutate := range map[string]func(*ceremony.CodeIssue){
		"цель не в списке": func(c *ceremony.CodeIssue) { c.RedirectURI = acTarget + "/" },
		"чужой человек":    func(c *ceremony.CodeIssue) { c.Subject = "usr00000000000000none" },
		"сессии нет":       func(c *ceremony.CodeIssue) { c.Session = "hss-none" },
	} {
		in := base
		mutate(&in)
		ok, err := w.repo.IssueCode(ctx, in)
		require.NoError(t, err, what)
		require.False(t, ok, "%s: запись кода легла", what)
	}
	_, err := w.pool.Exec(ctx, `UPDATE interactive_clients SET status = 'DELETING' WHERE id = $1`, string(w.client))
	require.NoError(t, err)
	ok, err := w.repo.IssueCode(ctx, base)
	require.NoError(t, err)
	require.False(t, ok, "снятому клиенту выдан код")
}

// TestAuthorizationCeremonyRepo_ConcurrentRedeemHasExactlyOneWinner — 17/26:
// одностатементное потребление; близнец — разные коды проходят оба; повтор
// потреблённого отзывает семейство и пишет отсечку.
func TestAuthorizationCeremonyRepo_ConcurrentRedeemHasExactlyOneWinner(t *testing.T) {
	w := newACWorld(t, "r1")
	ctx := context.Background()

	// Горутины не зовут FailNow: исход и ошибка возвращаются и судятся в
	// горутине пробы.
	type outcome struct {
		ok  bool
		g   ceremony.Grant
		err error
	}
	redeemOnce := func(r ceremony.CodeRedemption) outcome {
		wr, err := w.repo.Writer(ctx)
		if err != nil {
			return outcome{err: err}
		}
		defer func() { _ = wr.Rollback(ctx) }()
		g, ok, err := wr.RedeemCode(ctx, r)
		if err == nil && ok {
			err = wr.Commit(ctx)
		}
		return outcome{ok: ok, g: g, err: err}
	}

	c1, ch1 := w.issue(t)
	c2, ch2 := w.issue(t)
	var wg sync.WaitGroup
	results := make([]outcome, 2)
	for i, r := range []ceremony.CodeRedemption{w.redemption(c1, ch1), w.redemption(c2, ch2)} {
		wg.Add(1)
		go func(i int, r ceremony.CodeRedemption) { defer wg.Done(); results[i] = redeemOnce(r) }(i, r)
	}
	wg.Wait()
	for _, r := range results {
		require.NoError(t, r.err)
		require.True(t, r.ok, "близнец: разные коды обязаны пройти оба")
		require.Equal(t, w.user, r.g.Subject)
		require.Equal(t, "1", r.g.Level, "уровень — из записи сессии")
	}

	code, ch := w.issue(t)
	const n = 12
	won := make(chan outcome, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); won <- redeemOnce(w.redemption(code, ch)) }()
	}
	wg.Wait()
	close(won)
	winners := 0
	for r := range won {
		require.NoError(t, r.err)
		if r.ok {
			winners++
		}
	}
	require.Equal(t, 1, winners, "одним кодом прошло не ровно одно потребление")

	wr, err := w.repo.Writer(ctx)
	require.NoError(t, err)
	g, revoked, err := wr.RevokeFamilyOfCode(ctx, code.Digest(), time.Now().Add(time.Minute))
	require.NoError(t, err)
	require.True(t, revoked, "повтор потреблённого кода не отозвал семейство")
	require.NoError(t, wr.Commit(ctx))
	var before time.Time
	require.NoError(t, w.pool.QueryRow(ctx, `SELECT revoke_before FROM minted_token_revocations WHERE subject = $1`, string(g.ID)).Scan(&before))

	unused, _ := w.issue(t)
	wr, err = w.repo.Writer(ctx)
	require.NoError(t, err)
	_, revoked, err = wr.RevokeFamilyOfCode(ctx, unused.Digest(), time.Now())
	require.NoError(t, err)
	require.False(t, revoked, "непотреблённый код отозвал семейство")
	require.NoError(t, wr.Rollback(ctx))
}

// TestAuthorizationCeremonyRepo_ExpiryIsTheDatabaseClock — истёкший по часам
// базы код не потребляется; классификатор называет срок.
func TestAuthorizationCeremonyRepo_ExpiryIsTheDatabaseClock(t *testing.T) {
	w := newACWorld(t, "e1")
	ctx := context.Background()
	code, ch := w.issue(t)
	_, err := w.pool.Exec(ctx, `UPDATE authorization_codes SET issued_at = now() - interval '2 minutes', expires_at = now() - interval '1 minute'`)
	require.NoError(t, err)
	wr, err := w.repo.Writer(ctx)
	require.NoError(t, err)
	_, ok, err := wr.RedeemCode(ctx, w.redemption(code, ch))
	require.NoError(t, err)
	require.False(t, ok, "истёкший код потреблён")
	require.NoError(t, wr.Rollback(ctx))
	reason, err := w.repo.ClassifyCode(ctx, w.redemption(code, ch))
	require.NoError(t, err)
	require.Equal(t, ceremony.CodeExpired, reason)

	// Уборка: истёкший дольше окна снимается, свежий остаётся.
	fresh, _ := w.issue(t)
	_, err = w.pool.Exec(ctx, `UPDATE authorization_codes SET issued_at = now() - interval '3 hours', expires_at = now() - interval '2 hours' WHERE code_digest = $1`, string(code.Digest()))
	require.NoError(t, err)
	removed, _, err := w.repo.SweepUnservableCodes(ctx, domain.AuthorizationCodeReplayRetention, 100)
	require.NoError(t, err)
	require.EqualValues(t, 1, removed)
	var left int
	require.NoError(t, w.pool.QueryRow(ctx, `SELECT count(*) FROM authorization_codes WHERE code_digest = $1`, string(fresh.Digest())).Scan(&left))
	require.Equal(t, 1, left, "уборка сняла свежий код")
}

// TestAuthorizationCeremonyRepo_OneCurrentRefreshPerFamily — 28: ротация —
// CAS; действующее удостоверение у семейства ровно одно (частичный уникальный
// индекс); повторная ротация того же предшественника — ноль строк.
func TestAuthorizationCeremonyRepo_OneCurrentRefreshPerFamily(t *testing.T) {
	w := newACWorld(t, "f1")
	ctx := context.Background()
	code, ch := w.issue(t)
	red := w.redemption(code, ch)
	wr, err := w.repo.Writer(ctx)
	require.NoError(t, err)
	_, ok, err := wr.RedeemCode(ctx, red)
	require.NoError(t, err)
	require.True(t, ok)
	rt1, _ := domain.NewCeremonySecret()
	require.NoError(t, wr.InsertRefresh(ctx, rt1.Digest(), red.Grant))
	require.NoError(t, wr.Commit(ctx))

	second, _ := domain.NewCeremonySecret()
	_, err = w.pool.Exec(ctx, `INSERT INTO authorization_refresh_tokens (token_digest, grant_id) VALUES ($1, $2)`,
		string(second.Digest()), string(red.Grant))
	require.Error(t, err, "у семейства легло второе действующее удостоверение")

	rt2, _ := domain.NewCeremonySecret()
	wr, err = w.repo.Writer(ctx)
	require.NoError(t, err)
	st, err := wr.LockRefresh(ctx, rt1.Digest())
	require.NoError(t, err)
	require.True(t, st.Found && st.SessionLive && !st.Rotated && !st.Revoked && !st.CutOff, "состояние %+v", st)
	rotated, err := wr.RotateRefresh(ctx, rt1.Digest(), rt2.Digest(), red.Grant)
	require.NoError(t, err)
	require.True(t, rotated)
	require.NoError(t, wr.Commit(ctx))

	rt3, _ := domain.NewCeremonySecret()
	wr, err = w.repo.Writer(ctx)
	require.NoError(t, err)
	st, err = wr.LockRefresh(ctx, rt1.Digest())
	require.NoError(t, err)
	require.True(t, st.Rotated, "ротированный предшественник читается действующим")
	rotated, err = wr.RotateRefresh(ctx, rt1.Digest(), rt3.Digest(), red.Grant)
	require.NoError(t, err)
	require.False(t, rotated, "предшественник ротирован дважды")
	revoked, err := wr.RevokeFamily(ctx, ceremony.FamilyRevocation{Grant: red.Grant, Reason: ceremony.RevokedRefreshReplay, Before: time.Now()})
	require.NoError(t, err)
	require.True(t, revoked)
	require.NoError(t, wr.Commit(ctx))

	wr, err = w.repo.Writer(ctx)
	require.NoError(t, err)
	st, err = wr.LockRefresh(ctx, rt2.Digest())
	require.NoError(t, err)
	require.True(t, st.Revoked, "отзыв семейства не виден преемнику")
	require.NoError(t, wr.Rollback(ctx))
}
