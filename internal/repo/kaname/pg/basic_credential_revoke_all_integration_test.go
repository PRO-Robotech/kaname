// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// basic_credential_revoke_all_integration_test.go — отсечка отзыва-всех
// владельца действует на полосе БАЗОВОГО СЕКРЕТА тем же правилом, что на
// полосах выдачи токена (задача kaname#379).
//
// # Что здесь утверждается
//
// Наблюдаемое у обработчика, а не «репозиторий вернул ошибку»: после того как
// отсечка человека закоммичена — каждым путём записи строки и настоящими
// глаголами, — тот же предъявленный секрет не резолвится, и открытое
// соединение, спросившее о его живости, слышит тот же отказ. Отказ совпадает с
// отказом удостоверению, которого нет, ПОБАЙТНО, в том виде, в каком статус
// уходит на провод: различимый отказ был бы оракулом состояния владельца.
//
// # Чем проба защищена от собственной снисходительности
//
//   - положительный контроль ДО отсечки в том же прогоне — иначе отказ после
//     неё неотличим от полосы, не пропускающей никого;
//   - граница включительна: писатель ставит отсечку РОВНО в момент выдачи
//     секрета, и равенство — отказ;
//   - законный близнец: секрет, выданный ПОСЛЕ отсечки, проходит — отсечка
//     прекращает прежние полномочия, а не запирает учётку;
//   - секрет служебной учётки того же аккаунта не затронут: отсечка — о
//     человеке;
//   - пути записи выводятся переписью по дереву
//     (`cutoff_write_paths_census_test.go`), а не длиной выписанного перечня;
//   - отсечка, которую прочитать нельзя, даёт исход «состояние не
//     установлено», а не пропуск и не отказ в удостоверении;
//   - полоса базового секрета сличается с полосой ключа нашего эндпоинта на
//     одних и тех же отсечках: один принципал, одна отсечка — один вердикт.
package pg_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/PRO-Robotech/corelib/credsecret"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/corelib/tokenpolicy"

	internaliam "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	sessionrev "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/session_revocations"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// basicLaneStrangerID — идентификатор нашей формы, строки которого нет. Отказ
// ему — эталон, с которым сличается всякий другой отказ полосы.
const basicLaneStrangerID = "uoc_rvkb0000000000099"

// basicLaneHandler — обработчик полосы над НАСТОЯЩИМ авторитетом, так, как его
// провязывает композиционный корень.
func basicLaneHandler(t testing.TB, pool *pgxpool.Pool) *internaliam.Handler {
	t.Helper()
	return internaliam.NewHandler(internaliam.NewLookupSubjectUseCase(nil), nil).
		WithBasicCredentialResolver(newBasicAuthority(t, pool))
}

// mintUserSecret кладёт живой базовый секрет человека стенда и возвращает
// предъявляемую строку.
func (f assertionFixture) mintUserSecret(t *testing.T, id string) string {
	t.Helper()
	secret, hash, err := credsecret.Mint(id)
	require.NoError(t, err)
	_, err = f.pool.Exec(context.Background(), `
INSERT INTO kaname.user_oauth_clients
    (id, user_id, hydra_client_id, created_by_user_id, credential_kind, secret_hash, expires_at)
VALUES ($1, $2, NULL, $2, 'SECRET', $3, now() + interval '30 days')`, id, f.user, hash)
	require.NoError(t, err)
	return secret
}

// mintSASecret — то же для служебной учётки стенда.
func (f assertionFixture) mintSASecret(t *testing.T, id string) string {
	t.Helper()
	secret, hash, err := credsecret.Mint(id)
	require.NoError(t, err)
	_, err = f.pool.Exec(context.Background(), `
INSERT INTO kaname.service_account_oauth_clients
    (id, sva_id, hydra_client_id, created_by_user_id, credential_kind, secret_hash, expires_at)
VALUES ($1, $2, NULL, $3, 'SECRET', $4, now() + interval '30 days')`, id, f.sva, f.user, hash)
	require.NoError(t, err)
	return secret
}

// ownerCutoffOf читает отсечку человека стенда из её строки.
func ownerCutoffOf(t *testing.T, f assertionFixture) time.Time {
	t.Helper()
	var at time.Time
	require.NoError(t, f.pool.QueryRow(context.Background(),
		`SELECT revoke_before FROM kaname.user_token_revocations WHERE user_id = $1`, f.user).Scan(&at),
		"отсечка человека обязана быть записана")
	return at.UTC()
}

// basicAnswer — что видит вызывающий полосу: код и статус В ТОМ ВИДЕ, в каком
// он уходит на провод, и принципал ответа.
type basicAnswer struct {
	code      codes.Code
	wire      []byte
	principal string
}

func statusWire(t *testing.T, err error) (codes.Code, []byte) {
	t.Helper()
	st := status.Convert(err)
	b, merr := proto.MarshalOptions{Deterministic: true}.Marshal(st.Proto())
	require.NoError(t, merr)
	return st.Code(), b
}

func basicResolve(t *testing.T, ctx context.Context, h *internaliam.Handler, presented string) basicAnswer {
	t.Helper()
	resp, err := h.ResolveBasicCredential(ctx, &iamv1.ResolveBasicCredentialRequest{Presented: presented})
	code, wire := statusWire(t, err)
	a := basicAnswer{code: code, wire: wire}
	if err != nil {
		require.Nil(t, resp, "в отказе не бывает принципала")
		return a
	}
	require.NotNil(t, resp)
	a.principal = resp.GetPrincipalType() + "/" + resp.GetPrincipalId()
	return a
}

func basicLive(t *testing.T, ctx context.Context, h *internaliam.Handler, credentialID string) basicAnswer {
	t.Helper()
	_, err := h.CheckBasicCredentialLive(ctx, &iamv1.CheckBasicCredentialLiveRequest{CredentialId: credentialID})
	code, wire := statusWire(t, err)
	return basicAnswer{code: code, wire: wire}
}

// basicLaneAcrossCutoff — одна подача целиком: секрет до отсечки проходит,
// писатель ставит отсечку (моментом выдачи секрета, если он им управляет),
// тот же секрет отвергается тем же отказом на обоих вопросах, близнец после
// отсечки проходит, секрет машины рядом не затронут.
func basicLaneAcrossCutoff(t *testing.T, f assertionFixture, subject string, write func(t *testing.T, issued time.Time)) {
	t.Helper()
	ctx := context.Background()
	h := basicLaneHandler(t, f.pool)
	const (
		beforeID = "uoc_rvkb0000000000001"
		afterID  = "uoc_rvkb0000000000002"
		machine  = "soc_rvkb0000000000003"
	)
	before := f.mintUserSecret(t, beforeID)
	issued := userClientIssuedAt(t, f, beforeID)

	// Эталоны отказа — ответы ТЕХ ЖЕ глаголов удостоверению, которого нет.
	stranger, _, err := credsecret.Mint(basicLaneStrangerID)
	require.NoError(t, err)
	refResolve := basicResolve(t, ctx, h, stranger)
	refLive := basicLive(t, ctx, h, basicLaneStrangerID)
	require.Equal(t, codes.Unauthenticated, refResolve.code, "эталон: секрет удостоверения, которого нет, отвергается")
	require.Equal(t, codes.Unauthenticated, refLive.code, "эталон: живость удостоверения, которого нет, отвергается")

	// (1) Положительный контроль ДО отсечки.
	got := basicResolve(t, ctx, h, before)
	require.Equal(t, codes.OK, got.code, "контроль: до отсечки секрет человека обязан резолвиться")
	require.Equal(t, "user/"+f.user, got.principal)
	require.Equal(t, codes.OK, basicLive(t, ctx, h, beforeID).code, "контроль: до отсечки секрет человека жив")

	// (2) Отсечка владельца.
	write(t, issued)
	cutoff := ownerCutoffOf(t, f)
	require.Falsef(t, cutoff.Before(issued),
		"%s: предпосылка — отсечка не раньше выдачи секрета (%s против %s)", subject, cutoff, issued)

	got = basicResolve(t, ctx, h, before)
	require.Equalf(t, codes.Unauthenticated, got.code,
		"%s: секрет, выданный не позже отсечки владельца, резолвится (принципал %q)", subject, got.principal)
	require.Equalf(t, refResolve.wire, got.wire, "%s: отказ по отсечке различим снаружи", subject)
	live := basicLive(t, ctx, h, beforeID)
	require.Equalf(t, codes.Unauthenticated, live.code,
		"%s: соединение, открытое секретом, выданным не позже отсечки, признано живым", subject)
	require.Equalf(t, refLive.wire, live.wire, "%s: отказ живости по отсечке различим снаружи", subject)

	// (3) Законный близнец: секрет, выданный ПОСЛЕ отсечки, проходит.
	after := f.mintUserSecret(t, afterID)
	afterIssued := userClientIssuedAt(t, f, afterID)
	require.Truef(t, afterIssued.After(cutoff),
		"%s: предпосылка близнеца — секрет выдан позже отсечки (%s против %s)", subject, afterIssued, cutoff)
	got = basicResolve(t, ctx, h, after)
	require.Equalf(t, codes.OK, got.code, "%s: секрет, выданный после отсечки, отвергнут — отсечка заперла учётку", subject)
	require.Equal(t, "user/"+f.user, got.principal)
	require.Equalf(t, codes.OK, basicLive(t, ctx, h, afterID).code, "%s: секрет, выданный после отсечки, не жив", subject)

	// (4) Секрет служебной учётки того же аккаунта отсечкой человека не затронут.
	sa := f.mintSASecret(t, machine)
	got = basicResolve(t, ctx, h, sa)
	require.Equalf(t, codes.OK, got.code, "%s: секрет служебной учётки задет отсечкой человека", subject)
	require.Equal(t, "service_account/"+f.sva, got.principal)
	require.Equalf(t, codes.OK, basicLive(t, ctx, h, machine).code, "%s: секрет служебной учётки не жив", subject)
}

// TestBasicLane_RevokeAllCutoffRefusesASecretIssuedNoLaterThanIt — по каждому
// пути записи строки отсечки, выведенному переписью; граница — включительная.
func TestBasicLane_RevokeAllCutoffRefusesASecretIssuedNoLaterThanIt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	inTree, parsed := cutoffWritePathsInTree(t)
	require.NotEmptyf(t, inTree, "перепись путей записи отсечки пуста среди %d файлов — не выполнилась", parsed)
	writers := revokeAllWritersUnderTest()
	executed := map[string]struct{}{}
	for _, w := range writers {
		t.Run(w.name, func(t *testing.T) {
			f := newAssertionFixture(t)
			basicLaneAcrossCutoff(t, f, w.name, func(t *testing.T, issued time.Time) {
				t.Helper()
				w.write(t, f, issued)
				require.Equalf(t, issued, ownerCutoffOf(t, f),
					"%s: предпосылка границы — отсечка стоит РОВНО в момент выдачи секрета", w.name)
			})
			executed[w.path] = struct{}{}
		})
	}
	var unexecuted []string
	for _, p := range inTree {
		if _, ok := executed[p]; !ok {
			unexecuted = append(unexecuted, p)
		}
	}
	t.Logf("перепись: путей записи отсечки по дереву %d · исполнено пробой до конца %d · подач %d",
		len(inTree), len(executed), len(writers))
	require.Emptyf(t, unexecuted, "пути записи отсечки, не исполненные пробой до конца: %v", unexecuted)
}

// basicLaneAdmin — разрешающая проверка администратора: предмет пробы —
// действие отсечки на предъявлении, а не ворота глагола (у них свои пробы).
type basicLaneAdmin struct{}

func (basicLaneAdmin) Check(context.Context, string, string, string) (bool, error) { return true, nil }

func basicLaneAdminCtx() context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr0000000000000admin"})
}

// basicLaneExternalIDs — имя человека у поставщика, прочитанное тем же
// репозиторием, которым его читает корень под `external`.
type basicLaneExternalIDs struct{ users *kanamepg.UserPoolRepo }

func (r basicLaneExternalIDs) ExternalIDOf(ctx context.Context, id domain.UserID) (string, error) {
	u, err := r.users.GetByID(ctx, id)
	if err != nil {
		return "", err
	}
	return string(u.ExternalID), nil
}

// basicLaneProviderSessions — поставщик под `external`, единственная подмена
// в сборке. Записывает, чью сессию сняли: провязка доказывается тем, что её
// позвали.
type basicLaneProviderSessions struct{ ended []string }

func (p *basicLaneProviderSessions) DeleteLoginSessions(_ context.Context, subject string) error {
	p.ended = append(p.ended, subject)
	return nil
}

// TestBasicLane_LogoutVerbsReachThePresentedSecret — настоящие глаголы
// «вывести человека отовсюду», собранные так, как их собирает корень: после
// каждого прежний секрет не проходит.
//
// ForceLogout корень собирает по посадке и ВСЕГДА со снятием сессии — ровно
// одним из двух (`cmd/kaname/wiring.go`, kaname#313). Сборка без снятия корню
// не принадлежит: глагол в ней отказывает закрыто (kaname#340), и это держит
// своя проба. Отсечку две посадки кладут разными писателями — под `own`
// транзакция снятия, под `external` писатель отзыва, — поэтому подаются обе.
func TestBasicLane_LogoutVerbsReachThePresentedSecret(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	verbs := []struct {
		name string
		call func(t *testing.T, f assertionFixture)
	}{
		{"ForceLogout(own)", func(t *testing.T, f assertionFixture) {
			t.Helper()
			h := internaliam.NewHandler(internaliam.NewLookupSubjectUseCase(nil), nil).
				WithSessionRevoker(kanamepg.NewSessionRevocationsAdapter(f.pool)).
				WithOwnSessions(kanamepg.NewHumanSessionRepo(f.pool)).
				WithAdminChecker(basicLaneAdmin{}).
				WithOperations(operations.NewRepo(f.pool, "kaname"))
			_, err := h.ForceLogout(basicLaneAdminCtx(), &iamv1.ForceLogoutRequest{UserId: f.user})
			require.NoError(t, err)
		}},
		{"ForceLogout(external)", func(t *testing.T, f assertionFixture) {
			t.Helper()
			provider := &basicLaneProviderSessions{}
			h := internaliam.NewHandler(internaliam.NewLookupSubjectUseCase(nil), nil).
				WithSessionRevoker(kanamepg.NewSessionRevocationsAdapter(f.pool)).
				WithProviderSessions(provider, basicLaneExternalIDs{users: kanamepg.NewUserPoolRepo(f.pool)}).
				WithAdminChecker(basicLaneAdmin{}).
				WithOperations(operations.NewRepo(f.pool, "kaname"))
			_, err := h.ForceLogout(basicLaneAdminCtx(), &iamv1.ForceLogoutRequest{UserId: f.user})
			require.NoError(t, err)
			var external string
			require.NoError(t, f.pool.QueryRow(context.Background(),
				`SELECT external_id FROM kaname.users WHERE id = $1`, f.user).Scan(&external))
			require.Equal(t, []string{external}, provider.ended,
				"снятие у поставщика не позвано либо позвано не о том человеке")
		}},
		{"Revoke(revoke_all_user_tokens)", func(t *testing.T, f assertionFixture) {
			t.Helper()
			adapter := kanamepg.NewSessionRevocationsAdapter(f.pool)
			h := sessionrev.NewHandler(sessionrev.NewRevokeUseCase(adapter, operations.NewRepo(f.pool, "kaname")), adapter)
			_, err := h.Revoke(basicLaneAdminCtx(), &iamv1.RevokeRequest{UserId: f.user, RevokeAllUserTokens: true})
			require.NoError(t, err)
		}},
	}
	ran := 0
	for _, v := range verbs {
		t.Run(v.name, func(t *testing.T) {
			f := newAssertionFixture(t)
			basicLaneAcrossCutoff(t, f, v.name, func(t *testing.T, _ time.Time) {
				t.Helper()
				v.call(t, f)
			})
			ran++
		})
	}
	t.Logf("перепись: глаголов подано %d · исполнено до конца %d", len(verbs), ran)
	require.Equal(t, len(verbs), ran, "не каждый глагол исполнен до конца")
}

// TestBasicLane_CutoffThatCannotBeReadIsNotAGrant — отсечку прочитать нельзя, а
// строку удостоверения можно: исход — «состояние не установлено», тот же, что
// у всякой недоступности авторитета, и не пропуск.
func TestBasicLane_CutoffThatCannotBeReadIsNotAGrant(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	f := newAssertionFixture(t)
	h := basicLaneHandler(t, f.pool)
	ctx := context.Background()
	const (
		humanID   = "uoc_rvkd0000000000001"
		machineID = "soc_rvkd0000000000002"
	)
	human := f.mintUserSecret(t, humanID)
	machine := f.mintSASecret(t, machineID)

	// Эталон исхода «состояние не установлено» — ответ того же обработчика с
	// непровязанным авторитетом. Своего написания текста здесь не заводится.
	unwired := internaliam.NewHandler(internaliam.NewLookupSubjectUseCase(nil), nil)
	ref := basicLive(t, ctx, unwired, humanID)
	require.Equal(t, codes.Unavailable, ref.code, "эталон: непровязанный авторитет — «состояние не установлено»")

	// Контроль без помехи.
	require.Equal(t, codes.OK, basicResolve(t, ctx, h, human).code, "контроль: секрет человека проходит")
	require.Equal(t, codes.OK, basicResolve(t, ctx, h, machine).code, "контроль: секрет машины проходит")

	// Помеха ровно одна: таблица отсечек заперта другой транзакцией, строки
	// удостоверений свободны.
	lock, err := f.pool.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = lock.Rollback(context.Background()) })
	_, err = lock.Exec(ctx, `LOCK TABLE kaname.user_token_revocations IN ACCESS EXCLUSIVE MODE`)
	require.NoError(t, err)

	// Вопросы задаются контекстом БЕЗ срока: предел обязан стоять у самого
	// авторитета. Будь он у вызывающего, запертая таблица держала бы глагол,
	// пока помеху не снимут, — и сторож ниже назвал бы это, а не повис.
	got := withinOwnLimit(t, "резолв человека", func(c context.Context) error {
		_, err := h.ResolveBasicCredential(c, &iamv1.ResolveBasicCredentialRequest{Presented: human})
		return err
	})
	require.Equalf(t, codes.Unavailable, got.code,
		"отсечку прочитать нельзя, а резолв ответил %s — не «состояние не установлено»", got.code)
	require.Equal(t, ref.wire, got.wire, "исход «состояние не установлено» различим по тексту")
	live := withinOwnLimit(t, "живость человека", func(c context.Context) error {
		_, err := h.CheckBasicCredentialLive(c, &iamv1.CheckBasicCredentialLiveRequest{CredentialId: humanID})
		return err
	})
	require.Equalf(t, codes.Unavailable, live.code,
		"отсечку прочитать нельзя, а живость ответила %s — не «состояние не установлено»", live.code)
	require.Equal(t, ref.wire, live.wire, "исход «состояние не установлено» у живости различим по тексту")

	// Машина под той же помехой: отсечка человека о ней не спрашивается.
	require.Equal(t, codes.OK, basicResolve(t, ctx, h, machine).code,
		"секрет машины споткнулся о таблицу отсечек человека")
	require.Equal(t, codes.OK, basicLive(t, ctx, h, machineID).code,
		"живость машины споткнулась о таблицу отсечек человека")

	// Помеха снята — тот же секрет снова проходит: исход выше дала она.
	require.NoError(t, lock.Rollback(ctx))
	require.Equal(t, codes.OK, basicResolve(t, ctx, h, human).code, "помеха снята, а секрет человека не проходит")
}

// basicCutoffInput — один вход сличения: чьё удостоверение и где отсечка.
type basicCutoffInput struct {
	name      string
	machine   bool
	cutoff    *time.Time
	wantIssue bool
}

// basicCutoffLane — полоса глазами этой пробы: пропустила ли она удостоверение.
type basicCutoffLane struct {
	name string
	pass func(t *testing.T, in basicCutoffInput, n int) bool
}

// TestRevokeAllCutoff_BasicSecretLaneAgreesWithTheKeyLane — полоса базового
// секрета (оба её вопроса) и полоса ключа нашего эндпоинта на одной базе,
// одном человеке, одном моменте выдачи и одной отсечке. Перепись выводится из
// исполненного: полос N · сверяют отсечку M.
func TestRevokeAllCutoff_BasicSecretLaneAgreesWithTheKeyLane(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	f := newAssertionFixture(t)
	contour := ctBuild(t, f, now)
	h := basicLaneHandler(t, f.pool)

	const (
		userKeyID    = "uoc_rvkc0000000000001"
		userSecretID = "uoc_rvkc0000000000002"
		saKeyID      = "soc_rvkc0000000000003"
		saSecretID   = "soc_rvkc0000000000004"
	)
	userKey := ctNewKey(t)
	f.seedUserClient(t, userKeyID, "mirror-lanes-user", userKey.publicPEM, tokenpolicy.AlgES256, nil)
	userSecret := f.mintUserSecret(t, userSecretID)
	saKey := ctNewKey(t)
	f.seedSAClient(t, saKeyID, "mirror-lanes-sa", saKey.publicPEM, tokenpolicy.AlgES256)
	saSecret := f.mintSASecret(t, saSecretID)

	// Один момент выдачи на все удостоверения: отсечка взвешивается против него,
	// и разные моменты сличали бы разные вопросы.
	issued := time.Now().UTC().Add(-24 * time.Hour).Truncate(time.Second)
	_, err := f.pool.Exec(ctx, `UPDATE kaname.user_oauth_clients SET created_at = $1`, issued)
	require.NoError(t, err)
	_, err = f.pool.Exec(ctx, `UPDATE kaname.service_account_oauth_clients SET created_at = $1`, issued)
	require.NoError(t, err)
	require.Equal(t, userClientIssuedAt(t, f, userKeyID), userClientIssuedAt(t, f, userSecretID),
		"предпосылка: ключ и секрет человека выданы в один момент")

	at := func(t time.Time) *time.Time { return &t }
	inputs := []basicCutoffInput{
		{name: "человек, отсечки нет", wantIssue: true},
		{name: "человек: удостоверение выдано до отсечки", cutoff: at(issued.Add(time.Hour))},
		{name: "человек: удостоверение выдано ровно в момент отсечки", cutoff: at(issued)},
		{name: "человек: удостоверение выдано после отсечки", cutoff: at(issued.Add(-time.Hour)), wantIssue: true},
		{name: "машина при отсечке человека", machine: true, cutoff: at(issued.Add(365 * 24 * time.Hour)), wantIssue: true},
	}
	setCutoff := func(t *testing.T, cutoff *time.Time) {
		t.Helper()
		if cutoff == nil {
			_, err := f.pool.Exec(ctx, `DELETE FROM kaname.user_token_revocations WHERE user_id = $1`, f.user)
			require.NoError(t, err)
			return
		}
		// Сличение ставит отсечку и НАЗАД: оператор записи продукта монотонен
		// и этого не умеет, поэтому здесь — прямая запись строки.
		_, err := f.pool.Exec(ctx, `
INSERT INTO kaname.user_token_revocations (user_id, revoke_before) VALUES ($1, $2)
ON CONFLICT (user_id) DO UPDATE SET revoke_before = EXCLUDED.revoke_before`, f.user, *cutoff)
		require.NoError(t, err)
	}

	lanes := []basicCutoffLane{
		{name: "наш токен-эндпоинт: ключ", pass: func(t *testing.T, in basicCutoffInput, n int) bool {
			t.Helper()
			key, id := userKey, userKeyID
			if in.machine {
				key, id = saKey, saKeyID
			}
			code, body := ctPost(t, contour.endpoint, ctAssertion(t, key, id, fmt.Sprintf("jti-lanes-%d", n), now))
			require.Truef(t, code == 200 || code == 401, "ответ ни выдачей, ни отказом: %d %v", code, body)
			return code == 200
		}},
		{name: "базовый секрет: резолв", pass: func(t *testing.T, in basicCutoffInput, _ int) bool {
			t.Helper()
			presented := userSecret
			if in.machine {
				presented = saSecret
			}
			a := basicResolve(t, ctx, h, presented)
			require.Truef(t, a.code == codes.OK || a.code == codes.Unauthenticated, "ответ ни пропуском, ни отказом: %s", a.code)
			return a.code == codes.OK
		}},
		{name: "базовый секрет: живость", pass: func(t *testing.T, in basicCutoffInput, _ int) bool {
			t.Helper()
			id := userSecretID
			if in.machine {
				id = saSecretID
			}
			a := basicLive(t, ctx, h, id)
			require.Truef(t, a.code == codes.OK || a.code == codes.Unauthenticated, "ответ ни пропуском, ни отказом: %s", a.code)
			return a.code == codes.OK
		}},
	}

	type seen struct{ ran, passedOnControl, refusedByCutoff bool }
	obs := map[string]*seen{}
	n := 0
	for _, in := range inputs {
		t.Run(in.name, func(t *testing.T) {
			setCutoff(t, in.cutoff)
			verdicts := make([]bool, len(lanes))
			for i, l := range lanes {
				n++
				passed := l.pass(t, in, n)
				verdicts[i] = passed
				o := obs[l.name]
				if o == nil {
					o = &seen{}
					obs[l.name] = o
				}
				o.ran = true
				if !in.machine && in.cutoff == nil && passed {
					o.passedOnControl = true
				}
				if !in.machine && in.cutoff != nil && !passed {
					o.refusedByCutoff = true
				}
				require.Equalf(t, in.wantIssue, passed, "полоса %q: пропуск=%v", l.name, passed)
			}
			for i := 1; i < len(lanes); i++ {
				require.Equalf(t, verdicts[0], verdicts[i],
					"полосы разошлись на входе %q: %q сказала %v, %q сказала %v",
					in.name, lanes[0].name, verdicts[0], lanes[i].name, verdicts[i])
			}
		})
	}

	ran, honoring := 0, 0
	for _, l := range lanes {
		o := obs[l.name]
		if o == nil || !o.ran {
			continue
		}
		ran++
		if o.passedOnControl && o.refusedByCutoff {
			honoring++
		}
	}
	t.Logf("перепись: полос исполнено %d из %d · сверяют отсечку %d · входов %d · вопросов %d",
		ran, len(lanes), honoring, len(inputs), n)
	require.GreaterOrEqualf(t, ran, 2, "исполнилось полос %d: сравнение одной полосы с собой ничего не сравнивает", ran)
	require.Equalf(t, ran, honoring,
		"исполнилось полос %d, а вердикт отсечка сменила у %d: полоса, чей вердикт от отсечки не меняется, отсечку не читает",
		ran, honoring)
}

// withinOwnLimit задаёт глаголу вопрос контекстом без срока и ждёт ответа не
// дольше собственного предела авторитета с запасом.
//
// Вопрос задаётся в своей горутине, а утверждения — здесь: проверки пробы из
// чужой горутины не останавливают её. Не дождавшись, сторож падает с именем
// предмета: глагол, повисший на помехе, есть ровно тот дефект, который он
// ловит, и виснуть вместе с ним проба не вправе. Горутина освобождается
// снятием помехи в очистке пробы.
func withinOwnLimit(t *testing.T, name string, ask func(context.Context) error) basicAnswer {
	t.Helper()
	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- ask(context.Background()) }()
	select {
	case err := <-done:
		code, wire := statusWire(t, err)
		t.Logf("%s: ответ за %s при пределе авторитета %s", name, time.Since(start).Round(time.Millisecond),
			basicAuthorityCallLimit)
		return basicAnswer{code: code, wire: wire}
	case <-time.After(basicAuthorityCallLimit + 10*time.Second):
		t.Fatalf("%s: глагол не ответил за %s при пределе авторитета %s — обращение к базе идёт без "+
			"своего предела и держит глагол, пока помеху не снимут", name,
			basicAuthorityCallLimit+10*time.Second, basicAuthorityCallLimit)
		return basicAnswer{}
	}
}
