// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package loginlanehttp_test

// mfa_fresh_condition_integration_test.go — условие `mfa_fresh` выполнимо
// (kaname#133, исход (а)): Ф11-34…44 и Ф11-48 приёмки
// `assurance-level-is-declared-by-our-session.md` §3.4.
//
// # Где наблюдается
//
// Вопрос о правах о себе — `AuthorizeService.Check` (`required_relation` =
// `ssh` либо `console`, ресурс — машина X), заданный на границе службы так, как
// его задаёт край от имени сессии: доверенная личность, доверенный уровень и
// номер записи сессии ключом каталога фундамента (`x-kacho-token-session-id`),
// пропущенным через пару извлечения фундамента и читатель края (`edgeChain`,
// kaname#711). Утверждается поле
// `allowed`; текст отказа контрактом здесь не является.
//
// # Как строится «Дано»
//
//   - факт `ssh` (`console`) человека U на машине X — СТРОКОЙ ЖУРНАЛА
//     `fga.tuple.write`, той же формой, какой пишет посев бутстрапа; факт
//     складывает писатель (триггер журнала, З2). Прямая вставка в проекцию дала
//     бы состояние, которого продукт не производит;
//   - сессии — НАСТОЯЩИМ входом ключом (Ф13): «3» — утверждение с проверкой
//     пользователя без допуска резервного копирования (Ф13-11), «2» — без
//     проверки пользователя (Ф13-10);
//   - моменты — управляемыми часами пробы (§3.0а): часы входа ключом, церемонии
//     повышения и службы прав — одни;
//   - подтверждённость адреса — записью хранилища (§3.0а): без неё дверь
//     отказывает раньше условия, и отрицания ниже зеленели бы по чужой причине.
//     Положительные близнецы это ловят.
//
// Ссылка R_S — значение, которое служба назвала краю в ответе о сессии
// (`ResolveHumanSessionResponse.session.session_id`).

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/PRO-Robotech/corelib/grpcsrv"
	"github.com/PRO-Robotech/corelib/principalwire"

	"github.com/PRO-Robotech/kaname/internal/authzcascade"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/edgecredential"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/personmarks"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify/webauthntest"
)

// probeClock — управляемые часы пробы: одни на вход ключом, церемонию и
// службу прав.
type probeClock struct {
	mu sync.Mutex
	at time.Time
}

func (c *probeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *probeClock) set(at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = at
}

// mfaWorld — стенд полосы сессии и служба прав над той же базой.
type mfaWorld struct {
	h     *sessionLane
	clk   *probeClock
	t0    time.Time
	authz *service.AuthorizeService
}

func newMFAWorld(t *testing.T) *mfaWorld {
	t.Helper()
	// T0 — момент «сейчас», округлённый до секунды: момент выхода по носителю
	// (Ф11-43) пишут часы процесса, и он обязан лечь не раньше выдачи.
	t0 := time.Now().UTC().Truncate(time.Second)
	clk := &probeClock{at: t0}
	h := newSessionLaneWith(t, sessionLaneOptions{ceremonyNow: clk.now})
	_, err := h.pool.Exec(h.ctx, `INSERT INTO kaname.clusters (id, name) VALUES ('cluster_root', 'kacho')
	           ON CONFLICT DO NOTHING`)
	require.NoError(t, err)
	door := authzcascade.WrapAdmitted(relverdict.NewAsker(h.pool), personmarks.New(h.pool))
	require.True(t, door.FormReachable(), "ПРЕДПОСЫЛКА: дверь решения собрана с формой")
	return &mfaWorld{h: h, clk: clk, t0: t0, authz: service.NewAuthorizeService(service.AuthorizeServiceConfig{
		Relations:           door,
		ClusterAdminChecker: door,
		SessionRecords:      h.sessions,
		Now:                 clk.now,
	})}
}

// verified — подтверждённость адреса личности (состояние хранилища Ф2, §3.0а).
func (w *mfaWorld) verified(t *testing.T, user domain.UserID) {
	t.Helper()
	_, err := w.h.pool.Exec(w.h.ctx, `UPDATE kaname.users SET email_verified_at = now() WHERE id = $1`, string(user))
	require.NoError(t, err, "Дано: адрес личности подтверждён")
}

// grant — факт отношения человека на машине строкой журнала (общее «Дано»).
func (w *mfaWorld) grant(t *testing.T, user domain.UserID, relation, instance string) {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"object": "compute_instance:" + instance, "relation": relation, "user": "user:" + string(user),
	})
	require.NoError(t, err)
	_, err = w.h.pool.Exec(w.h.ctx,
		`INSERT INTO kaname.fga_outbox (event_type, payload, created_at) VALUES ('fga.tuple.write', $1::jsonb, now())`,
		payload)
	require.NoError(t, err, "Дано: строка журнала о факте %s", relation)
}

// keySession — вход ключом человека u в момент `at`; возвращает носитель и
// контекст формы.
func (w *mfaWorld) keySession(t *testing.T, k akKey, at time.Time, o webauthntest.AssertionOptions) laneSession {
	t.Helper()
	w.clk.set(at)
	f := givenAKForm(t, w.h)
	c := givenChallenge(t, w.h, f)
	r := akLoginWith(t, w.h, f, k, c, o)
	require.Equalf(t, http.StatusOK, r.status, "Дано: вход ключом выдаёт сессию: %s", r.body)
	s := laneSession{bearer: cookieNamed(r.cookies, loginlanehttp.CookieSession), form: cookieNamed(r.cookies, loginlanehttp.CookieForm)}
	require.NotNil(t, s.bearer)
	return s
}

// ref — ссылка, которую служба называет краю в ответе о сессии (R_S).
func (w *mfaWorld) ref(t *testing.T, s laneSession) string {
	t.Helper()
	id := w.h.resolve(t, s.bearer.Value).GetSession().GetSessionId()
	require.NotEmpty(t, id, "Дано: ответ службы краю о сессии называет запись")
	return id
}

// ask — вопрос о правах о себе так, как его задаёт край: личность и уровень
// доверенными значениями, ссылка — ключом каталога фундамента через читатель
// края. Пустая ссылка — вопрос без неё (полоса предъявителя).
func (w *mfaWorld) ask(t *testing.T, at time.Time, user domain.UserID, acr, ref, relation, instance string,
	body map[string]any) bool {
	t.Helper()
	w.clk.set(at)
	md := metadata.Pairs(
		principalwire.MetaPrincipalType, "user",
		principalwire.MetaPrincipalID, string(user),
		principalwire.MetaTokenACR, acr,
	)
	if ref != "" {
		md.Set(principalwire.MetaTokenSessionID, ref)
	}
	ctx := edgeChain(t, metadata.NewIncomingContext(context.Background(), md))
	res, err := w.authz.Check(ctx, service.CheckRequest{
		Subject:          "user:" + string(user),
		Resource:         service.ResourceRef{Type: "compute_instance", ID: instance},
		Action:           "compute.instances." + relation,
		RequiredRelation: relation,
		Context:          body,
	})
	require.NoError(t, err, "вопрос о правах")
	return res.Allowed
}

// givenFreshKeyPerson — общее «Дано» Ф11-34: личность U с подтверждённым
// адресом, факт `relation` на X строкой журнала и ключ.
func givenFreshKeyPerson(t *testing.T, w *mfaWorld, relation, instance string) akKey {
	t.Helper()
	w.verified(t, w.h.user.ID)
	w.grant(t, w.h.user.ID, relation, instance)
	return givenAcceptedKey(t, w.h, w.h.user.ID)
}

var uv3 = webauthntest.AssertionOptions{UserVerified: true}

// Ф11-34 / Ф11-35 — свежий ключ с проверкой пользователя допускает по прямой
// ветви; тот же вопрос через 16 минут — нет. Пара отличается ОДНИМ фактом —
// моментом вопроса.
func TestF11_34_35_FreshKeySessionPassesAndAStaleOneDoesNot(t *testing.T) {
	w := newMFAWorld(t)
	k := givenFreshKeyPerson(t, w, "ssh", "ins-mfa-34")
	s := w.keySession(t, k, w.t0, uv3)
	r := w.ref(t, s)

	require.True(t, w.ask(t, w.t0.Add(time.Minute), w.h.user.ID, "3", r, "ssh", "ins-mfa-34", nil),
		"Ф11-34: свежий ключ с проверкой пользователя — допуск по прямой ветви")
	require.False(t, w.ask(t, w.t0.Add(16*time.Minute), w.h.user.ID, "3", r, "ssh", "ins-mfa-34", nil),
		"Ф11-35: окно 15 мин истекло")
}

// Ф11-36 — сессия «2» ключом без проверки пользователя: уровень не «3».
func TestF11_36_LevelTwoKeySessionDoesNotPass(t *testing.T) {
	w := newMFAWorld(t)
	k := givenFreshKeyPerson(t, w, "ssh", "ins-mfa-36")
	s := w.keySession(t, k, w.t0, webauthntest.AssertionOptions{})
	r := w.ref(t, s)
	require.Equal(t, "2", w.h.resolve(t, s.bearer.Value).GetSession().GetAssuranceLevel(), "Дано: сессия «2»")

	require.False(t, w.ask(t, w.t0.Add(time.Minute), w.h.user.ID, "2", r, "ssh", "ins-mfa-36", nil),
		"Ф11-36: уровень не «3»")
}

// Ф11-37 / Ф11-38 — две живые сессии одной личности; доводы берутся из записи
// сессии ВОПРОСА. Предъявление пароля внутри S1 момент аутентификации S1 не
// двигает; свежесть S2 к S1 не относится.
func TestF11_37_38_EvidenceIsTheRecordOfTheQuestionsSession(t *testing.T) {
	w := newMFAWorld(t)
	k := givenFreshKeyPerson(t, w, "ssh", "ins-mfa-37")
	s1 := w.keySession(t, k, w.t0, uv3)
	s2 := w.keySession(t, k, w.t0.Add(14*time.Minute), uv3)

	// В T0 + 14 мин внутри S1 успешно предъявлен пароль: носитель перевыпущен (Р5).
	w.clk.set(w.t0.Add(14 * time.Minute))
	su := w.h.stepUpPassword(t, s1, integrationPassword, w.h.csrfFor(t, domain.FormStepUp, s1.form))
	require.Equalf(t, http.StatusOK, su.status, "Дано: предъявление пароля внутри S1: %s", su.body)
	if b := cookieNamed(su.cookies, loginlanehttp.CookieSession); b != nil {
		s1.bearer = b
	}
	row, ok := w.h.rowByBearer(t, s1.bearer.Value)
	require.True(t, ok)
	require.Equal(t, "3", row.level, "Дано: уровень S1 остаётся «3»")
	require.Truef(t, !row.lastSeen.Before(w.t0.Add(14*time.Minute)),
		"Дано: момент последнего предъявления S1 сдвинут к T0 + 14 мин, а он %v", row.lastSeen)

	r1, r2 := w.ref(t, s1), w.ref(t, s2)
	require.NotEqual(t, r1, r2, "Дано: две разные записи")
	at := w.t0.Add(16 * time.Minute)
	require.False(t, w.ask(t, at, w.h.user.ID, "3", r1, "ssh", "ins-mfa-37", nil),
		"Ф11-37: довод момента — момент аутентификации S1 (T0)")
	require.True(t, w.ask(t, at, w.h.user.ID, "3", r2, "ssh", "ins-mfa-37", nil),
		"Ф11-38: доводы — из записи S2, аутентифицированной в T0 + 14 мин")
}

// Ф11-39 / Ф11-42 — тело вопроса не читается ни в сторону допуска, ни в
// сторону отказа.
func TestF11_39_42_BodyIsNotReadEitherWay(t *testing.T) {
	w := newMFAWorld(t)
	k := givenFreshKeyPerson(t, w, "ssh", "ins-mfa-39")
	weak := w.keySession(t, k, w.t0, webauthntest.AssertionOptions{})
	strong := w.keySession(t, k, w.t0, uv3)
	at := w.t0.Add(time.Minute)

	forged := map[string]any{"acr_value": "3", "amr_claims": []any{"webauthn"}, "mfa_at": at.Unix()}
	require.False(t, w.ask(t, at, w.h.user.ID, "2", w.ref(t, weak), "ssh", "ins-mfa-39", forged),
		"Ф11-39: сильные доводы тела допуска не дают")
	weakBody := map[string]any{"acr_value": "1", "amr_claims": []any{"password"}, "mfa_at": w.t0.Add(-time.Hour).Unix()}
	require.True(t, w.ask(t, at, w.h.user.ID, "3", w.ref(t, strong), "ssh", "ins-mfa-39", weakBody),
		"Ф11-42: слабые доводы тела отказа не дают")
}

// Ф11-40 / Ф11-41 — второе условное отношение модели ведёт себя так же.
func TestF11_40_41_ConsoleBehavesTheSame(t *testing.T) {
	w := newMFAWorld(t)
	k := givenFreshKeyPerson(t, w, "console", "ins-mfa-40")
	s := w.keySession(t, k, w.t0, uv3)
	r := w.ref(t, s)

	require.True(t, w.ask(t, w.t0.Add(time.Minute), w.h.user.ID, "3", r, "console", "ins-mfa-40", nil), "Ф11-40")
	require.False(t, w.ask(t, w.t0.Add(16*time.Minute), w.h.user.ID, "3", r, "console", "ins-mfa-40", nil), "Ф11-41")
}

// Ф11-43 — сессия окончена выходом между ответом краю о сессии и вопросом о
// правах: живость судит служба на самом вопросе.
func TestF11_43_EndedSessionGivesNoEvidence(t *testing.T) {
	w := newMFAWorld(t)
	k := givenFreshKeyPerson(t, w, "ssh", "ins-mfa-43")
	s := w.keySession(t, k, w.t0, uv3)
	r := w.ref(t, s)
	at := w.t0.Add(time.Minute)

	// Положительный близнец — до выхода тот же вопрос проходит.
	require.True(t, w.ask(t, at, w.h.user.ID, "3", r, "ssh", "ins-mfa-43", nil), "близнец Ф11-43: до выхода — допуск")

	lo := w.h.logout(t, s)
	require.Equalf(t, http.StatusOK, lo.status, "Дано: выход по носителю: %s", lo.body)
	row := w.h.rowByID(t, r)
	require.True(t, row.ended, "Дано: запись осталась, помеченная оконченной")

	require.False(t, w.ask(t, at, w.h.user.ID, "3", r, "ssh", "ins-mfa-43", nil),
		"Ф11-43: запись по ссылке не жива — как вопрос без нашей сессии")
}

// Ф11-44 — ссылка на живую сессию «3» ДРУГОЙ личности при доверенной личности U.
func TestF11_44_ForeignRecordGivesNoEvidence(t *testing.T) {
	w := newMFAWorld(t)
	k := givenFreshKeyPerson(t, w, "ssh", "ins-mfa-44")
	s := w.keySession(t, k, w.t0, uv3)
	other := registerPerson(t, w.h, "mfa44")
	w.verified(t, other)
	kv := givenAcceptedKey(t, w.h, other)
	sv := w.keySession(t, kv, w.t0, uv3)
	at := w.t0.Add(time.Minute)

	require.True(t, w.ask(t, at, w.h.user.ID, "3", w.ref(t, s), "ssh", "ins-mfa-44", nil),
		"близнец Ф11-44: своя ссылка — допуск")
	require.False(t, w.ask(t, at, w.h.user.ID, "3", w.ref(t, sv), "ssh", "ins-mfa-44", nil),
		"Ф11-44: личность записи не равна доверенной личности вопроса")
}

// Ф11-48 — вопрос без ссылки: последнюю либо иную сессию личности служба не
// подставляет.
func TestF11_48_QuestionWithoutAReferenceGetsNoEvidence(t *testing.T) {
	w := newMFAWorld(t)
	k := givenFreshKeyPerson(t, w, "ssh", "ins-mfa-48")
	s := w.keySession(t, k, w.t0, uv3)
	at := w.t0.Add(time.Minute)

	require.True(t, w.ask(t, at, w.h.user.ID, "3", w.ref(t, s), "ssh", "ins-mfa-48", nil),
		"близнец Ф11-48: со ссылкой — допуск")
	require.False(t, w.ask(t, at, w.h.user.ID, "3", "", "ssh", "ins-mfa-48", nil),
		"Ф11-48: за вопросом нет нашей сессии — доводов способов и момента нет")
}

// edgeChain — контекст глагола за цепочкой публичного слушателя: пара
// извлечения фундамента (личность, уровень и номер записи — одним решением о
// доверии) и читатель края (`edgecredential`). Номер записи доезжает до службы
// только через носитель фундамента (kaname#711), поэтому вопрос задаётся
// метаданными, а не готовым контекстом.
func edgeChain(t *testing.T, ctx context.Context) context.Context {
	t.Helper()
	chain := append(grpcsrv.PrincipalExtractUnary(grpcsrv.NewTrustDomain(""), grpcsrv.NewTrustedForwarders()),
		edgecredential.Unary())
	var out context.Context
	invoke := func(c context.Context, _ any) (any, error) {
		out = c
		return nil, nil
	}
	for i := len(chain) - 1; i >= 0; i-- {
		ic, next := chain[i], invoke
		invoke = func(c context.Context, req any) (any, error) {
			return ic(c, req, &grpc.UnaryServerInfo{FullMethod: "/kaname.cloud.iam.v1.AuthorizeService/Check"}, next)
		}
	}
	_, err := invoke(ctx, nil)
	require.NoError(t, err, "цепочка публичного слушателя отвергла вопрос")
	require.NotNil(t, out)
	return out
}
