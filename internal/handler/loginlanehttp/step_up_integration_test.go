// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// step_up_integration_test.go — ПОВЫШЕНИЕ ВНУТРИ ЖИВОЙ СЕССИИ на проводе, ветвь
// пароля (задача PRO-Robotech/kacho#1280; приёмка
// `docs/engineering/acceptance/assurance-level-is-declared-by-our-session.md`
// ред. 5, §3.2: Ф11-09, Ф11-10, Ф11-12, Ф11-13, Ф11-31; решения Р2, Р5, Р6).
//
// # Как наблюдается исход
//
// Носитель — печенье `kaname_session`, которое выдаёт слушатель полосы; уровень
// — ответ церемонии (объект `assurance` и состав сессии) и ответ службы краю о
// сессии (`Resolve`, §3.0: «уровень в ответе службы краю о сессии — тот, что
// край читает и пересылает дальше»). «Глагол с полом L проходит пол» на границе
// службы спрашивается у ТОЙ ЖЕ функции решения, что зовёт край
// (`grpcsrv.EvaluateStepUp`), над уровнем из ответа краю.
//
// # Близнецы (§7 инв. 2)
//
// Отрицания Ф11-12, Ф11-13, Ф11-31 — близнецы Ф11-09 с ОДНИМ изменённым
// фактом: отзыв · неверный пароль · признак защиты формы. У каждого близнец
// исполняется в той же пробе: без него отказ зеленел бы на полосе, отвергающей
// всё.
//
// # Способность падать (доказана инъекцией, не прочтением)
//
// Каждая проба прогнана красной против одно-фактной инъекции в прод-код и
// зелёной после отката; перечень инъекций — в шапке каждой пробы.
//
// Run: `go test ./internal/handler/loginlanehttp/ -run 'F11_' -count=1`
// (Docker). Skipped under -short.
package loginlanehttp_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/grpcsrv"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/assurance"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
)

// authenticationFailedBody — тело отказа предъявления на полосе (фиксированный
// текст Ф3-02): один и тот же у неверного пароля и у несуществующей сессии.
const authenticationFailedBody = `{"code":16,"message":"authentication failed","details":[]}`

// TestLaneIntegration_F11_09_PasswordAgainRotatesTheBearerAndKeepsTheLevel —
// Ф11-09: внутри живой сессии уровня «1» повторно предъявлен пароль. Носитель
// перевыпущен: прежний, предъявленный снова, получает отказ, побайтово равный
// отказу по несуществующей сессии — и на полосе, и в ответе краю; новый годен и
// несёт ТОТ ЖЕ уровень «1»; выход по новому носителю гасит сессию целиком (Р5).
//
// Инъекция (step_up.go): запись предъявления кладёт в хранилище дайджест
// ПРЕЖНЕГО носителя (`in.Bearer.Digest()` вместо `bearer.Digest()`) —
// перевыпуска нет → красное «прежний носитель годен после предъявления».
func TestLaneIntegration_F11_09_PasswordAgainRotatesTheBearerAndKeepsTheLevel(t *testing.T) {
	h := newSessionLane(t)
	s := h.login(t, integrationPassword)

	// Дано — проверяется ДО предмета: живая сессия уровня «1», выданная паролем.
	given := h.resolve(t, s.bearer.Value)
	require.True(t, given.GetFound(), "Дано: сессия входа жива")
	require.Equal(t, "1", given.GetSession().GetAssuranceLevel(), "Дано: вход паролем — уровень «1»")
	before, ok := h.rowByBearer(t, s.bearer.Value)
	require.True(t, ok, "Дано: запись сессии найдена по носителю")
	totalBefore, _ := h.sessionsOfPerson(t)

	tok := h.csrfFor(t, domain.FormStepUp, s.form)
	r := h.stepUpPassword(t, s, integrationPassword, tok)
	require.Equal(t, http.StatusOK, r.status, "повторный пароль — успешное предъявление: %s", r.body)
	fresh := cookieNamed(r.cookies, loginlanehttp.CookieSession)
	require.NotNil(t, fresh, "успешное предъявление перевыпускает носитель (Р5): Set-Cookie обязан быть")
	require.NotEqual(t, s.bearer.Value, fresh.Value, "перевыпуск — новое значение носителя")
	assuranceLevel, sessionLevel := ceremonyLevels(t, r.body)
	require.Equal(t, "1", assuranceLevel, "ответ церемонии называет тот же уровень «1»")
	require.Equal(t, "1", sessionLevel, "состав сессии в ответе церемонии — уровень «1»")

	// Прежний носитель, предъявленный снова, — отказ, побайтово равный отказу по
	// несуществующей сессии. Поверхностей две, и на обеих одно и то же.
	ghost := ghostBearer(t)
	againOld := h.stepUpPassword(t, laneSession{bearer: s.bearer, form: s.form}, integrationPassword, tok)
	againGhost := h.stepUpPassword(t, laneSession{bearer: ghost, form: s.form}, integrationPassword, tok)
	require.Equal(t, http.StatusUnauthorized, againOld.status,
		"прежний носитель годен после предъявления — перевыпуска не было (Р5): %s", againOld.body)
	require.Equal(t, againGhost.status, againOld.status, "полоса: код отказа по прежнему носителю равен коду по несуществующему")
	require.Equal(t, againGhost.body, againOld.body, "полоса: тело отказа по прежнему носителю побайтово равно телу по несуществующему")
	require.JSONEq(t, authenticationFailedBody, againOld.body)
	require.Nil(t, cookieNamed(againOld.cookies, loginlanehttp.CookieSession), "отказ носителя не пишет")
	require.False(t, h.resolve(t, s.bearer.Value).GetFound(), "ответ краю: прежний носитель — «сессии нет»")
	require.Equal(t, h.resolveWire(t, ghost.Value), h.resolveWire(t, s.bearer.Value),
		"ответ краю по прежнему носителю побайтово равен ответу по несуществующему")

	// Новый годен и несёт ТОТ ЖЕ уровень; сессия та же — запись одна.
	got := h.resolve(t, fresh.Value)
	require.True(t, got.GetFound(), "новый носитель годен")
	require.Equal(t, "1", got.GetSession().GetAssuranceLevel(), "новый носитель несёт тот же уровень «1»")
	after, ok := h.rowByBearer(t, fresh.Value)
	require.True(t, ok)
	require.Equal(t, before.id, after.id, "перевыпуск — та же запись сессии, а не вторая сессия")
	totalAfter, _ := h.sessionsOfPerson(t)
	require.Equal(t, totalBefore, totalAfter, "предъявление не заводит записей сессии")

	// Выход по новому носителю гасит сессию ЦЕЛИКОМ: единица отзыва — сессия.
	lo := h.logout(t, laneSession{bearer: fresh, form: s.form})
	require.Equal(t, http.StatusOK, lo.status, lo.body)
	require.False(t, h.resolve(t, fresh.Value).GetFound(), "после выхода новый носитель — «сессии нет»")
	require.False(t, h.resolve(t, s.bearer.Value).GetFound(), "после выхода прежний носитель — «сессии нет»")
	require.True(t, h.rowByID(t, before.id).ended, "запись сессии снята выходом")
}

// TestLaneIntegration_F11_10_PasswordAgainInALevelTwoSessionKeepsLevelTwo —
// Ф11-10: сессия в согласованном состоянии «2» при множестве {`password`,
// `totp`} (§3.0а); внутри неё повторно предъявлен ТОЛЬКО пароль. Уровень
// остаётся «2»: ответ церемонии называет «2», глагол с полом «2» проходит пол.
//
// Дано строит ПРОИЗВОДИТЕЛЬ выдачи продукта (`humansession.IssueSession`) с
// множеством, которое даёт вход паролем и кодом (Ф11-02): уровень выводит
// правило, а не проба, — состояние согласовано by construction (§3.0а).
//
// Инъекция (step_up.go): множество ЗАМЕЩАЕТСЯ последним предъявлением
// (`[]string{in.Method.String()}` вместо `withMethod(...)`) → красное «уровень
// понижен предъявлением».
func TestLaneIntegration_F11_10_PasswordAgainInALevelTwoSessionKeepsLevelTwo(t *testing.T) {
	h := newSessionLane(t)
	presented := []assurance.Presentation{assurance.PasswordPresented(), assurance.TOTPPresented()}
	lvl, ok := assurance.LevelOf(presented)
	require.True(t, ok)
	require.Equal(t, "2", lvl.String(), "Дано: правило над {password, totp} даёт «2» — иначе состояние не то, о котором сценарий")

	w, err := h.sessions.Writer(h.ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(h.ctx) }()
	issued, bearer, err := humansession.IssueSession(h.ctx, w, humansession.IssueInput{
		User: h.user, Presented: presented, At: time.Now().UTC(), TTL: laneSessionTTL, EmitAudit: true,
	})
	require.NoError(t, err)
	require.NoError(t, w.Commit(h.ctx))
	require.Equal(t, "2", h.resolve(t, bearer.CookieValue()).GetSession().GetAssuranceLevel(),
		"Дано: ответ краю о сессии называет «2»")

	// Контекст формы — как у браузера: выдаётся признаковым глаголом.
	tok, form := h.lane.csrf(t, h.c, string(domain.FormStepUp), nil)
	s := laneSession{bearer: &http.Cookie{Name: loginlanehttp.CookieSession, Value: bearer.CookieValue()}, form: form}
	r := h.stepUpPassword(t, s, integrationPassword, tok)
	require.Equal(t, http.StatusOK, r.status, r.body)
	assuranceLevel, sessionLevel := ceremonyLevels(t, r.body)
	require.Equal(t, "2", assuranceLevel, "ответ церемонии называет «2»: уровень понижен предъявлением — множество замещено, а не накоплено")
	require.Equal(t, "2", sessionLevel, "состав сессии в ответе церемонии — «2»")

	fresh := cookieNamed(r.cookies, loginlanehttp.CookieSession)
	require.NotNil(t, fresh)
	got := h.resolve(t, fresh.Value)
	require.True(t, got.GetFound())
	require.Equal(t, "2", got.GetSession().GetAssuranceLevel(), "ответ краю о сессии после предъявления — «2»")
	require.Equal(t, grpcsrv.StepUpAllow, grpcsrv.EvaluateStepUp(grpcsrv.StepUpInput{
		PrincipalType: "user", PresentedACR: got.GetSession().GetAssuranceLevel(), RequiredACR: "2",
	}), "глагол с полом «2» проходит пол — решает та же функция, что у края")

	row := h.rowByID(t, string(issued.ID))
	require.ElementsMatch(t, []string{"password", "totp"}, row.methods,
		"множество предъявленного накапливается: второй фактор остался в нём (Р2, монотонность)")
}

// TestLaneIntegration_F11_12_RevokedSessionIsNotRevivedByAPresentation —
// Ф11-12: сессия, покрытая отзывом любым из трёх способов (выход · смена пароля
// из другой сессии · блокировка); с её носителем выполнено предъявление внутри
// сессии → отказ; нового носителя ответ не несёт, прежний по-прежнему
// отвергается. Близнец — Ф11-09: живая сессия той же личности то же
// предъявление проходит; единственное отличие — отзыв (Р6).
//
// Пароль в «Когда» — ДЕЙСТВУЮЩИЙ пароль личности на момент предъявления (после
// смены — новый): иначе отказ давал бы неверный пароль, а не отзыв, и фактов
// было бы два.
//
// Инъекции (repo `human_session_repo.go`, `Resolve`): (1) чтение сессии не
// сверяет снятие (ветвь `endedAt != nil` снята) → красные подпробы «выход» и
// «смена пароля»; (2) чтение не сверяет состояние личности (ветвь блокировки
// снята) → красная подпроба «блокировка».
func TestLaneIntegration_F11_12_RevokedSessionIsNotRevivedByAPresentation(t *testing.T) {
	const changedPassword = "a-brand-new-password-of-f11-12"
	cases := []struct {
		name string
		// revoke покрывает сессию s отзывом и возвращает действующий пароль.
		revoke func(t *testing.T, h *sessionLane, s laneSession) string
		// twin — сессия, отличающаяся от отозванной ОДНИМ фактом: отзыва нет.
		twin func(t *testing.T, h *sessionLane, s laneSession, password string) laneSession
	}{
		{
			name: "logout",
			revoke: func(t *testing.T, h *sessionLane, s laneSession) string {
				r := h.logout(t, s)
				require.Equal(t, http.StatusOK, r.status, "Дано: выход: %s", r.body)
				return integrationPassword
			},
			twin: func(t *testing.T, h *sessionLane, _ laneSession, password string) laneSession {
				return h.login(t, password)
			},
		},
		{
			name: "password-change-from-another-session",
			revoke: func(t *testing.T, h *sessionLane, _ laneSession) string {
				other := h.login(t, integrationPassword)
				r := h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathPassword, map[string]any{
					"currentPassword": integrationPassword, "newPassword": changedPassword,
					"csrfToken": h.csrfFor(t, domain.FormPassword, other.form),
				}, fwd(), other.bearer, other.form)
				require.Equal(t, http.StatusOK, r.status, "Дано: смена пароля из другой сессии: %s", r.body)
				return changedPassword
			},
			twin: func(t *testing.T, h *sessionLane, _ laneSession, password string) laneSession {
				return h.login(t, password)
			},
		},
		{
			name: "block",
			revoke: func(t *testing.T, h *sessionLane, _ laneSession) string {
				h.setInviteStatus(t, domain.InviteStatusBlocked)
				return integrationPassword
			},
			// Блокировка обратима, и близнец — ТА ЖЕ сессия после снятия
			// блокировки (Ф3-10: снятие возвращает сессию): отличие ровно одно.
			twin: func(t *testing.T, h *sessionLane, s laneSession, _ string) laneSession {
				h.setInviteStatus(t, domain.InviteStatusActive)
				return s
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newSessionLane(t)
			s := h.login(t, integrationPassword)
			row, ok := h.rowByBearer(t, s.bearer.Value)
			require.True(t, ok)
			tok := h.csrfFor(t, domain.FormStepUp, s.form)
			password := tc.revoke(t, h, s)
			_, liveBefore := h.sessionsOfPerson(t)

			r := h.stepUpPassword(t, s, password, tok)
			require.Equal(t, http.StatusUnauthorized, r.status,
				"%s: предъявление с носителем отозванной сессии обязано получить отказ: %s", tc.name, r.body)
			require.JSONEq(t, authenticationFailedBody, r.body)
			require.Nil(t, cookieNamed(r.cookies, loginlanehttp.CookieSession), "%s: отказ нового носителя не несёт", tc.name)
			require.False(t, h.resolve(t, s.bearer.Value).GetFound(), "%s: прежний носитель по-прежнему отвергается", tc.name)
			after := h.rowByID(t, row.id)
			require.Equal(t, row.digest, after.digest, "%s: носитель отозванной сессии не перевыпущен", tc.name)
			require.Equal(t, row.methods, after.methods, "%s: множество отозванной сессии не тронуто", tc.name)
			_, liveAfter := h.sessionsOfPerson(t)
			require.Equal(t, liveBefore, liveAfter, "%s: предъявление не оживило ни одной сессии", tc.name)

			// Близнец (Ф11-09): отличие одно — отзыва нет.
			live := tc.twin(t, h, s, password)
			twin := h.stepUpPassword(t, live, password, h.csrfFor(t, domain.FormStepUp, live.form))
			require.Equal(t, http.StatusOK, twin.status, "%s: близнец — живая сессия то же предъявление проходит: %s", tc.name, twin.body)
		})
	}
}

// TestLaneIntegration_F11_13_WrongPasswordHasNoConsequences — Ф11-13: внутри
// живой сессии уровня «1» предъявлен НЕВЕРНЫЙ пароль → отказ предъявления;
// уровень и носитель прежние, и носитель ГОДЕН: неудачное предъявление сессию не
// гасит и не понижает. Близнец — Ф11-09, отличие — неверный пароль.
//
// Инъекции (step_up.go, ветвь несовпадения): (1) неудача гасит сессию
// (`EndSession` перед отказом) → красное «носитель погашен неудачным
// предъявлением»; (2) несовпадение засчитано совпадением → красное «неверный
// пароль прошёл».
func TestLaneIntegration_F11_13_WrongPasswordHasNoConsequences(t *testing.T) {
	h := newSessionLane(t)
	s := h.login(t, integrationPassword)
	before, ok := h.rowByBearer(t, s.bearer.Value)
	require.True(t, ok)
	tok := h.csrfFor(t, domain.FormStepUp, s.form)

	r := h.stepUpPassword(t, s, laneWrongPassword, tok)
	require.Equal(t, http.StatusUnauthorized, r.status, "неверный пароль — отказ предъявления: %s", r.body)
	require.JSONEq(t, authenticationFailedBody, r.body)
	require.Nil(t, cookieNamed(r.cookies, loginlanehttp.CookieSession), "отказ носителя не перевыпускает")

	got := h.resolve(t, s.bearer.Value)
	require.True(t, got.GetFound(), "носитель погашен неудачным предъявлением — неудача обязана быть без последствий")
	require.Equal(t, "1", got.GetSession().GetAssuranceLevel(), "уровень прежний")
	after := h.rowByID(t, before.id)
	require.Equal(t, before.digest, after.digest, "носитель прежний")
	require.Equal(t, before.methods, after.methods, "множество прежнее")
	require.False(t, after.ended, "запись не снята")
	require.True(t, before.lastSeen.Equal(after.lastSeen), "момент последнего предъявления неудачей не сдвинут")

	// Близнец (Ф11-09): тот же носитель, верный пароль — проходит.
	twin := h.stepUpPassword(t, s, integrationPassword, tok)
	require.Equal(t, http.StatusOK, twin.status, "близнец: верный пароль в той же сессии проходит: %s", twin.body)
}

// TestLaneIntegration_F11_31_CeremonyWithoutAValidFormTokenIsRefused — Ф11-31:
// верный пароль, но запрос церемонии без действительного признака защиты формы
// (единственное отличие от Ф11-09) → отказ; прежний носитель ГОДЕН — перевыпуска
// не было. Недействительных форм две, обе закрыты: признака нет вовсе и признак
// чужого вида (вход) в том же контексте.
//
// Инъекция (handler.go, `stepUp`): проверка признака формы снята → красное
// «церемония прошла без признака».
func TestLaneIntegration_F11_31_CeremonyWithoutAValidFormTokenIsRefused(t *testing.T) {
	h := newSessionLane(t)
	s := h.login(t, integrationPassword)
	before, ok := h.rowByBearer(t, s.bearer.Value)
	require.True(t, ok)

	for _, bad := range []struct {
		name, token string
		status      int
	}{
		{"absent", "", http.StatusBadRequest},
		{"foreign-kind", h.csrfFor(t, domain.FormLogin, s.form), http.StatusForbidden},
	} {
		r := h.stepUpPassword(t, s, integrationPassword, bad.token)
		require.Equal(t, bad.status, r.status, "%s: церемония без действительного признака обязана получить отказ: %s", bad.name, r.body)
		require.Nil(t, cookieNamed(r.cookies, loginlanehttp.CookieSession), "%s: перевыпуска нет", bad.name)
		got := h.resolve(t, s.bearer.Value)
		require.True(t, got.GetFound(), "%s: прежний носитель годен", bad.name)
		require.Equal(t, "1", got.GetSession().GetAssuranceLevel())
		require.Equal(t, before.digest, h.rowByID(t, before.id).digest, "%s: носитель в хранилище прежний", bad.name)
	}

	// Близнец (Ф11-09): тот же запрос с действительным признаком — перевыпуск, и
	// прежний носитель отвергается.
	twin := h.stepUpPassword(t, s, integrationPassword, h.csrfFor(t, domain.FormStepUp, s.form))
	require.Equal(t, http.StatusOK, twin.status, "близнец: с действительным признаком церемония проходит: %s", twin.body)
	require.False(t, h.resolve(t, s.bearer.Value).GetFound(), "близнец: после перевыпуска прежний носитель отвергается")
}
