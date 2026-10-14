// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// own_sessions_harness_integration_test.go — СТЕНД проб приёмки
// `docs/engineering/acceptance/own-sessions-are-listed-and-ended-by-their-owner.md`
// (задача PRO-Robotech/kaname#634, сценарии уровня I, OS-01…OS-14) на ПРОВОДЕ
// полосы формы: слушатель над настоящими глаголами и настоящими адаптерами
// базы — стенд подтверждения адреса (`avLane`), ответ краю о сессии через
// соединение, часы глаголов управляемые (`avClock`, только вперёд).
//
// # Ступени пробы и их слова
//
//  1. МИР — посев (§4.0 приёмки) заведён и прочитан обратно. Отказ —
//     «НЕ-ВЫПОЛНИЛОСЬ(фикстура)».
//  2. ВОЗМОЖНОСТЬ — три пути смонтированы на слушателе. Путь, отвечающий 404, —
//     «ЧЕСТНЫЙ-КРАСНЫЙ: глагола нет». Ступень стоит ПОСЛЕ мира: сломанная
//     фикстура не выдаёт себя за отсутствие глагола.
//  3. ПРЕДМЕТ — утверждения сценария; отказ несёт номер сценария.
//
// # Что харнесс задаёт сверх стенда подтверждения адреса
//
// Ровно то, что разрешает приёмка (§0.2, последняя строка «Разрешает»): выдача
// сессии с ЗАДАННЫМ заголовком `User-Agent` и чтение строки записи. Клиент Go
// подставляет свой заголовок, когда запрос его не несёт; «без заголовка» — это
// заголовок с пустым значением, который клиент не отправляет вовсе.
package loginlanehttp_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	sessionrev "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/session_revocations"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// Пути, вид признака, причина снятия и событие — ДОСЛОВНО из приёмки (Р1, Р6):
// литералы, а не константы слушателя, — предмет пробы и есть то, что слушатель
// их объявил.
const (
	osPathList      = "/iam/v1/auth/sessions"
	osPathEnd       = "/iam/v1/auth/sessions/end"
	osPathEndOthers = "/iam/v1/auth/sessions/end-others"
	osForm          = "session-end"
	osEndReason     = "ended-from-another-session"
	osAudit         = "iam.session.ended_by_person"
	osRegisterAgent = "os-agent-register"
)

// Тела отказов полосы побайтово (Р5, Р8, Р9).
const (
	osBodyNotFound   = `{"code":5,"message":"session not found","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"SESSION_NOT_FOUND","domain":"iam.kaname.cloud"}]}`
	osBodyIsCurrent  = `{"code":9,"message":"the current session ends by logout","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"SESSION_IS_CURRENT","domain":"iam.kaname.cloud"}]}`
	osBodyNotFresh   = `{"code":7,"message":"re-authentication required: present a credential again","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"SESSION_NOT_FRESH","domain":"iam.kaname.cloud"}]}`
	osBodyAuthFailed = `{"code":16,"message":"authentication failed","details":[]}`
)

// osSeed — «Дано I» (§4.0): личность регистрацией и (если verified) отметкой,
// три входа `S_A`, `S_B`, `S_C` подряд, затем выход носителем `S₀`.
type osSeed struct {
	u          avSession
	s0         avSession
	a, b, c    avSession
	s0ID       string
	aID, bID   string
	cID        string
	registerUA string
}

// registerWithAgent — регистрация через слушатель с заданным `User-Agent`.
func (h *avLane) registerWithAgent(t *testing.T, email, ua string) avSession {
	t.Helper()
	tok, ctxCk := h.lane.csrf(t, h.c, string(domain.FormRegister), nil)
	r := h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathRegister,
		map[string]any{"email": email, "password": integrationPassword, "csrfToken": tok}, osHeaders(ua), ctxCk)
	require.Equal(t, http.StatusOK, r.status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): регистрация %s: %s", email, r.body)
	var out struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	require.NoError(t, json.Unmarshal([]byte(r.body), &out))
	s := avSession{user: domain.UserID(out.User.ID), email: email,
		bearer: cookieNamed(r.cookies, loginlanehttp.CookieSession), form: cookieNamed(r.cookies, loginlanehttp.CookieForm)}
	require.NotEmpty(t, s.user, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): регистрация не назвала человека")
	require.NotNil(t, s.bearer, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): регистрация не выдала носитель")
	return s
}

// osHeaders — заголовки запроса харнесса: адрес источника и описание клиента.
// Пустое описание — заголовок не отправляется (клиент Go пустой не пишет).
func osHeaders(ua string) map[string]string {
	hs := fwd()
	hs["User-Agent"] = ua
	return hs
}

// loginWithAgentReply — вход паролем с заданным `User-Agent`; ответ как есть.
func (h *avLane) loginWithAgentReply(t *testing.T, s avSession, ua string) reply {
	t.Helper()
	tok, ctxCk := h.lane.csrf(t, h.c, string(domain.FormLogin), nil)
	return h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathLogin,
		map[string]any{"email": s.email, "password": integrationPassword, "csrfToken": tok}, osHeaders(ua), ctxCk)
}

// loginWithAgent — вход, выдавший сессию.
func (h *avLane) loginWithAgent(t *testing.T, s avSession, ua string) avSession {
	t.Helper()
	r := h.loginWithAgentReply(t, s, ua)
	require.Equal(t, http.StatusOK, r.status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): вход %s: %s", s.email, r.body)
	out := s
	out.bearer = cookieNamed(r.cookies, loginlanehttp.CookieSession)
	out.form = cookieNamed(r.cookies, loginlanehttp.CookieForm)
	require.NotNil(t, out.bearer, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): вход не выдал носитель")
	return out
}

// logoutOf — выход (Ф3-15) носителем s.
func (h *avLane) logoutOf(t *testing.T, s avSession) {
	t.Helper()
	r := h.post(t, s, loginlanehttp.PathLogout, map[string]any{"csrfToken": h.token(s, string(domain.FormLogout))})
	require.Equal(t, http.StatusOK, r.status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): выход: %s", r.body)
}

// sessionIDOf — идентификатор записи по носителю (чтение строки, §4.0).
func (h *avLane) sessionIDOf(t *testing.T, s avSession) string {
	t.Helper()
	var id string
	err := h.pool.QueryRow(h.ctx, `SELECT id FROM kaname.human_sessions WHERE bearer_digest = $1`,
		string(domain.PresentedSessionBearer(s.bearer.Value).Digest())).Scan(&id)
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): строка записи по носителю")
	return id
}

// seedI — «Дано I» (verified=true) либо его вариант без отметки (OS-07).
func (h *avLane) seedI(t *testing.T, tag string, verified bool) osSeed {
	t.Helper()
	u := h.registerWithAgent(t, freshAddress(tag), osRegisterAgent)
	if verified {
		h.mark(t, u)
	}
	sd := osSeed{u: u, s0: u, registerUA: osRegisterAgent}
	sd.a = h.loginWithAgent(t, u, "os-agent-A")
	sd.b = h.loginWithAgent(t, u, "os-agent-B")
	sd.c = h.loginWithAgent(t, u, "")
	sd.s0ID, sd.aID, sd.bID, sd.cID = h.sessionIDOf(t, sd.s0), h.sessionIDOf(t, sd.a), h.sessionIDOf(t, sd.b), h.sessionIDOf(t, sd.c)
	h.logoutOf(t, sd.s0)
	require.Equal(t, "logout", h.endReasonByID(t, sd.s0ID), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): S₀ не снята выходом")
	return sd
}

// seedIV — «Дано I-V»: второй человек с одной живой записью `T_A`.
func (h *avLane) seedIV(t *testing.T, tag string) (avSession, string) {
	t.Helper()
	v := h.registerWithAgent(t, freshAddress(tag), osRegisterAgent)
	h.mark(t, v)
	ta := h.loginWithAgent(t, v, "os-agent-V")
	h.logoutOf(t, v)
	return ta, h.sessionIDOf(t, ta)
}

// requireOwnSessionVerbs — ступень ВОЗМОЖНОСТИ: три пути смонтированы. 404 —
// честный красный («глагола нет»): на базе приёмки путей 0 (§1.1).
func (h *avLane) requireOwnSessionVerbs(t *testing.T, id string) {
	t.Helper()
	probe := avSession{bearer: ghostBearer(t), form: &http.Cookie{Name: loginlanehttp.CookieForm, Value: "probe-context"}}
	if r := h.listOf(t, probe, ""); r.status == http.StatusNotFound {
		t.Fatalf("%s ЧЕСТНЫЙ-КРАСНЫЙ: глагола перечня нет — GET %s отвечает 404: %s", id, osPathList, r.body)
	}
	for _, p := range []string{osPathEnd, osPathEndOthers} {
		if r := h.post(t, probe, p, map[string]any{}); r.status == http.StatusNotFound {
			t.Fatalf("%s ЧЕСТНЫЙ-КРАСНЫЙ: глагола снятия нет — POST %s отвечает 404: %s", id, p, r.body)
		}
	}
}

// listOf — `GET /iam/v1/auth/sessions` носителем s; query — строка запроса без `?`.
func (h *avLane) listOf(t *testing.T, s avSession, query string) reply {
	t.Helper()
	path := osPathList
	if query != "" {
		path += "?" + query
	}
	cookies := []*http.Cookie{}
	if s.bearer != nil {
		cookies = append(cookies, s.bearer)
	}
	if s.form != nil {
		cookies = append(cookies, s.form)
	}
	return h.lane.do(t, h.c, http.MethodGet, path, nil, fwd(), cookies...)
}

// endToken — признак вида `session-end` признаковым глаголом полосы в контексте
// формы носителя (§4.0).
func (h *avLane) endToken(t *testing.T, s avSession) string {
	t.Helper()
	r := h.lane.do(t, h.c, http.MethodGet, loginlanehttp.PathCSRF+"?form="+osForm, nil, nil, s.form)
	require.Equal(t, http.StatusOK, r.status, "признак вида %s не выдан: %s", osForm, r.body)
	var out struct {
		CSRFToken string `json:"csrfToken"`
	}
	require.NoError(t, json.Unmarshal([]byte(r.body), &out))
	require.NotEmpty(t, out.CSRFToken)
	return out.CSRFToken
}

// endOne — `end` носителем s с `sessionId` и признаком `session-end`.
func (h *avLane) endOne(t *testing.T, s avSession, sessionID string) reply {
	t.Helper()
	return h.post(t, s, osPathEnd, map[string]any{"sessionId": sessionID, "csrfToken": h.endToken(t, s)})
}

// endOthers — `end-others` носителем s с признаком `session-end`.
func (h *avLane) endOthers(t *testing.T, s avSession) reply {
	t.Helper()
	return h.post(t, s, osPathEndOthers, map[string]any{"csrfToken": h.endToken(t, s)})
}

// osItem — элемент перечня как его разобрал клиент: ключи — сырьём, чтобы
// отсутствие ключа было отличимо от пустого значения.
type osItem map[string]json.RawMessage

func (it osItem) str(t *testing.T, key string) string {
	t.Helper()
	raw, ok := it[key]
	require.True(t, ok, "ключа %s нет в элементе %v", key, it)
	var s string
	require.NoError(t, json.Unmarshal(raw, &s))
	return s
}

func (it osItem) current(t *testing.T) bool {
	t.Helper()
	raw, ok := it["current"]
	require.True(t, ok, "ключа current нет в элементе")
	var b bool
	require.NoError(t, json.Unmarshal(raw, &b))
	return b
}

// osPage — разобранный ответ перечня.
type osPage struct {
	items []osItem
	next  string
	keys  []string
}

func parseOSPage(t *testing.T, body string) osPage {
	t.Helper()
	var top map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(body), &top), "тело перечня не разбирается: %s", body)
	var p osPage
	for k := range top {
		p.keys = append(p.keys, k)
	}
	require.Contains(t, top, "sessions", "ключа sessions нет: %s", body)
	require.Contains(t, top, "nextPageToken", "ключа nextPageToken нет: %s", body)
	require.NoError(t, json.Unmarshal(top["sessions"], &p.items))
	require.NotNil(t, p.items, "sessions — массив, а не null: %s", body)
	require.NoError(t, json.Unmarshal(top["nextPageToken"], &p.next))
	return p
}

func (p osPage) ids(t *testing.T) []string {
	t.Helper()
	out := make([]string, 0, len(p.items))
	for _, it := range p.items {
		out = append(out, it.str(t, "id"))
	}
	return out
}

func (p osPage) byID(t *testing.T, id string) osItem {
	t.Helper()
	for _, it := range p.items {
		if it.str(t, "id") == id {
			return it
		}
	}
	t.Fatalf("записи %s в перечне нет", id)
	return nil
}

// resolveFound — ответ краю о носителе: найдена ли сессия.
func (h *avLane) resolveFound(t *testing.T, s avSession) bool {
	t.Helper()
	return h.resolve(t, s.bearer).GetFound()
}

// cutoffOf — отсечка личности, как её читает край (`SessionCutoffOf`).
func (h *avLane) cutoffOf(t *testing.T, user domain.UserID) *iamv1.SessionCutoffOfResponse {
	t.Helper()
	resp, err := sessionrev.NewHandler(nil, nil).WithCutoffReader(kanamepg.NewUserTokenRevocationRepo(h.pool)).
		SessionCutoffOf(h.ctx, &iamv1.SessionCutoffOfRequest{UserId: string(user)})
	require.NoError(t, err, "SessionCutoffOf")
	return resp
}

// endedEvents — события `iam.session.ended_by_person` о человеке.
func (h *avLane) endedEvents(t *testing.T, user domain.UserID) []map[string]any {
	t.Helper()
	return h.auditEvents(t, osAudit, user)
}

// endedIDs — `ended_session_ids` события набором (порядок не значим, Р6).
func endedIDs(t *testing.T, ev map[string]any) []string {
	t.Helper()
	raw, ok := ev["ended_session_ids"].([]any)
	require.True(t, ok, "ended_session_ids — массив: %v", ev)
	out := make([]string, 0, len(raw))
	for _, x := range raw {
		out = append(out, toString(x))
	}
	sortStrings(out)
	return out
}

// sessionRowAgent — значение столбца описания клиента у записи; NULL — ok=false.
func (h *avLane) sessionRowAgent(t *testing.T, id string) (string, bool) {
	t.Helper()
	var v *string
	err := h.pool.QueryRow(h.ctx, `SELECT user_agent FROM kaname.human_sessions WHERE id = $1`, id).Scan(&v)
	if errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("строки записи %s нет", id)
	}
	require.NoError(t, err)
	if v == nil {
		return "", false
	}
	return *v, true
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sortStrings(out)
	return out
}
