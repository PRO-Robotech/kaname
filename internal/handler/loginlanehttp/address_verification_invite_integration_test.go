// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// address_verification_invite_integration_test.go — полосы З, К, М приёмки
// `access-beyond-login-needs-a-verified-address.md` (kaname#456) и условия
// аудита поверхности, наблюдаемые на полосе формы: приглашение активируется
// подтверждением и только живое; запись, заведённая до посадки; след без адреса
// и кода; посеянная строка не-человека не присваивается регистрацией; темп
// регистрации и запроса восстановления по источнику и адресату.
package loginlanehttp_test

import (
	"bytes"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
)

// avInvite — приглашение адреса в аккаунт с ролью на проект.
type avInvite struct {
	user    domain.UserID
	email   string
	account domain.AccountID
	project domain.ProjectID
	inviter avSession
}

// inviter — подтверждённый распорядитель: регистрация глаголом и отметка.
func (h *avLane) inviter(t *testing.T) (avSession, domain.AccountID, domain.ProjectID) {
	t.Helper()
	s := h.register(t, freshAddress("inviter"))
	h.mark(t, s)
	var acc, prj string
	require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT id FROM kaname.accounts WHERE owner_user_id = $1`, string(s.user)).Scan(&acc),
		"НЕ-ВЫПОЛНИЛОСЬ(фикстура): личный аккаунт распорядителя")
	require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT id FROM kaname.projects WHERE account_id = $1`, acc).Scan(&prj),
		"НЕ-ВЫПОЛНИЛОСЬ(фикстура): проект распорядителя")
	return s, domain.AccountID(acc), domain.ProjectID(prj)
}

// invite — приглашение адреса V тем же, что пишет `UserService.Invite`
// (`project_id` и `role_id`): строка PENDING со сроком, членство PENDING,
// выдача роли на проект с составом субъектов и указателем предка.
func (h *avLane) invite(t *testing.T, inv avSession, acc domain.AccountID, prj domain.ProjectID, email string, ttl time.Duration) avInvite {
	t.Helper()
	w, err := h.users.Writer(h.ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(h.ctx) }()
	row, _, err := w.UsersW().InsertPending(h.ctx, domain.User{
		ID: domain.UserID(ids.NewID(domain.PrefixUser)), AccountID: acc, Email: domain.Email(email),
		DisplayName: "invitee", InviteStatus: domain.InviteStatusPending, InvitedBy: inv.user,
	}, time.Now().UTC().Add(ttl))
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): строка приглашения")
	ab, err := w.AccessBindingsW().Insert(h.ctx, domain.AccessBinding{
		ID: domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding)), SubjectType: domain.SubjectTypeUser,
		SubjectID: domain.SubjectID(row.ID), RoleID: domain.RoleID(domain.ClusterAdminRoleID),
		ResourceType: domain.ResourceType("project"), ResourceID: string(prj), Target: domain.AccessTarget{AllInScope: true},
	})
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): выдача роли на проект")
	require.NoError(t, w.AccessBindingsW().InsertSubjects(h.ctx, ab.ID, []domain.Subject{{Type: domain.SubjectTypeUser, ID: domain.SubjectID(row.ID)}}))
	// Право приглашённого на P — прямым фактом журнала: каталог прав стенд не
	// компилирует (строк `role_verb` в свежей базе ноль), и выдача строкой без
	// него ни о чём не говорит двери. Факт — тот же, что даёт выдача роли
	// администратора проекта; предмет проб — допуск субъекта, а не план выдачи.
	require.NoError(t, w.EmitFGARelationWrite(h.ctx, []outboxtypes.RelationTuple{{
		User: "project:" + string(prj), Relation: "project", Object: "iam_access_binding:" + string(ab.ID),
	}, {
		User: "user:" + string(row.ID), Relation: "admin", Object: "project:" + string(prj),
	}}))
	require.NoError(t, w.Commit(h.ctx))
	return avInvite{user: row.ID, email: email, account: acc, project: prj, inviter: inv}
}

// inviteState — состояние строки приглашённого и его членства в аккаунте.
func (h *avLane) inviteState(t *testing.T, iv avInvite) (userStatus, membership, externalID string) {
	t.Helper()
	require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT invite_status, external_id FROM kaname.users WHERE id = $1`, string(iv.user)).
		Scan(&userStatus, &externalID))
	err := h.pool.QueryRow(h.ctx, `SELECT state FROM kaname.memberships WHERE user_id = $1 AND account_id = $2`,
		string(iv.user), string(iv.account)).Scan(&membership)
	if err != nil {
		membership = "<none>"
	}
	return userStatus, membership, externalID
}

// projectAllowed — вопрос двери решения о приглашённом на проекте.
func (h *avLane) projectAllowed(t *testing.T, iv avInvite) bool {
	t.Helper()
	ok, err := h.door.Check(h.ctx, "user:"+string(iv.user), "admin", "project:"+string(iv.project))
	require.NoError(t, err)
	return ok
}

// registerInvitee — регистрация адресом приглашения; сессия — как у EV-01.
func (h *avLane) registerInvitee(t *testing.T, iv avInvite) avSession {
	t.Helper()
	s := h.register(t, iv.email)
	require.Equal(t, iv.user, s.user, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): регистрация приглашённого — строка приглашения")
	return s
}

// TestEV70_TheInviteeRegisteredWithoutActivation — EV-70.
func TestEV70_TheInviteeRegisteredWithoutActivation(t *testing.T) {
	h := newAVLane(t)
	inv, acc, prj := h.inviter(t)
	iv := h.invite(t, inv, acc, prj, freshAddress("ev70"), 7*24*time.Hour)
	s := h.registerInvitee(t, iv)
	st, mem, ext := h.inviteState(t, iv)
	require.Equal(t, "PENDING", st, "EV-70: inviteStatus = PENDING после регистрации")
	require.Equal(t, "PENDING", mem, "EV-70: членство PENDING")
	require.Equal(t, "", ext, "EV-70: личности на строке нет")
	require.False(t, h.resolve(t, s.bearer).GetSession().GetEmailVerified(), "EV-70: сессия в положении подтверждения")
	require.NotEmpty(t, h.letters(t, iv.user), "EV-70: письмо поставлено")
	require.False(t, h.projectAllowed(t, iv), "EV-70: Check приглашённого на P — false")
}

// TestEV71_TheInviteeSignsInBeforeVerification — EV-71.
func TestEV71_TheInviteeSignsInBeforeVerification(t *testing.T) {
	h := newAVLane(t)
	inv, acc, prj := h.inviter(t)
	iv := h.invite(t, inv, acc, prj, freshAddress("ev71"), 7*24*time.Hour)
	h.registerInvitee(t, iv)
	r := h.loginReply(t, iv.email, integrationPassword)
	require.Equal(t, http.StatusOK, r.status, "EV-71 (а): вход приглашённого при PENDING — 200: %s", r.body)
	v, _ := sessionEmailVerified(t, r.body)
	require.False(t, v)

	blocked := h.register(t, freshAddress("ev71b"))
	_, err := h.pool.Exec(h.ctx, `UPDATE kaname.users SET invite_status = 'BLOCKED' WHERE id = $1`, string(blocked.user))
	require.NoError(t, err)
	rb := h.loginReply(t, blocked.email, integrationPassword)
	require.Equal(t, http.StatusUnauthorized, rb.status, "EV-71 (б): заблокированный — единый отказ входа: %s", rb.body)
}

// TestEV72_VerificationActivatesTheInvite — EV-72.
func TestEV72_VerificationActivatesTheInvite(t *testing.T) {
	h := newAVLane(t)
	h.requireVerbs(t, "EV-72")
	inv, acc, prj := h.inviter(t)
	iv := h.invite(t, inv, acc, prj, freshAddress("ev72"), 7*24*time.Hour)
	s := h.registerInvitee(t, iv)
	r := h.confirm(t, s, h.latestCode(t, "EV-72", iv.user))
	require.Equal(t, http.StatusOK, r.status, "EV-72: исход EV-30: %s", r.body)
	st, mem, ext := h.inviteState(t, iv)
	require.Equal(t, "ACTIVE", st, "EV-72: inviteStatus = ACTIVE")
	require.Equal(t, "ACTIVE", mem, "EV-72: Membership.state = ACTIVE")
	require.NotEmpty(t, ext, "EV-72: личность на строке есть")
	var updated int
	require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT count(*) FROM kaname.audit_outbox WHERE event_type = 'iam.user.updated'
		AND event_payload->>'resource_id' = $1 AND event_payload->'changed_fields' ? 'invite_status'`, string(iv.user)).Scan(&updated))
	require.Equal(t, 1, updated, "EV-72: событие iam.user.updated с invite_status в изменённых полях")
	require.True(t, h.projectAllowed(t, iv), "EV-72: Check на P — true")
}

// TestEV73_InviteTermIsJudgedAtRegistrationAndAtVerification — EV-73.
func TestEV73_InviteTermIsJudgedAtRegistrationAndAtVerification(t *testing.T) {
	h := newAVLane(t)
	h.requireVerbs(t, "EV-73")
	inv, acc, prj := h.inviter(t)

	// (а) регистрация в срок, срок истекает до предъявления кода.
	a := h.invite(t, inv, acc, prj, freshAddress("ev73a"), 7*24*time.Hour)
	sa := h.registerInvitee(t, a)
	ka := h.latestCode(t, "EV-73", a.user)
	_, err := h.pool.Exec(h.ctx, `UPDATE kaname.users SET invite_expires_at = now() - interval '1 second' WHERE id = $1`, string(a.user))
	require.NoError(t, err)
	ra := h.confirm(t, sa, ka)
	require.Equal(t, http.StatusBadRequest, ra.status, "EV-73 (а): %s", ra.body)
	refA := parseRefusal(t, ra.body)
	require.Equal(t, 9, refA.Code)
	require.Equal(t, "invite is no longer valid; ask an account administrator to invite again", refA.Message)
	require.Equal(t, "INVITE_NOT_VALID", refA.reason())
	_, marked := h.markedAt(t, a.user)
	require.False(t, marked, "EV-73 (а): отметки нет")
	st, _, _ := h.inviteState(t, a)
	require.Equal(t, "PENDING", st)
	var attempts int
	require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT attempts FROM kaname.email_verification_codes WHERE user_id = $1 AND superseded_at IS NULL`,
		string(a.user)).Scan(&attempts))
	require.Zero(t, attempts, "EV-73 (а): попытка не истрачена")

	// (б) регистрация в срок, код до истечения — исход EV-72.
	b := h.invite(t, inv, acc, prj, freshAddress("ev73b"), 7*24*time.Hour)
	sb := h.registerInvitee(t, b)
	require.Equal(t, http.StatusOK, h.confirm(t, sb, h.latestCode(t, "EV-73", b.user)).status, "EV-73 (б)")

	// (в) регистрация после срока — единый отказ регистрации, письма нет.
	c := h.invite(t, inv, acc, prj, freshAddress("ev73c"), 7*24*time.Hour)
	_, err = h.pool.Exec(h.ctx, `UPDATE kaname.users SET invite_expires_at = now() - interval '1 second' WHERE id = $1`, string(c.user))
	require.NoError(t, err)
	tok, ctxCk := h.lane.csrf(t, h.c, string(domain.FormRegister), nil)
	rc := h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathRegister,
		map[string]any{"email": c.email, "password": integrationPassword, "csrfToken": tok}, fwd(), ctxCk)
	require.Equal(t, http.StatusBadRequest, rc.status, "EV-73 (в): единый отказ Ф4: %s", rc.body)
	require.Empty(t, h.letters(t, c.user), "EV-73 (в): письма нет")
}

// TestEV75_RemovedInviteIsNotActivatedByVerification — EV-75.
func TestEV75_RemovedInviteIsNotActivatedByVerification(t *testing.T) {
	h := newAVLane(t)
	h.requireVerbs(t, "EV-75")
	inv, acc, prj := h.inviter(t)
	for _, removed := range []bool{true, false} {
		iv := h.invite(t, inv, acc, prj, freshAddress("ev75"), 7*24*time.Hour)
		s := h.registerInvitee(t, iv)
		k := h.latestCode(t, "EV-75", iv.user)
		if removed {
			h.removeInvite(t, iv)
		}
		r := h.confirm(t, s, k)
		if removed {
			require.Equal(t, http.StatusBadRequest, r.status, "EV-75 (а): %s", r.body)
			require.Equal(t, "INVITE_NOT_VALID", parseRefusal(t, r.body).reason())
			st, mem, _ := h.inviteState(t, iv)
			require.Equal(t, "PENDING", st, "EV-75 (а): inviteStatus = PENDING")
			require.Equal(t, "<none>", mem, "EV-75 (а): членства нет")
			require.False(t, h.projectAllowed(t, iv), "EV-75 (а): Check на P — false")
			continue
		}
		require.Equal(t, http.StatusOK, r.status, "EV-75 (б): исход EV-72: %s", r.body)
		st, _, _ := h.inviteState(t, iv)
		require.Equal(t, "ACTIVE", st)
		require.True(t, h.projectAllowed(t, iv), "EV-75 (б): Check на P — true")
	}
}

// TestEV76_ReInviteMakesVerificationPossible — EV-76.
func TestEV76_ReInviteMakesVerificationPossible(t *testing.T) {
	h := newAVLane(t)
	h.requireVerbs(t, "EV-76")
	inv, acc, prj := h.inviter(t)
	for _, reinvite := range []bool{true, false} {
		iv := h.invite(t, inv, acc, prj, freshAddress("ev76"), 7*24*time.Hour)
		s := h.registerInvitee(t, iv)
		k := h.latestCode(t, "EV-76", iv.user)
		h.removeInvite(t, iv)
		if reinvite {
			again := h.invite(t, inv, acc, prj, iv.email, 7*24*time.Hour)
			require.Equal(t, iv.user, again.user, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): повторное приглашение — та же строка")
		}
		r := h.confirm(t, s, k)
		if reinvite {
			require.Equal(t, http.StatusOK, r.status, "EV-76 (а): исход EV-72: %s", r.body)
			st, _, _ := h.inviteState(t, iv)
			require.Equal(t, "ACTIVE", st)
			require.True(t, h.projectAllowed(t, iv), "EV-76 (а): Check на P — true")
			continue
		}
		require.Equal(t, "INVITE_NOT_VALID", parseRefusal(t, r.body).reason(), "EV-76 (б): снова INVITE_NOT_VALID: %s", r.body)
	}
}

// removeInvite — распорядитель снимает приглашение порядком контракта: выдачу,
// затем участие (оператором хранилища, которым это делает глагол).
func (h *avLane) removeInvite(t *testing.T, iv avInvite) {
	t.Helper()
	_, err := h.pool.Exec(h.ctx, `UPDATE kaname.access_bindings SET status = 'REVOKED', revoked_at = now()
		 WHERE subject_id = $1 AND revoked_at IS NULL`, string(iv.user))
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): снятие выдачи")
	w, err := h.users.Writer(h.ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(h.ctx) }()
	removed, err := w.UsersW().RemoveMembership(h.ctx, iv.user, iv.account)
	require.NoError(t, err)
	require.True(t, removed, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): участие снято")
	require.NoError(t, w.Commit(h.ctx))
}

// TestEV85_RecordMadeBeforeLanding_LaneHalf — EV-85, половина полосы формы:
// запись без отметки, заведённая до посадки, со следующего запроса в
// положении подтверждения; письмо запрошено в S, подтверждение выдаёт B2 ≠ B1.
// Остальные вопросы EV-85 (право, токен, сверка) — пробы полос Д, Ж.
func TestEV85_RecordMadeBeforeLanding_LaneHalf(t *testing.T) {
	h := newAVLane(t)
	h.requireVerbs(t, "EV-85")
	s := h.register(t, freshAddress("ev85"))
	// Письма регистрации у записи, заведённой до посадки, нет.
	_, err := h.pool.Exec(h.ctx, `DELETE FROM kaname.invite_mail_outbox WHERE payload->>'user_id' = $1`, string(s.user))
	require.NoError(t, err)
	_, err = h.pool.Exec(h.ctx, `DELETE FROM kaname.email_verification_codes WHERE user_id = $1`, string(s.user))
	require.NoError(t, err)

	require.False(t, h.resolve(t, s.bearer).GetSession().GetEmailVerified(), "EV-85: email_verified = false")
	rp := h.post(t, s, loginlanehttp.PathPassword, map[string]any{
		"currentPassword": integrationPassword, "newPassword": "a-fresh-password-for-ev85", "csrfToken": h.token(s, string(domain.FormPassword)),
	})
	require.Equal(t, http.StatusForbidden, rp.status, "EV-85: отказ Р3: %s", rp.body)
	var status string
	require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT state FROM kaname.memberships WHERE user_id = $1`, string(s.user)).Scan(&status))
	require.Equal(t, "ACTIVE", status, "EV-85: членство остаётся ACTIVE")

	require.Equal(t, http.StatusOK, h.requestLetter(t, s).status, "EV-85: письмо запрошено в S")
	r := h.confirm(t, s, h.latestCode(t, "EV-85", s.user))
	require.Equal(t, http.StatusOK, r.status, "EV-85: EV-30 в S: %s", r.body)
	b2 := cookieNamed(r.cookies, loginlanehttp.CookieSession)
	require.NotEqual(t, s.bearer.Value, b2.Value, "EV-85: B2 ≠ B1")
	require.False(t, h.resolve(t, s.bearer).GetFound(), "EV-85: Resolve(B1) — found = false")
	after := s
	after.bearer = b2
	require.True(t, h.resolve(t, b2).GetSession().GetEmailVerified())
	rp2 := h.post(t, after, loginlanehttp.PathPassword, map[string]any{
		"currentPassword": integrationPassword, "newPassword": "a-fresh-password-for-ev85", "csrfToken": h.token(after, string(domain.FormPassword)),
	})
	require.Equal(t, http.StatusOK, rp2.status, "EV-85: смена пароля носителем B2 — обычный исход: %s", rp2.body)
}

// TestEV95_NoAddressAndNoCodeInEventsOrLog — EV-95 (и условие аудита: пути
// исчерпанного кода и отказа по частоте тоже).
func TestEV95_NoAddressAndNoCodeInEventsOrLog(t *testing.T) {
	var logs bytes.Buffer
	h := newAVLaneLogging(t, slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	h.requireVerbs(t, "EV-95")
	s := h.register(t, freshAddress("ev95"))
	k1 := h.latestCode(t, "EV-95", s.user)
	h.clock.Advance(avIntervalProfile + time.Second)
	require.Equal(t, http.StatusOK, h.requestLetter(t, s).status) // EV-20
	require.Equal(t, http.StatusTooManyRequests, h.requestLetter(t, s).status)
	k2 := h.latestCode(t, "EV-95", s.user)
	for i := 0; i < avAttemptsProfile+1; i++ { // EV-32 и исчерпанный код
		h.confirm(t, s, wrongCodeLike(k2))
	}
	h.clock.Advance(avIntervalProfile + time.Second)
	require.Equal(t, http.StatusOK, h.requestLetter(t, s).status)
	k3 := h.latestCode(t, "EV-95", s.user)
	require.Equal(t, http.StatusOK, h.confirm(t, s, k3).status) // EV-30
	// Положительный контроль тем же читателем по тем же источникам: событие
	// исхода EV-30 найдено и называет user_id; строка, внесённая пробой в
	// журнал с адресом, найдена.
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("probe control line", "email", s.email)
	events := h.allAuditPayloads(t)
	var found bool
	for _, e := range events {
		if strings.Contains(e, `"iam.user.email_verified"`) || strings.Contains(e, string(s.user)) {
			found = true
		}
	}
	require.True(t, found, "EV-95: контроль — событие подтверждения найдено")
	require.Contains(t, logs.String(), "probe control line", "EV-95: контроль — внесённая строка журнала найдена")

	secrets := []string{s.email, strings.ToLower(s.email), k1, k2, k3,
		strings.ReplaceAll(k1, "-", ""), strings.ReplaceAll(k2, "-", ""), strings.ReplaceAll(k3, "-", "")}
	for _, e := range events {
		for _, sec := range secrets {
			require.NotContains(t, e, sec, "EV-95: события аудита не несут адреса и кода")
		}
	}
	journal := strings.ReplaceAll(logs.String(), `"email":"`+s.email+`"`, "") // строка контроля
	for _, sec := range secrets {
		require.NotContains(t, journal, sec, "EV-95: журнал процесса не несёт адреса и кода")
	}
}

// allAuditPayloads — нагрузки всех событий аудита базы строками.
func (h *avLane) allAuditPayloads(t *testing.T) []string {
	t.Helper()
	rows, err := h.pool.Query(h.ctx, `SELECT event_type || ' ' || event_payload::text FROM kaname.audit_outbox`)
	require.NoError(t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		require.NoError(t, rows.Scan(&s))
		out = append(out, s)
	}
	require.NoError(t, rows.Err())
	return out
}

// TestSeededNonPersonRowIsNotClaimedByRegistration — условие аудита
// поверхности: посеянная строка владельца системного аккаунта (строка
// PENDING, не приглашение) регистрацией не присваивается; близнец — свежий
// адрес заводит новую строку.
func TestSeededNonPersonRowIsNotClaimedByRegistration(t *testing.T) {
	h := newAVLane(t)
	var seeded, email string
	require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT u.id, u.email FROM kaname.users u JOIN kaname.accounts a ON a.owner_user_id = u.id
		 WHERE u.invite_status = 'PENDING' ORDER BY u.created_at LIMIT 1`).Scan(&seeded, &email),
		"НЕ-ВЫПОЛНИЛОСЬ(фикстура): посеянной строки не-человека в свежей базе нет")
	tok, ctxCk := h.lane.csrf(t, h.c, string(domain.FormRegister), nil)
	r := h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathRegister,
		map[string]any{"email": email, "password": integrationPassword, "csrfToken": tok}, fwd(), ctxCk)
	require.Equal(t, http.StatusBadRequest, r.status, "регистрация адресом посеянной строки — единый отказ Ф4: %s", r.body)
	var methods, sessions int
	var status, membership string
	require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT count(*) FROM kaname.user_login_methods WHERE user_id = $1`, seeded).Scan(&methods))
	require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT count(*) FROM kaname.human_sessions WHERE user_id = $1`, seeded).Scan(&sessions))
	require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT invite_status FROM kaname.users WHERE id = $1`, seeded).Scan(&status))
	require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT state FROM kaname.memberships WHERE user_id = $1`, seeded).Scan(&membership))
	require.Zero(t, methods, "у посеянной строки способов входа ноль")
	require.Zero(t, sessions, "у посеянной строки сессий ноль")
	require.Equal(t, "PENDING", status)
	require.Equal(t, "PENDING", membership)

	twin := h.register(t, freshAddress("seedtwin"))
	require.NotEqual(t, seeded, string(twin.user), "близнец: свежий адрес — новая строка")
}

// TestRegistrationIsBoundedPerSource — условие аудита поверхности: окно
// регистраций по источнику ДО транзакции; сверх него — единый отказ, ни строки
// человека, ни строки письма. Близнец — другой источник проходит.
func TestRegistrationIsBoundedPerSource(t *testing.T) {
	h := newAVLaneWith(t, avOptions{registrationsPerSource: avRegistrationPerSource})
	registerFrom := func(source, email string) reply {
		tok, ctxCk := h.lane.csrf(t, h.c, string(domain.FormRegister), nil)
		return h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathRegister,
			map[string]any{"email": email, "password": integrationPassword, "csrfToken": tok},
			map[string]string{"X-Forwarded-For": source}, ctxCk)
	}
	const source = "198.51.100.23"
	var refusedEmail string
	for i := 0; i < avRegistrationPerSource+1; i++ {
		email := freshAddress("regsrc")
		r := registerFrom(source, email)
		if i < avRegistrationPerSource {
			require.Equal(t, http.StatusOK, r.status, "регистрация %d из окна: %s", i+1, r.body)
			continue
		}
		require.Equal(t, http.StatusBadRequest, r.status, "регистрация сверх окна источника — единый отказ: %s", r.body)
		require.Equal(t, "REGISTRATION_REFUSED", parseRefusal(t, r.body).reason())
		refusedEmail = email
	}
	var rows, letters int
	require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT count(*) FROM kaname.users WHERE lower(email) = lower($1)`, refusedEmail).Scan(&rows))
	require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT count(*) FROM kaname.invite_mail_outbox WHERE payload->>'to' = $1`, refusedEmail).Scan(&letters))
	require.Zero(t, rows, "сверх окна — строки человека нет")
	require.Zero(t, letters, "сверх окна — строки письма нет")
	require.Equal(t, http.StatusOK, registerFrom("198.51.100.24", freshAddress("regsrc2")).status, "близнец: другой источник проходит")
}

// TestRecoveryRequestIsBoundedPerRecipient — условие аудита поверхности: окно
// писем восстановления на адресата списывается тем же оператором, что
// постановка, и сверх него письмо молча не ставится при неизменном ответе.
func TestRecoveryRequestIsBoundedPerRecipient(t *testing.T) {
	h := newAVLaneWith(t, avOptions{recoveryLettersPerRecipient: avRecoveryPerRecipient})
	s := h.register(t, freshAddress("rcv"))
	h.mark(t, s)
	request := func(email string) reply {
		tok, ctxCk := h.lane.csrf(t, h.c, string(domain.FormRecovery), nil)
		return h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathRecovery,
			map[string]any{"email": email, "csrfToken": tok}, fwd(), ctxCk)
	}
	nobody := request(freshAddress("rcvnobody"))
	require.Equal(t, http.StatusOK, nobody.status)
	for i := 0; i < avRecoveryPerRecipient+1; i++ {
		r := request(s.email)
		require.Equal(t, nobody.status, r.status, "ответ побайтово тот же, что на несуществующий адрес")
		require.Equal(t, nobody.body, r.body)
	}
	var letters int
	require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT count(*) FROM kaname.invite_mail_outbox WHERE event_type = 'mail.recovery.send'
		 AND payload->>'user_id' = $1`, string(s.user)).Scan(&letters))
	require.Equal(t, avRecoveryPerRecipient, letters, "N+1 запросов в окне — N писем")
}

// Величины окон условий аудита на стенде (профиль стенда, а не продукта).
const (
	avRegistrationPerSource = 3
	avRecoveryPerRecipient  = 3
)

// TestParallelLetterRequestsQueueExactlyOne — условие аудита поверхности:
// предел писем решается одним условным оператором под замком строки человека.
// 20 одновременных запросов письма одного человека после промежутка — ровно
// одна строка очереди и 19 отказов по частоте со сроком; повторов не меньше
// 10, распределение печатается. Близнец — последовательная пара EV-23.
func TestParallelLetterRequestsQueueExactlyOne(t *testing.T) {
	h := newAVLane(t)
	h.requireVerbs(t, "параллельные запросы письма")
	const (
		repeats  = 10
		parallel = 20
	)
	dist := map[int]int{}
	for i := 0; i < repeats; i++ {
		s := h.register(t, freshAddress("parletter"))
		h.clock.Advance(avIntervalProfile + time.Second)
		before := len(h.letters(t, s.user))
		statuses := make([]int, parallel)
		var wg sync.WaitGroup
		for j := 0; j < parallel; j++ {
			wg.Add(1)
			go func(j int) {
				defer wg.Done()
				statuses[j] = h.requestLetter(t, s).status
			}(j)
		}
		wg.Wait()
		var ok, paced int
		for _, st := range statuses {
			switch st {
			case http.StatusOK:
				ok++
			case http.StatusTooManyRequests:
				paced++
			default:
				t.Fatalf("повтор %d: исход, которого у запроса письма нет: %d", i, st)
			}
		}
		require.Equal(t, 1, ok, "повтор %d: ровно одно письмо из %d одновременных", i, parallel)
		require.Equal(t, parallel-1, paced, "повтор %d: прочие — отказ по частоте", i)
		require.Len(t, h.letters(t, s.user), before+1, "повтор %d: в очереди ровно одна новая строка", i)
		dist[ok]++
	}
	t.Logf("повторов %d · распределение числа поставленных писем: %v", repeats, dist)
}

// TestSecondRegistrationOnTheInviteRowIsRefused — условие аудита поверхности:
// вторая регистрация тем же адресом на строку приглашения, у которой способ
// входа уже записан, — единый отказ; материал первого не замещается, второго
// письма нет. Близнец — EV-70.
func TestSecondRegistrationOnTheInviteRowIsRefused(t *testing.T) {
	h := newAVLane(t)
	inv, acc, prj := h.inviter(t)
	iv := h.invite(t, inv, acc, prj, freshAddress("secondreg"), 7*24*time.Hour)
	h.registerInvitee(t, iv)
	letters := len(h.letters(t, iv.user))

	const secondPassword = "a-second-registrant-password-7"
	tok, ctxCk := h.lane.csrf(t, h.c, string(domain.FormRegister), nil)
	r := h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathRegister,
		map[string]any{"email": iv.email, "password": secondPassword, "csrfToken": tok}, fwd(), ctxCk)
	require.Equal(t, http.StatusBadRequest, r.status, "вторая регистрация — единый отказ: %s", r.body)
	require.Equal(t, "REGISTRATION_REFUSED", parseRefusal(t, r.body).reason())
	require.Len(t, h.letters(t, iv.user), letters, "второго письма нет")
	require.Equal(t, http.StatusOK, h.loginReply(t, iv.email, integrationPassword).status, "пароль первого входит")
	require.Equal(t, http.StatusUnauthorized, h.loginReply(t, iv.email, secondPassword).status, "пароль второго — единый отказ входа")
}
