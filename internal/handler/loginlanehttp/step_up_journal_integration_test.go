// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// step_up_journal_integration_test.go — ЖУРНАЛ ПОВЫШЕНИЯ: каждое суждённое
// предъявление внутри сессии, успешное и отклонённое, оставляет запись
// (задача PRO-Robotech/kaname#283; эпик PRO-Robotech/kacho#1280; приёмка
// `docs/engineering/acceptance/assurance-level-is-declared-by-our-session.md`
// ред. 5, Ф11-14; Р1 «копии уровня», Р8; очередь аудита — П9,
// `kaname.audit_outbox`).
//
// Ф11-14: предъявления Ф11-09 (успех) и Ф11-13 (отказ) — КАЖДОЕ оставило
// запись журнала повышения: уровень до и после (оба «1»), имя предъявленного
// способа из словаря Р8 (`password`), исход. Секрета и значения носителя в
// записи нет.
//
// # Форма исхода
//
// Приёмка называет исход, но не его форму. Форма решена задачей kaname#283
// (решение диспетчера по делегированию владельца, 2026-09-18): исход — поле
// `outcome` записи ТОГО ЖЕ вида `iam.session.step_up`; `accepted` у успеха,
// `refused` у отказа. Значения утверждаются литералами — так их читает
// потребитель очереди.
//
// # Три отказных выхода церемонии — три пробы
//
// Суждённое предъявление церемония отклоняет в трёх местах, и у каждого своя
// проба:
//
//   - пароль не сошёлся — Ф11-13, сценарий Ф11-14 дословно;
//   - код по времени не сошёлся на ПОДГОТОВКЕ, до транзакции предъявления —
//     отказ Ф11-30;
//   - запасной код не сошёлся на СВЕРКЕ под транзакцией предъявления, которую
//     церемония затем откатывает, — отказ Ф11-30, ветвь набора. Запись,
//     положенная в откатываемую транзакцию, пропала бы; это видит только
//     настоящая база.
//
// Две последние — «Тогда» Ф11-14 на отказе Ф11-30: в Ф11-14 приёмка называет
// только пароль, предмет задачи — всякое суждённое предъявление.
//
// Не покрыто здесь и не записывается реализацией: отказ при исчерпанной
// ёмкости проверяющего (не судился и попыткой не считается).
//
// # Близнец (§7 инв. 2)
//
// В каждой пробе в той же сессии исполняется успешное предъявление тем же
// способом; от отказа его отличает один факт — верный секрет. Его запись
// `accepted` показывает, что проба читает журнал именно этой сессии и
// краснеет на отсутствии записи отказа, а не на чём-то ином.
//
// Run: `go test ./internal/handler/loginlanehttp/ -run F11_14 -count=1`
// (Docker). Skipped under -short.
package loginlanehttp_test

import (
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- RFC 6238 задаёт HMAC-SHA1; оракул кода, не защита
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
	"github.com/PRO-Robotech/kaname/internal/totpverify"
)

// journalRecord — запись очереди аудита о сессии.
type journalRecord struct {
	eventType string
	raw       string
	payload   map[string]any
}

func (r journalRecord) String() string { return r.eventType + " " + r.raw }

// presentationRecords — записи очереди о сессии, кроме записи о её выдаче, в
// порядке появления. Вид события не отбирается: запись отказа, ушедшая под
// другим видом, попадёт в выборку и будет названа утверждением о виде.
func (h *sessionLane) presentationRecords(t *testing.T, sessionID string) []journalRecord {
	t.Helper()
	rows, err := h.pool.Query(h.ctx, `
		SELECT event_type, event_payload::text FROM audit_outbox
		 WHERE event_payload->>'session_id' = $1 AND event_type <> $2
		 ORDER BY created_at, id`, sessionID, humansession.AuditSessionIssued)
	require.NoError(t, err)
	defer rows.Close()
	var out []journalRecord
	for rows.Next() {
		var r journalRecord
		require.NoError(t, rows.Scan(&r.eventType, &r.raw))
		require.NoError(t, json.Unmarshal([]byte(r.raw), &r.payload), r.raw)
		out = append(out, r)
	}
	require.NoError(t, rows.Err())
	return out
}

// journalEntry — ожидаемая запись журнала повышения.
type journalEntry struct {
	method, before, after, outcome string
}

// requireJournal — записи о предъявлениях в сессии ровно want, по порядку; ни
// одна не несёт ни секрета предъявления, ни значения носителя.
func requireJournal(t *testing.T, what string, records []journalRecord, want []journalEntry, secrets []string) {
	t.Helper()
	require.Len(t, records, len(want),
		"журнал повышения: записей о предъявлениях в этой сессии %d, ожидалось %d — %s; записи: %v",
		len(records), len(want), what, records)
	for i, w := range want {
		r := records[i]
		require.Equal(t, humansession.AuditSessionStepUp, r.eventType, "запись %d: вид события — журнал повышения: %s", i, r.raw)
		require.Equal(t, w.outcome, r.payload["outcome"], "запись %d: исход: %s", i, r.raw)
		require.Equal(t, w.method, r.payload["method"], "запись %d: имя способа из словаря Р8: %s", i, r.raw)
		require.Equal(t, w.before, r.payload["level_before"], "запись %d: уровень до: %s", i, r.raw)
		require.Equal(t, w.after, r.payload["level_after"], "запись %d: уровень после: %s", i, r.raw)
		for _, secret := range secrets {
			require.NotEmpty(t, secret, "пустой секрет совпал бы с любой записью")
			require.False(t, strings.Contains(r.raw, secret), "запись %d несёт секрет либо носитель: %s", i, r.raw)
		}
	}
}

// bearerSecrets — значения носителей и их дайджесты: ни то ни другое в
// журнал не выходит.
func bearerSecrets(bearers ...*http.Cookie) []string {
	var out []string
	for _, b := range bearers {
		out = append(out, b.Value, string(domain.PresentedSessionBearer(b.Value).Digest()))
	}
	return out
}

// TestLaneIntegration_F11_14_EveryPresentationLeavesAJournalRecordWithoutSecrets
// — Ф11-14 дословно: успех Ф11-09 и отказ Ф11-13 в одной сессии, ветвь пароля.
func TestLaneIntegration_F11_14_EveryPresentationLeavesAJournalRecordWithoutSecrets(t *testing.T) {
	h := newSessionLane(t)
	s := h.login(t, integrationPassword)
	row, ok := h.rowByBearer(t, s.bearer.Value)
	require.True(t, ok)
	tok := h.csrfFor(t, domain.FormStepUp, s.form)

	// Ф11-09: успех.
	okReply := h.stepUpPassword(t, s, integrationPassword, tok)
	require.Equal(t, http.StatusOK, okReply.status, "Дано: успешное предъявление Ф11-09: %s", okReply.body)
	fresh := cookieNamed(okReply.cookies, loginlanehttp.CookieSession)
	require.NotNil(t, fresh)
	// Ф11-13: отказ — в той же сессии, по новому носителю.
	bad := h.stepUpPassword(t, laneSession{bearer: fresh, form: s.form}, laneWrongPassword, tok)
	require.Equal(t, http.StatusUnauthorized, bad.status, "Дано: отказ предъявления Ф11-13: %s", bad.body)

	requireJournal(t, "успех (Ф11-09) и отказ (Ф11-13)", h.presentationRecords(t, row.id),
		[]journalEntry{
			{method: "password", before: "1", after: "1", outcome: "accepted"},
			{method: "password", before: "1", after: "1", outcome: "refused"},
		},
		append([]string{integrationPassword, laneWrongPassword}, bearerSecrets(s.bearer, fresh)...))
}

// TestLaneIntegration_F11_14_RefusedSecondFactorLeavesAJournalRecordWithoutSecrets
// — «Тогда» Ф11-14 на отказе Ф11-30 (неверный код второго фактора в сессии
// уровня «1»), по одной подпробе на отказной выход церемонии: код по времени
// отвергается на подготовке, запасной код — на сверке под транзакцией. Близнец
// в той же сессии — верный код тем же способом (1 → 2).
func TestLaneIntegration_F11_14_RefusedSecondFactorLeavesAJournalRecordWithoutSecrets(t *testing.T) {
	t.Run("totp: отказ на подготовке", func(t *testing.T) {
		h := newSessionLane(t)
		secret, _, accepted := h.enrolledSecondFactor(t)
		s, sessionID := h.levelOneSession(t)
		tok := h.csrfFor(t, domain.FormStepUp, s.form)

		wrong := wrongTOTP(t, secret, accepted)
		bad := h.stepUpCode(t, s, "totp", wrong, tok)
		require.Equal(t, http.StatusUnauthorized, bad.status, "Дано: отказ предъявления Ф11-30: %s", bad.body)
		right := laneTOTP(t, secret, accepted+1)
		good := h.stepUpCode(t, s, "totp", right, tok)
		require.Equal(t, http.StatusOK, good.status, "близнец: верный код — успешное предъявление: %s", good.body)
		fresh := cookieNamed(good.cookies, loginlanehttp.CookieSession)
		require.NotNil(t, fresh)

		requireJournal(t, "отказ (Ф11-30, код по времени) и успех тем же способом", h.presentationRecords(t, sessionID),
			[]journalEntry{
				{method: "totp", before: "1", after: "1", outcome: "refused"},
				{method: "totp", before: "1", after: "2", outcome: "accepted"},
			},
			append([]string{wrong, right, secret.Base32()}, bearerSecrets(s.bearer, fresh)...))
	})

	t.Run("lookup_secret: отказ на сверке под транзакцией", func(t *testing.T) {
		h := newSessionLane(t)
		_, codes, _ := h.enrolledSecondFactor(t)
		s, sessionID := h.levelOneSession(t)
		tok := h.csrfFor(t, domain.FormStepUp, s.form)

		wrong := wrongBackupCode(t, codes)
		bad := h.stepUpCode(t, s, "lookup_secret", wrong, tok)
		require.Equal(t, http.StatusUnauthorized, bad.status, "Дано: отказ предъявления Ф11-30: %s", bad.body)
		good := h.stepUpCode(t, s, "lookup_secret", codes[0], tok)
		require.Equal(t, http.StatusOK, good.status, "близнец: верный код набора — успешное предъявление: %s", good.body)
		fresh := cookieNamed(good.cookies, loginlanehttp.CookieSession)
		require.NotNil(t, fresh)

		requireJournal(t, "отказ (Ф11-30, запасной код) и успех тем же способом", h.presentationRecords(t, sessionID),
			[]journalEntry{
				{method: "lookup_secret", before: "1", after: "1", outcome: "refused"},
				{method: "lookup_secret", before: "1", after: "2", outcome: "accepted"},
			},
			append(append([]string{wrong}, codes...), bearerSecrets(s.bearer, fresh)...))
	})
}

// enrolledSecondFactor — «Дано: у личности заведён второй фактор» (Ф11-30):
// настоящие глаголы заведения и подтверждения над теми же адаптерами и тем же
// проверяющим кода, что у церемонии слушателя, в своей сессии. Пробе
// достаются секрет, коды набора и ступень, принятая подтверждением.
func (h *sessionLane) enrolledSecondFactor(t *testing.T) (totpverify.Secret, []string, int64) {
	t.Helper()
	enroll, err := humansession.NewEnrollSecondFactorUseCase(h.secondFactor)
	require.NoError(t, err)
	confirm, err := humansession.NewConfirmSecondFactorUseCase(h.secondFactor)
	require.NoError(t, err)

	s := h.login(t, integrationPassword)
	bearer := domain.PresentedSessionBearer(s.bearer.Value)
	en, err := enroll.Execute(h.ctx, humansession.EnrollInput{Bearer: bearer})
	require.NoError(t, err, "Дано: заведение начато")
	step := totpverify.StepAt(time.Now())
	out, err := confirm.Execute(h.ctx, humansession.ConfirmInput{
		Bearer: bearer, Code: laneTOTP(t, en.Secret, step), Source: fwd()[loginlanehttp.HeaderForwardedFor],
	})
	require.NoError(t, err, "Дано: заведение подтверждено первым кодом")
	require.Len(t, out.BackupCodes, passwordverify.BackupCodeCount, "Дано: подтверждение выдало набор")
	return en.Secret, out.BackupCodes, step
}

// levelOneSession — новая сессия входа паролем у личности с заведённым
// фактором: уровень «1» проверяется ДО предмета.
func (h *sessionLane) levelOneSession(t *testing.T) (laneSession, string) {
	t.Helper()
	s := h.login(t, integrationPassword)
	row, ok := h.rowByBearer(t, s.bearer.Value)
	require.True(t, ok, "Дано: запись сессии найдена по носителю")
	require.Equal(t, "1", row.level, "Дано Ф11-30: сессия уровня «1»")
	return s, row.id
}

// stepUpCode — церемония, ветвь кода (`totp` либо `lookup_secret`).
func (h *sessionLane) stepUpCode(t *testing.T, s laneSession, method, code, csrfToken string) reply {
	t.Helper()
	return h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathStepUp,
		map[string]any{"method": method, "code": code, "csrfToken": csrfToken}, fwd(), s.bearer, s.form)
}

// laneTOTP — код ступени step от секрета, посчитанный пробой по RFC 6238
// независимо от проверяющего: оракул, а не вызов прод-функции.
func laneTOTP(t *testing.T, secret totpverify.Secret, step int64) string {
	t.Helper()
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret.Base32())
	require.NoError(t, err)
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step)) // #nosec G115 -- ступень неотрицательна
	mac := hmac.New(sha1.New, raw)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[off])&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	return fmt.Sprintf("%06d", bin%1000000)
}

// wrongTOTP — код формы `totp`, не совпадающий ни с одной ступенью вокруг
// принятой: окно проверяющего ±Skew плюс запас на переход ступени во время
// пробы. Отказ детерминирован, а не вероятен.
func wrongTOTP(t *testing.T, secret totpverify.Secret, accepted int64) string {
	t.Helper()
	near := map[string]bool{}
	for d := int64(-3); d <= 4; d++ {
		near[laneTOTP(t, secret, accepted+d)] = true
	}
	for d := int64(9); d < 64; d++ {
		if c := laneTOTP(t, secret, accepted+d); !near[c] {
			return c
		}
	}
	t.Fatal("не найден код, отличный от кодов окна")
	return ""
}

// wrongBackupCode — код формы набора, которого в наборе нет: последний знак
// настоящего кода заменён, и результат сверен со всеми кодами набора.
func wrongBackupCode(t *testing.T, codes []string) string {
	t.Helper()
	in := map[string]bool{}
	for _, c := range codes {
		in[strings.ToUpper(c)] = true
	}
	base := []byte(strings.ToUpper(codes[0]))
	for _, r := range []byte("0123456789ABCDEFGHJKMNPQRSTVWXYZ") {
		base[len(base)-1] = r
		if c := string(base); !in[c] && passwordverify.IsWellFormedBackupCode(c) {
			return c
		}
	}
	t.Fatal("не найден код формы набора вне набора")
	return ""
}
