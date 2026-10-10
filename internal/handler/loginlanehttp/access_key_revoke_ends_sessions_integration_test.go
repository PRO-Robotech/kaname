// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// access_key_revoke_ends_sessions_integration_test.go — снятие ключа доступа
// снимает сессии человека (Ф13-21, задача PRO-Robotech/kaname#669; приёмка
// `docs/engineering/acceptance/passwordless-login-with-access-key.md`,
// отпечаток 5fe6cca1…, Р8).
//
// # Что наблюдается
//
// «Дано» строится ДЕЙСТВИЕМ продукта: сессия S1 — входом ключом через слушатель
// формы, сессия S2 — входом паролем; снятие — НАСТОЯЩИМ глаголом
// `access_keys.RevokeUseCase` над адаптерами базы, теми же, что провязывает
// корень композиции. Исход судится тем, что видит край: ответ службы о
// носителе (`Resolve`), — и записью сессии с её причиной.
//
// # Почему S2 жива — и чем она названа
//
// Р8 гасит ВСЕ ПРОЧИЕ сессии человека и оставляет текущую. Здесь снятие
// зовётся так, как его зовёт личность, переданная краем (kaname#677): край
// спросил службу о носителе S2 (`Resolve`), получил номер её записи и вернул
// его службе вместе с личностью. Номер берётся из ОТВЕТА `Resolve`, а не из
// базы: так проба держит оба звена цепочки — ответ краю называет запись, и
// снятие её бережёт. Доставку номера от края до глагола только по доверенному
// отправителю держит `internal/edgecredential`; выбор текущей по выпуску
// предъявленного токена — `internal/repo/kaname/pg/access_key_revoke_writer_integration_test.go`.
//
// Отрицание — номер чужой записи: он не бережёт ни одной сессии человека, и
// сессии другого не касается.
//
// # Почему причина — литералом
//
// Проба обязана КОМПИЛИРОВАТЬСЯ на ревизии без правки: ссылка на не заведённую
// константу сорвала бы сборку, а сорванная сборка — «не выполнилось», не
// красный (`change-graph.md` §5).
package loginlanehttp_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_keys"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify/webauthntest"
)

// reasonAccessKeyRevoked — седьмая причина конца сессии (Р8).
const reasonAccessKeyRevoked = "access-key-revoked"

// keySession — вход ключом k через слушатель: носитель выданной сессии.
func keySession(t *testing.T, h *sessionLane, k akKey) string {
	t.Helper()
	f := givenAKForm(t, h)
	c := givenChallenge(t, h, f)
	r := akLoginWith(t, h, f, k, c, webauthntest.AssertionOptions{})
	require.Equalf(t, http.StatusOK, r.status, "Дано: вход ключом выдаёт сессию: %s", r.body)
	ck := cookieNamed(r.cookies, loginlanehttp.CookieSession)
	require.NotNil(t, ck, "Дано: вход ключом пишет носитель")
	return ck.Value
}

// revokeOverProduct — снятие ключа НАСТОЯЩИМ глаголом над адаптерами базы, без
// номера текущей записи. Синхронный отказ возвращается как есть; принятая
// операция дожидается исполнителя (событием очереди, не сроком) и
// возвращается терминальной.
func revokeOverProduct(t *testing.T, h *sessionLane, user domain.UserID, keyID string) (*operations.Operation, error) {
	t.Helper()
	return revokeOverProductAs(t, h, access_keys.RevokeInput{UserID: user, Actor: user, AccessKeyID: keyID})
}

// revokeOverProductAs — то же снятие с полным входом глагола: номер записи
// текущей сессии, который передал край, — `in.ActingSession`.
func revokeOverProductAs(t *testing.T, h *sessionLane, in access_keys.RevokeInput) (*operations.Operation, error) {
	t.Helper()
	ops := operations.NewRepo(h.pool, "kaname")
	uc, err := access_keys.NewRevokeUseCase(access_keys.Deps{
		Store:           kanamepg.NewAccessKeyRepo(h.pool),
		Freshness:       kanamepg.NewHumanSessionFreshness(h.pool),
		Methods:         kanamepg.NewLoginMethodRepo(h.pool),
		Binding:         laneKeyBinding(),
		FreshnessWindow: laneFreshness,
		Now:             time.Now,
	}, ops)
	require.NoError(t, err)
	op, err := uc.Execute(h.ctx, in)
	if err != nil {
		return nil, err
	}
	waitCtx, cancel := context.WithTimeout(h.ctx, 20*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(waitCtx), "исполнитель операций не завершил очередь")
	got, err := ops.Get(h.ctx, op.ID)
	require.NoErrorf(t, err, "операция %s не прочитана — это «не выполнилось», а не отказ", op.ID)
	require.Truef(t, got.Done, "операция %s не терминальна", op.ID)
	return got, nil
}

// recordOf — номер записи сессии из ответа краю (`Resolve`) — ровно то, что
// край возвращает службе (kaname#677).
func (h *sessionLane) recordOf(t *testing.T, bearer string) domain.HumanSessionID {
	t.Helper()
	id := h.resolve(t, bearer).GetSession().GetSessionId()
	require.NotEmpty(t, id, "Дано: ответ краю называет номер записи сессии (kaname#677)")
	return domain.HumanSessionID(id)
}

// endedReason — причина конца записи сессии по носителю; "" — не снята.
func (h *sessionLane) endedReason(t *testing.T, bearer string) string {
	t.Helper()
	var reason *string
	require.NoError(t, h.pool.QueryRow(h.ctx,
		`SELECT ended_reason FROM human_sessions WHERE bearer_digest = $1`,
		string(domain.PresentedSessionBearer(bearer).Digest())).Scan(&reason))
	if reason == nil {
		return ""
	}
	return *reason
}

// cutoffReason — причина отсечки личности; "" — отсечки нет.
func (h *sessionLane) cutoffReason(t *testing.T, user domain.UserID) string {
	t.Helper()
	var reason string
	err := h.pool.QueryRow(h.ctx, `SELECT reason FROM user_token_revocations WHERE user_id = $1`, string(user)).Scan(&reason)
	if err != nil {
		return ""
	}
	return reason
}

// TestF13_21_RevokingAKeyEndsTheSessionsOfThePerson — Ф13-21, первая ветвь:
// из S2 снят ключ A — сессия S1, выданная входом A, снята причиной
// `access-key-revoked`; S2 — текущая, названная краем номером записи, — жива,
// её уровень «1» не изменён; ключ B входит дальше.
func TestF13_21_RevokingAKeyEndsTheSessionsOfThePerson(t *testing.T) {
	h := newSessionLane(t)
	kA := givenAcceptedKey(t, h, h.user.ID)
	kB := givenAcceptedKey(t, h, h.user.ID)
	s1 := keySession(t, h, kA)
	s2 := h.login(t, integrationPassword).bearer.Value

	// Положительный контроль: до снятия оба носителя годны.
	require.True(t, h.resolve(t, s1).GetFound(), "ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: S1 годна до снятия")
	require.True(t, h.resolve(t, s2).GetFound(), "ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: S2 годна до снятия")

	op, err := revokeOverProductAs(t, h, access_keys.RevokeInput{UserID: h.user.ID, Actor: h.user.ID,
		AccessKeyID: string(kA.id), ActingSession: h.recordOf(t, s2)})
	require.NoError(t, err)
	require.Nilf(t, op.Error, "Ф13-21: снятие ключа исполнено: %v", op.Error)

	require.False(t, h.resolve(t, s1).GetFound(), "Ф13-21: носитель S1 (вход снятым ключом) отвергается")
	require.Equal(t, reasonAccessKeyRevoked, h.endedReason(t, s1), "Ф13-21: причина конца S1 — снятие ключа (Р8)")
	// Текущая — запись, названная краем (шапка файла): жива, уровень прежний.
	current := h.resolve(t, s2)
	require.True(t, current.GetFound(), "Ф13-21: S2 — текущая — жива (kaname#677)")
	require.Equal(t, "1", current.GetSession().GetAssuranceLevel(), "Ф13-21: уровень текущей не изменён")
	require.Empty(t, h.endedReason(t, s2), "Ф13-21: запись S2 не снята")
	require.Equal(t, reasonAccessKeyRevoked, h.cutoffReason(t, h.user.ID), "Ф13-21: отсечка личности той же причиной")

	// Ключ A — единый отказ входа; ключ B входит и выдаёт годную сессию.
	f := givenAKForm(t, h)
	c := givenChallenge(t, h, f)
	refused := akLoginWith(t, h, f, kA, c, webauthntest.AssertionOptions{})
	require.Equal(t, http.StatusUnauthorized, refused.status, "Ф13-21: снятый ключ не входит: %s", refused.body)
	sB := keySession(t, h, kB)
	require.True(t, h.resolve(t, sB).GetFound(), "Ф13-21: сессия, выданная после снятия, годна")
}

// TestF13_21_RevokingAnotherKeyEndsTheSessionOfTheFirst — Ф13-21, вторая ветвь
// оси: снят НЕ ключ A, а B — S1, выданная A, тоже снята (Р8: гаснут сессии
// человека, а не «сессии этого ключа»).
func TestF13_21_RevokingAnotherKeyEndsTheSessionOfTheFirst(t *testing.T) {
	h := newSessionLane(t)
	kA := givenAcceptedKey(t, h, h.user.ID)
	kB := givenAcceptedKey(t, h, h.user.ID)
	s1 := keySession(t, h, kA)
	require.True(t, h.resolve(t, s1).GetFound(), "ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: S1 годна до снятия")

	op, err := revokeOverProduct(t, h, h.user.ID, string(kB.id))
	require.NoError(t, err)
	require.Nil(t, op.Error)

	require.False(t, h.resolve(t, s1).GetFound(), "Ф13-21 вторая ветвь: S1 снята снятием другого ключа")
	require.Equal(t, reasonAccessKeyRevoked, h.endedReason(t, s1))
}

// TestF13_21_RefusedRevokeAndAnotherPersonKeepTheirSessions — законные
// близнецы, каждый отличается ОДНИМ фактом: (а) снятие ключа, которого у
// человека нет, — синхронный отказ, S1 жива; (б) снятие ключа одного человека
// сессий другого не трогает.
func TestF13_21_RefusedRevokeAndAnotherPersonKeepTheirSessions(t *testing.T) {
	h := newSessionLane(t)
	kA := givenAcceptedKey(t, h, h.user.ID)
	givenAcceptedKey(t, h, h.user.ID)
	s1 := keySession(t, h, kA)

	other := registerPerson(t, h, "ak-revoke-other")
	kOther := givenAcceptedKey(t, h, other)
	sOther := keySession(t, h, kOther)
	require.True(t, h.resolve(t, sOther).GetFound(), "ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: сессия другого годна")

	// (а) ключа нет — отказ до операции, сессии нетронуты.
	_, err := revokeOverProduct(t, h, h.user.ID, "ak-0000000000000000z")
	st, ok := status.FromError(err)
	require.True(t, ok, "ожидался gRPC-статус, получено %v", err)
	require.Equal(t, codes.NotFound, st.Code())
	require.True(t, h.resolve(t, s1).GetFound(), "близнец (а): отвергнутое снятие сессий не снимает")
	require.Empty(t, h.endedReason(t, s1))

	// (б) снят ключ этого человека — сессия другого жива.
	op, err := revokeOverProduct(t, h, h.user.ID, string(kA.id))
	require.NoError(t, err)
	require.Nil(t, op.Error)
	require.False(t, h.resolve(t, s1).GetFound())
	require.True(t, h.resolve(t, sOther).GetFound(), "близнец (б): сессия другого человека жива")
	require.Empty(t, h.endedReason(t, sOther))
}

// TestF13_21_ForeignRecordSavesNoSession — отрицание (kaname#677): номер записи
// ДРУГОГО человека, пришедший вместо номера текущей, не бережёт ни одной сессии
// снимающего — S1 и S2 сняты, — и сессии другого не касается: она жива и до, и
// после. Отличие от первой ветви — один факт: чей номер записи передан.
func TestF13_21_ForeignRecordSavesNoSession(t *testing.T) {
	h := newSessionLane(t)
	kA := givenAcceptedKey(t, h, h.user.ID)
	givenAcceptedKey(t, h, h.user.ID)
	s1 := keySession(t, h, kA)
	s2 := h.login(t, integrationPassword).bearer.Value

	other := registerPerson(t, h, "ak-revoke-foreign")
	kOther := givenAcceptedKey(t, h, other)
	sOther := keySession(t, h, kOther)
	foreign := h.recordOf(t, sOther)

	op, err := revokeOverProductAs(t, h, access_keys.RevokeInput{UserID: h.user.ID, Actor: h.user.ID,
		AccessKeyID: string(kA.id), ActingSession: foreign})
	require.NoError(t, err)
	require.Nil(t, op.Error)

	require.False(t, h.resolve(t, s1).GetFound(), "чужой номер не бережёт S1")
	require.False(t, h.resolve(t, s2).GetFound(), "чужой номер не бережёт S2")
	require.Equal(t, reasonAccessKeyRevoked, h.endedReason(t, s2))
	require.True(t, h.resolve(t, sOther).GetFound(), "сессия другого человека жива")
	require.Empty(t, h.endedReason(t, sOther))
}
