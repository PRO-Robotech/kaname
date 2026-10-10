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
// # Почему S2 тоже снята — и где это решено
//
// Р8 гасит ВСЕ ПРОЧИЕ сессии человека и оставляет текущую. Номера записи у
// глагола RPC нет: текущую он находит по выпуску предъявленного токена
// (выпуск → семейство → сессия церемонии; держит
// `internal/repo/kaname/pg/access_key_revoke_writer_integration_test.go`).
// Здесь снятие зовётся так, как его зовёт личность, переданная краем: выпуска
// нет, текущую отличить нечем, и снимаются ВСЕ записи человека — сторона,
// закрывающая доступ. Различение текущей на полосах края — задача
// PRO-Robotech/kaname#677; предикат её снятия — утверждение о S2 ниже
// переворачивается в «жива».
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

// revokeOverProduct — снятие ключа НАСТОЯЩИМ глаголом над адаптерами базы.
// Синхронный отказ возвращается как есть; принятая операция дожидается
// исполнителя (событием очереди, не сроком) и возвращается терминальной.
func revokeOverProduct(t *testing.T, h *sessionLane, user domain.UserID, keyID string) (*operations.Operation, error) {
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
	op, err := uc.Execute(h.ctx, access_keys.RevokeInput{UserID: user, Actor: user, AccessKeyID: keyID})
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
// снятие ключа A снимает сессию S1, выданную входом A, причиной
// `access-key-revoked`; ключ B входит дальше.
func TestF13_21_RevokingAKeyEndsTheSessionsOfThePerson(t *testing.T) {
	h := newSessionLane(t)
	kA := givenAcceptedKey(t, h, h.user.ID)
	kB := givenAcceptedKey(t, h, h.user.ID)
	s1 := keySession(t, h, kA)
	s2 := h.login(t, integrationPassword).bearer.Value

	// Положительный контроль: до снятия оба носителя годны.
	require.True(t, h.resolve(t, s1).GetFound(), "ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: S1 годна до снятия")
	require.True(t, h.resolve(t, s2).GetFound(), "ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: S2 годна до снятия")

	op, err := revokeOverProduct(t, h, h.user.ID, string(kA.id))
	require.NoError(t, err)
	require.Nilf(t, op.Error, "Ф13-21: снятие ключа исполнено: %v", op.Error)

	require.False(t, h.resolve(t, s1).GetFound(), "Ф13-21: носитель S1 (вход снятым ключом) отвергается")
	require.Equal(t, reasonAccessKeyRevoked, h.endedReason(t, s1), "Ф13-21: причина конца S1 — снятие ключа (Р8)")
	// Текущей сессии глагол RPC не знает (шапка файла): S2 снята той же
	// причиной; kaname#677 переворачивает это утверждение.
	require.False(t, h.resolve(t, s2).GetFound(), "без номера записи вызывающего снимаются все сессии человека")
	require.Equal(t, reasonAccessKeyRevoked, h.endedReason(t, s2))
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
