// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_keys_test

// revoke_ends_sessions_test.go — снятие ключа снимает ПРОЧИЕ записи сессии
// человека и ставит его отсечку ОДНИМ исходом с событием снятия (Ф13-21, Р8;
// задача PRO-Robotech/kaname#669). Наблюдаемое на настоящей базе держит
// `internal/handler/loginlanehttp/access_key_revoke_ends_sessions_integration_test.go`;
// здесь — то, что базой не вызвать: подставной отказ КАЖДОЙ записи
// транзакции (форма Ф3-16), выбор текущей сессии по выпуску предъявленного и
// по номеру записи, названному краем (kaname#677), и выбор момента отсечки.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_keys"
	"github.com/PRO-Robotech/kaname/internal/callerorigin"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify/webauthntest"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

const (
	s1     = domain.HumanSessionID("hss-0000000000000000s1")
	s2     = domain.HumanSessionID("hss-0000000000000000s2")
	sBob   = domain.HumanSessionID("hss-0000000000000000b1")
	tokS2  = "tok0000000000000000s2"
	tokBob = "tok0000000000000000b1"
)

// revokeActing — снятие из вызова, аутентифицированного выпуском acting.
func (h *harness) revokeActing(user domain.UserID, id, acting string) (*operations.Operation, error) {
	h.t.Helper()
	uc, err := access_keys.NewRevokeUseCase(h.deps, h.ops)
	require.NoError(h.t, err)
	op, err := uc.Execute(h.ctx(), access_keys.RevokeInput{UserID: user, Actor: user, AccessKeyID: id, ActingCredential: acting})
	if err != nil {
		return nil, err
	}
	return h.ops.await(h.t, op.ID), nil
}

// givenTwoSessions — у Алисы S1 (вход ключом) и S2 (выпуск tokS2), у Боба —
// своя; ключей у Алисы два.
func givenTwoSessions(t *testing.T) (*harness, domain.AccessKey) {
	t.Helper()
	h := newHarness(t)
	k := h.mustRegister(alice, webauthntest.New(t, webauthntest.AlgES256))
	h.mustRegister(alice, webauthntest.New(t, webauthntest.AlgES256))
	h.store.addSession(alice, s1)
	h.store.addSession(alice, s2)
	h.store.addSession(bob, sBob)
	h.store.credentials[tokS2] = fakeCredential{user: alice, session: s2}
	h.store.credentials[tokBob] = fakeCredential{user: bob, session: sBob}
	return h, k
}

// TestRevokeEndsOtherSessionsKeepsTheCurrent — Р8: из S2 снят ключ — S1 снята
// причиной `access-key-revoked`, S2 (сессия выпуска, которым звонят) жива;
// отсечка на микросекунду раньше первой аутентификации, поставлена самим
// человеком; событие снятия одно; сессия Боба не тронута.
func TestRevokeEndsOtherSessionsKeepsTheCurrent(t *testing.T) {
	t.Parallel()
	h, k := givenTwoSessions(t)
	first := h.now.Add(-3 * time.Hour)
	h.store.firstAuth[alice] = first

	op, err := h.revokeActing(alice, string(k.ID), tokS2)
	require.NoError(t, err)
	require.Nil(t, op.Error)

	require.Equal(t, domain.RevokeReasonAccessKeyRevoked, h.store.endedOf(s1), "Р8: прочая сессия снята")
	require.Empty(t, h.store.endedOf(s2), "Р8: текущая сессия жива")
	require.Equal(t, "access-key-revoked", domain.RevokeReasonAccessKeyRevoked, "слово причины — контракт журнала (Р8)")
	cut, ok := h.store.cutoffs[alice]
	require.True(t, ok, "Р8: отсечка личности поставлена")
	require.Equal(t, first.Add(-time.Microsecond), cut.RevokeBefore, "отсечка — та же, что у смены пароля")
	require.Equal(t, domain.RevokeReasonAccessKeyRevoked, cut.Reason)
	require.Equal(t, alice, cut.RevokedBy, "актор — сам человек (Р8)")
	require.Len(t, h.store.auditOf(access_keys.AuditAccessKeyRevoked), 1)

	require.Empty(t, h.store.endedOf(sBob), "сессии другого человека снятие не трогает")
	_, cutBob := h.store.cutoffs[bob]
	require.False(t, cutBob)
}

// TestRevokeWithoutActingCredentialEndsEverySession — ни выпуска, ни номера
// записи: текущую отличить нечем, сняты ВСЕ записи человека; чужой выпуск
// текущей не называет — тот же исход.
func TestRevokeWithoutActingCredentialEndsEverySession(t *testing.T) {
	t.Parallel()
	for name, acting := range map[string]string{"no-credential": "", "foreign-credential": tokBob, "unknown-credential": "tok0000000000000000zz"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h, k := givenTwoSessions(t)
			op, err := h.revokeActing(alice, string(k.ID), acting)
			require.NoError(t, err)
			require.Nil(t, op.Error)
			require.Equal(t, domain.RevokeReasonAccessKeyRevoked, h.store.endedOf(s1))
			require.Equal(t, domain.RevokeReasonAccessKeyRevoked, h.store.endedOf(s2))
			require.Empty(t, h.store.endedOf(sBob), "выпуск Боба не снимает и не бережёт его сессию")
		})
	}
}

// TestRevokeWithoutFirstAuthenticationWritesNoCutoff — памяти первой
// аутентификации нет: момента отсечки не из чего вывести, отсечка не пишется,
// записи сессии сняты.
func TestRevokeWithoutFirstAuthenticationWritesNoCutoff(t *testing.T) {
	t.Parallel()
	h, k := givenTwoSessions(t)
	op, err := h.revokeActing(alice, string(k.ID), tokS2)
	require.NoError(t, err)
	require.Nil(t, op.Error)
	_, cut := h.store.cutoffs[alice]
	require.False(t, cut)
	require.Equal(t, domain.RevokeReasonAccessKeyRevoked, h.store.endedOf(s1))
}

// TestRevokeWriteFaultRollsBackEveryRecord — форма Ф3-16: подставной отказ
// ЛЮБОЙ записи транзакции снятия откатывает всё — ключ на месте, записи сессии
// живы, отсечки и события нет; текст хранилища наружу не выходит.
func TestRevokeWriteFaultRollsBackEveryRecord(t *testing.T) {
	t.Parallel()
	for _, fault := range []string{"current", "sessions", "first", "cutoff", "audit"} {
		t.Run(fault, func(t *testing.T) {
			t.Parallel()
			h, k := givenTwoSessions(t)
			h.store.firstAuth[alice] = h.now.Add(-time.Hour)
			h.store.revokeFault = fault

			op, err := h.revokeActing(alice, string(k.ID), tokS2)
			require.NoError(t, err, "синхронные сверки прошли — отказ живёт в операции")
			require.NotNil(t, op.Error, "отказ записи %s — исход операции", fault)
			require.NotContains(t, op.Error.GetMessage(), revokeStoreFault, "текст хранилища наружу не выходит")

			require.Equal(t, 2, h.store.keyCount(alice), "ключ на месте")
			require.Empty(t, h.store.endedOf(s1), "S1 жива")
			require.Empty(t, h.store.endedOf(s2), "S2 жива")
			_, cut := h.store.cutoffs[alice]
			require.False(t, cut, "отсечки нет")
			require.Empty(t, h.store.auditOf(access_keys.AuditAccessKeyRevoked), "события нет")
		})
	}
}

// TestRefusedRevokeLeavesSessionsAlive — законный близнец: снятие, которое
// отвергнуто (ключа нет), сессий не снимает.
func TestRefusedRevokeLeavesSessionsAlive(t *testing.T) {
	t.Parallel()
	h, _ := givenTwoSessions(t)
	_, err := h.revokeActing(alice, "ak-0000000000000000z", tokS2)
	require.Error(t, err)
	require.Empty(t, h.store.endedOf(s1))
	require.Empty(t, h.store.endedOf(s2))
	require.Empty(t, h.store.cutoffs)
}

// revokeFromSession — снятие из вызова, чью сессию назвал край номером записи
// session (kaname#677); actor — кто звонит, user — чей ключ.
func (h *harness) revokeFromSession(user, actor domain.UserID, id string, session domain.HumanSessionID) (*operations.Operation, error) {
	h.t.Helper()
	uc, err := access_keys.NewRevokeUseCase(h.deps, h.ops)
	require.NoError(h.t, err)
	op, err := uc.Execute(h.ctx(), access_keys.RevokeInput{UserID: user, Actor: actor, AccessKeyID: id, ActingSession: session})
	if err != nil {
		return nil, err
	}
	return h.ops.await(h.t, op.ID), nil
}

// TestRevokeFromAForwardedSessionKeepsIt — Р8 на полосе края (kaname#677):
// край назвал номер записи S2 — S2 жива, S1 снята причиной
// `access-key-revoked`, сессия Боба не тронута. Выпуска у вызова нет: текущую
// называет номер записи, а не выпуск.
func TestRevokeFromAForwardedSessionKeepsIt(t *testing.T) {
	t.Parallel()
	h, k := givenTwoSessions(t)
	op, err := h.revokeFromSession(alice, alice, string(k.ID), s2)
	require.NoError(t, err)
	require.Nil(t, op.Error)
	require.Equal(t, domain.RevokeReasonAccessKeyRevoked, h.store.endedOf(s1), "Р8: прочая сессия снята")
	require.Empty(t, h.store.endedOf(s2), "Р8: текущая сессия, названная краем, жива")
	require.Empty(t, h.store.endedOf(sBob))
}

// TestForwardedSessionSavesNothingThatIsNotTheCallers — отрицание (kaname#677):
// номер записи бережёт ТОЛЬКО сессию самого человека, который снимает СВОЙ
// ключ. (а) Номер чужой записи (Боба) не бережёт ни одной записи Алисы и записи
// Боба не касается; (б) снимает не сам человек — номер его же записи S2,
// пришедший с вызовом другого, S2 не бережёт: текущая сессия вызывающего —
// не сессия человека, чей ключ снят; (в) номера нет — прежний исход, сняты все.
func TestForwardedSessionSavesNothingThatIsNotTheCallers(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		actor   domain.UserID
		session domain.HumanSessionID
	}{
		"foreign-record": {actor: alice, session: sBob},
		"another-caller": {actor: bob, session: s2},
		"no-record":      {actor: alice, session: ""},
		"unknown-record": {actor: alice, session: "hss-0000000000000000zz"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h, k := givenTwoSessions(t)
			op, err := h.revokeFromSession(alice, c.actor, string(k.ID), c.session)
			require.NoError(t, err)
			require.Nil(t, op.Error)
			require.Equal(t, domain.RevokeReasonAccessKeyRevoked, h.store.endedOf(s1))
			require.Equal(t, domain.RevokeReasonAccessKeyRevoked, h.store.endedOf(s2), "номер записи не бережёт S2")
			require.Empty(t, h.store.endedOf(sBob), "запись Боба снятие ключа Алисы не трогает")
		})
	}
}

// TestRevokeHandlerTakesTheCurrentSessionFromTheCarrier — транспорт (kaname#677):
// номер записи, положенный читателем переданного краем в носитель
// `callerorigin`, доезжает до глагола — S2 жива, S1 снята. Близнец — тот же
// вызов без носителя: сняты обе (прежний исход личности без номера).
func TestRevokeHandlerTakesTheCurrentSessionFromTheCarrier(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		ctx    func() context.Context
		s2Kept bool
	}{
		"carrier":    {ctx: func() context.Context { return callerorigin.WithSessionID(asUser(alice), string(s2)) }, s2Kept: true},
		"no-carrier": {ctx: func() context.Context { return asUser(alice) }, s2Kept: false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h, k := givenTwoSessions(t)
			op, err := h.handler().Revoke(c.ctx(), &iamv1.RevokeAccessKeyRequest{UserId: string(alice), AccessKeyId: string(k.ID)})
			require.NoError(t, err)
			done := h.ops.await(t, op.GetId())
			require.Nil(t, done.Error)
			require.Equal(t, domain.RevokeReasonAccessKeyRevoked, h.store.endedOf(s1))
			if c.s2Kept {
				require.Empty(t, h.store.endedOf(s2), "текущая, названная носителем, жива")
			} else {
				require.Equal(t, domain.RevokeReasonAccessKeyRevoked, h.store.endedOf(s2), "без носителя текущая не названа")
			}
		})
	}
}
