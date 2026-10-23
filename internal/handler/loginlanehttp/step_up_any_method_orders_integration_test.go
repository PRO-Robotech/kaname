// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// step_up_any_method_orders_integration_test.go — пробы, заказанные разбором
// классов приёмки `step-up-with-any-enrolled-method.md` (задача
// PRO-Robotech/kaname#827; разбор `docs/specs/reviews/step-up-with-any-enrolled-method-class-exposure/initial/c9224c8b….md`,
// раздел «Заказы», адресат integration-tester): условия на код, которые
// исполняются, но по коду не видны.
//
//   - SUAX-ORDER — `allowCredentials` упорядочен по `(createdAt, id)` на ≥ 3
//     ключах, вставленных не в порядке идентификаторов (`api-repeated-order`);
//   - SUAX-POSITION — выдача испытания в положении подтверждения адреса
//     отвечает отказом положения (Р2, `PathRefusedInVerification`), испытание
//     не выдаётся; близнец — подтверждённый адрес;
//   - SUAX-CROSS — испытания трёх видов не принимаются друг у друга: испытание
//     входа ключом (Ф13) церемония повышения не находит; испытание повышения
//     не принимают ни вход ключом, ни проверка утверждения Ф7.
//
// Не построено здесь — уборка хранилища испытаний повышения: имени хранилища
// до замысла нет, и проба по нему была бы выдумкой (вопрос к замыслу в
// возврате полосы).
//
// Run: `go test ./internal/handler/loginlanehttp/ -run 'TestSUAX' -count=1`
// (нужен Docker); под -short пропускается.
package loginlanehttp_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_keys"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify/webauthntest"
)

// TestSUAX_ORDER_AllowCredentialsAreOrderedByCreationThenID — SUAX-ORDER.
func TestSUAX_ORDER_AllowCredentialsAreOrderedByCreationThenID(t *testing.T) {
	const id = "SUAX-ORDER"
	h := newSUAStand(t)
	p := h.person(t, "xorder")
	keys := []akKey{h.withKey(t, p), h.withKey(t, p), h.withKey(t, p)}

	// Моменты добавления — обратные лексикографическому порядку
	// идентификаторов: порядок по `id` и порядок по `(createdAt, id)` различны.
	byID := append([]akKey(nil), keys...)
	for i := 0; i < len(byID); i++ {
		for j := i + 1; j < len(byID); j++ {
			if string(byID[j].id) < string(byID[i].id) {
				byID[i], byID[j] = byID[j], byID[i]
			}
		}
	}
	base := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	for i, k := range byID {
		at := base.Add(time.Duration(len(byID)-i) * time.Minute)
		tag, err := h.pool.Exec(h.ctx, `UPDATE kaname.user_access_keys SET created_at = $2 WHERE id = $1`, string(k.id), at)
		require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): момент добавления ключа")
		require.EqualValues(t, 1, tag.RowsAffected(), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): строка ключа найдена")
	}
	want := []string{}
	for i := len(byID) - 1; i >= 0; i-- {
		want = append(want, credentialIDOf(byID[i]))
	}
	idOrder := []string{}
	for _, k := range byID {
		idOrder = append(idOrder, credentialIDOf(k))
	}
	require.NotEqual(t, idOrder, want, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): порядки различимы")

	c := h.challenge(t, id, h.login(t, p))
	require.Equal(t, want, c.allow, "%s: allowCredentials упорядочен по (createdAt, id)", id)
}

// TestSUAX_POSITION_BeginIsRefusedInVerificationPosition — SUAX-POSITION.
func TestSUAX_POSITION_BeginIsRefusedInVerificationPosition(t *testing.T) {
	const id = "SUAX-POSITION"
	h := newAVLane(t)
	begin := func(s avSession) reply {
		return h.post(t, s, suaPathBegin, map[string]any{"csrfToken": h.token(s, suaKindBegin)})
	}
	a := h.register(t, freshAddress("suaxpa"))
	r := begin(a)
	requireBeginMounted(t, id, r)
	require.Equalf(t, http.StatusForbidden, r.status, "%s: отказ положения — 403: %s", id, r.body)
	require.JSONEq(t, avRefusalBody, r.body, "%s: значение отказа положения Р3 побайтово", id)

	b := h.register(t, freshAddress("suaxpb"))
	h.mark(t, b)
	rb := begin(b)
	if rb.status >= 400 {
		require.NotEqual(t, "EMAIL_NOT_VERIFIED", parseRefusal(t, rb.body).reason(), "%s близнец: подтверждённый адрес — без отказа положения", id)
	}
}

// TestSUAX_CROSS_ChallengesOfThreeKindsAreNotInterchangeable — SUAX-CROSS.
func TestSUAX_CROSS_ChallengesOfThreeKindsAreNotInterchangeable(t *testing.T) {
	const id = "SUAX-CROSS"
	h := newSUAStand(t)
	p := h.person(t, "xcross")
	k := h.withKey(t, p)
	s := h.login(t, p)

	// Возможность и близнец: испытание повышения принимается своей церемонией.
	own := h.challenge(t, id, s)
	ok := h.keyStepUp(t, id, s, k, own.raw, strong())
	require.Equalf(t, http.StatusOK, ok.status, "%s близнец: испытание повышения — своей церемонией 200: %s", id, ok.body)

	// (1) Испытание входа ключом (Ф13) церемония повышения не находит.
	s1 := h.login(t, p)
	f := givenAKForm(t, h.sessionLane)
	loginChallenge := givenChallenge(t, h.sessionLane, f)
	r1 := h.keyStepUp(t, id, s1, k, loginChallenge, strong())
	requireRefusalOf(t, id+" (1)", r1, http.StatusBadRequest, 9, suaReasonNotIssued, suaTextNotIssued)

	// (2) Испытание повышения вход ключом не принимает: сессии не выдаётся.
	s2 := h.login(t, p)
	stepUp := h.challenge(t, id, s2)
	g := givenAKForm(t, h.sessionLane)
	r2 := akLoginWith(t, h.sessionLane, g, k, stepUp.raw, strong())
	require.NotEqualf(t, http.StatusOK, r2.status, "%s (2): вход ключом над испытанием повышения не выдаёт сессию: %s", id, r2.body)
	require.Nil(t, cookieNamed(r2.cookies, loginlanehttp.CookieSession), "%s (2): носителя нет", id)

	// (3) Испытание повышения не принимает проверка утверждения Ф7.
	s3 := h.login(t, p)
	stepUp3 := h.challenge(t, id, s3)
	finish, err := access_keys.NewFinishAssertionUseCase(h.keyDepsOf(false))
	require.NoError(t, err)
	as := assertOver(t, k, stepUp3.raw, webauthntest.AssertionOptions{UserVerified: true, BackupEligible: true})
	_, err = finish.Execute(h.ctx, access_keys.FinishAssertionInput{
		UserID: p.user, CredentialID: as.CredentialID, ClientDataJSON: as.ClientDataJSON,
		AuthenticatorData: as.AuthenticatorData, Signature: as.Signature,
	})
	require.Errorf(t, err, "%s (3): проверка утверждения Ф7 не принимает испытание повышения", id)
}
