// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession_test

// session_set_writer_test.go — ТРАНЗАКЦИЯ, СНИМАЮЩАЯ НЕСКОЛЬКО СЕССИЙ ЧЕЛОВЕКА,
// ОТКРЫВАЕТСЯ ДЕРЖАЩЕЙ ЕГО СТРОКУ ЛИЧНОСТИ (задача kaname#340).
//
// Писатели нескольких записей сессии одного человека сериализуются на его
// строке личности, и берут её ПЕРВОЙ — раньше строки способа входа, фактора,
// кода восстановления и любой строки сессии. Иначе порядок у них встречный с
// удалением личности (личность → каскадом всё прочее) и с принудительным
// выходом (личность → все сессии). Как это ложится в базу, судят
// интеграционные пробы (`internal_iam/session_set_writers_person_first_integration_test.go`,
// `internal_iam/force_logout_concurrent_teardown_integration_test.go`); здесь —
// что каждый из трёх вариантов использования открывает свою транзакцию именно
// так: дверью `SessionSetWriter` той личности, чьи записи снимает.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/assurance"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// requireSessionSetTransactionsHoldThePerson — каждая транзакция, снявшая
// записи сессии, открыта держащей строку ТОЙ личности, чьи записи сняты.
// Перепись печатается: «ноль таких транзакций» — не зелёное, а несостоявшаяся
// сцена.
func requireSessionSetTransactionsHoldThePerson(t *testing.T, store *fakeStore, person domain.UserID) {
	t.Helper()
	store.mu.Lock()
	opened := append([]*fakeWriter(nil), store.opened...)
	store.mu.Unlock()
	var ending int
	for _, w := range opened {
		for _, of := range w.endedOthersOf {
			ending++
			require.Equal(t, person, of, "фикстура: сняты записи не той личности")
			require.Equal(t, person, w.lockedFor,
				"транзакция, снявшая записи сессии, открыта без строки личности: строки сессии "+
					"и строки, взятые до них, она берёт навстречу принудительному выходу и удалению личности")
		}
	}
	t.Logf("транзакций открыто %d · снимавших записи сессии %d", len(opened), ending)
	require.Positive(t, ending, "ни одна транзакция не снимала записей сессии — сцена не построена")
}

func TestChangePassword_TransactionHoldsThePersonFirst(t *testing.T) {
	h := newHarness(t, nil)
	u := h.person(t, "usr-ss1", "ss1@example.invalid", "correct horse battery", true)
	h.mustLogin(t, "ss1@example.invalid", "correct horse battery")
	h.clock = ucBase.Add(time.Minute)
	s2 := h.mustLogin(t, "ss1@example.invalid", "correct horse battery")

	h.clock = ucBase.Add(time.Hour)
	_, err := h.change.Execute(context.Background(), humansession.ChangePasswordInput{
		Bearer: s2.Bearer, CurrentPassword: "correct horse battery", NewPassword: "brand new passphrase", Source: "203.0.113.7",
	})
	require.NoError(t, err)
	requireSessionSetTransactionsHoldThePerson(t, h.store, u.ID)
}

func TestRemoveSecondFactor_TransactionHoldsThePersonFirst(t *testing.T) {
	h := newSFHarness(t)
	_, _, codes := h.enrolled(t, "usr-ss2", "ss2@example.invalid", "correct horse battery")
	s1 := h.mustLogin(t, "ss2@example.invalid", "correct horse battery")
	h.mustLogin(t, "ss2@example.invalid", "correct horse battery")

	_, err := h.remove.Execute(context.Background(), humansession.RemoveSecondFactorInput{
		Bearer: s1.Bearer, Factor: humansession.SecondFactorPresentation{Method: assurance.MethodLookupSecret, Code: codes[0]},
		Source: "203.0.113.7",
	})
	require.NoError(t, err)
	requireSessionSetTransactionsHoldThePerson(t, h.store, s1.View.User.ID)
}

func TestCompleteRecovery_TransactionHoldsThePersonFirst(t *testing.T) {
	h := newHarness(t, nil)
	u := h.person(t, "usr-ss3", "ss3@example.invalid", "old-password-ss3", true)
	h.mustLogin(t, "ss3@example.invalid", "old-password-ss3")
	h.clock = ucBase.Add(time.Minute)
	h.request(t, "ss3@example.invalid")
	letter := h.letterOf(t, u.ID)

	h.clock = ucBase.Add(2 * time.Minute)
	_, err := h.complete("ss3@example.invalid", letter, "brand-new-password-ss3")
	require.NoError(t, err)
	requireSessionSetTransactionsHoldThePerson(t, h.store, u.ID)
}
