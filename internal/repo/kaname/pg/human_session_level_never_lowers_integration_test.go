// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// human_session_level_never_lowers_integration_test.go — оператор
// предъявления ВНУТРИ сессии не понижает записанный уровень уверенности
// (задача PRO-Robotech/kaname#343; приёмка Ф11
// `docs/engineering/acceptance/assurance-level-is-declared-by-our-session.md`,
// Р2 — понижение в пределах сессии невыразимо).
//
// # Почему проба на базе, а не на варианте использования
//
// Уровень записи пишет ОДИН оператор (`PresentInSession`), а вызывающих его —
// четыре глагола (повышение, подтверждение, снятие второго фактора, новый
// набор запасных кодов). Каждый считает кандидата от СВОЕГО множества
// предъявленного; кандидат «бедного» вызывающего ниже записанного, как только у
// сессии появляется производитель верхней ступени (вход ключом, Ф13). Поэтому
// условие на прежнее значение обязано стоять В ОПЕРАТОРЕ: проверка у каждого
// вызывающего — пять мест одного правила, и шестой вызывающий появился бы без
// неё молча.
//
// Наблюдаемое — уровень строки после записи с меньшим кандидатом; близнец —
// запись с большим кандидатом поднимает уровень. Различие пары — ровно одно:
// кандидат ниже или выше записанного.
package pg_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// hsLevelOf — записанный уровень и множество предъявленного строки сессии.
func hsLevelOf(t *testing.T, repo *pg.HumanSessionRepo, b domain.SessionBearer) (string, []string) {
	t.Helper()
	got, r := hsResolve(t, repo, b, hsBase.Add(hsTTL/2))
	require.Equal(t, humansession.SessionFound, r, "ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: сессия жива и читается носителем")
	return got.Session.AssuranceLevel, got.Session.PresentedMethods
}

// TestHumanSessionWriter_343_PresentInSessionNeverLowersTheRecordedLevel — у
// сессии уровня «3» (выдана ключом с проверкой пользователя) предъявление
// пароля внутри неё приносит кандидата «1»: запись остаётся «3», множество
// предъявленного накапливается. Близнец: у сессии «1» кандидат «2» поднимает
// запись до «2».
func TestHumanSessionWriter_343_PresentInSessionNeverLowersTheRecordedLevel(t *testing.T) {
	pool := hsPool(t)
	repo := pg.NewHumanSessionRepo(pool)
	people := lmPeople(t, pool, "hs343", 2)
	ctx := context.Background()

	// Дано: сессия уровня «3», выданная утверждением ключа (Ф11 §3.0а —
	// согласованное состояние для множества {webauthn}).
	high := hsSession(people[0], "343hi", hsBase)
	high.AssuranceLevel, high.PresentedMethods = "3", []string{"webauthn"}
	bHigh := hsIssue(t, repo, high)
	// Близнец: сессия уровня «1», выданная паролем.
	low := hsSession(people[1], "343lo", hsBase)
	bLow := hsIssue(t, repo, low)

	present := func(s domain.HumanSession, methods []string, candidate string) domain.SessionBearer {
		t.Helper()
		next, err := domain.NewSessionBearer()
		require.NoError(t, err)
		w, err := repo.Writer(ctx)
		require.NoError(t, err)
		defer func() { _ = w.Rollback(ctx) }()
		require.NoError(t, presentInSessionOf(ctx, w, s.ID, methods, candidate, next, hsBase.Add(hsTTL/4)))
		require.NoError(t, w.Commit(ctx))
		return next
	}

	// Кандидат НИЖЕ записанного: предъявлен пароль внутри сессии ключа.
	bHigh2 := present(high, []string{"webauthn", "password"}, "1")
	level, methods := hsLevelOf(t, repo, bHigh2)
	require.Equal(t, "3", level,
		"kaname#343: предъявление с кандидатом «1» в сессии «3» обязано оставить запись «3» — понижение в пределах сессии невыразимо (Ф11 Р2)")
	require.ElementsMatch(t, []string{"webauthn", "password"}, methods, "множество предъявленного накоплено")

	// Близнец: кандидат ВЫШЕ записанного поднимает запись.
	bLow2 := present(low, []string{"password", "totp"}, "2")
	level, _ = hsLevelOf(t, repo, bLow2)
	require.Equal(t, "2", level, "БЛИЗНЕЦ: кандидат «2» в сессии «1» поднимает запись до «2»")

	// Прежние носители перевыпущены: тот же оператор пишет новый дайджест.
	_, r := hsResolve(t, repo, bHigh, hsBase.Add(hsTTL/2))
	require.NotEqual(t, humansession.SessionFound, r, "прежний носитель сессии «3» погашен перевыпуском")
	_, r = hsResolve(t, repo, bLow, hsBase.Add(hsTTL/2))
	require.NotEqual(t, humansession.SessionFound, r, "прежний носитель сессии «1» погашен перевыпуском")
}

// presentInSessionOf — вызов оператора предъявления; уровень, который он
// записал, судится чтением строки, а не его ответом.
func presentInSessionOf(ctx context.Context, w humansession.Writer, id domain.HumanSessionID, methods []string, candidate string, next domain.SessionBearer, at time.Time) error {
	return w.PresentInSession(ctx, id, methods, candidate, next.Digest(), at)
}
