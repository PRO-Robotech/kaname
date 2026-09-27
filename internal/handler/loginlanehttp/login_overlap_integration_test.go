// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// login_overlap_integration_test.go — ВХОД, ВСТРЕТИВШИЙ ПРИНУДИТЕЛЬНЫЙ ВЫХОД,
// НЕ ВЫДАЁТ СЕССИИ, КОТОРУЮ ОТСЕЧКА УЖЕ НАКРЫЛА (задача kaname#385; приёмка
// того же имени, сценарии KN-OVL-01…12). Стенд, обёртки и наблюдения —
// `login_overlap_harness_integration_test.go`; унитарная половина KN-OVL-02
// (огибающая) — `humansession/login_cutoff_envelope_test.go`.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ СУДИТСЯ
//
// Граница — момент аутентификации входа m (показание часов входа в разрешении
// хранилища) против момента отсечки T, включающе: вход накрыт ⟺ m ≤ T (Р1).
// После обоих глаголов, в любом порядке их старта, у человека нет живой записи
// сессии, чей момент не позже стоящей отсечки, и вход отвечает «выдана» только
// на сессию, которая годна краю либо снята выходом и сосчитана в его событии
// (Р2). Отказ по отсечке — тот же один отказ, не попытка, своя клетка
// `before-cutoff`, ничего не записано (Р3). Сериализация — захватом строки
// личности `FOR SHARE` первой операцией транзакции выдачи и чтением отсечки
// отдельным оператором после него (Р4).
//
// Каждый сценарий называет «Тогда» так, чтобы красный на дереве до правки
// прочитался причиной: какое событие пришло первым, какая запись жива, какая
// клетка не выросла.
//
// Run: `go test ./internal/handler/loginlanehttp/ -run '^TestLoginOverlap_' -count=1`
// (Docker). Skipped under -short.
package loginlanehttp_test

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

const (
	// overlapContestedRounds — раундов KN-OVL-05: «не меньше двадцати».
	overlapContestedRounds = 20
	// overlapDeletionRounds — раундов каждой половины KN-OVL-09: «не меньше
	// шести».
	overlapDeletionRounds = 6
)

// requireOnlyS0 — «Дано»: у личности одна запись сессии S0, и она жива.
func (h *overlapLane) requireOnlyS0(t *testing.T, p overlapPerson) overlapRow {
	t.Helper()
	rows := h.rowsOf(t, p)
	require.Len(t, rows, 1, "НЕ ВЫПОЛНИЛОСЬ: у личности обязана быть одна запись S0 от регистрации: %v", rows)
	require.True(t, rows[0].live(), "НЕ ВЫПОЛНИЛОСЬ: S0 до сцены жива: %s", rows[0])
	return rows[0]
}

// momentAtOpen — m входа: показание часов входа к открытию его первой
// транзакции записи после отметки opens, в разрешении хранилища.
func (h *overlapLane) momentAtOpen(t *testing.T, opens int) time.Time {
	t.Helper()
	readings := h.store.readingsAtOpen(opens)
	require.NotEmpty(t, readings, "НЕ ВЫПОЛНИЛОСЬ: вход не открыл транзакции записи — момента нет")
	return storeResolution(readings[0])
}

// issuedFacts — что на дереве сказал о себе вход, ответивший 200: жива ли
// выданная запись, её момент против T и ответ края. Печатается в красном.
func (h *overlapLane) issuedFacts(t *testing.T, r overlapLoginReply, p overlapPerson, cutoff time.Time) string {
	t.Helper()
	if r.status != http.StatusOK || r.bearer == "" {
		return fmt.Sprintf("вход ответил %d %s", r.status, r.body)
	}
	row, ok := h.rowOfBearer(t, r.bearer)
	if !ok {
		return "вход ответил 200, а записи по его носителю нет"
	}
	pair := h.edgePair(t, r.bearer, p)
	return fmt.Sprintf("вход ответил 200 с сессией S1: %s; authenticated_at(S1) не позже T=%s — %t; пара края: %s",
		row, momentLabel(cutoff), !row.authAt.After(cutoff), pair)
}

// sceneAtOpenThenExit — «вход стоит в З1; выход завершён; задержка снята»
// (KN-OVL-02, 06, 08): вход, момент m и отсечка T.
func (h *overlapLane) sceneAtOpenThenExit(t *testing.T, p overlapPerson, password, code string) (overlapLoginReply, time.Time, time.Time) {
	t.Helper()
	gate := h.gates.arm(t, pointOpen)
	opens := h.store.opens()
	call := h.startLogin(t, p, password, code)
	gate.awaitReached(t, "вход")
	m := h.momentAtOpen(t, opens)
	h.forceLogoutDone(t, p)
	cutoff := h.requireCutoff(t, p)
	gate.lift()
	r := call.await(t, "вход")
	gate.requireLiftedByProbe(t)
	return r, m, cutoff
}

// ─────────────────────────────────────────────────────────────────────────────
// KN-OVL-01

// TestLoginOverlap_KN_OVL_01_LoginAfterTheForcedExitIsANewLoginFitForTheEdge —
// вход после завершённого выхода — новый вход: сессия жива и годна краю.
// Положительный близнец 02, 07/2 и 10/1.
func TestLoginOverlap_KN_OVL_01_LoginAfterTheForcedExitIsANewLoginFitForTheEdge(t *testing.T) {
	h := newOverlapLane(t)
	p := h.personP()
	h.requireOnlyS0(t, p)
	h.forceLogoutDone(t, p)
	cutoff := h.requireCutoff(t, p)

	before := h.obs.snapshot()
	opens := h.store.opens()
	r := h.startLogin(t, p, integrationPassword, "").await(t, "вход P")
	after := h.obs.snapshot()
	m := h.momentAtOpen(t, opens)

	require.Equal(t, http.StatusOK, r.status, "вход после выхода обязан выдать сессию: %s", r.body)
	require.NotEmpty(t, r.bearer, "вход пишет носитель")
	assert.Equal(t, 1, grew(before, after, cellIssued), "клетка `issued` обязана вырасти на один")
	row, ok := h.rowOfBearer(t, r.bearer)
	require.True(t, ok, "запись S1 по носителю есть")
	assert.True(t, row.live(), "S1 жива: %s", row)
	assert.True(t, row.authAt.Equal(m), "authenticated_at(S1)=%s обязан равняться m=%s", momentLabel(row.authAt), momentLabel(m))
	assert.True(t, m.After(cutoff), "m=%s обязан быть позже T=%s", momentLabel(m), momentLabel(cutoff))
	pair := h.edgePair(t, r.bearer, p)
	assert.True(t, pair.resolved, "Resolve находит S1: %s", pair)
	assert.True(t, pair.cutoffFound, "SessionCutoffOf(P) — отсечка найдена: %s", pair)
	assert.True(t, pair.fit(), "пара края говорит «годна»: T строго раньше authenticated_at(S1): %s", pair)
}

// ─────────────────────────────────────────────────────────────────────────────
// KN-OVL-02

// TestLoginOverlap_KN_OVL_02_MomentBeforeTheExitIssueAfterItsCommitIsRefused —
// момент входа раньше выхода, выдача — после его фиксации: вход отказывает и
// ничего не пишет. Дельта против 01 — где стоит момент входа относительно
// момента выхода.
func TestLoginOverlap_KN_OVL_02_MomentBeforeTheExitIssueAfterItsCommitIsRefused(t *testing.T) {
	h := newOverlapLane(t)
	p := h.personP()
	s0 := h.requireOnlyS0(t, p)
	before := h.obs.snapshot()

	r, m, cutoff := h.sceneAtOpenThenExit(t, p, integrationPassword, "")
	after := h.obs.snapshot()
	fp := h.footprint(t, p)

	assert.Empty(t, oneRefusal(r), "вход, чей момент не позже отсечки, обязан отказать тем же одним отказом: %s",
		h.issuedFacts(t, r, p, cutoff))
	assert.False(t, m.After(cutoff), "Дано: m=%s не позже T=%s", momentLabel(m), momentLabel(cutoff))
	rows := h.rowsOf(t, p)
	if assert.Len(t, rows, 1, "входом ничего не записано: у P одна запись — S0: %v", rows) {
		assert.Equal(t, s0.id, rows[0].id, "единственная запись — S0")
		assert.Equal(t, overlapForcedExitReason, rows[0].endedReason(), "S0 снята выходом: %s", rows[0])
	}
	assert.Zero(t, fp.issuedEvents, "событий `iam.session.issued` для P — ноль")
	assert.Zero(t, fp.failures, "следов неверного предъявления по адресу P — ноль")
	assert.Equal(t, 1, grew(before, after, cellBeforeCutoff), "клетка `before-cutoff` обязана вырасти на один")
	assert.Zero(t, grew(before, after, cellIssued), "клетка `issued` не меняется")
	assert.Zero(t, grew(before, after, cellMismatched), "клетка `mismatched` не меняется")
	assert.Equal(t, 1, h.sessionsEnded(t, p), "событие выхода несёт `sessions_ended = 1`")
}

// ─────────────────────────────────────────────────────────────────────────────
// KN-OVL-03

// TestLoginOverlap_KN_OVL_03_ExitArrivingInsideAnOpenIssueWaitsAndEndsIt —
// выход пришёл, когда выдача уже положила запись: выход дожидается выдачи и
// снимает выданное. Дельта против 02 — где стоит выход относительно выдачи.
func TestLoginOverlap_KN_OVL_03_ExitArrivingInsideAnOpenIssueWaitsAndEndsIt(t *testing.T) {
	h := newOverlapLane(t)
	p := h.personP()
	h.requireOnlyS0(t, p)

	gate := h.gates.arm(t, pointCommit)
	call := h.startLogin(t, p, integrationPassword, "")
	gate.awaitReached(t, "вход P")
	exit := h.startForceLogout(p)
	first, waiters := h.firstOf(t, "транзакция выхода", exit.done)
	gate.lift()
	r := call.await(t, "вход P")
	er := exit.await(t)
	gate.requireLiftedByProbe(t)
	h.requireCompleted(t, er)
	cutoff := h.requireCutoff(t, p)
	t.Logf("первым пришло «%s» (ждущие замка: %v)", first, waiters)

	assert.Equal(t, eventWaitsOnLock, first,
		"транзакция выхода обязана встать на замке открытой выдачи; первым пришло «выход завершён»")
	require.Equal(t, http.StatusOK, r.status, "вход отвечает 200 с сессией S1: %s", r.body)
	require.NotEmpty(t, r.bearer)
	assert.Greater(t, er.seq, h.store.committing.Load(), "выход обязан завершиться после фиксации выдачи")
	row, ok := h.rowOfBearer(t, r.bearer)
	require.True(t, ok, "запись S1 по носителю есть")
	assert.Equal(t, overlapForcedExitReason, row.endedReason(), "S1 снята выходом: %s; T=%s", row, momentLabel(cutoff))
	if assert.NotNil(t, row.endedAt, "S1 снята: %s", row) {
		assert.True(t, row.endedAt.Equal(cutoff), "ended_at(S1)=%s обязан равняться T=%s", momentLabel(*row.endedAt), momentLabel(cutoff))
	}
	assert.Equal(t, 2, h.sessionsEnded(t, p), "событие выхода несёт `sessions_ended = 2` (S0 и S1)")
	assert.Equal(t, humansession.NoSessionEnded, h.storeReason(t, r.bearer), "Resolve на носитель S1 — «сессия снята»")
}

// ─────────────────────────────────────────────────────────────────────────────
// KN-OVL-04

// TestLoginOverlap_KN_OVL_04_ExitAfterACompletedLoginEndsWhatItIssued — вход
// завершён до выхода: выход снимает выданное (близнец 03).
func TestLoginOverlap_KN_OVL_04_ExitAfterACompletedLoginEndsWhatItIssued(t *testing.T) {
	h := newOverlapLane(t)
	p := h.personP()
	h.requireOnlyS0(t, p)
	r := h.startLogin(t, p, integrationPassword, "").await(t, "вход P")
	require.Equal(t, http.StatusOK, r.status, "НЕ ВЫПОЛНИЛОСЬ: Дано — вход P завершён 200: %s", r.body)
	given, ok := h.rowOfBearer(t, r.bearer)
	require.True(t, ok && given.live(), "НЕ ВЫПОЛНИЛОСЬ: Дано — S1 жива")

	h.forceLogoutDone(t, p)
	cutoff := h.requireCutoff(t, p)

	row, _ := h.rowOfBearer(t, r.bearer)
	assert.Equal(t, overlapForcedExitReason, row.endedReason(), "S1 снята выходом: %s", row)
	if assert.NotNil(t, row.endedAt, "S1 снята: %s", row) {
		assert.True(t, row.endedAt.Equal(cutoff), "ended_at(S1)=%s обязан равняться T=%s", momentLabel(*row.endedAt), momentLabel(cutoff))
	}
	assert.Equal(t, 2, h.sessionsEnded(t, p), "событие выхода несёт `sessions_ended = 2`")
}

// ─────────────────────────────────────────────────────────────────────────────
// KN-OVL-05

// overlapBarrier — свод старта KN-OVL-05: вход ждёт на открытии транзакции
// выдачи, выход — на открытии своей; обе стороны отпускаются вместе.
type overlapBarrier struct {
	login, exit         chan struct{}
	loginOnce, exitOnce sync.Once
	met                 atomic.Int32
}

func newOverlapBarrier() *overlapBarrier {
	return &overlapBarrier{login: make(chan struct{}), exit: make(chan struct{})}
}

func (b *overlapBarrier) arrive(mine chan struct{}, once *sync.Once, other chan struct{}) {
	once.Do(func() { close(mine) })
	select {
	case <-other:
		b.met.Add(1)
	case <-time.After(overlapBarrierBudget):
	}
}

func (b *overlapBarrier) loginArrives() { b.arrive(b.login, &b.loginOnce, b.exit) }
func (b *overlapBarrier) exitArrives()  { b.arrive(b.exit, &b.exitOnce, b.login) }

// overlapRound — исход одного раунда KN-OVL-05.
type overlapRound struct {
	n       int
	outcome string
	faults  []string
}

// TestLoginOverlap_KN_OVL_05_ContestedRoundsAgreeWithTheRecordAndTheEdge —
// спорный путь без порядка: в каждом раунде запись согласна с краем и с ответом
// входа. Исходы печатаются, а не требуются.
func TestLoginOverlap_KN_OVL_05_ContestedRoundsAgreeWithTheRecordAndTheEdge(t *testing.T) {
	h := newOverlapLane(t)
	var (
		rounds []overlapRound
		counts = map[string]int{}
		met    int
	)
	for n := 1; n <= overlapContestedRounds; n++ {
		p := h.registerPerson(t)
		s0 := h.requireOnlyS0(t, p)
		barrier := newOverlapBarrier()
		h.store.setBarrier(barrier.loginArrives)
		h.exit.setBarrier(barrier.exitArrives)
		opens := h.store.opens()
		before := h.obs.snapshot()

		login := h.startLogin(t, p, integrationPassword, "")
		exit := h.startForceLogout(p)
		r := login.await(t, "вход раунда")
		er := exit.await(t)
		after := h.obs.snapshot()
		if barrier.met.Load() == 2 {
			met++
		}

		rd := overlapRound{n: n}
		fault := func(format string, args ...any) { rd.faults = append(rd.faults, fmt.Sprintf(format, args...)) }
		if !er.completed() {
			fault("выход не завершён: err=%v done=%t error=%q (шаги: %s)", er.err, er.done, er.opErr,
				strings.Join(h.exit.refusedSteps(), "; "))
		}
		cutoff, hasCutoff := h.cutoffOf(t, p)
		m := h.momentAtOpen(t, opens)
		rows := h.rowsOf(t, p)
		endedByExit := 0
		for _, row := range rows {
			if row.endedReason() == overlapForcedExitReason {
				endedByExit++
			}
			if hasCutoff && row.live() && !row.authAt.After(cutoff) {
				fault("живая запись под отсечкой: %s, T=%s", row, momentLabel(cutoff))
			}
		}
		switch {
		case r.status == http.StatusOK:
			row, ok := h.rowOfBearer(t, r.bearer)
			switch {
			case !ok:
				fault("вход ответил 200, а записи по его носителю нет")
			case !row.live():
				rd.outcome = "выдана и снята"
				if row.endedReason() != overlapForcedExitReason || !hasCutoff || !row.endedAt.Equal(cutoff) {
					fault("S1 снята не выходом либо не моментом T: %s, T=%s", row, momentLabel(cutoff))
				}
			default:
				rd.outcome = "выдана после отсечки"
				if !row.authAt.Equal(m) || !hasCutoff || !m.After(cutoff) {
					fault("S1 жива, а m=%s не позже T=%s либо не равен её моменту: %s", momentLabel(m), momentLabel(cutoff), row)
				}
			}
		case oneRefusal(r) == "":
			rd.outcome = "отказ"
			for _, row := range rows {
				if row.id != s0.id {
					fault("отказ, а у личности запись от входа: %s", row)
				}
			}
			if !hasCutoff || m.After(cutoff) {
				fault("отказ при m=%s позже T=%s", momentLabel(m), momentLabel(cutoff))
			}
			if grew(before, after, cellBeforeCutoff) != 1 {
				fault("отказ, а клетка `before-cutoff` выросла на %d", grew(before, after, cellBeforeCutoff))
			}
		default:
			fault("вход ответил ни 200, ни одним отказом: %d %s", r.status, r.body)
		}
		if er.completed() {
			if ended := h.sessionsEnded(t, p); ended != endedByExit {
				fault("`sessions_ended`=%d, а снятых выходом записей %d", ended, endedByExit)
			}
		}
		counts[rd.outcome]++
		rounds = append(rounds, rd)
	}

	t.Logf("раундов %d: «отказ» %d, «выдана и снята» %d, «выдана после отсечки» %d, без исхода %d; свод старта состоялся в %d",
		len(rounds), counts["отказ"], counts["выдана и снята"], counts["выдана после отсечки"], counts[""], met)
	var faults []string
	for _, rd := range rounds {
		if len(rd.faults) != 0 {
			faults = append(faults, fmt.Sprintf("раунд %d (%s): %s", rd.n, rd.outcome, strings.Join(rd.faults, "; ")))
		}
	}
	assert.Empty(t, faults, "запись разошлась с краем либо с ответом входа в %d раундах из %d:\n  %s",
		len(faults), len(rounds), strings.Join(faults, "\n  "))
}

// ─────────────────────────────────────────────────────────────────────────────
// KN-OVL-06

// TestLoginOverlap_KN_OVL_06_WrongPasswordAtTheSameBoundaryIsAnAttempt —
// неверный пароль на той же границе — попытка; отказ по отсечке — нет.
// Дельта против 02 — верен ли пароль. Первая половина сравнивает тело с
// ответом 02 на той же сцене.
func TestLoginOverlap_KN_OVL_06_WrongPasswordAtTheSameBoundaryIsAnAttempt(t *testing.T) {
	h := newOverlapLane(t)
	p02 := h.personP()
	h.requireOnlyS0(t, p02)
	r02, _, cut02 := h.sceneAtOpenThenExit(t, p02, integrationPassword, "")
	facts02 := h.issuedFacts(t, r02, p02, cut02)

	p := h.registerPerson(t)
	h.requireOnlyS0(t, p)
	before := h.obs.snapshot()
	fpBefore := h.footprint(t, p)
	r, _, _ := h.sceneAtOpenThenExit(t, p, laneWrongPassword, "")
	after := h.obs.snapshot()
	fpAfter := h.footprint(t, p)

	t.Run("06/1 тело ответа побайтово равно телу KN-OVL-02", func(t *testing.T) {
		assert.Empty(t, oneRefusal(r), "неверный пароль — тот же один отказ")
		assert.Equal(t, r02.status, r.status, "код ответа тот же, что у KN-OVL-02 (KN-OVL-02: %s)", facts02)
		assert.Empty(t, firstDiff(r02.body, r.body), "тело побайтово равно телу KN-OVL-02; первое различие — %s",
			firstDiff(r02.body, r.body))
	})
	t.Run("06/2 неверный пароль — попытка, отказ по отсечке — нет", func(t *testing.T) {
		assert.Equal(t, 1, fpAfter.failures-fpBefore.failures, "следов неверного предъявления по адресу P — один")
		assert.Equal(t, 1, grew(before, after, cellMismatched), "клетка `mismatched` выросла на один")
		assert.Zero(t, grew(before, after, cellBeforeCutoff), "клетка `before-cutoff` не меняется")
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// KN-OVL-07

// TestLoginOverlap_KN_OVL_07_TheRuleJudgesTheCutoffInclusivelyAtStoreResolution
// — правило судит отсечку, а не её писателя; граница включающая и судится в
// разрешении хранилища. Отсечку кладёт дверь записи отсечки с причиной
// `second-factor-reset`; часы входа подают значения пробы.
func TestLoginOverlap_KN_OVL_07_TheRuleJudgesTheCutoffInclusivelyAtStoreResolution(t *testing.T) {
	h := newOverlapLane(t)
	for _, tc := range []struct {
		name    string
		shift   time.Duration
		covered bool
	}{
		{name: "07/1 показание ровно X — отказ", shift: 0, covered: true},
		{name: "07/2 показание X плюс микросекунда — выдача", shift: time.Microsecond, covered: false},
		{name: "07/3 показание X плюс 500 нс — отказ", shift: 500 * time.Nanosecond, covered: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := h.registerPerson(t)
			h.requireOnlyS0(t, p)
			x := storeResolution(time.Now())
			h.clock.fix(x.Add(tc.shift))
			t.Cleanup(h.clock.unfix)

			gate := h.gates.arm(t, pointOpen)
			before := h.obs.snapshot()
			fpBefore := h.footprint(t, p)
			call := h.startLogin(t, p, integrationPassword, "")
			gate.awaitReached(t, "вход P")
			w, err := h.sessions.Writer(h.ctx)
			require.NoError(t, err, "НЕ ВЫПОЛНИЛОСЬ: дверь записи отсечки")
			require.NoError(t, w.UpsertCutoff(h.ctx, domain.UserTokenRevocation{
				UserID: p.id, RevokeBefore: x, Reason: domain.RevokeReasonSecondFactorReset,
			}, ""), "НЕ ВЫПОЛНИЛОСЬ: отсечка не положена")
			require.NoError(t, w.Commit(h.ctx), "НЕ ВЫПОЛНИЛОСЬ: отсечка не зафиксирована")
			cutoff := h.requireCutoff(t, p)
			require.True(t, cutoff.Equal(x), "НЕ ВЫПОЛНИЛОСЬ: отсечка %s, а положен X=%s", momentLabel(cutoff), momentLabel(x))
			gate.lift()
			r := call.await(t, "вход P")
			gate.requireLiftedByProbe(t)
			after := h.obs.snapshot()
			fpAfter := h.footprint(t, p)

			if tc.covered {
				assert.Empty(t, oneRefusal(r), "показание %s, m=%s, отсечка X=%s: вход накрыт и обязан отказать: %s",
					momentLabel(x.Add(tc.shift)), momentLabel(storeResolution(x.Add(tc.shift))), momentLabel(x),
					h.issuedFacts(t, r, p, cutoff))
				assert.Zero(t, fpAfter.sessions-fpBefore.sessions, "входом ничего не записано: записей сессии не прибавилось")
				assert.Zero(t, fpAfter.issuedEvents-fpBefore.issuedEvents, "входом ничего не записано: событий выдачи не прибавилось")
				assert.Zero(t, fpAfter.failures-fpBefore.failures, "входом ничего не записано: следов не прибавилось")
				assert.Equal(t, 1, grew(before, after, cellBeforeCutoff), "клетка `before-cutoff` выросла на один")
				return
			}
			require.Equal(t, http.StatusOK, r.status, "показание позже отсечки на микросекунду — выдача: %s", r.body)
			row, ok := h.rowOfBearer(t, r.bearer)
			require.True(t, ok, "запись по носителю есть")
			assert.True(t, row.live(), "сессия жива: %s", row)
			assert.True(t, row.authAt.Equal(x.Add(time.Microsecond)), "authenticated_at=%s обязан быть X+1 мкс=%s",
				momentLabel(row.authAt), momentLabel(x.Add(time.Microsecond)))
			pair := h.edgePair(t, r.bearer, p)
			assert.True(t, pair.fit(), "пара края говорит «годна»: %s", pair)
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// KN-OVL-08

// TestLoginOverlap_KN_OVL_08_RefusalByTheCutoffDoesNotConsumeTheCode — отказ
// по отсечке не потребляет предъявленного кода второго фактора. Дельта против
// 02 — вход несёт код.
func TestLoginOverlap_KN_OVL_08_RefusalByTheCutoffDoesNotConsumeTheCode(t *testing.T) {
	h := newOverlapLane(t)
	p := h.personP()
	codes := h.enrolledFactor(t, p)
	code := codes[0]

	fpBefore := h.footprint(t, p)
	r, _, cutoff := h.sceneAtOpenThenExit(t, p, integrationPassword, code)
	fpAfter := h.footprint(t, p)

	assert.Empty(t, oneRefusal(r), "вход с кодом, накрытый отсечкой, обязан отказать тем же одним отказом: %s",
		h.issuedFacts(t, r, p, cutoff))
	assert.Zero(t, fpAfter.sessions-fpBefore.sessions, "входом ничего не записано: записей сессии у P не прибавилось")
	assert.Zero(t, fpAfter.issuedEvents-fpBefore.issuedEvents, "входом ничего не записано: событий `iam.session.issued` не прибавилось")
	assert.Zero(t, fpAfter.failures-fpBefore.failures, "входом ничего не записано: следов неверного предъявления не прибавилось")

	retry := h.startLogin(t, p, integrationPassword, code).await(t, "повторный вход P")
	if assert.Equal(t, http.StatusOK, retry.status, "повторный вход паролем и тем же кодом c обязан выдать сессию: %s", retry.body) {
		assert.Equal(t, passwordverify.BackupCodeCount-1, h.backupCodesRemaining(t, retry.bearer),
			"остаток набора на один меньше полного: код потреблён ровно один раз — повтором")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// KN-OVL-09

// overlapDeletionRound — исход раунда KN-OVL-09.
type overlapDeletionRound struct {
	n         int
	first     overlapEvent
	waiters   []string
	login     overlapLoginReply
	deleteErr error
	users     int
	sessions  int
	methods   int
	cells     [2]overlapCells
	fp        [2]overlapFootprint
}

// victim — чья транзакция откачена отказом `conflicting concurrent change`
// (`40P01` под `read committed` — ровно он): удаление — его ошибкой, вход —
// ответом «не выполнено». "" — никто.
func (r overlapDeletionRound) victim() string {
	switch {
	case errors.Is(r.deleteErr, iamerr.ErrAborted):
		return "удаление"
	case r.login.status == http.StatusServiceUnavailable:
		return "вход"
	}
	return ""
}

func (r overlapDeletionRound) String() string {
	login := fmt.Sprintf("%d", r.login.status)
	if ref, ok := refusalOf(r.login.body); ok {
		login += fmt.Sprintf(" code=%d %q", ref.Code, ref.Message)
	}
	return fmt.Sprintf("раунд %d: первым «%s» (ждущие %v); вход %s; удаление err=%v; откачено: %q; после: users=%d sessions=%d methods=%d",
		r.n, r.first, r.waiters, login, r.deleteErr, r.victim(), r.users, r.sessions, r.methods)
}

// deletionHalf — половины 09/1 и 09/2: вход Q с кодом задержан в точке, удаление
// Q начато и видно стоящим на замке, затем задержка снята.
func deletionHalf(t *testing.T, point overlapPoint) {
	h := newOverlapLane(t)
	deadlocksBefore := h.deadlocksNow(t)
	var rounds []overlapDeletionRound
	for n := 1; n <= overlapDeletionRounds; n++ {
		q := h.seedMember(t)
		codes := h.enrolledFactor(t, q)
		gate := h.gates.arm(t, point)
		call := h.startLogin(t, q, integrationPassword, codes[0])
		gate.awaitReached(t, "вход Q")
		del := h.startDelete(q)
		first, waiters := h.firstOf(t, "удаление Q", del.done)
		if first != eventWaitsOnLock {
			gate.lift()
			t.Fatalf("НЕ ВЫПОЛНИЛОСЬ: раунд %d — удаление Q не встало на замке, а ответило (err=%v): «Когда» не построено",
				n, del.await(t))
		}
		gate.lift()
		rd := overlapDeletionRound{n: n, first: first, waiters: waiters}
		rd.login = call.await(t, "вход Q")
		rd.deleteErr = del.await(t)
		gate.requireLiftedByProbe(t)
		rd.users, rd.sessions, rd.methods = h.personGone(t, q)
		rounds = append(rounds, rd)
		t.Log(rd)
	}
	deadlocks := h.overlapDeadlocksAfterPoolClose(t) - deadlocksBefore
	t.Logf("раундов %d · pg_stat_database.deadlocks +%d", len(rounds), deadlocks)

	assert.Zero(t, deadlocks, "взаимных блокировок ноль: счётчик базы вырос на %d", deadlocks)
	for _, rd := range rounds {
		assert.Empty(t, rd.victim(), "раунд %d: одна из двух транзакций откачена взаимной блокировкой: %s", rd.n, rd)
		assert.Equal(t, http.StatusOK, rd.login.status, "раунд %d: вход отвечает 200: %s", rd.n, rd)
		assert.NoError(t, rd.deleteErr, "раунд %d: удаление зафиксировано: %s", rd.n, rd)
		assert.Zero(t, rd.users+rd.sessions+rd.methods, "раунд %d: личности Q нет, записей сессии и строк способов нет: %s", rd.n, rd)
	}
}

// TestLoginOverlap_KN_OVL_09_1_DeletionWaitsForAnIssueHeldAtItsCommit — 09/1,
// контроль: вход стоит в З2, строку личности держит вставка при любом месте
// захвата.
func TestLoginOverlap_KN_OVL_09_1_DeletionWaitsForAnIssueHeldAtItsCommit(t *testing.T) {
	deletionHalf(t, pointCommit)
}

// TestLoginOverlap_KN_OVL_09_2_DeletionWaitsForAnIssueHeldBeforeItsInsert —
// 09/2: вход стоит в З4 — код потреблён, записи сессии нет. Держит «строка
// личности взята до вставки записи сессии».
func TestLoginOverlap_KN_OVL_09_2_DeletionWaitsForAnIssueHeldBeforeItsInsert(t *testing.T) {
	deletionHalf(t, pointInsert)
}

// TestLoginOverlap_KN_OVL_09_3_CaptureAfterTheDeletionMeetsNoRow — 09/3: вход
// стоит на входе в захват строки личности (З3); удаление идёт; исход захвата
// «строки нет» — тот же один отказ, клетка `no-row`. Держит «строка личности
// взята до записи фактора» и исход 3 Р4.
func TestLoginOverlap_KN_OVL_09_3_CaptureAfterTheDeletionMeetsNoRow(t *testing.T) {
	h := newOverlapLane(t)
	deadlocksBefore := h.deadlocksNow(t)
	var rounds []overlapDeletionRound
	for n := 1; n <= overlapDeletionRounds; n++ {
		q := h.seedMember(t)
		codes := h.enrolledFactor(t, q)
		gate := h.gates.arm(t, pointCapture)
		rd := overlapDeletionRound{n: n}
		rd.cells[0], rd.fp[0] = h.obs.snapshot(), h.footprint(t, q)
		call := h.startLogin(t, q, integrationPassword, codes[0])
		select {
		case <-gate.reached:
		case <-call.done:
			t.Fatalf("НЕ ВЫПОЛНИЛОСЬ: раунд %d — вход ответил %d, не войдя в З3: транзакция выдачи захвата "+
				"строки личности не зовёт (вызовов захвата %d), и сцены 09/3 на этом дереве нет",
				n, call.res.status, h.store.captureCalls.Load())
		case <-time.After(overlapSceneBudget):
			t.Fatalf("НЕ ВЫПОЛНИЛОСЬ: раунд %d — вход не дошёл до З3 и не ответил за %s", n, overlapSceneBudget)
		}
		del := h.startDelete(q)
		rd.first, rd.waiters = h.firstOf(t, "удаление Q", del.done)
		gate.lift()
		rd.login = call.await(t, "вход Q")
		rd.deleteErr = del.await(t)
		gate.requireLiftedByProbe(t)
		rd.cells[1], rd.fp[1] = h.obs.snapshot(), h.footprint(t, q)
		rd.users, rd.sessions, rd.methods = h.personGone(t, q)
		rounds = append(rounds, rd)
		t.Log(rd)
	}
	deadlocks := h.overlapDeadlocksAfterPoolClose(t) - deadlocksBefore
	t.Logf("раундов %d · pg_stat_database.deadlocks +%d", len(rounds), deadlocks)

	assert.Zero(t, deadlocks, "взаимных блокировок ноль: счётчик базы вырос на %d", deadlocks)
	for _, rd := range rounds {
		before, after := rd.cells[0], rd.cells[1]
		assert.NoError(t, rd.deleteErr, "раунд %d: удаление зафиксировано: %s", rd.n, rd)
		assert.Zero(t, rd.users+rd.sessions, "раунд %d: личности Q нет, записей сессии Q нет: %s", rd.n, rd)
		assert.Empty(t, oneRefusal(rd.login), "раунд %d: вход — тот же один отказ: %s", rd.n, rd)
		assert.Equal(t, 1, grew(before, after, cellNoRow), "раунд %d: клетка `no-row` выросла на один: %s", rd.n, rd)
		for _, cell := range []humansession.LoginOutcome{cellIssued, cellBeforeCutoff, cellStoreFailed} {
			assert.Zero(t, grew(before, after, cell), "раунд %d: клетка `%s` не меняется: %s", rd.n, cell, rd)
		}
		assert.Zero(t, rd.fp[1].issuedEvents-rd.fp[0].issuedEvents, "раунд %d: событий выдачи для Q не прибавилось", rd.n)
		assert.Equal(t, 1, rd.fp[1].failures-rd.fp[0].failures, "раунд %d: следов по адресу Q на один больше (исход `no-row`)", rd.n)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// KN-OVL-10

// TestLoginOverlap_KN_OVL_10_1_ACaptureThatDidNotAnswerClosesTheLoginNotPerformed
// — 10/1: захват строки личности не ответил — вход закрыт ответом «не
// выполнено» и ничего не пишет. Дельта против 01 — ответила ли операция захвата.
func TestLoginOverlap_KN_OVL_10_1_ACaptureThatDidNotAnswerClosesTheLoginNotPerformed(t *testing.T) {
	h := newOverlapLane(t)
	p := h.personP()
	h.forceLogoutDone(t, p)
	cutoff := h.requireCutoff(t, p)

	h.store.failCapture.Store(true)
	calls := h.store.captureCalls.Load()
	before := h.obs.snapshot()
	fpBefore := h.footprint(t, p)
	r := h.startLogin(t, p, integrationPassword, "").await(t, "вход P")
	after := h.obs.snapshot()
	fpAfter := h.footprint(t, p)
	captured := h.store.captureCalls.Load() - calls

	assert.Empty(t, notPerformed(r), "захват не ответил — вход закрыт «не выполнено»; вызовов захвата %d; %s",
		captured, h.issuedFacts(t, r, p, cutoff))
	assert.Equal(t, int32(1), captured, "обёртка отметила ровно один вызов захвата")
	assert.Zero(t, fpAfter.sessions-fpBefore.sessions, "входом ничего не записано: записей сессии не прибавилось")
	assert.Zero(t, fpAfter.issuedEvents-fpBefore.issuedEvents, "входом ничего не записано: событий выдачи не прибавилось")
	assert.Zero(t, fpAfter.failures-fpBefore.failures, "входом ничего не записано: следов не прибавилось")
	assert.Equal(t, 1, grew(before, after, cellStoreFailed), "клетка `store-failed` выросла на один")
	for _, cell := range []humansession.LoginOutcome{cellIssued, cellBeforeCutoff, cellMismatched} {
		assert.Zero(t, grew(before, after, cell), "клетка `%s` не меняется", cell)
	}
}

// TestLoginOverlap_KN_OVL_10_2_ACaptureThatDidNotAnswerLeavesTheCodeUnconsumed
// — 10/2: то же с кодом второго фактора; повтор при ответившем захвате выдаёт
// сессию и потребляет код ровно один раз.
func TestLoginOverlap_KN_OVL_10_2_ACaptureThatDidNotAnswerLeavesTheCodeUnconsumed(t *testing.T) {
	h := newOverlapLane(t)
	p := h.personP()
	codes := h.enrolledFactor(t, p)
	code := codes[0]
	h.forceLogoutDone(t, p)
	cutoff := h.requireCutoff(t, p)

	h.store.failCapture.Store(true)
	calls := h.store.captureCalls.Load()
	fpBefore := h.footprint(t, p)
	r := h.startLogin(t, p, integrationPassword, code).await(t, "вход P")
	fpAfter := h.footprint(t, p)
	captured := h.store.captureCalls.Load() - calls

	assert.Empty(t, notPerformed(r), "захват не ответил — вход закрыт «не выполнено»; вызовов захвата %d; %s",
		captured, h.issuedFacts(t, r, p, cutoff))
	assert.Equal(t, int32(1), captured, "обёртка отметила ровно один вызов захвата")
	assert.Zero(t, fpAfter.sessions-fpBefore.sessions, "входом ничего не записано: записей сессии не прибавилось")
	assert.Zero(t, fpAfter.issuedEvents-fpBefore.issuedEvents, "входом ничего не записано: событий выдачи не прибавилось")
	assert.Zero(t, fpAfter.failures-fpBefore.failures, "входом ничего не записано: следов не прибавилось")

	h.store.failCapture.Store(false)
	retry := h.startLogin(t, p, integrationPassword, code).await(t, "повторный вход P")
	if assert.Equal(t, http.StatusOK, retry.status, "повтор тем же кодом c при ответившем захвате обязан выдать сессию: %s", retry.body) {
		assert.Equal(t, passwordverify.BackupCodeCount-1, h.backupCodesRemaining(t, retry.bearer),
			"остаток набора на один меньше полного: код потреблён ровно один раз — повтором")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// KN-OVL-11

// TestLoginOverlap_KN_OVL_11_ExitCommittedWhileTheCaptureWaitsCoversTheLogin —
// выход фиксируется, пока захват ждёт замка: отсечка, прочитанная после
// захвата, накрывает вход. Дельта против 02 — когда выход зафиксирован
// относительно транзакции выдачи.
func TestLoginOverlap_KN_OVL_11_ExitCommittedWhileTheCaptureWaitsCoversTheLogin(t *testing.T) {
	h := newOverlapLane(t)
	p := h.personP()
	s0 := h.requireOnlyS0(t, p)
	before := h.obs.snapshot()

	gate := h.gates.arm(t, pointOpen)
	opens := h.store.opens()
	call := h.startLogin(t, p, integrationPassword, "")
	gate.awaitReached(t, "вход P")
	m := h.momentAtOpen(t, opens)
	exitGate := h.gates.arm(t, pointExitCommit)
	exit := h.startForceLogout(p)
	exitGate.awaitReached(t, "транзакция выхода")
	gate.lift()
	first, waiters := h.firstOf(t, "транзакция выдачи входа", call.done)
	exitGate.lift()
	r := call.await(t, "вход P")
	er := exit.await(t)
	gate.requireLiftedByProbe(t)
	exitGate.requireLiftedByProbe(t)
	h.requireCompleted(t, er)
	cutoff := h.requireCutoff(t, p)
	after := h.obs.snapshot()
	fp := h.footprint(t, p)
	t.Logf("первым пришло «%s» (ждущие замка: %v)", first, waiters)

	assert.Equal(t, eventWaitsOnLock, first,
		"транзакция выдачи входа обязана встать на замке выхода; первым пришло «вход ответил»: %s", h.issuedFacts(t, r, p, cutoff))
	assert.Empty(t, oneRefusal(r), "вход, чей момент не позже отсечки, обязан отказать тем же одним отказом: %s",
		h.issuedFacts(t, r, p, cutoff))
	assert.False(t, m.After(cutoff), "m=%s не позже T=%s", momentLabel(m), momentLabel(cutoff))
	rows := h.rowsOf(t, p)
	if assert.Len(t, rows, 1, "входом ничего не записано: у P одна запись — S0: %v", rows) {
		assert.Equal(t, s0.id, rows[0].id, "единственная запись — S0")
		assert.Equal(t, overlapForcedExitReason, rows[0].endedReason(), "S0 снята выходом: %s", rows[0])
	}
	assert.Zero(t, fp.issuedEvents, "событий `iam.session.issued` для P — ноль")
	assert.Zero(t, fp.failures, "следов неверного предъявления по адресу P — ноль")
	assert.Equal(t, 1, grew(before, after, cellBeforeCutoff), "клетка `before-cutoff` обязана вырасти на один")
	assert.Zero(t, grew(before, after, cellIssued), "клетка `issued` не меняется")
	assert.Zero(t, grew(before, after, cellMismatched), "клетка `mismatched` не меняется")
	assert.Equal(t, 1, h.sessionsEnded(t, p), "событие выхода несёт `sessions_ended = 1`")
}

// ─────────────────────────────────────────────────────────────────────────────
// KN-OVL-12

// TestLoginOverlap_KN_OVL_12_1_ASecondLoginDoesNotWaitForTheHeldCapture —
// 12/1: сила захвата не сильнее `FOR SHARE` — второй вход того же человека
// захвата первого не ждёт. Дельта против 12/2 — кто приходит к удерживаемому
// захвату.
func TestLoginOverlap_KN_OVL_12_1_ASecondLoginDoesNotWaitForTheHeldCapture(t *testing.T) {
	h := newOverlapLane(t)
	p := h.personP()
	h.requireOnlyS0(t, p)
	deadlocksBefore := h.deadlocksNow(t)
	before := h.obs.snapshot()

	gate := h.gates.arm(t, pointInsert)
	l1 := h.startLogin(t, p, integrationPassword, "")
	gate.awaitReached(t, "вход L1")
	l2 := h.startLogin(t, p, integrationPassword, "")
	first, waiters := h.firstOf(t, "транзакция выдачи L2", l2.done)
	gate.lift()
	r1 := l1.await(t, "вход L1")
	r2 := l2.await(t, "вход L2")
	gate.requireLiftedByProbe(t)
	after := h.obs.snapshot()
	rows := h.rowsOf(t, p)
	t.Logf("первым пришло «%s» (ждущие замка: %v); записи: %v", first, waiters, rows)
	deadlocks := h.overlapDeadlocksAfterPoolClose(t) - deadlocksBefore

	assert.Equal(t, eventFinished, first, "второй вход не ждёт захвата первого; первым пришло «L2 стоит на замке»: %v", waiters)
	assert.Equal(t, http.StatusOK, r2.status, "L2 отвечает 200 с сессией S2: %s", r2.body)
	assert.Equal(t, http.StatusOK, r1.status, "L1 отвечает 200 с сессией S1: %s", r1.body)
	live := 0
	for _, row := range rows {
		if row.live() {
			live++
		}
	}
	assert.Equal(t, 3, live, "S0, S1 и S2 живы: %v", rows)
	assert.Equal(t, 2, grew(before, after, cellIssued), "клетка `issued` выросла на два")
	assert.Zero(t, deadlocks, "взаимных блокировок ноль")
}

// TestLoginOverlap_KN_OVL_12_2_TheExitWaitsForTheHeldCaptureAndEndsTheIssue —
// 12/2: сила захвата не слабее замка снятия — выход ждёт вход, стоящий в З4, и
// снимает выданное. Дельта против 03 — вход стоит до вставки записи сессии.
func TestLoginOverlap_KN_OVL_12_2_TheExitWaitsForTheHeldCaptureAndEndsTheIssue(t *testing.T) {
	h := newOverlapLane(t)
	p := h.personP()
	h.requireOnlyS0(t, p)

	gate := h.gates.arm(t, pointInsert)
	l1 := h.startLogin(t, p, integrationPassword, "")
	gate.awaitReached(t, "вход L1")
	exit := h.startForceLogout(p)
	first, waiters := h.firstOf(t, "транзакция выхода", exit.done)
	gate.lift()
	r1 := l1.await(t, "вход L1")
	er := exit.await(t)
	gate.requireLiftedByProbe(t)
	h.requireCompleted(t, er)
	cutoff := h.requireCutoff(t, p)
	t.Logf("первым пришло «%s» (ждущие замка: %v)", first, waiters)

	assert.Equal(t, eventWaitsOnLock, first,
		"транзакция выхода обязана встать на захвате входа, стоящего в З4; первым пришло «выход завершён»: %s",
		h.issuedFacts(t, r1, p, cutoff))
	require.Equal(t, http.StatusOK, r1.status, "L1 отвечает 200 с сессией S1: %s", r1.body)
	assert.Greater(t, er.seq, h.store.committing.Load(), "выход обязан завершиться после фиксации выдачи")
	row, ok := h.rowOfBearer(t, r1.bearer)
	require.True(t, ok, "запись S1 по носителю есть")
	assert.Equal(t, overlapForcedExitReason, row.endedReason(), "S1 снята выходом: %s; T=%s", row, momentLabel(cutoff))
	if assert.NotNil(t, row.endedAt, "S1 снята: %s", row) {
		assert.True(t, row.endedAt.Equal(cutoff), "ended_at(S1)=%s обязан равняться T=%s", momentLabel(*row.endedAt), momentLabel(cutoff))
	}
	assert.Equal(t, 2, h.sessionsEnded(t, p), "событие выхода несёт `sessions_ended = 2` (S0 и S1)")
}
