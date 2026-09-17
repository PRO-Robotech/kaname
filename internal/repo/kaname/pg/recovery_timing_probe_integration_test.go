// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// recovery_timing_probe_integration_test.go — ИЗМЕРИТЕЛЬНАЯ проба Ф5-20…22:
// критерий Ф1-48 на полосе восстановления (Ф1-51, Ф5 Р2, Р7).
//
// # Что меряется
//
// Две полосы обращений к запросу кода, чередуясь по кругу (Ф1-48: чередование,
// а не блоками — иначе дрейф стенда лёг бы на одну полосу): «адрес подтверждён»
// (как Ф5-01) и «адрес не принадлежит никому» (как Ф5-02). У первой есть шаг,
// которого у второй нет, — чеканка кода и постановка письма, — и Р2 требует,
// чтобы ответ его НЕ ждал: постановка идёт диспетчером вне пути ответа. Проба
// идёт на НАСТОЯЩЕЙ базе: стоимость, которую Р2 выносит за измеряемый участок,
// — запись двух строк одной транзакцией, а не работа процессора.
//
// Критерий Ф1-48: |медиана₁ − медиана₂| ≤ max(IQR₁, IQR₂). Печатаются медианы,
// размахи, N на полосу, потолок годности, нижняя граница и сам критерий.
//
// # Три величины Ф1 §3.9 — выведены прогоном, не назначены
//
//   - ВНЕСЁННОЕ РАЗЛИЧИЕ (Ф5-21) — ровно то, что Р2 запрещает: постановка письма
//     синхронно, на пути ответа. Это и есть «порядка стоимости чеканки кода и
//     не больше»: ни одной лишней микросекунды сверх настоящей работы;
//   - ПОТОЛОК ГОДНОСТИ (Ф5-22) — самоограничен: годен тот потолок, при котором
//     внесённое различие краснеет; здесь он равен медианной стоимости
//     синхронной чеканки с постановкой, измеренной тем же прогоном;
//   - НИЖНЯЯ ГРАНИЦА обращений — 10 (Ф1-48), прогон берёт больше.
//
// # Три исхода
//
// Зелёный — критерий выполнен и инъекция красна. Красный — критерий нарушен на
// честном прогоне: полоса названа. «Не выполнилось» — размах любой полосы выше
// потолка (стенд шумит сильнее измеряемого) либо инъекция не покраснела
// (потолок негоден by construction) — вердикта нет ни в одну сторону (Ф1-50).
//
// # Почему ручной прогон
//
// На общем ранере размах превышает потолок годности by construction: постановка
// строки стоит доли миллисекунды, а шум соседних проб — миллисекунды. Прогон —
// ручкой, как у соседних измерительных приборов:
//
//	KACHO_RECOVERY_TIMING=1 go test ./internal/repo/kaname/pg/ -run TestRecovery_F5_20 -count=1 -v -timeout 30m
package pg_test

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

const (
	recoveryTimingEnv        = "KACHO_RECOVERY_TIMING"
	recoveryTimingRunCommand = "KACHO_RECOVERY_TIMING=1 go test ./internal/repo/kaname/pg/ " +
		"-run TestRecovery_F5_20 -count=1 -v -timeout 30m"
	// recoveryTimingLaneN — обращений на полосу; нижняя граница Ф1-48 — 10.
	recoveryTimingLaneN = 40
	recoveryTimingFloor = 10
	// recoveryTimingCostSamples — сколько раз меряется стоимость синхронной
	// чеканки с постановкой: из них выводятся и внесённое различие, и потолок.
	recoveryTimingCostSamples = 15
)

type recoveryLane struct {
	name    string
	email   string
	samples []time.Duration
}

func (l *recoveryLane) stats() (median, iqr time.Duration) {
	s := append([]time.Duration(nil), l.samples...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	q := func(p float64) time.Duration { return s[int(float64(len(s)-1)*p)] }
	return q(0.5), q(0.75) - q(0.25)
}

func medianOf(ds []time.Duration) time.Duration {
	s := append([]time.Duration(nil), ds...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[len(s)/2]
}

func newRequestUC(t *testing.T, repo *pg.HumanSessionRepo, d humansession.Dispatcher, obs humansession.Observer) *humansession.RequestRecoveryUseCase {
	t.Helper()
	uc, err := humansession.NewRequestRecoveryUseCase(humansession.RequestRecoveryDeps{
		Store: repo, CodeTTL: rcTTL, Dispatcher: d, Observer: obs, Now: time.Now, Logger: slog.New(slog.DiscardHandler),
	})
	require.NoError(t, err)
	return uc
}

// runRecoveryLanes — чередующийся прогон двух полос; возвращает медианы и
// размахи и вердикт критерия (пусто — выполнен, иначе — какая полоса быстрее и
// на сколько).
func runRecoveryLanes(t *testing.T, uc *humansession.RequestRecoveryUseCase, lanes []*recoveryLane) (verdict string, rows []string, maxIQR time.Duration) {
	t.Helper()
	ctx := context.Background()
	for _, l := range lanes { // прогрев, в замер не идёт
		_ = uc.Execute(ctx, humansession.RequestRecoveryInput{Email: l.email, Source: "203.0.113.20"})
	}
	for i := 0; i < recoveryTimingLaneN; i++ {
		for _, l := range lanes {
			start := time.Now()
			err := uc.Execute(ctx, humansession.RequestRecoveryInput{Email: l.email, Source: "203.0.113.20"})
			l.samples = append(l.samples, time.Since(start))
			require.NoError(t, err, "полоса %s: запрос кода отказом не отвечает", l.name)
		}
	}
	type row struct {
		lane        *recoveryLane
		median, iqr time.Duration
	}
	var rs []row
	for _, l := range lanes {
		m, q := l.stats()
		rs = append(rs, row{l, m, q})
		rows = append(rows, fmt.Sprintf("полоса %-24s медиана %10v · IQR %10v · n=%d", l.name, m, q, len(l.samples)))
		if q > maxIQR {
			maxIQR = q
		}
	}
	diff := rs[0].median - rs[1].median
	faster, slower := rs[1], rs[0]
	if diff < 0 {
		diff, faster, slower = -diff, rs[0], rs[1]
	}
	rows = append(rows, fmt.Sprintf("критерий Ф1-48: |Δмедиан| %v ≤ max(IQR) %v", diff, maxIQR))
	if diff > maxIQR {
		verdict = fmt.Sprintf("полоса %q быстрее полосы %q на %v при размахе %v", faster.lane.name, slower.lane.name, diff, maxIQR)
	}
	return verdict, rows, maxIQR
}

// TestRecovery_F5_20_21_22_RequestTimeIsIndistinguishableAndTheInjectionIsRed —
// Ф5-20: критерий на честном прогоне; Ф5-21: инъекция (постановка на пути
// ответа) — красное, называющее полосу и разницу; Ф5-22: размах выше потолка
// либо не покрасневшая инъекция — «не выполнилось».
func TestRecovery_F5_20_21_22_RequestTimeIsIndistinguishableAndTheInjectionIsRed(t *testing.T) {
	if os.Getenv(recoveryTimingEnv) == "" {
		t.Skipf("измерительная проба Ф5-20…22 идёт РУЧНЫМ прогоном: %s", recoveryTimingRunCommand)
	}
	pool := hsPool(t)
	repo := pg.NewHumanSessionRepo(pool)
	ctx := context.Background()
	people := lmPeople(t, pool, "rct", 1)
	_, err := pool.Exec(ctx, `UPDATE users SET email_verified_at = now() WHERE id = $1`, string(people[0]))
	require.NoError(t, err)
	obs := &recoveryTimingObserver{}

	// Стоимость синхронной чеканки с постановкой — из неё выводятся и внесённое
	// различие, и потолок годности (Ф1-49, Ф1-50).
	sync := newRequestUC(t, repo, humansession.SyncDispatcher{}, obs)
	var costs []time.Duration
	for i := 0; i < recoveryTimingCostSamples; i++ {
		start := time.Now()
		require.NoError(t, sync.Execute(ctx, humansession.RequestRecoveryInput{Email: "rct-00@example.invalid", Source: "203.0.113.20"}))
		costs = append(costs, time.Since(start))
	}
	nobodyUC := newRequestUC(t, repo, humansession.SyncDispatcher{}, obs)
	var bases []time.Duration
	for i := 0; i < recoveryTimingCostSamples; i++ {
		start := time.Now()
		require.NoError(t, nobodyUC.Execute(ctx, humansession.RequestRecoveryInput{Email: "nobody-rct@example.invalid", Source: "203.0.113.20"}))
		bases = append(bases, time.Since(start))
	}
	ceiling := medianOf(costs) - medianOf(bases)
	if ceiling <= 0 {
		ceiling = medianOf(costs)
	}
	t.Logf("внесённое различие Ф5-21 = постановка на пути ответа; его стоимость (медиана, %d замеров): %v; "+
		"потолок годности Ф5-22 = та же величина; нижняя граница N — %d; обращений на полосу — %d",
		recoveryTimingCostSamples, ceiling, recoveryTimingFloor, recoveryTimingLaneN)
	require.GreaterOrEqual(t, recoveryTimingLaneN, recoveryTimingFloor)

	// Честный прогон: постановка — диспетчером вне пути ответа (Р2).
	dispatcher := humansession.NewGoDispatcher(30 * time.Second)
	defer dispatcher.Wait()
	honest := newRequestUC(t, repo, dispatcher, obs)
	lanes := []*recoveryLane{
		{name: "адрес подтверждён", email: "rct-00@example.invalid"},
		{name: "адреса нет", email: "nobody-rct@example.invalid"},
	}
	verdict, rows, maxIQR := runRecoveryLanes(t, honest, lanes)
	for _, r := range rows {
		t.Log(r)
	}
	if maxIQR > ceiling {
		t.Fatalf("НЕ ВЫПОЛНИЛОСЬ (Ф5-22, Ф1-50): размах %v выше потолка годности %v — стенд шумит сильнее измеряемого, вердикта нет",
			maxIQR, ceiling)
	}
	require.Zero(t, obs.rateLimited, "Ф5-20: ни одно обращение не получило отказа по частоте")

	// Инъекция Ф5-21: та же проба, постановка синхронно — красное с именем полосы.
	injected := []*recoveryLane{
		{name: "адрес подтверждён (инъекция)", email: "rct-00@example.invalid"},
		{name: "адреса нет", email: "nobody-rct@example.invalid"},
	}
	injVerdict, injRows, injIQR := runRecoveryLanes(t, sync, injected)
	for _, r := range injRows {
		t.Log(r)
	}
	if injIQR > ceiling {
		t.Fatalf("НЕ ВЫПОЛНИЛОСЬ (Ф5-22): размах инъекционного прогона %v выше потолка %v", injIQR, ceiling)
	}
	if injVerdict == "" {
		t.Fatalf("НЕ ВЫПОЛНИЛОСЬ (Ф5-22): инъекция Ф5-21 не покраснела — потолок годности не различает внесённого различия, вердикт честного прогона беспредметен")
	}
	t.Logf("Ф5-21 КРАСНОЕ (положительный контроль): %s", injVerdict)

	require.Empty(t, verdict, "Ф5-20 / Ф1-51 нарушен: %s — время ответа различает, принадлежит ли адрес кому-нибудь", verdict)
}

// recoveryTimingObserver — считает только то, что нужно вердикту пробы.
type recoveryTimingObserver struct {
	humansession.NopObserver
	rateLimited int
}

func (o *recoveryTimingObserver) RateLimitObserved(humansession.FailureScope) { o.rateLimited++ }
