// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// recovery_timing_probe_integration_test.go — ИЗМЕРИТЕЛЬНАЯ проба Ф5-20…22 и
// последнего «И» Ф5-29: критерий Ф1-48 на полосе восстановления (Ф1-51, Ф5 Р2,
// Р7, Р9 п. 2).
//
// # Что меряется
//
// Три полосы обращений к запросу кода, чередуясь по кругу (Ф1-48: чередование,
// а не блоками — иначе дрейф стенда лёг бы на одну полосу): «адрес подтверждён»
// (как Ф5-01), «A» — личность `ACTIVE` без пароля с неподтверждённым адресом
// (Ф5-29, посевом §5.5 (6)) и «Z» — адрес, не принадлежащий никому (как Ф5-02).
// Критерий судится парами: «адрес подтверждён» против «Z» — Ф5-20, «A» против
// «Z» — Ф5-29. У полос с кодом есть шаг, которого у «Z» нет, — чеканка кода и
// постановка письма, — и Р2 требует, чтобы ответ его НЕ ждал: постановка идёт
// диспетчером вне пути ответа. Проба идёт на НАСТОЯЩЕЙ базе: стоимость, которую
// Р2 выносит за измеряемый участок, — запись двух строк одной транзакцией, а не
// работа процессора.
//
// Критерий Ф1-48 на паре: |медиана₁ − медиана₂| ≤ max(IQR₁, IQR₂). Печатаются
// медианы, размахи, N на полосу, потолок годности, нижняя граница, величины
// окон запроса кода (Р8) и сам критерий по каждой паре.
//
// # Три величины Ф1 §3.9 — выведены прогоном, не назначены
//
//   - ВНЕСЁННОЕ РАЗЛИЧИЕ (Ф5-21) — ровно то, что Р2 запрещает: постановка письма
//     синхронно, на пути ответа, в ОДНОЙ полосе. Это и есть «порядка стоимости
//     чеканки кода и не больше»: ни одной лишней микросекунды сверх настоящей
//     работы. Вносится по очереди в каждую из трёх полос («Z» получает на путь
//     ответа ту же работу приманки) и в окружении честного прогона: прочие
//     полосы с кодом ставят работу диспетчером, и их фоновая чеканка идёт, как
//     шла бы при дефекте продукта в одной полосе. Контроль, убравший этот фон
//     (постановка синхронно во всех полосах), был бы слабее настоящего дефекта:
//     фон раздувает размах дефектной полосы, и дефект прошёл бы зелёным;
//   - ПОТОЛОК ГОДНОСТИ (Ф5-22) — самоограничен: годен тот потолок, при котором
//     внесённое различие краснеет; здесь он равен медианной стоимости
//     синхронной чеканки с постановкой, измеренной тем же прогоном;
//   - НИЖНЯЯ ГРАНИЦА обращений — 10 (Ф1-48), прогон берёт больше.
//
// # Три исхода
//
// Зелёный — критерий выполнен на обеих парах честного прогона и каждая
// однополосная инъекция красна на паре своей полосы, называя её медленной.
// Красный — критерий нарушен на честном прогоне: пара и полоса названы;
// судится сразу после честного прогона — различие, превысившее размах, уже
// обнаружение, контроль нужен только зелёному. «Не выполнилось» — размах любой
// полосы выше потолка (стенд шумит сильнее измеряемого), инъекция не
// покраснела хоть на одной паре своей полосы (потолок негоден by construction)
// либо хоть одно обращение получило отказ по частоте (Ф5-08: полоса мерила бы
// предел частоты) — вердикта нет ни в одну сторону (Ф1-50).
// Отказ по частоте у запроса кода — исход `source-paced` или `recipient-paced`
// счётчика исходов запроса (`RecoveryRequestObserved`); общий счётчик отказов
// по частоте (`RateLimitObserved`) запрос кода не зовёт, и судить по нему
// значило бы судить по величине, которая не бывает ненулевой.
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
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
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
	recoveryTimingSource      = "203.0.113.20"
)

// Окна запроса кода (Р8) — больше числа обращений пробы (Ф5-29 «Дано»): окно,
// которое прогон способен заполнить, сделало бы полосу мерилом предела частоты.
var (
	recoveryTimingSourcePace = humansession.SourcePace{Limit: 100000, Window: time.Hour}
	recoveryTimingMailLimit  = outboxtypes.InviteMailRateLimit{MaxPerWindow: 100000, Window: time.Hour}
)

type recoveryLane struct {
	// tag — метка полосы в контексте запроса: по ней диспетчер прогона узнаёт
	// полосу, в которую внесён дефект.
	tag   string
	name  string
	email string
	// after — работа на пути ответа ПОСЛЕ глагола: однополосный дефект полосы
	// «Z» (у неё нет работы вне пути ответа, которую можно было бы втянуть на
	// путь); у прочих прогонов пуста.
	after   func(ctx context.Context)
	samples []time.Duration
}

func (l *recoveryLane) stats() (median, iqr time.Duration) {
	s := append([]time.Duration(nil), l.samples...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	q := func(p float64) time.Duration { return s[int(float64(len(s)-1)*p)] }
	return q(0.5), q(0.75) - q(0.25)
}

// recoveryPair — пара полос, которую судит критерий: полоса с кодом против
// полосы, где адреса нет; scenario — чью часть «Тогда» пара несёт.
type recoveryPair struct {
	scenario string
	coded    *recoveryLane
	nobody   *recoveryLane
}

// pairVerdict — исход критерия на паре: red — неравенство нарушено, slower —
// медленная полоса пары, text — строка красного (пуста, если критерий выполнен).
type pairVerdict struct {
	pair   recoveryPair
	red    bool
	slower *recoveryLane
	text   string
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
		Sources: repo, SourcePace: recoveryTimingSourcePace, MailLimit: recoveryTimingMailLimit,
	})
	require.NoError(t, err)
	return uc
}

// laneTagKey — ключ метки полосы в контексте запроса.
type laneTagKey struct{}

// laneDispatcher — диспетчер прогона. Работа полосы syncLane исполняется на
// пути ответа — однополосная инъекция Ф5-21; работа прочих полос идёт тем же
// диспетчером, что у честного прогона, и их фоновая чеканка остаётся на месте.
// У честного прогона syncLane пуст: диспетчер — тот же GoDispatcher, и прогоны
// различаются ровно одним фактом — путём работы одной полосы.
type laneDispatcher struct {
	inner    humansession.Dispatcher
	syncLane string
}

func (d laneDispatcher) Dispatch(reqCtx context.Context, work func(ctx context.Context)) {
	if tag, _ := reqCtx.Value(laneTagKey{}).(string); d.syncLane != "" && tag == d.syncLane {
		work(reqCtx)
		return
	}
	d.inner.Dispatch(reqCtx, work)
}

// captureDispatcher — берёт работу, не исполняя: так проба получает ровно ту
// работу, которую глагол ставит полосе с кодом (чеканка, вытеснение, строка
// кода и намерение письма), без чтения адреса и окна источника. Её стоимость —
// внесённое различие полосы «Z», той же величины, что у полос с кодом.
type captureDispatcher struct{ work func(ctx context.Context) }

func (c *captureDispatcher) Dispatch(_ context.Context, work func(ctx context.Context)) {
	c.work = work
}

// runRecoveryLanes — чередующийся прогон полос; возвращает исход критерия по
// каждой паре, строки печати и наибольший размах.
func runRecoveryLanes(t *testing.T, uc *humansession.RequestRecoveryUseCase, lanes []*recoveryLane, pairs []recoveryPair) (verdicts []pairVerdict, rows []string, maxIQR time.Duration) {
	t.Helper()
	call := func(l *recoveryLane) error {
		ctx := context.WithValue(context.Background(), laneTagKey{}, l.tag)
		err := uc.Execute(ctx, humansession.RequestRecoveryInput{Email: l.email, Source: recoveryTimingSource})
		if err == nil && l.after != nil {
			l.after(ctx)
		}
		return err
	}
	for _, l := range lanes { // прогрев, в замер не идёт
		_ = call(l)
	}
	for i := 0; i < recoveryTimingLaneN; i++ {
		for _, l := range lanes {
			start := time.Now()
			err := call(l)
			l.samples = append(l.samples, time.Since(start))
			require.NoError(t, err, "полоса %s: запрос кода отказом не отвечает", l.name)
		}
	}
	type stat struct{ median, iqr time.Duration }
	st := map[*recoveryLane]stat{}
	for _, l := range lanes {
		m, q := l.stats()
		st[l] = stat{m, q}
		rows = append(rows, fmt.Sprintf("полоса %-50s медиана %10v · IQR %10v · n=%d", l.name, m, q, len(l.samples)))
		if q > maxIQR {
			maxIQR = q
		}
	}
	for _, p := range pairs {
		a, b := st[p.coded], st[p.nobody]
		pairIQR := max(a.iqr, b.iqr)
		diff := a.median - b.median
		faster, slower := p.nobody, p.coded
		if diff < 0 {
			diff, faster, slower = -diff, p.coded, p.nobody
		}
		// Строка печатает исход сравнения, а не формулу: на инъекции «≤» стоял бы
		// под нарушенным неравенством.
		holds, rel := "выполнен", "≤"
		if diff > pairIQR {
			holds, rel = "НАРУШЕН", ">"
		}
		rows = append(rows, fmt.Sprintf("критерий Ф1-48 (%s, %q ↔ %q): |Δмедиан| %v %s max(IQR) %v — %s",
			p.scenario, p.coded.name, p.nobody.name, diff, rel, pairIQR, holds))
		v := pairVerdict{pair: p, red: diff > pairIQR, slower: slower}
		if v.red {
			v.text = fmt.Sprintf("%s: полоса %q быстрее полосы %q на %v при размахе %v",
				p.scenario, faster.name, slower.name, diff, pairIQR)
		}
		verdicts = append(verdicts, v)
	}
	return verdicts, rows, maxIQR
}

// TestRecovery_F5_20_21_22_RequestTimeIsIndistinguishableAndTheInjectionIsRed —
// Ф5-20 и последнее «И» Ф5-29: критерий на честном прогоне по паре «адрес
// подтверждён» / «Z» и паре «A» / «Z»; Ф5-21: однополосная инъекция в каждую
// из трёх полос в окружении честного прогона — красное на паре этой полосы,
// называющее её медленной; Ф5-22: размах выше потолка, не покрасневшая
// инъекция либо отказ по частоте — «не выполнилось».
func TestRecovery_F5_20_21_22_RequestTimeIsIndistinguishableAndTheInjectionIsRed(t *testing.T) {
	if os.Getenv(recoveryTimingEnv) == "" {
		t.Skipf("измерительная проба Ф5-20…22 идёт РУЧНЫМ прогоном: %s", recoveryTimingRunCommand)
	}
	pool := hsPool(t)
	repo := pg.NewHumanSessionRepo(pool)
	ctx := context.Background()
	// Посев: три личности — `ACTIVE`, без строки пароля, адрес не подтверждён,
	// путь открыт (форма «после переноса», §5.5 (6)). Первой ставится отметка
	// подтверждения — полоса «адрес подтверждён»; вторая остаётся «A»; третья,
	// подтверждённая, — приманка однополосного дефекта полосы «Z»: в замер как
	// полоса не идёт.
	people := lmPeople(t, pool, "rct", 3)
	_, err := pool.Exec(ctx, `UPDATE users SET email_verified_at = now() WHERE id = ANY($1)`,
		[]string{string(people[0]), string(people[2])})
	require.NoError(t, err, "НЕ ВЫПОЛНИЛОСЬ (фикстура): отметка подтверждения адреса")
	type world struct {
		passwords int
		verified  bool
		status    string
	}
	worldOf := func(id string) world {
		var w world
		require.NoError(t, pool.QueryRow(ctx, `
			SELECT (SELECT count(*) FROM user_login_methods WHERE user_id = u.id AND kind = 'password'),
			       u.email_verified_at IS NOT NULL, u.invite_status
			  FROM users u WHERE u.id = $1`, id).Scan(&w.passwords, &w.verified, &w.status))
		return w
	}
	require.Equal(t, world{passwords: 0, verified: true, status: "ACTIVE"}, worldOf(string(people[0])),
		"НЕ ВЫПОЛНИЛОСЬ (фикстура): «Дано» полосы «адрес подтверждён» (Ф5-01) не построено")
	require.Equal(t, world{passwords: 0, verified: false, status: "ACTIVE"}, worldOf(string(people[1])),
		"НЕ ВЫПОЛНИЛОСЬ (фикстура): «Дано» полосы «A» (Ф5-29: ACTIVE, без пароля, адрес не подтверждён) не построено")
	require.Equal(t, world{passwords: 0, verified: true, status: "ACTIVE"}, worldOf(string(people[2])),
		"НЕ ВЫПОЛНИЛОСЬ (фикстура): приманка дефекта полосы «Z» не построена")
	const (
		verifiedEmail = "rct-00@example.invalid"
		wayInEmail    = "rct-01@example.invalid"
		decoyEmail    = "rct-02@example.invalid"
		nobodyEmail   = "nobody-rct@example.invalid"
	)

	// Стоимость синхронной чеканки с постановкой — из неё выводится потолок
	// годности (Ф1-49, Ф1-50).
	costObs := newRecoveryTimingObserver()
	syncUC := newRequestUC(t, repo, humansession.SyncDispatcher{}, costObs)
	var costs []time.Duration
	for i := 0; i < recoveryTimingCostSamples; i++ {
		start := time.Now()
		require.NoError(t, syncUC.Execute(ctx, humansession.RequestRecoveryInput{Email: verifiedEmail, Source: recoveryTimingSource}))
		costs = append(costs, time.Since(start))
	}
	var bases []time.Duration
	for i := 0; i < recoveryTimingCostSamples; i++ {
		start := time.Now()
		require.NoError(t, syncUC.Execute(ctx, humansession.RequestRecoveryInput{Email: nobodyEmail, Source: recoveryTimingSource}))
		bases = append(bases, time.Since(start))
	}
	ceiling := medianOf(costs) - medianOf(bases)
	if ceiling <= 0 {
		ceiling = medianOf(costs)
	}
	t.Logf("внесённое различие Ф5-21 = постановка на пути ответа ОДНОЙ полосы; её стоимость (медиана, %d замеров): %v; "+
		"потолок годности Ф5-22 = та же величина; нижняя граница N — %d; обращений на полосу — %d",
		recoveryTimingCostSamples, ceiling, recoveryTimingFloor, recoveryTimingLaneN)
	t.Logf("окна запроса кода (Р8): источник — %d за %v; письма адресата — %d за %v; обращений пробы — %d",
		recoveryTimingSourcePace.Limit, recoveryTimingSourcePace.Window,
		recoveryTimingMailLimit.MaxPerWindow, recoveryTimingMailLimit.Window,
		2*recoveryTimingCostSamples+1+4*3*(recoveryTimingLaneN+1))
	require.GreaterOrEqual(t, recoveryTimingLaneN, recoveryTimingFloor)
	costObs.mustBeExecuted(t, "замер стоимости")

	type laneRun struct {
		verdicts []pairVerdict
		maxIQR   time.Duration
	}
	// run — прогон трёх полос, чередующихся по кругу, через диспетчер прогона:
	// defect — метка полосы, чья работа идёт на пути ответа (пусто — честный
	// прогон), zAfter — дефект полосы «Z». Окружение у всех прогонов одно:
	// полосы с кодом вне дефекта ставят работу GoDispatcher-ом, как в честном.
	run := func(label, defect string, zAfter func(ctx context.Context)) laneRun {
		obs := newRecoveryTimingObserver()
		inner := humansession.NewGoDispatcher(30 * time.Second)
		t.Cleanup(inner.Wait)
		uc := newRequestUC(t, repo, laneDispatcher{inner: inner, syncLane: defect}, obs)
		v := &recoveryLane{tag: "V", name: "адрес подтверждён", email: verifiedEmail}
		a := &recoveryLane{tag: "A", name: "A: без пароля, адрес не подтверждён", email: wayInEmail}
		z := &recoveryLane{tag: "Z", name: "Z: адреса нет", email: nobodyEmail, after: zAfter}
		for _, l := range []*recoveryLane{v, a, z} {
			if l.tag == defect {
				l.name += " (дефект)"
			}
		}
		verdicts, rows, maxIQR := runRecoveryLanes(t, uc, []*recoveryLane{v, a, z},
			[]recoveryPair{{"Ф5-20", v, z}, {"Ф5-29", a, z}})
		inner.Wait() // работа вне пути ответа досчитана до суда по исходам
		for _, r := range rows {
			t.Logf("%s · %s", label, r)
		}
		obs.mustBeExecuted(t, label)
		obs.mustHaveQueued(t, label, 2*(recoveryTimingLaneN+1), recoveryTimingLaneN+1)
		return laneRun{verdicts: verdicts, maxIQR: maxIQR}
	}

	// Честный прогон: постановка — диспетчером вне пути ответа (Р2). Красное
	// судится сразу: различие, превысившее размах честного прогона, — уже
	// обнаружение, и контроль для него не нужен; контроль нужен зелёному.
	honest := run("честный прогон", "", nil)
	if honest.maxIQR > ceiling {
		t.Fatalf("НЕ ВЫПОЛНИЛОСЬ (Ф5-22, Ф1-50): размах %v выше потолка годности %v — стенд шумит сильнее измеряемого, вердикта нет",
			honest.maxIQR, ceiling)
	}
	var broken []string
	for _, v := range honest.verdicts {
		if v.red {
			broken = append(broken, v.text)
		}
	}
	require.Empty(t, broken, "Ф5-20 / Ф5-29 / Ф1-51 нарушен — время ответа различает, принадлежит ли адрес кому-нибудь: %s",
		strings.Join(broken, "; "))

	// Инъекция Ф5-21 — в ОДНУ полосу, по очереди в каждую, в окружении честного
	// прогона: фоновая чеканка прочих полос с кодом идёт, как шла бы при дефекте
	// продукта в одной полосе. Красное обязано стоять на каждой паре дефектной
	// полосы и называть её медленной.
	capture := &captureDispatcher{}
	decoyObs := newRecoveryTimingObserver()
	require.NoError(t, newRequestUC(t, repo, capture, decoyObs).Execute(ctx,
		humansession.RequestRecoveryInput{Email: decoyEmail, Source: recoveryTimingSource}))
	require.NotNil(t, capture.work, "НЕ ВЫПОЛНИЛОСЬ (фикстура): глагол не поставил работы приманке — дефекта полосы «Z» не внести")
	controls := []struct {
		defect    string
		after     func(ctx context.Context)
		scenarios []string
	}{
		{"V", nil, []string{"Ф5-20"}},
		{"A", nil, []string{"Ф5-29"}},
		{"Z", capture.work, []string{"Ф5-20", "Ф5-29"}},
	}
	for _, c := range controls {
		label := "инъекция Ф5-21 в полосу " + c.defect
		r := run(label, c.defect, c.after)
		if r.maxIQR > ceiling {
			t.Fatalf("НЕ ВЫПОЛНИЛОСЬ (Ф5-22): %s — размах %v выше потолка %v", label, r.maxIQR, ceiling)
		}
		for _, v := range r.verdicts {
			if !slices.Contains(c.scenarios, v.pair.scenario) {
				continue
			}
			if !v.red || v.slower.tag != c.defect {
				t.Fatalf("НЕ ВЫПОЛНИЛОСЬ (Ф5-22): %s не покраснела на паре %s с этой полосой медленной — "+
					"потолок годности не различает однополосного дефекта, вердикт честного прогона беспредметен", label, v.pair.scenario)
			}
			t.Logf("Ф5-21 КРАСНОЕ (положительный контроль, полоса %s): %s", c.defect, v.text)
		}
	}
	decoyObs.mustBeExecuted(t, "приманка дефекта полосы «Z»")
	require.Equal(t, recoveryTimingLaneN+1, decoyObs.count(humansession.RecoveryRequestQueued),
		"НЕ ВЫПОЛНИЛОСЬ (условие): приманка — работ на пути ответа полосы «Z» не столько, сколько её обращений")
}

// recoveryTimingObserver — считает исходы запроса кода: из них судится, не
// получило ли обращение отказа по частоте (Ф5-08) и шла ли полоса тем путём,
// который проба меряет. Работа вне пути ответа досчитывает исходы из своей
// горутины — отсюда замок.
type recoveryTimingObserver struct {
	humansession.NopObserver
	mu       sync.Mutex
	outcomes map[humansession.RecoveryRequestOutcome]int
}

func newRecoveryTimingObserver() *recoveryTimingObserver {
	return &recoveryTimingObserver{outcomes: map[humansession.RecoveryRequestOutcome]int{}}
}

func (o *recoveryTimingObserver) RecoveryRequestObserved(outcome humansession.RecoveryRequestOutcome) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.outcomes[outcome]++
}

func (o *recoveryTimingObserver) count(outcome humansession.RecoveryRequestOutcome) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.outcomes[outcome]
}

// notExecuted — исход «не выполнилось» по счёту исходов, пустая строка — счёт
// прогону не мешает. Отказ по частоте — «не выполнилось» с меткой Ф5-20, а не
// нарушение критерия (Ф5-20, последнее «И»); отказ хранилища и непринятая
// работа вне пути ответа — тоже: полоса мерила бы не ту работу.
func (o *recoveryTimingObserver) notExecuted(phase string) string {
	source, recipient := o.count(humansession.RecoveryRequestSourcePaced), o.count(humansession.RecoveryRequestRecipientPaced)
	if source+recipient > 0 {
		return fmt.Sprintf("НЕ ВЫПОЛНИЛОСЬ (Ф5-20, Ф5-08): %s — отказов по частоте %d (окно источника %d, окно писем адресата %d); "+
			"полоса мерила бы предел частоты, вердикта нет", phase, source+recipient, source, recipient)
	}
	store, dropped := o.count(humansession.RecoveryRequestStoreFailed), o.count(humansession.RecoveryRequestDispatchDropped)
	if store+dropped > 0 {
		return fmt.Sprintf("НЕ ВЫПОЛНИЛОСЬ (Ф5-20, условие): %s — отказов хранилища %d, непринятых работ вне пути ответа %d; "+
			"полоса мерила бы не ту работу, вердикта нет", phase, store, dropped)
	}
	return ""
}

func (o *recoveryTimingObserver) mustBeExecuted(t *testing.T, phase string) {
	t.Helper()
	if msg := o.notExecuted(phase); msg != "" {
		t.Fatal(msg)
	}
}

// mustHaveQueued — постусловие «наблюдатель прочитан продуктом» и «Дано» полос:
// код выдан каждому обращению полос «адрес подтверждён» и «A», «адреса нет» —
// каждому обращению «Z», и ни одно не ушло в отказ неподтверждённого адреса.
func (o *recoveryTimingObserver) mustHaveQueued(t *testing.T, phase string, queued, noRow int) {
	t.Helper()
	require.Zero(t, o.count(humansession.RecoveryRequestUnverified),
		"НЕ ВЫПОЛНИЛОСЬ (Ф5-29 «Дано»): %s — полоса «A» кода не получила, мерится не та работа", phase)
	require.Equal(t, queued, o.count(humansession.RecoveryRequestQueued),
		"НЕ ВЫПОЛНИЛОСЬ (условие): %s — выданных кодов не столько, сколько обращений полос с кодом", phase)
	require.Equal(t, noRow, o.count(humansession.RecoveryRequestNoRow),
		"НЕ ВЫПОЛНИЛОСЬ (условие): %s — исходов «адреса нет» не столько, сколько обращений полосы «Z»", phase)
}

// TestRecoveryTimingObserver_RateRefusalIsNotExecutedAndTheTwinIsSilent —
// инъекция в суд пробы (пробел-заказ (1) §22): отказ по частоте в прогоне —
// «не выполнилось» с меткой Ф5-20, а не нарушение критерия; законный близнец
// без отказа молчит. Исходы подаются тем же методом порта, которым их подаёт
// глагол запроса кода.
func TestRecoveryTimingObserver_RateRefusalIsNotExecutedAndTheTwinIsSilent(t *testing.T) {
	lawful := func() *recoveryTimingObserver {
		o := newRecoveryTimingObserver()
		var obs humansession.Observer = o
		obs.RecoveryRequestObserved(humansession.RecoveryRequestQueued)
		obs.RecoveryRequestObserved(humansession.RecoveryRequestNoRow)
		return o
	}
	require.Empty(t, lawful().notExecuted("близнец"), "законный близнец: отказов по частоте нет — суд молчит")

	for _, paced := range []humansession.RecoveryRequestOutcome{
		humansession.RecoveryRequestSourcePaced, humansession.RecoveryRequestRecipientPaced,
	} {
		o := lawful()
		var obs humansession.Observer = o
		obs.RecoveryRequestObserved(paced)
		msg := o.notExecuted("инъекция")
		require.Contains(t, msg, "НЕ ВЫПОЛНИЛОСЬ", "исход %s: прогон с отказом по частоте — «не выполнилось»", paced)
		require.Contains(t, msg, "Ф5-20", "исход %s: метка части «Тогда», которую прогон не исполнил", paced)
		require.Contains(t, msg, "Ф5-08", "исход %s: названа причина — отказ по частоте", paced)
		require.NotContains(t, msg, "нарушен", "исход %s: отказ по частоте — не нарушение критерия", paced)
	}
	for _, cond := range []humansession.RecoveryRequestOutcome{
		humansession.RecoveryRequestStoreFailed, humansession.RecoveryRequestDispatchDropped,
	} {
		o := lawful()
		var obs humansession.Observer = o
		obs.RecoveryRequestObserved(cond)
		require.Contains(t, o.notExecuted("инъекция"), "НЕ ВЫПОЛНИЛОСЬ (Ф5-20, условие)", "исход %s: мерилась не та работа", cond)
	}
}
