// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// envelope_test.go — ОГИБАЮЩАЯ ПО ПОТОЛКУ фактической популяции (решение
// kaname#188 по Ф3-31 / ID-PW-1 Р4, PWV-03): калибратор классов стоимости и
// потолок, от которого полоса входа отсчитывает задержку всякого исхода.
//
// Предмет проб — свойства САМОЙ огибающей, не полосы входа (та — в
// `humansession`):
//
//  1. допуск класса КАЛИБРУЕТ его прогоном проверяющего и поднимает потолок,
//     если класс дороже текущего; дешевле — потолок не трогает;
//  2. известный класс второй раз не калибруется: стоимость взята у первого
//     прогона, а не измерена заново — иначе потолок плыл бы с каждым входом;
//  3. класс, который проверяющий не читает (выше потолка записи, чужой формат),
//     не калибруется: ось годности от времени освобождена (Р4), а вычислять
//     выше потолка значило бы платить ту цену, от которой потолок защищает;
//  4. калибровка занимает ЁМКОСТЬ проверяющего: страж старта сверил с пределом
//     памяти ровно `ёмкость × память проверки`, и прогон мимо ёмкости вышел бы
//     за бюджет;
//  5. префикс класса, каким его отдаёт перепись хранилища, разбирается в класс
//     обоими форматами и отвергается на чужом;
//  6. мера стоимости — вход огибающей: без неё огибающая не строится, мера,
//     не позвавшая прогон ровно один раз либо отдавшая неположительную
//     стоимость, — отказ, а не потолок; паника меры не уносит место ёмкости
//     и класса не держит: калибровка, не дошедшая до исхода, снята, ждавший
//     получает отказ, следующий допуск калибрует класс заново;
//  7. мера композиционного корня (настенные часы) мерит САМ прогон: часы
//     читаются до его начала и после его конца, и мера не короче прогона.
//
// Пробы ВЫБОРА (какой класс стал потолком, поднялся ли потолок) идут на мере с
// назначенной стоимостью (`assignedMeter`), а не на настенных часах: порядок
// стоимостей, измеренный часами, переворачивается одной задержкой
// планировщика, и проба выбора по нему судила бы расписание машины.
// Настенные часы остаются у проб одного класса, чьи утверждения устойчивы к
// любой задержке (стоимость положительна, запас над ней есть).
package passwordverify_test

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

func bcryptClass(cost uint32) domain.PasswordCostClass {
	return domain.PasswordCostClass{Format: domain.PasswordHashFormatBcrypt,
		Params: map[domain.PasswordHashCostParam]uint32{domain.CostParamBcryptCost: cost}}
}

func argon2Class(memory, iterations, parallelism uint32) domain.PasswordCostClass {
	return domain.PasswordCostClass{Format: domain.PasswordHashFormatArgon2id,
		Params: map[domain.PasswordHashCostParam]uint32{
			domain.CostParamArgon2Memory: memory, domain.CostParamArgon2Iterations: iterations,
			domain.CostParamArgon2Parallelism: parallelism}}
}

// recordingEnvelopeObserver — приёмник событий огибающей для проб.
type recordingEnvelopeObserver struct {
	mu         sync.Mutex
	calibrated []string
	triggers   []passwordverify.EnvelopeTrigger
	floors     []time.Duration
}

func (o *recordingEnvelopeObserver) ClassCalibrated(class domain.PasswordCostClass, _ time.Duration, trigger passwordverify.EnvelopeTrigger) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.calibrated = append(o.calibrated, class.Key())
	o.triggers = append(o.triggers, trigger)
}

func (o *recordingEnvelopeObserver) EnvelopeFloorObserved(floor time.Duration, _ domain.PasswordCostClass) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.floors = append(o.floors, floor)
}

// snapshot — копии записанного под замком: для проб, где огибающую зовут и
// другие горутины.
func (o *recordingEnvelopeObserver) snapshot() (calibrated []string, floors []time.Duration) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.calibrated...), append([]time.Duration(nil), o.floors...)
}

// newEnvelope — огибающая на настенных часах процесса, как в композиционном
// корне. Только для проб, чьи утверждения не зависят от порядка стоимостей
// разных классов.
func newEnvelope(t *testing.T, capacity int) (*passwordverify.Envelope, *passwordverify.Verifier, *recordingEnvelopeObserver) {
	t.Helper()
	return newEnvelopeMeasuredBy(t, capacity, passwordverify.WallClockCostMeter)
}

func newEnvelopeMeasuredBy(t *testing.T, capacity int, meter passwordverify.CostMeter) (*passwordverify.Envelope, *passwordverify.Verifier, *recordingEnvelopeObserver) {
	t.Helper()
	v := newVerifier(t, capacity, newRecordingObserver())
	obs := &recordingEnvelopeObserver{}
	e, err := passwordverify.NewEnvelope(v, obs, meter)
	require.NoError(t, err)
	return e, v, obs
}

// assignedMeter — мера пробы: стоимость класса НАЗНАЧЕНА пробой, а не взята у
// планировщика машины. Прогон проверяющего исполняется по-настоящему (в
// ёмкости, с исходом «не совпал») — отброшено только его время. Класс, которому
// стоимость не назначена, — провал пробы, а не нулевая стоимость.
type assignedMeter struct {
	t     *testing.T
	mu    sync.Mutex
	costs map[string]time.Duration
	runs  map[string]int
}

// newAssignedMeter — мера со стоимостями по ключу класса (`PasswordCostClass.Key`).
func newAssignedMeter(t *testing.T, costs map[string]time.Duration) *assignedMeter {
	return &assignedMeter{t: t, costs: costs, runs: map[string]int{}}
}

func (m *assignedMeter) measure(class domain.PasswordCostClass, verify func()) time.Duration {
	verify()
	m.mu.Lock()
	defer m.mu.Unlock()
	cost, ok := m.costs[class.Key()]
	if !ok {
		m.t.Errorf("мера пробы: стоимость класса %s не назначена", class.Key())
	}
	m.runs[class.Key()]++
	return cost
}

func (m *assignedMeter) runsOf(class domain.PasswordCostClass) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.runs[class.Key()]
}

// TestEnvelope_AdmitCalibratesTheClassAndRaisesTheFloor — пустая огибающая
// не держит ничего; допуск первого класса калибрует его и ставит потолок на
// него; потолок — не меньше самого дорогого прогона калибровки.
func TestEnvelope_AdmitCalibratesTheClassAndRaisesTheFloor(t *testing.T) {
	e, _, obs := newEnvelope(t, 2)
	require.Zero(t, e.Floor(), "до калибровки огибающей нет")
	_, ok := e.Ceiling()
	require.False(t, ok)

	adm, err := e.Admit(context.Background(), bcryptClass(4), passwordverify.EnvelopeTriggerStartup)
	require.NoError(t, err)
	require.True(t, adm.Calibrated, "первый допуск класса — калибровка")
	require.Greater(t, adm.Cost, time.Duration(0))
	require.GreaterOrEqual(t, adm.Floor, adm.Cost, "потолок не ниже стоимости самого дорогого прогона")
	require.Greater(t, adm.Floor, adm.Cost, "запас над стоимостью есть: прогон под нагрузкой длиннее калибровочного")
	require.Equal(t, adm.Floor, e.Floor())

	ceiling, ok := e.Ceiling()
	require.True(t, ok)
	require.Equal(t, bcryptClass(4).Key(), ceiling.Class.Key())
	require.Equal(t, adm.Cost, ceiling.Cost)

	require.Equal(t, []string{bcryptClass(4).Key()}, obs.calibrated)
	require.Equal(t, []passwordverify.EnvelopeTrigger{passwordverify.EnvelopeTriggerStartup}, obs.triggers)
	require.Equal(t, []time.Duration{adm.Floor}, obs.floors, "новый потолок сообщён приёмнику ровно один раз")
}

// TestEnvelope_ADearerClassRaisesTheFloorACheaperOneDoesNot — второй класс
// дороже первого поднимает потолок на себя; третий, дешевле обоих,
// калибруется, но потолка не трогает. Стоимости назначены мерой пробы
// (соотношение — как у настоящих классов: bcrypt вдвое на единицу стоимости,
// argon2id на 8 КиБ — десятки микросекунд): предмет пробы — ВЫБОР потолка, а
// порядок, измеренный часами, переворачивается одной задержкой планировщика.
func TestEnvelope_ADearerClassRaisesTheFloorACheaperOneDoesNot(t *testing.T) {
	meter := newAssignedMeter(t, map[string]time.Duration{
		bcryptClass(4).Key():       time.Millisecond,
		bcryptClass(8).Key():       16 * time.Millisecond,
		argon2Class(8, 1, 1).Key(): 50 * time.Microsecond,
	})
	e, _, obs := newEnvelopeMeasuredBy(t, 2, meter.measure)
	ctx := context.Background()
	cheap, err := e.Admit(ctx, bcryptClass(4), passwordverify.EnvelopeTriggerStartup)
	require.NoError(t, err)
	require.Equal(t, time.Millisecond, cheap.Cost, "стоимость класса — число меры, а не иное")
	require.Equal(t, time.Millisecond+time.Millisecond/4, cheap.Floor, "потолок — стоимость с запасом в четверть")

	dear, err := e.Admit(ctx, bcryptClass(8), passwordverify.EnvelopeTriggerStartup)
	require.NoError(t, err)
	require.True(t, dear.Calibrated)
	require.Equal(t, 16*time.Millisecond, dear.Cost)
	require.Equal(t, 20*time.Millisecond, dear.Floor, "потолок поднялся на дорогой класс")
	ceiling, ok := e.Ceiling()
	require.True(t, ok)
	require.Equal(t, bcryptClass(8).Key(), ceiling.Class.Key())

	cheaper, err := e.Admit(ctx, argon2Class(8, 1, 1), passwordverify.EnvelopeTriggerRead)
	require.NoError(t, err)
	require.True(t, cheaper.Calibrated, "класс калибруется, даже когда потолка не поднимает: его стоимость — факт огибающей")
	require.Equal(t, 50*time.Microsecond, cheaper.Cost)
	require.Equal(t, dear.Floor, cheaper.Floor, "потолок не опустился")
	require.Equal(t, dear.Floor, e.Floor())
	ceiling, _ = e.Ceiling()
	require.Equal(t, bcryptClass(8).Key(), ceiling.Class.Key(), "потолок — по-прежнему самый дорогой класс")
	for _, class := range []domain.PasswordCostClass{bcryptClass(4), bcryptClass(8), argon2Class(8, 1, 1)} {
		require.Positive(t, meter.runsOf(class), "класс %s калиброван ПРОГОНОМ через меру, а не назначен мимо неё", class.Key())
	}

	classes := e.Classes()
	require.Len(t, classes, 3, "перепись огибающей несёт КАЖДЫЙ калиброванный класс, не только потолок")
	require.Equal(t, []passwordverify.EnvelopeTrigger{
		passwordverify.EnvelopeTriggerStartup, passwordverify.EnvelopeTriggerStartup, passwordverify.EnvelopeTriggerRead,
	}, obs.triggers)
	require.Len(t, obs.floors, 2, "потолок сообщён дважды: первый класс и подъём; третий класс потолка не менял")
}

// TestEnvelope_AKnownClassIsNotCalibratedTwice — повторный допуск известного
// класса отвечает стоимостью первого прогона, не меряя заново.
func TestEnvelope_AKnownClassIsNotCalibratedTwice(t *testing.T) {
	e, _, obs := newEnvelope(t, 2)
	ctx := context.Background()
	first, err := e.Admit(ctx, bcryptClass(5), passwordverify.EnvelopeTriggerStartup)
	require.NoError(t, err)
	require.True(t, first.Calibrated)

	again, err := e.Admit(ctx, bcryptClass(5), passwordverify.EnvelopeTriggerRead)
	require.NoError(t, err)
	require.False(t, again.Calibrated, "известный класс — без калибровки")
	require.Equal(t, first.Cost, again.Cost)
	require.Equal(t, first.Floor, again.Floor)
	require.Len(t, obs.calibrated, 1, "повторный допуск — поиск по ключу, а не прогон проверяющего")
}

// TestEnvelope_AClassTheVerifierDoesNotReadIsNotCalibrated — выше потолка
// записи и чужой формат — отказ с именем исхода, потолок и перепись не тронуты.
func TestEnvelope_AClassTheVerifierDoesNotReadIsNotCalibrated(t *testing.T) {
	e, _, obs := newEnvelope(t, 2)
	ctx := context.Background()
	base, err := e.Admit(ctx, bcryptClass(4), passwordverify.EnvelopeTriggerStartup)
	require.NoError(t, err)

	_, err = e.Admit(ctx, bcryptClass(15), passwordverify.EnvelopeTriggerStartup)
	require.Error(t, err)
	var unreadable *passwordverify.ClassNotReadableError
	require.ErrorAs(t, err, &unreadable, "отказ типом: вызывающий различает «не читается» от отказа среды")
	require.Equal(t, passwordverify.OutcomeParamsAboveCeiling, unreadable.Outcome)
	require.Equal(t, bcryptClass(15).Key(), unreadable.Class.Key())

	_, err = e.Admit(ctx, domain.PasswordCostClass{Format: "pbkdf2",
		Params: map[domain.PasswordHashCostParam]uint32{"rounds": 1000}}, passwordverify.EnvelopeTriggerStartup)
	require.Error(t, err)
	require.Contains(t, err.Error(), "pbkdf2")

	require.Equal(t, base.Floor, e.Floor(), "потолок не тронут")
	require.Len(t, e.Classes(), 1)
	require.Len(t, obs.calibrated, 1)
}

// TestEnvelope_CalibrationTakesTheVerifierCapacity — калибровка занимает
// место ёмкости: при занятой ёмкости она ЖДЁТ, а не считает мимо бюджета
// памяти; срок ожидания — контекст вызывающего.
func TestEnvelope_CalibrationTakesTheVerifierCapacity(t *testing.T) {
	e, v, _ := newEnvelope(t, 1)

	hold := make(chan struct{})
	held := make(chan struct{})
	go func() {
		v.WithCapacity(func() {
			close(held)
			<-hold
		})
	}()
	<-held

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := e.Admit(ctx, bcryptClass(4), passwordverify.EnvelopeTriggerStartup)
	require.Error(t, err, "ёмкость занята целиком — калибровка не прошла мимо неё")
	require.True(t, errors.Is(err, context.DeadlineExceeded), "отказ — срок ожидания вызывающего, не свой")
	require.Zero(t, e.Floor(), "потолок не выставлен")
	require.Empty(t, e.Classes())

	close(hold)
	adm, err := e.Admit(context.Background(), bcryptClass(4), passwordverify.EnvelopeTriggerStartup)
	require.NoError(t, err, "положительный контроль: ёмкость свободна — калибровка проходит")
	require.True(t, adm.Calibrated)
}

// TestEnvelope_ConcurrentAdmitsOfOneClassCalibrateOnce — два одновременных
// допуска одного класса дают одну калибровку: второй ждёт первую и берёт её
// стоимость.
func TestEnvelope_ConcurrentAdmitsOfOneClassCalibrateOnce(t *testing.T) {
	e, _, obs := newEnvelope(t, 4)
	var wg sync.WaitGroup
	results := make([]passwordverify.Admission, 4)
	errs := make([]error, 4)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = e.Admit(context.Background(), bcryptClass(6), passwordverify.EnvelopeTriggerRead)
		}(i)
	}
	wg.Wait()
	calibrated := 0
	for i, r := range results {
		require.NoError(t, errs[i])
		if r.Calibrated {
			calibrated++
		}
		require.Equal(t, results[0].Cost, r.Cost, "все получили одну стоимость")
	}
	require.Equal(t, 1, calibrated, "калибровка одна на класс")
	require.Len(t, obs.calibrated, 1)
}

// TestNewEnvelope_RequiresACostMeter — огибающая без меры не строится: стоимость
// класса нечем узнать, а умолчание выбирало бы меру за вызывающего молча.
func TestNewEnvelope_RequiresACostMeter(t *testing.T) {
	t.Parallel()
	v := newVerifier(t, 1, newRecordingObserver())
	_, err := passwordverify.NewEnvelope(v, passwordverify.NopEnvelopeObserver{}, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "meter")

	_, err = passwordverify.NewEnvelope(v, passwordverify.NopEnvelopeObserver{}, passwordverify.WallClockCostMeter)
	require.NoError(t, err, "законный близнец: мера есть — огибающая строится")
}

// TestWallClockCostMeter_MeasuresTheWholeRunItCalls — мера композиционного
// корня мерит САМ прогон: часы читаются до его начала и после его конца, прогон
// зовётся синхронно ровно один раз. Мера, прочитавшая часы мимо прогона,
// отдала бы десятки наносекунд, и потолок из них не задерживал бы ни одного
// исхода: полоса входа отвечала бы временем проверки. Пробы выбора потолка
// идут на назначенной стоимости и этого не видят — видит только эта.
//
// Устойчивость к нагрузке — из порядка чтений, а не из запаса: прогон пробы
// спит `nap` и сам мерит свою длительность; мера, читающая часы до начала и
// после конца, не короче её при ЛЮБОЙ задержке планировщика (монотонные часы
// не убывают). Верхней границы у меры нет: под нагрузкой прогон длиннее, и
// граница сверху судила бы расписание машины. Мера мимо прогона проходит
// лишь при задержке между двумя соседними чтениями часов не короче `nap` —
// в каждом из `samples` замеров подряд.
func TestWallClockCostMeter_MeasuresTheWholeRunItCalls(t *testing.T) {
	t.Parallel()
	const (
		nap     = 20 * time.Millisecond
		samples = 3
	)
	for i := 0; i < samples; i++ {
		calls := 0
		finished := false
		var inside time.Duration
		measured := passwordverify.WallClockCostMeter(bcryptClass(4), func() {
			calls++
			begin := time.Now()
			time.Sleep(nap)
			inside = time.Since(begin)
			finished = true
		})
		require.Equal(t, 1, calls, "замер %d: прогон позван ровно один раз", i)
		require.True(t, finished, "замер %d: мера вернулась после конца прогона, а не до него", i)
		require.GreaterOrEqual(t, inside, nap, "замер %d, предпосылка: прогон пробы длится не меньше своего сна", i)
		require.GreaterOrEqual(t, measured, inside,
			"замер %d: мера %v короче прогона %v — часы прочитаны мимо прогона", i, measured, inside)
	}
}

// TestEnvelope_APanickingMeterReleasesTheCapacitySlot — мера — довод
// вызывающего, и её паника не уносит место ёмкости: иначе каждая такая
// калибровка отнимала бы у полосы входа одно место до перезапуска. Законный
// близнец — та же огибающая: место свободно и до калибровки.
func TestEnvelope_APanickingMeterReleasesTheCapacitySlot(t *testing.T) {
	t.Parallel()
	meter := func(_ domain.PasswordCostClass, verify func()) time.Duration {
		verify()
		panic("мера пробы")
	}
	e, v, _ := newEnvelopeMeasuredBy(t, 1, meter)
	require.True(t, v.WithCapacity(func() {}), "предпосылка: место ёмкости свободно до калибровки")

	require.PanicsWithValue(t, "мера пробы", func() {
		_, _ = e.Admit(context.Background(), bcryptClass(4), passwordverify.EnvelopeTriggerStartup)
	}, "паника меры доходит до вызывающего, а не глотается огибающей")
	require.True(t, v.WithCapacity(func() {}), "место ёмкости освобождено и при панике меры")
}

const (
	// interruptedWaitBudget — срок ждавшего и следующего допусков: секунды,
	// много дольше прогона (1 мс по мере пробы). Производитель, держащий класс
	// «в калибровке», держит их до этого срока, и проба краснеет им, а не
	// пределом `go test`.
	interruptedWaitBudget = 3 * time.Second
	// interruptedPremiseBudget — предел ожидания предпосылок сцены (первый
	// допуск дошёл до меры, ждавший встал в ожидание). Истёк — проба НЕ
	// ИСПОЛНЯЛАСЬ, а не краснеет по предмету.
	interruptedPremiseBudget = 10 * time.Second
)

// waitReachedContext — контекст допуска, извещающий пробу о ПЕРВОМ обращении к
// Done(). Допуск, заставший калибровку своего класса идущей, до ожидания
// контекст не читает, и первое обращение — вход в ожидание: барьер
// предпосылки (м′) — «в момент паники ждавший уже ждёт» — стоит на действии
// самого допуска, а не на сне пробы.
type waitReachedContext struct {
	context.Context
	once    sync.Once
	reached chan struct{}
}

func (c *waitReachedContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.reached) })
	return c.Context.Done()
}

// interruptingMeter — мера пробы, прерывающая ПЕРВЫЙ прогон калибровки ПОСЛЕ
// самого прогона (`interrupt` — паника либо выход горутины), когда ждавший
// допуск уже встал в ожидание; дальше — стоимость 1 мс. От меры (ж) она
// отличается одним фактом — прерыванием первого прогона.
type interruptingMeter struct {
	interrupt func()
	waiter    <-chan struct{}
	entered   chan struct{}

	mu     sync.Mutex
	calls  int
	missed bool
}

func (m *interruptingMeter) measure(_ domain.PasswordCostClass, verify func()) time.Duration {
	verify()
	m.mu.Lock()
	m.calls++
	first := m.calls == 1
	m.mu.Unlock()
	if !first {
		return time.Millisecond
	}
	close(m.entered)
	select {
	case <-m.waiter:
	case <-time.After(interruptedPremiseBudget):
		m.mu.Lock()
		m.missed = true
		m.mu.Unlock()
	}
	m.interrupt()
	return time.Millisecond
}

func (m *interruptingMeter) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

func (m *interruptingMeter) premiseMissed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.missed
}

// TestEnvelope_APanickingMeterLeavesNoCalibrationInFlight — Ф3-53 (м) вторая
// половина, (м′), (м″): калибровка, прерванная паникой меры, класса НЕ ДЕРЖИТ.
// Тот же вред «до перезапуска», что у места ёмкости (м), стоял бы на классе:
// запись «в калибровке», пережившая прогон, держала бы до срока вызывающего
// и ждавший допуск, и каждый следующий допуск класса. Положительный близнец
// (м′) — (ж) TestEnvelope_ConcurrentAdmitsOfOneClassCalibrateOnce: те же
// ждущие за мерой без паники получают стоимость одной калибровки. Законный
// близнец (м″) — эта же мера: паникует только на самом первом прогоне.
func TestEnvelope_APanickingMeterLeavesNoCalibrationInFlight(t *testing.T) {
	t.Parallel()
	interruptedCalibrationLeavesNothingInFlight(t, func() { panic("мера пробы") }, "мера пробы")
}

// TestEnvelope_AMeterThatExitsItsGoroutineLeavesNoCalibrationInFlight — тот же
// предмет при ВЫХОДЕ горутины прогона (runtime.Goexit): отложенные функции
// исполняются, а recover() отдаёт nil. Снятие калибровки, построенное на
// перехвате паники, этот исход пропустило бы, и ждавший стоял бы до срока;
// снятие по признаку «исход не записан» видит оба.
func TestEnvelope_AMeterThatExitsItsGoroutineLeavesNoCalibrationInFlight(t *testing.T) {
	t.Parallel()
	interruptedCalibrationLeavesNothingInFlight(t, runtime.Goexit, nil)
}

// interruptedCalibrationLeavesNothingInFlight — сцена (м)…(м″) при ёмкости 1:
// первый допуск класса калибрует его, мера прерывает первый прогон, когда
// второй допуск того же класса ждёт идущей калибровки; затем — следующий
// допуск того же класса и допуск другого. `wantPanic` — значение, с которым
// прерывание обязано дойти до вызывающего (nil — выход горутины).
func interruptedCalibrationLeavesNothingInFlight(t *testing.T, interrupt func(), wantPanic any) {
	t.Helper()
	class := bcryptClass(4)
	waitCtx, cancelWait := context.WithTimeout(context.Background(), interruptedWaitBudget)
	defer cancelWait()
	waiterCtx := &waitReachedContext{Context: waitCtx, reached: make(chan struct{})}
	meter := &interruptingMeter{interrupt: interrupt, waiter: waiterCtx.reached, entered: make(chan struct{})}
	e, v, obs := newEnvelopeMeasuredBy(t, 1, meter.measure)

	type firstOutcome struct {
		returned bool
		panicked any
	}
	first := make(chan firstOutcome, 1)
	go func() {
		var out firstOutcome
		defer func() {
			out.panicked = recover()
			first <- out
		}()
		_, _ = e.Admit(context.Background(), class, passwordverify.EnvelopeTriggerStartup)
		out.returned = true
	}()
	select {
	case <-meter.entered:
	case <-time.After(interruptedPremiseBudget):
		t.Fatalf("проба НЕ ИСПОЛНЯЛАСЬ: первый допуск класса %s не дошёл до меры за %v", class.Key(), interruptedPremiseBudget)
	}

	type waiterOutcome struct {
		adm        passwordverify.Admission
		err        error
		ctxErr     error
		meterCalls int
	}
	waiter := make(chan waiterOutcome, 1)
	go func() {
		adm, err := e.Admit(waiterCtx, class, passwordverify.EnvelopeTriggerRead)
		waiter <- waiterOutcome{adm: adm, err: err, ctxErr: waitCtx.Err(), meterCalls: meter.callCount()}
	}()

	var got firstOutcome
	select {
	case got = <-first:
	case <-time.After(2 * interruptedPremiseBudget):
		t.Fatalf("проба НЕ ИСПОЛНЯЛАСЬ: первый допуск не завершился за %v", 2*interruptedPremiseBudget)
	}
	if meter.premiseMissed() {
		t.Fatalf("проба НЕ ИСПОЛНЯЛАСЬ: второй допуск класса %s не встал в ожидание идущей калибровки за %v — "+
			"(м′) судить не о чем", class.Key(), interruptedPremiseBudget)
	}
	require.False(t, got.returned, "(м): прерванная калибровка исхода не вернула — прерывание дошло до вызывающего, а не проглочено огибающей")
	require.Equal(t, wantPanic, got.panicked, "(м): паника меры доходит до вызывающего с её значением")
	require.True(t, v.WithCapacity(func() {}), "(м): место ёмкости свободно и после прерывания — иначе (м″) судила бы ёмкость, а не класс")
	require.Empty(t, e.Classes(), "(м): прерванная калибровка класса в огибающую не записала")
	require.Zero(t, e.Floor(), "(м): потолок из прерванной калибровки не выставлен")
	_, hasCeiling := e.Ceiling()
	require.False(t, hasCeiling, "(м): класса-потолка нет")
	calibrated, _ := obs.snapshot()
	require.Empty(t, calibrated, "(м): о прерванной калибровке приёмник не извещён")

	t.Run("(м′) ждавший получает отказ с именем класса, не дожидаясь срока", func(t *testing.T) {
		var w waiterOutcome
		select {
		case w = <-waiter:
		case <-time.After(interruptedWaitBudget + interruptedPremiseBudget):
			t.Fatalf("ждавший допуск не вернулся и после своего срока %v", interruptedWaitBudget)
		}
		require.Error(t, w.err, "ждавший прерванную калибровку получает отказ, а не стоимость")
		require.NotErrorIs(t, w.err, context.DeadlineExceeded, "отказ — прерванная калибровка, а не срок ждавшего")
		require.NoError(t, w.ctxErr, "ответ пришёл до срока ждавшего: он не стоял до него")
		require.Contains(t, w.err.Error(), class.Key(), "отказ называет класс")
		require.Contains(t, w.err.Error(), "прервана", "отказ называет прерванную калибровку")
		require.False(t, w.adm.Calibrated)
		require.Equal(t, 1, w.meterCalls, "к ответу ждавшего мера звана ровно раз: он получил исход прерванной калибровки, а не калибровал сам")
	})

	t.Run("(м″) следующий допуск калибрует класс заново", func(t *testing.T) {
		before := meter.callCount()
		ctx, cancel := context.WithTimeout(context.Background(), interruptedWaitBudget)
		defer cancel()
		adm, err := e.Admit(ctx, class, passwordverify.EnvelopeTriggerRead)
		require.NoError(t, err, "класс, чью калибровку прервали, «в калибровке» не держится")
		require.True(t, adm.Calibrated, "следующий допуск — калибровка, а не поиск по ключу")
		require.Equal(t, time.Millisecond, adm.Cost, "стоимость — число меры этой калибровки")
		require.Equal(t, time.Millisecond+time.Millisecond/4, adm.Floor, "потолок — стоимость с запасом в четверть")
		require.Greater(t, meter.callCount(), before, "класс калиброван прогоном через меру")
		classes := e.Classes()
		require.Len(t, classes, 1)
		require.Equal(t, class.Key(), classes[0].Class.Key())
		require.Equal(t, time.Millisecond, classes[0].Cost)
		calibrated, floors := obs.snapshot()
		require.Equal(t, []string{class.Key()}, calibrated, "приёмник извещён о калибровке ровно раз — прерванная не сосчитана")
		require.Equal(t, []time.Duration{time.Millisecond + time.Millisecond/4}, floors)
	})

	t.Run("допуск другого класса после того же прерывания проходит", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), interruptedWaitBudget)
		defer cancel()
		adm, err := e.Admit(ctx, bcryptClass(5), passwordverify.EnvelopeTriggerRead)
		require.NoError(t, err, "огибающая жива: держится один класс, а не она целиком")
		require.True(t, adm.Calibrated)
		require.Equal(t, time.Millisecond, adm.Cost)
	})
}

// TestEnvelope_AMeterThatDoesNotRunTheVerificationOnceIsRefused — мера обязана
// позвать прогон проверяющего РОВНО один раз: мера, вернувшая число без
// прогона, назначала бы стоимость мимо ёмкости и мимо исхода «не совпал», а
// позвавшая дважды мерила бы два прогона как один. Отказ называет меру, потолок
// не выставлен.
func TestEnvelope_AMeterThatDoesNotRunTheVerificationOnceIsRefused(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		calls int
	}{{"ни разу", 0}, {"дважды", 2}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			meter := func(_ domain.PasswordCostClass, verify func()) time.Duration {
				for i := 0; i < tc.calls; i++ {
					verify()
				}
				return time.Millisecond
			}
			e, _, obs := newEnvelopeMeasuredBy(t, 1, meter)
			_, err := e.Admit(context.Background(), bcryptClass(4), passwordverify.EnvelopeTriggerStartup)
			require.Error(t, err)
			require.Contains(t, err.Error(), "мера стоимости класса "+bcryptClass(4).Key())
			require.Zero(t, e.Floor(), "потолок из непрогнанной меры не выставлен")
			require.Empty(t, e.Classes())
			require.Empty(t, obs.calibrated)
		})
	}
}

// TestEnvelope_ANonPositiveCostIsRefused — неположительная стоимость — отказ, а
// не потолок: потолок, выставленный из нуля, не задерживал бы ни одного исхода,
// и полоса входа отвечала бы временем проверки. Законный близнец —
// положительная стоимость той же меры.
func TestEnvelope_ANonPositiveCostIsRefused(t *testing.T) {
	t.Parallel()
	for _, cost := range []time.Duration{0, -time.Millisecond} {
		meter := newAssignedMeter(t, map[string]time.Duration{bcryptClass(4).Key(): cost})
		e, _, _ := newEnvelopeMeasuredBy(t, 1, meter.measure)
		_, err := e.Admit(context.Background(), bcryptClass(4), passwordverify.EnvelopeTriggerStartup)
		require.Errorf(t, err, "стоимость %v обязана быть отвергнута", cost)
		require.Contains(t, err.Error(), "мера стоимости класса "+bcryptClass(4).Key())
		require.Zero(t, e.Floor())
		require.Empty(t, e.Classes())
	}

	meter := newAssignedMeter(t, map[string]time.Duration{bcryptClass(4).Key(): time.Nanosecond})
	e, _, _ := newEnvelopeMeasuredBy(t, 1, meter.measure)
	adm, err := e.Admit(context.Background(), bcryptClass(4), passwordverify.EnvelopeTriggerStartup)
	require.NoError(t, err, "законный близнец: наименьшая положительная стоимость принимается")
	require.Equal(t, time.Nanosecond, adm.Cost)
}

// TestParseCostClassPrefix_ReadsBothFormatsAndRefusesTheRest — префикс класса,
// каким его отдаёт перепись хранилища (значение без соли и тела), разбирается
// обоими форматами; чужой признак, чужая версия разметки и негодная
// стоимость — отказ.
func TestParseCostClassPrefix_ReadsBothFormatsAndRefusesTheRest(t *testing.T) {
	t.Parallel()

	got, err := passwordverify.ParseCostClassPrefix("$2a$12")
	require.NoError(t, err)
	require.Equal(t, bcryptClass(12).Key(), got.Key())

	got, err = passwordverify.ParseCostClassPrefix("$argon2id$v=19$m=65536,t=3,p=4")
	require.NoError(t, err)
	require.Equal(t, argon2Class(65536, 3, 4).Key(), got.Key())

	for _, bad := range []string{
		"", "$", "$pbkdf2$", "$2b$12", "$2a$xx", "$2a$1", "$2a$012",
		"$argon2id$v=18$m=65536,t=3,p=4", "$argon2id$v=19$m=65536,t=3", "$argon2id$v=19$m=65536,t=3,p=4,keyid=1",
		"$argon2id$v=19$m=65536,t=3,p=4$salt", "$2a$12$saltandbody",
	} {
		_, err := passwordverify.ParseCostClassPrefix(bad)
		require.Errorf(t, err, "префикс %q обязан быть отвергнут", bad)
	}
}

// TestEnvelopeTriggers_DictionaryIsClosed — поводов калибровки два: старт и
// чтение неизвестного класса; словарь закрыт ДВУМЯ и клетки счётчика
// заводятся из него. Третьего повода — `write` — нет и не будет: у записи
// класса дороже потолка своим процессом нет производителя (`kacho#1268`,
// `kaname#222`), и проба обязана краснеть на его появлении.
func TestEnvelopeTriggers_DictionaryIsClosed(t *testing.T) {
	t.Parallel()
	triggers := passwordverify.EnvelopeTriggers()
	require.Equal(t, []passwordverify.EnvelopeTrigger{passwordverify.EnvelopeTriggerStartup, passwordverify.EnvelopeTriggerRead}, triggers)
	triggers[0] = "tampered"
	require.Equal(t, passwordverify.EnvelopeTriggerStartup, passwordverify.EnvelopeTriggers()[0], "словарь отдаётся копией")
}
