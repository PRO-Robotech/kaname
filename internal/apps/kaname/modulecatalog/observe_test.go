// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package modulecatalog_test

// observe_test.go — применение каталога СДВИГАЕТ СЧЁТЧИК, а не только строку
// журнала (задача продукта #1963).
//
// # Предмет
//
// Перепись применения печатается журналом на старте, и число оператору
// ДОСТАЁТСЯ — если он этот журнал читает. Того же числа без чтения журнала не
// было: метрик в каталоге применителя было НОЛЬ (предикат:
// `git grep -c prometheus -- services/iam/internal/apps/kaname/modulecatalog/`).
//
// В три часа ночи вопрос стоит иначе, чем при разборе: «каталог отстал» или
// «продукт сломан». Журнал на него отвечает только после того, как оператор
// нашёл нужный под, нужный старт и нужную строку; счётчик отвечает сразу — и
// отвечает по трём величинам, потому что вопросов тоже три:
//
//	применений ноль        → применитель не ходил вовсе
//	снятий ноль            → каталог не менялся
//	переселений ноль       → снятие было, но ни одной роли не задело
//
// # Что здесь утверждается, а что нет
//
// Утверждается ПАРА, и обе половины обязательны: применение, задевшее хотя бы
// одну роль, счётчик двигает, а идемпотентное повторное применение — НЕ двигает.
// Без второй половины счётчик, растущий на каждом старте, неотличим от
// работающего.
//
// О самой метрике эти пробы не говорят ничего: наблюдатель подставной, а
// регистрация коллектора и форма имени — предмет пакета метрик.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/catalog"
)

// countingObserver — подставной наблюдатель. Считает по меткам, а не суммой:
// сумма не отличает «снято действие» от «переселена выдача», и ради этого
// различения счётчики и заводятся.
type countingObserver struct {
	applies   map[string]int
	retired   map[string]int
	resettled map[string]int
}

// observedTx — исполнитель транзакций над писателем, ОТДАЮЩИМ живые строки.
// Отдельный от recordingTx: тот держит конкретный тип писателя, а предмет здесь
// — другой писатель, а не другой порядок.
type observedTx struct{ w *resettlingWriter }

func (r *observedTx) RunInWriteTx(ctx context.Context,
	fn func(context.Context, modulecatalog.CatalogWriter) error) error {
	return fn(ctx, r.w)
}

func newCountingObserver() *countingObserver {
	return &countingObserver{
		applies:   map[string]int{},
		retired:   map[string]int{},
		resettled: map[string]int{},
	}
}

func (o *countingObserver) IncCatalogApply(outcome string) { o.applies[outcome]++ }
func (o *countingObserver) AddCatalogRetiredRows(kind string, n int) {
	o.retired[kind] += n
}
func (o *countingObserver) AddCatalogResettledProjections(population string, n int) {
	o.resettled[population] += n
}

// resettlingWriter — писатель, у которого ЕСТЬ живые строки (значит снятию есть
// что снимать) и снятие ЗАДЕВАЕТ роль (значит переселение непусто). Иначе проба
// утверждала бы про счётчики, у которых на этом входе нет производителя.
type resettlingWriter struct {
	recordingWriter
	live      catalog.Rows
	resettled modulecatalog.Resettled
}

func (w *resettlingWriter) ReadModule(_ context.Context, module string) (catalog.Rows, error) {
	w.calls = append(w.calls, "read:"+module)
	return w.live, nil
}

func (w *resettlingWriter) ResettleTenantProjections(context.Context,
	[]catalog.ResourceRow, []catalog.VerbRow, string, string) (modulecatalog.Resettled, error) {
	w.calls = append(w.calls, "resettle")
	return w.resettled, nil
}

// TestApplyMovesTheObservabilityCounters — снятие, задевшее роль, двигает
// счётчик; идемпотентное повторное применение — не двигает.
func TestApplyMovesTheObservabilityCounters(t *testing.T) {
	w := &resettlingWriter{resettled: modulecatalog.Resettled{RuleRefs: 2, RoleVerbs: 1}}
	// Строка каталога уже жива и манифестом больше не объявлена — вход снятия.
	w.live = catalog.Rows{
		Modules: []string{"vpc"},
		Resources: []catalog.ResourceRow{
			{Module: "vpc", Resource: "network", ObjectType: "vpc_network"},
			{Module: "vpc", Resource: "gone", ObjectType: "vpc_gone"},
		},
		Verbs: []catalog.VerbRow{
			{Module: "vpc", Resource: "network", Verb: "get"},
			{Module: "vpc", Resource: "gone", Verb: "get"},
		},
	}
	obs := newCountingObserver()
	applier := modulecatalog.NewApplier(&observedTx{w: w}).WithObserver(obs)

	rep, err := applier.Apply(context.Background(), fixtureManifest("vpc", "network"))
	require.NoError(t, err)
	require.Positivef(t, rep.RetiredResources, "вход не произведён: снятия нет (%s)", rep)

	require.Equal(t, 1, obs.applies[modulecatalog.ApplyOutcomeApplied],
		"применение обязано двигать знаменатель: без него ноль снятий не отличается "+
			"от «применитель не ходил вовсе»")
	require.Equal(t, 1, obs.retired[modulecatalog.RetiredKindResource])
	require.Equal(t, 1, obs.retired[modulecatalog.RetiredKindVerb])
	require.Equal(t, 2, obs.resettled[modulecatalog.ResettledPopulationRuleRef],
		"снятие задело роли — счётчик переселения обязан сдвинуться")
	require.Equal(t, 1, obs.resettled[modulecatalog.ResettledPopulationRoleVerb])

	// ── ВТОРАЯ ПОЛОВИНА: идемпотентное применение счётчиков строк НЕ двигает ──
	// Без неё счётчик, растущий на каждом старте, неотличим от работающего.
	w.live = catalog.Rows{Modules: []string{"vpc"}}
	w.resettled = modulecatalog.Resettled{}
	before := map[string]int{
		"res":  obs.retired[modulecatalog.RetiredKindResource],
		"verb": obs.retired[modulecatalog.RetiredKindVerb],
		"rule": obs.resettled[modulecatalog.ResettledPopulationRuleRef],
		"role": obs.resettled[modulecatalog.ResettledPopulationRoleVerb],
	}
	rep2, err := applier.Apply(context.Background(), fixtureManifest("vpc", "network"))
	require.NoError(t, err)
	require.Zerof(t, rep2.RetiredResources+rep2.RetiredVerbs,
		"повторное применение сняло строки (%s) — вход второй половины неверен", rep2)

	require.Equal(t, before["res"], obs.retired[modulecatalog.RetiredKindResource],
		"счётчик снятых ресурсов сдвинулся на применении, ничего не снявшем")
	require.Equal(t, before["verb"], obs.retired[modulecatalog.RetiredKindVerb])
	require.Equal(t, before["rule"], obs.resettled[modulecatalog.ResettledPopulationRuleRef])
	require.Equal(t, before["role"], obs.resettled[modulecatalog.ResettledPopulationRoleVerb])
	require.Equal(t, 2, obs.applies[modulecatalog.ApplyOutcomeApplied],
		"знаменатель обязан двигаться и на применении без изменений: иначе «изменений "+
			"не было» неотличимо от «применения не было»")
}

// TestApplyWithoutAnObserverIsStillApplied — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ на
// необязательность наблюдателя: применитель без него работает ровно так же.
//
// Без этой пробы «наблюдатель провязан» было бы неотличимо от «наблюдатель
// обязателен», и первый же вызывающий, метрик не завёдший, получил бы падение
// на пути старта.
func TestApplyWithoutAnObserverIsStillApplied(t *testing.T) {
	w := &recordingWriter{}
	applier := modulecatalog.NewApplier(&recordingTx{w: w})
	rep, err := applier.Apply(context.Background(), fixtureManifest("vpc", "network"))
	require.NoError(t, err)
	require.True(t, rep.Changed(), "применение без наблюдателя обязано менять каталог: %s", rep)
}

// TestApplyCountsTheRefusalSeparately — отказ применения двигает СВОЙ исход, а
// не знаменатель успехов.
//
// Слив их в одну величину, мы получили бы счётчик, растущий и тогда, когда
// применение не произошло, — то есть ровно ту неразличимость, ради которой
// метрика и заводится.
func TestApplyCountsTheRefusalSeparately(t *testing.T) {
	w := &recordingWriter{failOnModule: "vpc"}
	obs := newCountingObserver()
	applier := modulecatalog.NewApplier(&recordingTx{w: w}).WithObserver(obs)

	_, err := applier.Apply(context.Background(), fixtureManifest("vpc", "network"))
	require.Error(t, err)
	require.Equal(t, 1, obs.applies[modulecatalog.ApplyOutcomeFailed])
	require.Zero(t, obs.applies[modulecatalog.ApplyOutcomeApplied],
		"отказ засчитан в успехи — знаменатель перестал отвечать на свой вопрос")
	require.Empty(t, obs.retired, "откаченная транзакция не снимала строк, а счётчик их назвал")
}
