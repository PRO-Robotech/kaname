// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package modulecatalog_test

// plan_verdict_test.go — ВЕРДИКТ ПЛАНА отличает ПОЧИНКУ от КИРПИЧА.
//
// Приёмка `services/iam/docs/engineering/acceptance/plan-confirms-what-apply-withdraws.md`
// (APPROVED круга 4), §2.11 и §5 «Различение починки от кирпича»; сценарии
// `IAM-MA-1-02`, `-36`, `-36а`, `-36б`. Задача продукта #1034.
//
// # Что здесь утверждается
//
// Одно свойство, и оно несущее: **никакая функция от счётчиков плана вердикта не
// даёт**. Два состояния каталога — манифест ШИРЕ опоры и ОЖИВЛЕНИЕ снятой строки,
// которую опора объявляет, — неотличимы по паре «записано / снято» (1, 0) и
// требуют ПРОТИВОПОЛОЖНЫХ вердиктов. Значит реализация обязана позвать сверку
// (`seed.AssertCatalogParity`) над ГИПОТЕТИЧЕСКИМ состоянием после применения, а
// не выводить вердикт из чисел.
//
// Второе свойство того же набора — ЛОВУШКА реализации: порт стража
// (`seed.CatalogSource`) ДВУХметодный, и подавший ему только живое множество
// получит законное снятие в `MissingRows`, то есть план объявит отказ там, где
// применение пройдёт, а следующий пуск состоится.
//
// # Чего здесь НЕТ, и это сказано прямо
//
// О транспорте, правах, операции и подтверждении эти пробы не говорят НИЧЕГО:
// они подают состояние ЗНАЧЕНИЯМИ и спрашивают вердикт. О записи в базу —
// тоже ничего: `Plan` не пишет (`-03`), и здесь писать нечем by construction.
//
// # Что здесь ЗЕЛЕНО сегодня, а что КРАСНО
//
//	зелено   таблица состояний и её достижимость сверкой; неразличимость пары
//	         по счётчикам; провал каждой наивной подмены; РАЗЛИЧИЕ вердиктов
//	         наивного и верного построения гипотетического состояния
//	было красно   вердикт, произведённый ПРОДУКТОМ: производителя в дереве не
//	              было. Производитель заведён (`modulecatalog.PlanAgainstAnchor`),
//	              шов набора закрыт, и обе пробы утверждают ПОВЕДЕНИЕ
//
// Зелёная половина — не украшение: без неё утверждение о производителе зеленело
// бы на любой таблице, а «наивная подмена падает» было бы утверждением о моей
// арифметике, а не о дереве.

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/modulecatalog"
	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/seed"
	"github.com/PRO-Robotech/kacho-iam/internal/catalog"
	"github.com/PRO-Robotech/kacho-iam/internal/manifest"
)

// planVerdict — вердикт плана, как его объявляет §2.11.
type planVerdict string

const (
	wouldApply     planVerdict = "WOULD_APPLY"
	wouldBeRefused planVerdict = "WOULD_BE_REFUSED_BEYOND_ANCHOR"
)

// planVerdictModule — модуль, на котором ставятся состояния.
//
// НЕ синтетический, и это условие годности: опора стража — литерал платформы
// (`seed.LiteralRows()`), и строка синтетического модуля лежала бы вне опоры при
// ЛЮБОМ состоянии, то есть все четыре состояния дали бы один вердикт.
const planVerdictModule = "vpc"

// planVerdictSpareResource — ресурс модуля, на снятии и оживлении которого
// строятся состояния `-36а` и `-36б`.
//
// Выбран НЕ произвольно: он единственный из девяти ресурсов `vpc`, на который не
// ссылается ни одна проекция посеянной СИСТЕМНОЙ роли (замер по живой базе —
// `role_rule_ref` 0, `role_verb` 0, `role_rule_selectors` 0 против 6/0/4 у
// соседей). Здесь, в пробе над значениями, проекций нет вовсе, и выбор
// безразличен; он назван затем, чтобы интеграционная половина набора
// (`module_catalog_anchor_bound_apply_integration_test.go`) строила ТЕ ЖЕ
// состояния на той же строке, а не на своей.
const planVerdictSpareResource = "addressPool"

// planVerdictProducer — вердикт, произведённый ПРОДУКТОМ по состоянию каталога и
// объявленным строкам.
//
// ШОВ НАБОРА, и он ЗАКРЫТ: здесь стоял отказ «производителя в дереве нет», а
// набор падал УТВЕРЖДЕНИЕМ, называющим отсутствующее свойство. Производитель
// заведён (`modulecatalog.PlanAgainstAnchor`), и шов свёлся к одному вызову.
//
// Состояние подаётся ОБЕИМИ половинами позиционно: конструктор
// `NewCatalogState(live, retired)` пропустить снятую сторону не даёт, поэтому
// наивное построение, от которого предостерегает §2.11, здесь не выразимо — что
// и утверждает `TestPlanHypotheticalStateCarriesTheRetiredSideToo`.
func planVerdictProducer(live, retired catalog.Rows, declared modulecatalog.Declared) (planVerdict, error) {
	plan, err := modulecatalog.PlanAgainstAnchor(
		context.Background(), modulecatalog.NewCatalogState(live, retired), declared, seed.ImageAnchor())
	return planVerdict(plan.Verdict), err
}

// planState — одно состояние набора: каталог ДО применения плюс объявленные
// строки, вместе с исходом, которого требует приёмка.
type planState struct {
	// id — идентификатор сценария приёмки, дословно.
	id string
	// what — что именно это состояние изображает.
	what string
	// live / retired — каталог ПЛАТФОРМЫ до применения, обе половины.
	live    catalog.Rows
	retired catalog.Rows
	// declared — строки, объявленные манифестом модуля.
	declared modulecatalog.Declared
	// wantVerdict — вердикт, которого требует приёмка.
	wantVerdict planVerdict
	// wantWritten / wantWithdrawn — счётчики РЕСУРСОВ, которыми таблица §5
	// показывает неразличимость пары.
	wantWritten   int
	wantWithdrawn int
	// naiveDiffers — на этом состоянии НАИВНОЕ построение гипотетического
	// состояния (только живое множество) даёт ДРУГОЙ вердикт, чем верное.
	naiveDiffers bool
}

// TestPlanCountersCannotYieldTheVerdict — ЗАМОК: пара `-36`/`-36б` неразличима по
// счётчикам плана и требует противоположных вердиктов, а каждая наивная подмена
// падает хотя бы на одном состоянии набора.
//
// Зелена и до работы, и после: она утверждает не производителя, а СВОЙСТВО
// ЗАДАЧИ — что вердикт из чисел не выводится. Без неё проба производителя
// зеленела бы на подмене `written > 0`, и требование §2.11 «позвать сверку»
// держалось бы только на вид.
func TestPlanCountersCannotYieldTheVerdict(t *testing.T) {
	states := planStates(t)

	// ПРЕДПОСЫЛКА НАБОРА печатается всегда: «ноль находок» обязано быть отличимо
	// от «ноль прочитанного».
	anchor := seed.LiteralRows()
	t.Logf("перепись опоры: модулей %d, ресурсов %d, глаголов %d; состояний в наборе %d",
		len(anchor.Modules), len(anchor.Resources), len(anchor.Verbs), len(states))
	require.NotEmpty(t, anchor.Resources, "опора пуста: набор беспредметен")
	require.Len(t, states, 4, "набор обязан нести все четыре состояния таблицы §5")

	// Половина первая: таблица приёмки ДОСТИЖИМА сверкой над верно построенным
	// гипотетическим состоянием. Без неё всё остальное утверждало бы мою
	// арифметику, а не дерево.
	byID := map[string]planState{}
	for _, s := range states {
		byID[s.id] = s
		gotVerdict := verdictByTheAnchor(t, s, false)
		gotWritten, gotWithdrawn := referenceCounters(s.live, s.declared)
		t.Logf("%s (%s): записано %d снято %d вердикт %s",
			s.id, s.what, gotWritten, gotWithdrawn, gotVerdict)
		require.Equalf(t, s.wantVerdict, gotVerdict,
			"%s: сверка над гипотетическим состоянием дала не тот вердикт, который называет приёмка", s.id)
		require.Equalf(t, s.wantWritten, gotWritten, "%s: счётчик записанных ресурсов", s.id)
		require.Equalf(t, s.wantWithdrawn, gotWithdrawn, "%s: счётчик снимаемых ресурсов", s.id)
	}

	// Половина вторая — НЕСУЩАЯ: пара неразличима по счётчикам и противоположна
	// по вердикту.
	brick, revive := byID["IAM-MA-1-36"], byID["IAM-MA-1-36б"]
	bw, bd := referenceCounters(brick.live, brick.declared)
	rw, rd := referenceCounters(revive.live, revive.declared)
	require.Equal(t, [2]int{bw, bd}, [2]int{rw, rd},
		"пара -36/-36б обязана быть НЕРАЗЛИЧИМА по счётчикам — иначе она ничего не различает")
	require.NotEqual(t, brick.wantVerdict, revive.wantVerdict,
		"пара -36/-36б обязана требовать ПРОТИВОПОЛОЖНЫХ вердиктов")

	// Половина третья: каждая наивная подмена падает хотя бы на одном состоянии.
	// Перечень взят дословно из врезки §5 приёмки.
	naive := []struct {
		name string
		says func(written, withdrawn int) planVerdict
	}{
		{"written > 0", func(w, _ int) planVerdict { return refusedIf(w > 0) }},
		{"withdrawn > 0", func(_, d int) planVerdict { return refusedIf(d > 0) }},
		{"written > 0 && withdrawn == 0", func(w, d int) planVerdict { return refusedIf(w > 0 && d == 0) }},
	}
	for _, n := range naive {
		fell := make([]string, 0, len(states))
		for _, s := range states {
			w, d := referenceCounters(s.live, s.declared)
			if n.says(w, d) != s.wantVerdict {
				fell = append(fell, s.id)
			}
		}
		t.Logf("наивная подмена «%s» расходится с приёмкой на: %v", n.name, fell)
		require.NotEmptyf(t, fell,
			"наивная подмена «%s» согласна с приёмкой на ВСЕХ четырёх состояниях: "+
				"набор не различает функцию от счётчиков и сверку, то есть не держит §2.11", n.name)
	}
}

// TestPlanVerdictMatchesTheAnchorOnEachOfTheFourStates — вердикт, произведённый
// ПРОДУКТОМ, совпадает с тем, который называет приёмка, на каждом из четырёх
// состояний.
//
// Отрицание (`-36` отвергается) стоит здесь В ПАРЕ с положительным контролем
// (`-02`, `-36а`, `-36б` проходят): без пары проба зеленела бы на производителе,
// объявляющем отказ на всём.
func TestPlanVerdictMatchesTheAnchorOnEachOfTheFourStates(t *testing.T) {
	states := planStates(t)
	t.Logf("перепись: состояний %d, из них ждут %s — %d",
		len(states), wouldApply, countWanting(states, wouldApply))

	for _, s := range states {
		t.Run(s.id, func(t *testing.T) {
			got, err := planVerdictProducer(s.live, s.retired, s.declared)
			require.NoErrorf(t, err,
				"%s (%s): вердикт плана не производится — оператор не отличит починку от кирпича",
				s.id, s.what)
			require.Equalf(t, s.wantVerdict, got, "%s (%s): вердикт плана", s.id, s.what)
		})
	}
}

// TestPlanHypotheticalStateCarriesTheRetiredSideToo — гипотетическое состояние
// после применения подаётся стражу ОБЕИМИ половинами: живой и снятой.
//
// Ловушка §2.11: порт `seed.CatalogSource` двухметодный, и реализация в памяти,
// подающая только живое множество, получит законное снятие в `MissingRows` — то
// есть план объявит `WOULD_BE_REFUSED` там, где применение пройдёт, а следующий
// пуск состоится. План соврёт, а проба на этой лжи позеленеет, потому что
// наивное построение даёт ровно тот вердикт, которого ждёт круг 1–3.
//
// Контроль НЕВАКУУМНОСТИ исполняется первым: на состоянии `-36а` два построения
// обязаны РАСХОДИТЬСЯ, иначе утверждать нечего.
func TestPlanHypotheticalStateCarriesTheRetiredSideToo(t *testing.T) {
	states := planStates(t)

	traps := 0
	for _, s := range states {
		byAnchor := verdictByTheAnchor(t, s, false)
		byNaive := verdictByTheAnchor(t, s, true)
		if s.naiveDiffers {
			traps++
			require.NotEqualf(t, byAnchor, byNaive,
				"%s: наивное построение обязано РАСХОДИТЬСЯ с верным, иначе ловушки нет "+
					"и проба ниже ничего не ловит", s.id)
			require.Equalf(t, wouldBeRefused, byNaive,
				"%s: наивное построение обязано дать именно ложный ОТКАЗ — это и есть ложь плана", s.id)
		} else {
			require.Equalf(t, byAnchor, byNaive,
				"%s: состояние объявлено неразличающим, а построения разошлись — таблица набора неверна", s.id)
		}
		t.Logf("%s: верное построение %s, наивное (только живое множество) %s", s.id, byAnchor, byNaive)
	}
	require.Positive(t, traps,
		"ни на одном состоянии наивное построение не расходится с верным: ловушка не воспроизведена")
	t.Logf("перепись: состояний %d, различающих наивное построение %d", len(states), traps)

	// Красная половина: продукт обязан дать вердикт ВЕРНОГО построения.
	for _, s := range states {
		if !s.naiveDiffers {
			continue
		}
		got, err := planVerdictProducer(s.live, s.retired, s.declared)
		require.NoErrorf(t, err,
			"%s: вердикт плана не производится — подать стражу одно живое множество нечему, "+
				"и ловушка §2.11 остаётся неохраняемой", s.id)
		require.Equalf(t, s.wantVerdict, got,
			"%s: план подал стражу ОДНО живое множество: законное снятие приехало отказом", s.id)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Фикстура

// planStates — четыре состояния таблицы §5, собранные над ЖИВЫМ манифестом
// модуля и ЛИТЕРАЛОМ платформы.
//
// Манифест берётся из дерева, а не выписывается: выписанный разошёлся бы с
// доставляемым молча, и фикстура стала бы снисходительнее продукта.
func planStates(t *testing.T) []planState {
	t.Helper()

	base := seed.LiteralRows()
	declared := declaredRowsOfShippedModule(t, planVerdictModule)

	// Состояния строятся сдвигом ОДНОЙ строки, и строка эта названа: так
	// расхождение вердиктов нельзя списать на разный объём фикстуры.
	spare, ok := findResource(declared.Resources, planVerdictModule, planVerdictSpareResource)
	require.Truef(t, ok, "манифест модуля %s не объявляет ресурса %s — фикстура беспредметна",
		planVerdictModule, planVerdictSpareResource)
	spareVerbs := verbsOf(declared.Verbs, spare.Module, spare.Resource)
	require.NotEmpty(t, spareVerbs, "у ресурса фикстуры нет ни одного действия: снимать нечего")

	beyond := catalog.ResourceRow{
		Module: planVerdictModule, Resource: "probeBeyondAnchor",
		ObjectType: "vpc_probe_beyond_anchor",
	}
	beyondVerb := catalog.VerbRow{
		Module: beyond.Module, Resource: beyond.Resource, Verb: "get", PerObject: true,
	}
	drift := catalog.ResourceRow{
		Module: planVerdictModule, Resource: "probeDrift", ObjectType: "vpc_probe_drift",
	}

	// `-36а`: манифест перестал объявлять запасной ресурс.
	narrowed := modulecatalog.Declared{
		Module:    declared.Module,
		Resources: withoutResource(declared.Resources, spare),
		Verbs:     withoutVerbsOf(declared.Verbs, spare),
	}
	// `-36`: манифест объявляет строку, которой опора не знает.
	widened := modulecatalog.Declared{
		Module:    declared.Module,
		Resources: append(append([]catalog.ResourceRow{}, declared.Resources...), beyond),
		Verbs:     append(append([]catalog.VerbRow{}, declared.Verbs...), beyondVerb),
	}

	// `-36б`: запасной ресурс СНЯТ в базе, а манифест его объявляет.
	revivedLive := catalog.Rows{
		Modules:   base.Modules,
		Resources: withoutResource(base.Resources, spare),
		Verbs:     withoutVerbsOf(base.Verbs, spare),
	}
	revivedRetired := catalog.Rows{Resources: []catalog.ResourceRow{spare}, Verbs: spareVerbs}

	// `-02`: дрейф вне продукта — лишняя живая строка, которой не знает ни
	// манифест, ни опора.
	driftedLive := catalog.Rows{
		Modules:   base.Modules,
		Resources: append(append([]catalog.ResourceRow{}, base.Resources...), drift),
		Verbs:     base.Verbs,
	}

	return []planState{
		{
			id: "IAM-MA-1-02", what: "дрейф вне продукта, манифест равен опоре",
			live: driftedLive, retired: catalog.Rows{}, declared: declared,
			wantVerdict: wouldApply, wantWritten: 0, wantWithdrawn: 1,
		},
		{
			id: "IAM-MA-1-36", what: "манифест ШИРЕ опоры",
			live: base, retired: catalog.Rows{}, declared: widened,
			wantVerdict: wouldBeRefused, wantWritten: 1, wantWithdrawn: 0,
		},
		{
			id: "IAM-MA-1-36а", what: "манифест У́ЖЕ опоры",
			live: base, retired: catalog.Rows{}, declared: narrowed,
			wantVerdict: wouldApply, wantWritten: 0, wantWithdrawn: 1,
			naiveDiffers: true,
		},
		{
			id: "IAM-MA-1-36б", what: "ОЖИВЛЕНИЕ снятой строки, которую опора объявляет",
			live: revivedLive, retired: revivedRetired, declared: declared,
			wantVerdict: wouldApply, wantWritten: 1, wantWithdrawn: 0,
		},
	}
}

// declaredRowsOfShippedModule — строки, объявленные ДОСТАВЛЯЕМЫМ манифестом
// модуля. Читаются из дерева тем же путём, каким их читает применитель.
func declaredRowsOfShippedModule(t *testing.T, module string) modulecatalog.Declared {
	t.Helper()
	path := filepath.Join(manifestsRoot, module, "manifest.yaml")
	body, err := os.ReadFile(path) // #nosec G304 -- путь собран из константы пакета проб
	require.NoErrorf(t, err, "прочитать манифест %s", path)
	m, err := manifest.Load(body)
	require.NoErrorf(t, err, "разобрать манифест %s", path)
	d, err := modulecatalog.RowsOf(m)
	require.NoErrorf(t, err, "вывести строки каталога из манифеста %s", path)
	require.NotEmptyf(t, d.Resources, "манифест %s не даёт строк: фикстура беспредметна", path)
	return d
}

// hypotheticalRows — состояние каталога ПОСЛЕ применения объявленных строк.
//
// Обе половины, и это предмет ловушки: объявленное становится живым (в том числе
// ОЖИВАЕТ из снятого), живое этого модуля вне объявленного становится СНЯТЫМ и
// остаётся свидетельством. Строки чужих модулей не двигаются: применитель
// применяет один названный манифест (`apply.go`, п. 1 шапки).
func hypotheticalRows(live, retired catalog.Rows, d modulecatalog.Declared) (catalog.Rows, catalog.Rows) {
	declaredRes := map[string]bool{}
	for _, r := range d.Resources {
		declaredRes[r.Module+"."+r.Resource] = true
	}
	declaredVerb := map[string]bool{}
	for _, v := range d.Verbs {
		declaredVerb[v.Module+"."+v.Resource+"."+v.Verb] = true
	}

	var nextLive, nextRetired catalog.Rows

	nextLive.Modules = append(nextLive.Modules, live.Modules...)
	if !containsString(nextLive.Modules, d.Module) {
		nextLive.Modules = append(nextLive.Modules, d.Module)
	}
	for _, m := range retired.Modules {
		if m != d.Module {
			nextRetired.Modules = append(nextRetired.Modules, m)
		}
	}

	for _, r := range live.Resources {
		switch {
		case r.Module != d.Module:
			nextLive.Resources = append(nextLive.Resources, r)
		case declaredRes[r.Module+"."+r.Resource]:
			// объявленную строку кладёт цикл ниже — здесь она пропускается, чтобы
			// не задвоиться формой, которую объявил манифест.
		default:
			nextRetired.Resources = append(nextRetired.Resources, r)
		}
	}
	for _, r := range retired.Resources {
		if !declaredRes[r.Module+"."+r.Resource] {
			nextRetired.Resources = append(nextRetired.Resources, r)
		}
	}
	nextLive.Resources = append(nextLive.Resources, d.Resources...)

	for _, v := range live.Verbs {
		switch {
		case v.Module != d.Module:
			nextLive.Verbs = append(nextLive.Verbs, v)
		case declaredVerb[v.Module+"."+v.Resource+"."+v.Verb]:
		default:
			nextRetired.Verbs = append(nextRetired.Verbs, v)
		}
	}
	for _, v := range retired.Verbs {
		if !declaredVerb[v.Module+"."+v.Resource+"."+v.Verb] {
			nextRetired.Verbs = append(nextRetired.Verbs, v)
		}
	}
	nextLive.Verbs = append(nextLive.Verbs, d.Verbs...)

	return nextLive, nextRetired
}

// verdictByTheAnchor — вердикт, который даёт СТРАЖ над гипотетическим состоянием.
//
// `naive` истинно — снятая половина не подаётся вовсе: ровно то построение, от
// которого предостерегает §2.11.
func verdictByTheAnchor(t *testing.T, s planState, naive bool) planVerdict {
	t.Helper()
	nextLive, nextRetired := hypotheticalRows(s.live, s.retired, s.declared)
	if naive {
		nextRetired = catalog.Rows{}
	}
	census, _ := seed.AssertCatalogParity(context.Background(), &planStubSource{live: nextLive, retired: nextRetired}, seed.ImageAnchor())
	return refusedIf(census.Diverged())
}

// referenceCounters — счётчики РЕСУРСОВ, которыми таблица §5 показывает
// неразличимость пары: записано (заведено либо оживлено) и снято.
//
// Тот же ключ, каким адресует строку схема (`catalog_resource_pkey`), и та же
// форма, какую сверяет `UpsertResource` (пара плюс имя типа модели).
func referenceCounters(live catalog.Rows, d modulecatalog.Declared) (written, withdrawn int) {
	liveByKey := map[string]catalog.ResourceRow{}
	for _, r := range live.Resources {
		liveByKey[r.Module+"."+r.Resource] = r
	}
	for _, r := range d.Resources {
		cur, ok := liveByKey[r.Module+"."+r.Resource]
		if !ok || cur.ObjectType != r.ObjectType {
			written++
		}
	}
	declaredRes := map[string]bool{}
	for _, r := range d.Resources {
		declaredRes[r.Module+"."+r.Resource] = true
	}
	for _, r := range live.Resources {
		if r.Module == d.Module && !declaredRes[r.Module+"."+r.Resource] {
			withdrawn++
		}
	}
	return written, withdrawn
}

// planStubSource — порт стража над значениями. ДВУХметодный, как и настоящий:
// одностороннюю реализацию набор подаёт явным флагом, а не молчаливым пропуском.
type planStubSource struct {
	live    catalog.Rows
	retired catalog.Rows
}

func (s *planStubSource) ReadLiveCatalog(_ context.Context) (catalog.Rows, error) {
	return s.live, nil
}

func (s *planStubSource) ReadRetiredCatalog(_ context.Context) (catalog.Rows, error) {
	return s.retired, nil
}

func refusedIf(cond bool) planVerdict {
	if cond {
		return wouldBeRefused
	}
	return wouldApply
}

func countWanting(states []planState, v planVerdict) int {
	n := 0
	for _, s := range states {
		if s.wantVerdict == v {
			n++
		}
	}
	return n
}

func findResource(rows []catalog.ResourceRow, module, resource string) (catalog.ResourceRow, bool) {
	for _, r := range rows {
		if r.Module == module && r.Resource == resource {
			return r, true
		}
	}
	return catalog.ResourceRow{}, false
}

func verbsOf(rows []catalog.VerbRow, module, resource string) []catalog.VerbRow {
	var out []catalog.VerbRow
	for _, v := range rows {
		if v.Module == module && v.Resource == resource {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Verb < out[j].Verb })
	return out
}

func withoutResource(rows []catalog.ResourceRow, drop catalog.ResourceRow) []catalog.ResourceRow {
	out := make([]catalog.ResourceRow, 0, len(rows))
	for _, r := range rows {
		if r.Module == drop.Module && r.Resource == drop.Resource {
			continue
		}
		out = append(out, r)
	}
	return out
}

func withoutVerbsOf(rows []catalog.VerbRow, drop catalog.ResourceRow) []catalog.VerbRow {
	out := make([]catalog.VerbRow, 0, len(rows))
	for _, v := range rows {
		if v.Module == drop.Module && v.Resource == drop.Resource {
			continue
		}
		out = append(out, v)
	}
	return out
}

func containsString(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
