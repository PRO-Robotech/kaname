// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Витрина РОСТА ЧИСЛА ЛИЧНОСТЕЙ — страховка платформы, а не мера.
//
// # Предмет
//
// Потолок на число аккаунтов одной личности обходится заведением личностей:
// регистрация самообслуживаемая и стоит подтверждённого адреса. Потолок темпа
// удорожает автоматизацию, но не ловит МЕДЛЕННОЕ накопление, а его не
// производила ни одна величина: рост числа личностей не наблюдался ничем.
//
// Отказ по такому порогу пришёл бы СЛЕДУЮЩЕМУ честному человеку, а не тому, кто
// исчерпал полку, — поэтому сначала ВИДНО, и только потом, отдельным решением,
// отказ.
//
// # Почему величина накопительная, а не мгновенная
//
// Мгновенный счёт личностей немонотонен: человек уходит, и величина падает. На
// падающем ряде РОСТ не определён — `increase()` молчит там, где рост и был, — а
// «личностей ноль» перестаёт быть утверждением о всей жизни платформы. Журнал
// (`kacho_iam.identity_journal`) рядов не снимает никогда, поэтому здесь величина
// объявлена СЧЁТЧИКОМ: над ней осмысленны и `increase()`, и `rate()`.
//
// # Почему рядом ОБЯЗАТЕЛЕН счётчик снятых замеров
//
// Величина читается фоновым замером и до первого успешного замера равна нулю. То
// есть «личностей за всё время ноль» и «замер не работает» дают на витрине ОДНУ
// И ТУ ЖЕ картину — ровно то различие, ради которого величина и заводилась.
// Отличает их только второй ряд: пока `samples_total{outcome="ok"}` растёт, ноль
// в первом ряду означает ноль. Отказ замера держится своей клеткой, потому что
// «замеров не было» и «замеры отказывают» требуют разных действий.
const (
	// IdentitiesTotalMetric — личности, которые платформа видела за всё время.
	IdentitiesTotalMetric = "kacho_iam_identities_total"

	// IdentityLedgerSamplesMetric — исходы фонового замера журнала.
	IdentityLedgerSamplesMetric = "kacho_iam_identity_ledger_samples_total"

	// IdentityLedgerSampleOK — замер прочитал журнал.
	IdentityLedgerSampleOK = "ok"
	// IdentityLedgerSampleError — замер не прочитал журнал.
	IdentityLedgerSampleError = "error"
)

// IdentityLedgerSampleOutcomes — закрытый набор клеток исхода замера.
var IdentityLedgerSampleOutcomes = []string{
	IdentityLedgerSampleOK,
	IdentityLedgerSampleError,
}

// IdentityGrowthCounts — то, что витрина читает у замерщика.
type IdentityGrowthCounts struct {
	// IdentitiesEverSeen — рядов в накопительном журнале.
	IdentitiesEverSeen int64
	// SamplesOK — успешных замеров за жизнь процесса.
	SamplesOK uint64
	// SamplesFailed — отказавших замеров за жизнь процесса.
	SamplesFailed uint64
}

type identityGrowthCollector struct {
	read func() IdentityGrowthCounts

	identities *prometheus.Desc
	samples    *prometheus.Desc
}

// NewIdentityGrowthCollector регистрирует читателя величин роста числа личностей.
//
// nil-источник — ОТКАЗ, по той же причине, что и у соседних коллекторов: вечный
// ноль выглядит работающим наблюдением и утверждает о платформе неправду —
// «личностей не появлялось», — тогда как на деле замерщика просто забыли
// подключить. Отказ при сборке дешевле молчаливой лжи на витрине.
func (r *Registry) NewIdentityGrowthCollector(read func() IdentityGrowthCounts) {
	if read == nil {
		panic("metrics: NewIdentityGrowthCollector без источника величин — " +
			"вечный ноль неотличим от платформы, на которой не появилось ни одной личности")
	}
	c := &identityGrowthCollector{
		read: read,
		identities: prometheus.NewDesc(
			IdentitiesTotalMetric,
			"Login identities the platform has ever seen, from the accumulating "+
				"ledger kacho_iam.identity_journal. Monotone by construction: rows are "+
				"never removed, not even when a person leaves, so growth is defined on "+
				"it and \"zero over the whole life\" is a statement that can be made. An "+
				"instantaneous count of user rows answers a different question and falls "+
				"when someone leaves.",
			nil, nil,
		),
		samples: prometheus.NewDesc(
			IdentityLedgerSamplesMetric,
			"Outcomes of the background sampling of the identity ledger (ok|error). "+
				"Exists so that a zero in "+IdentitiesTotalMetric+" is distinguishable "+
				"from a sampler that never ran: before the first successful sample the "+
				"count is zero for a reason that has nothing to do with the platform.",
			[]string{"outcome"}, nil,
		),
	}
	r.reg.MustRegister(c)
}

// Describe — семейства видны и до первого сбора.
func (c *identityGrowthCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.identities
	ch <- c.samples
}

// Collect отдаёт величину и ОБЕ клетки исхода замера.
//
// Обе клетки печатаются всегда, включая нулевые: отсутствующий ряд читается как
// «такого не бывает», а нужен ответ «такого не случалось».
func (c *identityGrowthCollector) Collect(ch chan<- prometheus.Metric) {
	counts := c.read()
	ch <- prometheus.MustNewConstMetric(c.identities, prometheus.CounterValue,
		float64(counts.IdentitiesEverSeen))
	for outcome, value := range map[string]uint64{
		IdentityLedgerSampleOK:    counts.SamplesOK,
		IdentityLedgerSampleError: counts.SamplesFailed,
	} {
		ch <- prometheus.MustNewConstMetric(c.samples, prometheus.CounterValue,
			float64(value), outcome)
	}
}
