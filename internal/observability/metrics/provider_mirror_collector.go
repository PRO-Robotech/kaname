// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Витрина ОКНА ПРЕЖНЕГО ИЗДАТЕЛЯ — строки удостоверений, чьё зеркало у
// внешнего OAuth-сервера ещё предъявимо (эпик kacho#2564, линия B).
//
// # Предмет
//
// Снятие внешнего OAuth-сервера идёт ПОСЛЕДНИМ в линии и только когда «окно
// предъявленного закрыто счётом, а не сроком»: у строк прежнего выпуска
// зеркало клиента живёт у него, и токены, отчеканенные для них, действительны до
// собственного истечения — платформа их не отзывает и отозвать не может. Пока
// таких строк не ноль, снятие лишает их имени, которым их резолвит его хук.
//
// Величина названа эпиком одной из трёх, каждая из которых не ноль до снятия и
// ноль после: путей выдачи на провайдере · профилей, доверяющих прежнему
// издателю · СТРОК С ЗЕРКАЛОМ В БАЗЕ. Первые две — свойства дерева и профиля,
// третья — свойство базы стенда, и без ряда на витрине её «считали бы запросом»
// только тот, кто о запросе вспомнил.
//
// # Что считается зеркалом — по таблице, и разница несущая
//
//	service_account_oauth_clients   hydra_client_id IS NOT NULL AND hydra_client_id <> id
//	user_oauth_clients              hydra_client_id IS NOT NULL
//
// У ключей служебной учётки колонка НЕ пуста и на переведённом контуре: там она
// несёт НАШЕ имя клиента, равное идентификатору строки (`sa_keys.nameClient`), и
// ограничение схемы требует её непустой у KEYPAIR/FEDERATED. Зеркало — то, что
// от нашего имени ОТЛИЧАЕТСЯ. У токенов пользователя зеркала на переведённом
// контуре нет вовсе: колонка пуста, непустая — строка прежнего выпуска.
//
// # Почему ряд — мгновенная величина, а не счётчик
//
// Окно ЗАКРЫВАЕТСЯ, то есть величина обязана уметь падать до нуля и там стоять:
// ноль здесь не «ничего не случалось», а «предмет снятия исчерпан». Счётчик на
// падающем ряде не определён; здесь падение и есть искомый исход.
//
// # Почему рядом ОБЯЗАТЕЛЕН счётчик снятых замеров
//
// До первого успешного замера величина равна нулю, и «окно закрыто» с «замер не
// работает» дают на витрине одну картину — ровно то различие, ради которого
// величина заводится: ноль по этому ряду открывает необратимое снятие. Отличает
// их второй ряд: пока `samples_total{outcome="ok"}` растёт, ноль означает ноль.
const (
	// ProviderMirrorRowsMetric — строк с зеркалом у прежнего издателя, по таблице.
	ProviderMirrorRowsMetric = "kaname_provider_mirror_rows"

	// ProviderMirrorSamplesMetric — исходы фонового замера окна.
	ProviderMirrorSamplesMetric = "kaname_provider_mirror_samples_total"

	// ProviderMirrorTableServiceAccountKeys и ProviderMirrorTableUserTokens —
	// значения метки `table`: имена таблиц как они лежат в схеме.
	ProviderMirrorTableServiceAccountKeys = "service_account_oauth_clients"
	ProviderMirrorTableUserTokens         = "user_oauth_clients"

	// ProviderMirrorSampleOK — замер прочитал обе таблицы.
	ProviderMirrorSampleOK = "ok"
	// ProviderMirrorSampleError — замер не прочитал хотя бы одну.
	ProviderMirrorSampleError = "error"
)

// ProviderMirrorTables — закрытый набор клеток метки `table`.
var ProviderMirrorTables = []string{
	ProviderMirrorTableServiceAccountKeys,
	ProviderMirrorTableUserTokens,
}

// ProviderMirrorSampleOutcomes — закрытый набор клеток исхода замера.
var ProviderMirrorSampleOutcomes = []string{
	ProviderMirrorSampleOK,
	ProviderMirrorSampleError,
}

// ProviderMirrorCounts — то, что витрина читает у замерщика.
type ProviderMirrorCounts struct {
	// ServiceAccountKeys — строк с зеркалом среди ключей служебных учёток.
	ServiceAccountKeys int64
	// UserTokens — строк с зеркалом среди токенов пользователей.
	UserTokens int64
	// SamplesOK — успешных замеров за жизнь процесса.
	SamplesOK uint64
	// SamplesFailed — отказавших замеров за жизнь процесса.
	SamplesFailed uint64
}

type providerMirrorCollector struct {
	read func() ProviderMirrorCounts

	rows    *prometheus.Desc
	samples *prometheus.Desc
}

// NewProviderMirrorCollector регистрирует читателя величин окна прежнего издателя.
//
// nil-источник — ОТКАЗ, по той же причине, что у соседних коллекторов: вечный
// ноль здесь выглядит закрытым окном и открывает необратимое снятие, тогда как
// замерщика просто забыли подключить.
func (r *Registry) NewProviderMirrorCollector(read func() ProviderMirrorCounts) {
	if read == nil {
		panic("metrics: NewProviderMirrorCollector без источника величин — " +
			"вечный ноль неотличим от закрытого окна и открывает снятие прежнего издателя")
	}
	c := &providerMirrorCollector{
		read: read,
		rows: prometheus.NewDesc(
			ProviderMirrorRowsMetric,
			"Credential rows whose client mirror at the previous external OAuth server "+
				"is still presentable, per table. For "+ProviderMirrorTableServiceAccountKeys+
				" a mirror is a non-empty hydra_client_id that differs from the row id (our own "+
				"contour writes our own name there); for "+ProviderMirrorTableUserTokens+
				" any non-empty hydra_client_id. Zero in both rows is the measured half of the "+
				"readiness predicate for retiring the previous issuer (kacho#2564); read it "+
				"together with "+ProviderMirrorSamplesMetric+" — before the first successful "+
				"sample the value is zero for a reason unrelated to the database.",
			[]string{"table"}, nil,
		),
		samples: prometheus.NewDesc(
			ProviderMirrorSamplesMetric,
			"Outcomes of the background sampling of the provider-mirror window (ok|error). "+
				"Exists so that a zero in "+ProviderMirrorRowsMetric+" is distinguishable from a "+
				"sampler that never ran.",
			[]string{"outcome"}, nil,
		),
	}
	r.reg.MustRegister(c)
}

// Describe — семейства видны и до первого сбора.
func (c *providerMirrorCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.rows
	ch <- c.samples
}

// Collect отдаёт обе таблицы и ОБЕ клетки исхода замера, включая нулевые:
// отсутствующий ряд читается как «такого не бывает», а нужен ответ «ноль».
func (c *providerMirrorCollector) Collect(ch chan<- prometheus.Metric) {
	counts := c.read()
	ch <- prometheus.MustNewConstMetric(c.rows, prometheus.GaugeValue,
		float64(counts.ServiceAccountKeys), ProviderMirrorTableServiceAccountKeys)
	ch <- prometheus.MustNewConstMetric(c.rows, prometheus.GaugeValue,
		float64(counts.UserTokens), ProviderMirrorTableUserTokens)
	for outcome, value := range map[string]uint64{
		ProviderMirrorSampleOK:    counts.SamplesOK,
		ProviderMirrorSampleError: counts.SamplesFailed,
	} {
		ch <- prometheus.MustNewConstMetric(c.samples, prometheus.CounterValue,
			float64(value), outcome)
	}
}
