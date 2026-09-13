// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/PRO-Robotech/kaname/internal/clients"
)

// Перечни берутся у ВЛАДЕЛЬЦА дорог, а не выписываются здесь: второе место об
// одном наборе разошлось бы с первым молча — незнакомая клетка просто не
// завелась бы.
func clientsProviderRoads() []string        { return clients.ProviderRoads }
func clientsProviderRoadOutcomes() []string { return clients.ProviderRoadOutcomes }

// ProviderRoadOutcomesMetric — имя семейства исходов дорог к внешнему
// поставщику личности (kacho#2491, #2492).
const ProviderRoadOutcomesMetric = "kaname_provider_road_outcomes_total"

// ProviderRoadRecorder — счётчик исходов обращения по дороге к поставщику.
//
// # ЗАЧЕМ, ЕСЛИ ОДНА ДОРОГА УЖЕ СЧИТАЕТСЯ
//
// Профиль объявляет ТРИ дороги, считалась ОДНА — набор ключей. Его семейство
// расщепляет ровно два состояния оси: «не ответил» (лечится временем) и «по
// адресу не тот эндпоинт» (не лечится, чинится оператором). Две другие дороги
// такого расщепления не имели, потому что не имели счёта вовсе, — и для
// дежурного «сломан продукт» и «оператор не создал условие» на них были
// неразличимы.
//
// # ПОЧЕМУ ЭТО ОТДЕЛЬНОЕ СЕМЕЙСТВО, А НЕ МЕТКА У ЗЕРКАЛА
//
// У зеркала ключей другой предмет и другой производитель: оно ведёт СВОИ
// счётчики и отдаётся коллектором, читающим их на каждом скрейпе. Дописать ему
// метку дороги значило бы завести второе место об одном предмете и обязать
// зеркало знать про дороги, которых оно не проходит.
//
// # ЧТО ЗНАЧАТ КЛЕТКИ
//
// Разбор — у их объявления (`internal/clients/provider_road.go`), и здесь он не
// пересказывается. Важно следствие для читателя витрины: `absent` называется
// НЕРАЗЛИЧИМЫМ намеренно, и вопрос ему задают ПАРОЙ — растущий `absent` при
// нулевом `ok` на той же дороге есть настройка, а не идемпотентное снятие.
type ProviderRoadRecorder struct {
	outcomes *prometheus.CounterVec
}

// NewProviderRoadRecorder регистрирует счётчик в этом реестре.
//
// Клетки ЗАКРЫТОГО набора заводятся нулём СРАЗУ: без этого «дорога не провязана»
// и «дорога провязана и по ней ни разу не ходили» дают одну и ту же пустоту —
// то есть ровно то различение, ради которого счётчик заведён.
func (r *Registry) NewProviderRoadRecorder() *ProviderRoadRecorder {
	rec := &ProviderRoadRecorder{
		outcomes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: ProviderRoadOutcomesMetric,
			Help: "Исходы обращений по дорогам к внешнему поставщику личности, по дороге (" +
				strings.Join(clientsProviderRoads(), "|") + ") и клетке закрытого набора (" +
				strings.Join(clientsProviderRoadOutcomes(), "|") + "). Успехи считаются наравне " +
				"с отказами, поэтому «отказов не было» отличимо от «по дороге никто не ходил». " +
				"misconfigured стоит своей клеткой, потому что, в отличие от unavailable, " +
				"временем оно не лечится: по адресу не тот эндпоинт. absent — ответ «не " +
				"найдено», НЕРАЗЛИЧИМЫЙ по одному обращению: это либо ресурс, которого у " +
				"поставщика уже нет, либо адрес, где наших ресурсов нет вовсе; различает их " +
				"ПАРА клеток — растущий absent при нулевом ok есть настройка. Дорога набора " +
				"ключей здесь отсутствует намеренно: её исходы ведёт " +
				JWKSMirrorOutcomesMetric + ".",
		}, []string{"road", "outcome"}),
	}
	for _, road := range clientsProviderRoads() {
		for _, outcome := range clientsProviderRoadOutcomes() {
			rec.outcomes.WithLabelValues(road, outcome)
		}
	}
	r.reg.MustRegister(rec.outcomes)
	return rec
}

// ObserveProviderRoad — исход одного обращения. Реализует порт
// clients.ProviderRoadObserver.
func (rec *ProviderRoadRecorder) ObserveProviderRoad(road, outcome string) {
	rec.outcomes.WithLabelValues(road, outcome).Inc()
}

// ProviderRoadRecorder возвращает ЕДИНСТВЕННЫЙ экземпляр счётчика этого реестра.
//
// Потребителей несколько и собираются они в разных местах композиционного корня
// (административный клиент строится своим помощником, дорога обмена — сборщиком
// докерной полосы). Два независимых вызова конструктора уронили бы старт на
// повторной регистрации — и уронили бы именно тогда, когда счёт наконец
// провязали по всем дорогам.
func (r *Registry) ProviderRoadRecorder() *ProviderRoadRecorder {
	r.providerRoadOnce.Do(func() { r.providerRoad = r.NewProviderRoadRecorder() })
	return r.providerRoad
}
